//! TC program bodies: `lan_ingress`, `wan_egress`, `silk0peer_ingress`,
//! `silk0_ingress`.
//!
//! Capture (lan_ingress / wan_egress): decide() in the kernel; DIRECT passes
//! into the host stack untouched, BLOCK is shot, PROXY publishes FLOW_TRACK
//! framing and redirects the skb into `silk0` (host side of the pair bridging
//! into the `silkns` proxy namespace). "PROXY" means any node verdict
//! (VERDICT_NODE_BASE + i); the verdict is recorded in FLOW_TRACK so userspace
//! knows which node the flow belongs to.
//!
//! Reply (silk0_ingress): reverse-lookup FLOW_TRACK, restore original framing,
//! TX back to the LAN client or inject into WAN RX (BPF_F_INGRESS) so the
//! host stack delivers the packet to the originating socket.
//!
//! [方案九] 每个 capture hook 有 L2 / L3 两个入口（`lan_ingress` /
//! `lan_ingress_l3`，`wan_egress` / `wan_egress_l3`），用户态按接口的
//! ARPHRD 选择。L3（裸 IP）设备上的包在转向 silk0 之前补一个以太网头；
//! 回程 `bpf_redirect` 到 L3 设备时内核自己剥掉它。
//!
//! [方案十] TCP 判决只在 SYN 时产生：已在 FLOW_TRACK 里的代理 TCP 流，
//! 后续非 SYN 包直接沿用记录的判决，不再重跑规则（honk 的 forward-SYN-only
//! publication）。新 SYN 写不进 FLOW_TRACK 时 fail-closed 丢弃。
//!
//! [方案十一] 判决落地与回程时按 verdict 记 per-node 流量（NODE_STATS）。
//!
//! [方案十二] LAN ingress 可选 `bpf_redirect_peer`（内核 >= 6.8）。

use crate::action::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC, Verdict};
use crate::fragment;
use crate::maps::{
    cgroup_mode, datapath_ready, is_control_plane_socket, route_generation, FLOW_DECISION,
    FLOW_TRACK, PARAM,
};
use crate::observability;
use crate::packet::{dst_is_special, is_vlan_tagged, l3_link_type, parse, Pkt, ETH_HLEN};
use crate::routing::{decide_flow, decide_forced};
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::{
    bpf_redirect, bpf_redirect_peer, bpf_skb_change_head, bpf_skb_store_bytes,
};
use silk_ebpf_common::{
    verdict_is_proxy, CGROUP_MODE_BYPASS, DNS_PORT, FlowKey, IPPROTO_TCP, TrackEntry,
    CLASSIFIED_MARK, FLOW_TRACK_REFRESH_NS, LINK_L2, LINK_L3, TCP_STATE_CLOSING, TCP_STATE_OPEN,
    VERDICT_BLOCK, VERDICT_DIRECT, VERDICT_NODE_BASE,
};

const PACKET_HOST: u32 = 0;
const PACKET_OTHERHOST: u32 = 1;
const BPF_F_INGRESS: u64 = 1;

// Ethernet MAC field offsets (network_types::eth::EthHdr layout).
const OFF_ETH_DST: u32 = 0;
const OFF_ETH_SRC: u32 = 6;

/// Common capture path shared by lan_ingress and wan_egress.
/// `link` 是捕获接口的链路类型（LINK_L2 / LINK_L3），见方案九。
#[inline(always)]
fn do_capture(ctx: &TcContext, from_wan: u8, link: u8) -> Verdict {
    // [方案七] 准入门控：hook 已 attach、但静态规则 / 监听器 / recv 循环
    // 尚未就绪的窗口里，一律让包走原栈（fail-open），既不误代理也不丢包。
    // 对齐 honk 每个 TC 入口的 `datapath_ready()` 检查。
    if !datapath_ready() {
        return Ok(TC_ACT_OK);
    }
    let in_mark = unsafe { (*ctx.skb.skb).mark };
    // [方案一] 已判决包的快速通道：LAN ingress 判为 DIRECT 的包会被内核
    // 转发到 WAN egress，第二次进入 capture hook 时在这里直接放行，省掉
    // 重复解析与判决（honk 的 CLASSIFIED_MARK 思路）。控制面 socket 带的是
    // CONTROL_MARK，不含这一位，不会误伤。
    if in_mark & CLASSIFIED_MARK != 0 {
        return Ok(TC_ACT_OK);
    }
    if is_control_plane_socket(ctx.skb.skb) {
        // Control plane's own dials (SOCKS5, DNS upstream) must never loop.
        return Ok(TC_ACT_OK);
    }
    // Per-process policy: only host-originated packets carry a socket (and so
    // a cgroup); forwarded LAN traffic never matches.
    let param = PARAM.load();
    let mut forced_node = 0u8;
    if from_wan == 1 && param.cgroup_rules != 0 {
        let mode = cgroup_mode(ctx.skb.skb);
        if mode == CGROUP_MODE_BYPASS {
            return Ok(TC_ACT_OK);
        }
        if mode >= VERDICT_NODE_BASE {
            forced_node = mode;
        }
    }

    // [方案九] 硬件卸载的 VLAN 标签：交给 VLAN 子接口上的 hook。帧内
    // 802.1Q/802.1ad 标签由 parse() 直接放过。
    if is_vlan_tagged(ctx, link) {
        observability::count_vlan_passed();
        return Err(TC_ACT_UNSPEC);
    }

    let pkt = parse(ctx, link)?;

    // [方案七] 基础设施流量直通：L2 广播/组播、0.0.0.0、
    // 255.255.255.255、224.0.0.0/4、ff00::/8 与 veth own-link。
    // 必须排在 decide()（尤其 UDP/53 劫持）之前，并且不打任何 mark：
    // 用户态 CIDR 表达不了 L2 广播 MAC，而用户规则可以用更具体的 LPM
    // 覆盖私有直连。见 packet::dst_is_special。
    if dst_is_special(&pkt) {
        return Ok(TC_ACT_OK);
    }

    // [方案四] 非首片优先继承首片判决；没有记录（TTL 过期 / ID 首次出现）
    // 才退回原来的地址级规则。这样同一数据报的剩余分片不会各自判一次，
    // 也不会出现「首片进代理、后续片直连」的半截连接。
    if pkt.is_fragment {
        let inherited = fragment::inherited(&pkt);
        if inherited == VERDICT_BLOCK {
            observability::count_block();
            return Err(TC_ACT_SHOT);
        }
        if verdict_is_proxy(inherited) {
            observability::count_frag_inherited();
            observability::node_tx(inherited, ctx.skb.len());
            // 非首片读不到五元组端口，绝不能用垃圾端口写 FLOW_TRACK：
            // 回程查的是首片建立的那条真实五元组记录，多写只会污染表。
            return steer_to_silkns(ctx, from_wan, link);
        }
    }

    // [方案十] TCP 判决钉在 SYN 上。已被代理的 TCP 流（FLOW_TRACK 里有
    // 记录），后续非 SYN 包直接沿用记录的判决，不再查 FLOW_DECISION / 规则表：
    //   * 规则热重载翻转 ROUTE_GENERATION 后，FLOW_DECISION 整体失效，
    //     旧实现会对已建立连接重新判决；一旦新规则判 DIRECT，连接中途
    //     改走原栈，服务端只会回 RST，代理侧那一半则悬空；
    //   * FLOW_DECISION 是 LRU，被驱逐后同样会重判；
    //   * DOMAIN_ROUTE 条目随 DNS TTL 变化，同样可能让连接中途换道。
    // 这正是 honk 的 "established and cached/retransmitted TCP survive"
    // 与 forward-SYN-only publication。用户态 relay 也是按 FLOW_TRACK 的
    // verdict 选节点的，两边始终一致。
    // 没有记录的非 SYN（如 janitor 回收了空闲流）仍照旧重新判决、重建记录。
    if pkt.l4_proto == IPPROTO_TCP && !pkt.is_fragment && !pkt.is_new_syn() {
        let pinned = pinned_tcp_verdict(&pkt);
        if pinned != 0 {
            observability::count_tcp_pinned();
            observability::count_proxy(ctx.skb.len());
            observability::node_tx(pinned, ctx.skb.len());
            return redirect_to_proxy(ctx, &pkt, from_wan, pinned, link);
        }
    }

    // [方案六] 每源每秒新流预算。默认关闭；开启时只对 LAN ingress 上
    // FLOW_DECISION 未命中的首包生效（DNS 查询与分片豁免，避免误伤）。
    if from_wan == 0
        && param.new_flow_limit != 0
        && param.flow_cache != 0
        && !pkt.is_fragment
        && pkt.dport != DNS_PORT
        && FLOW_DECISION.get_ptr(pkt.flow_key()).is_none()
        && observability::new_flow_exceeded(&pkt)
    {
        observability::count_new_flow_limited();
        return Err(TC_ACT_SHOT);
    }

    // cgroup 强制路径是按进程判定的，不能按五元组缓存，直接走完整判决；
    // 其余流量走 decide_flow()，同流后续包由 FLOW_DECISION 命中即返回。
    let verdict = if forced_node != 0 {
        decide_forced(&pkt, forced_node, route_generation())
    } else {
        decide_flow(&pkt)
    };

    // 首片把最终判决写进 FRAG_VERDICT；DIRECT 会顺带清掉 ID 复用残留。
    fragment::record(&pkt, verdict);

    if verdict == VERDICT_DIRECT {
        observability::count_direct(ctx.skb.len());
        observability::node_tx(VERDICT_DIRECT, ctx.skb.len());
        // 保留原 mark 低位（Android netd 用低 16 位当 netId），只置已分类位。
        ctx.skb.set_mark(in_mark | CLASSIFIED_MARK);
        Ok(TC_ACT_OK)
    } else if verdict == VERDICT_BLOCK {
        observability::count_block();
        Err(TC_ACT_SHOT)
    } else if verdict_is_proxy(verdict) {
        observability::count_proxy(ctx.skb.len());
        observability::node_tx(verdict, ctx.skb.len());
        // [方案八] 确认 TCP/53 劫持路径真的走到用户态（UDP/53 不计）。
        if pkt.l4_proto == IPPROTO_TCP && pkt.dport == DNS_PORT {
            observability::count_dns_tcp();
        }
        redirect_to_proxy(ctx, &pkt, from_wan, verdict, link)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// [方案十] 已代理 TCP 流在 FLOW_TRACK 里记录的判决；0 = 没有记录。
/// 单独成函数，让 44 字节的 FlowKey 只占这一层栈帧。
#[inline(never)]
fn pinned_tcp_verdict(pkt: &Pkt) -> u8 {
    match FLOW_TRACK.get_ptr(pkt.flow_key()) {
        Some(e) => {
            let v = unsafe { (*e).verdict };
            if verdict_is_proxy(v) {
                v
            } else {
                0
            }
        }
        None => 0,
    }
}

/// [方案九] L3 设备上的包没有以太网头，而 silk0 是 veth：
/// `__bpf_redirect_common` 会拒收 mac_header >= network_header 的 skb。
/// 用 `bpf_skb_change_head` 在前面补 14 字节（内核已清零），只写
/// ethertype；目的 MAC 留 0 —— silk0peer_ingress 反正会把 pkt_type 强制成
/// PACKET_HOST。移植自 honk `prep_redirect_to_control_plane()`。
#[inline(always)]
fn push_eth_header(ctx: &TcContext) -> Result<(), c_long> {
    let skb = ctx.skb.skb;
    // skb->protocol 是 __be16 放在 u32 里：取低 16 位按内存序写回即为网络序。
    let proto = (unsafe { (*skb).protocol } as u16).to_ne_bytes();
    if unsafe { bpf_skb_change_head(skb, ETH_HLEN as u32, 0) } != 0 {
        observability::count_l3_head_failed();
        return Err(TC_ACT_SHOT);
    }
    let mut hdr = [0u8; ETH_HLEN];
    hdr[12] = proto[0];
    hdr[13] = proto[1];
    unsafe {
        bpf_skb_store_bytes(skb, 0, hdr.as_ptr() as *const _, ETH_HLEN as u32, 0);
    }
    Ok(())
}

/// 纯粹的转向动作：（L3 补头）、打 mark、备份到 cb[0]、redirect 到 silk0。
/// 分片后续片也走这里，只是不写 FLOW_TRACK（见 do_capture）。
#[inline(always)]
fn steer_to_silkns(ctx: &TcContext, from_wan: u8, link: u8) -> Verdict {
    let param = PARAM.load();
    if param.silk0_ifindex == 0 {
        return Err(TC_ACT_UNSPEC);
    }
    // [方案十二] bpf_redirect_peer 只在 TC ingress 合法，所以只给 LAN
    // ingress 用（from_wan == 0）；WAN egress 仍走普通 bpf_redirect。
    // peer 投递直接进入 silk0peer 的 ingress 处理，不经过 veth xmit，
    // 也就不需要 mac 头：L3 包此时可以不补头（与 honk 一致）。
    let peer = param.use_redirect_peer != 0 && from_wan == 0;
    if link == LINK_L3 && !peer {
        push_eth_header(ctx)?;
    }
    // Reply path authority: mark + tracked framing. silk0peer_ingress restores
    // the mark from cb[0] because the link crossing may scrub skb->mark.
    // The mark value comes from Param (userspace `general.mark`), so a custom
    // mark in the config is honoured end to end.
    ctx.skb.set_mark(param.mark);
    unsafe {
        (*ctx.skb.skb).cb[0] = param.mark;
    }
    let ret = if peer {
        unsafe { bpf_redirect_peer(param.silk0_ifindex, 0) }
    } else {
        unsafe { bpf_redirect(param.silk0_ifindex, 0) }
    };
    Ok(ret)
}

/// 构造一份完整的捕获档案。新 SYN 覆盖与首次插入共用同一处，避免两处
/// 字段漂移；单独成函数也让 48 字节的结构体只占一层栈帧。
#[inline(always)]
fn new_track_entry(
    ctx: &TcContext,
    pkt: &Pkt,
    from_wan: u8,
    verdict: u8,
    now: u64,
    closing: bool,
    link: u8,
) -> TrackEntry {
    TrackEntry {
        ifindex: unsafe { (*ctx.skb.skb).ifindex },
        from_wan,
        verdict,
        tcp_state: if closing {
            TCP_STATE_CLOSING
        } else {
            TCP_STATE_OPEN
        },
        link,
        smac: pkt.smac,
        dmac: pkt.dmac,
        last_seen_ns: now,
    }
}

/// Record framing and steer the packet into the proxy namespace.
#[inline(always)]
fn redirect_to_proxy(ctx: &TcContext, pkt: &Pkt, from_wan: u8, verdict: u8, link: u8) -> Verdict {
    let key = pkt.flow_key();
    let now = unsafe { bpf_ktime_get_ns() };
    // [方案七] TCP 首部 flags 决定这条记录是"新连接 / 正在关闭 / 普通包"。
    let new_syn = pkt.is_new_syn();
    let closing = pkt.is_fin_or_rst();

    // [方案五] FLOW_TRACK 换成普通 HashMap 后不再被内核静默驱逐，但仍要
    // 告诉用户态 janitor 这条流还活着。普通包按 30s 节流刷新（只写 8
    // 字节，不重建整条档案）。
    if let Some(ptr) = FLOW_TRACK.get_ptr_mut(key) {
        let e = unsafe { &mut *ptr };
        if new_syn {
            // [方案七] 五元组复用：客户端在 TIME_WAIT 后面用同一 sport
            // 重连，或 Wi-Fi→蜂窝切换导致 ifindex 变化。只刷新时间戳会让
            // 新流沿用旧 incarnation 的 MAC / ifindex / verdict，回程被
            // 送到错误接口或错误节点。纯 SYN 是"新连接声明"，整条覆盖。
            // 对齐 honk 的 forward-SYN-only publication，但不需要它的
            // conntrack / sock_ops / retirement fence 全套。
            *e = new_track_entry(ctx, pkt, from_wan, verdict, now, false, link);
            observability::count_tcp_syn_reset();
        } else {
            // FIN/RST 与 CLOSING 期间的包都强制刷新：30 s 节流会让短回收
            // 窗口从"上一次刷新"起算，并把仍在半关闭（client 发完 FIN、
            // server 继续推数据）的流提前删掉。OPEN 才保留原来的节流。
            if closing
                || e.tcp_state == TCP_STATE_CLOSING
                || now.wrapping_sub(e.last_seen_ns) > FLOW_TRACK_REFRESH_NS
            {
                e.last_seen_ns = now;
            }
            // CLOSING 是单向状态：只有新 SYN 能重置它。FIN 之后的 ACK /
            // 重传不会把流"复活"回 120 s 生命周期。
            if closing {
                e.tcp_state = TCP_STATE_CLOSING;
                observability::count_tcp_closing();
            }
        }
    } else {
        let entry = new_track_entry(ctx, pkt, from_wan, verdict, now, closing, link);
        // 表满时 insert 只是失败（可观测、可重试），不是内核 LRU 静默驱逐
        // 活跃长连接。
        if FLOW_TRACK.insert(key, entry, 0).is_err() {
            observability::count_track_insert_failed();
            // [方案十] 新 TCP 连接 fail-closed：没有 FLOW_TRACK 的 SYN 即使
            // 被 listener 接受，SYN-ACK 也找不到回程 framing，连接注定半通；
            // 丢掉它让客户端按 SYN 重传节奏重试，等 janitor 腾出空间
            //（honk: "Inserts under memory pressure fail closed"）。
            // UDP 与非 SYN 维持原样继续转向。
            if new_syn {
                observability::count_syn_track_full();
                return Err(TC_ACT_SHOT);
            }
        }
    }
    steer_to_silkns(ctx, from_wan, link)
}

/// LAN forwarded traffic capture (ingress on the LAN interface).
#[inline(always)]
fn do_lan_ingress(ctx: &TcContext, link: u8) -> Verdict {
    do_capture(ctx, 0, link)
}

/// Host-originated traffic capture (egress on the WAN interface).
#[inline(always)]
fn do_wan_egress(ctx: &TcContext, link: u8) -> Verdict {
    do_capture(ctx, 1, link)
}

/// Packets arriving in `silkns` on `silk0peer`: restore the mark scrubbed by
/// the link crossing, then let the `silkns` policy routing (fwmark ->
/// local table) plus the sk_lookup program deliver to the transparent
/// listeners.
#[inline(always)]
fn do_silk0peer_ingress(ctx: &TcContext) -> Verdict {
    // [方案七] 与 capture hook 共用同一道准入门控，避免启动窗口里对
    // 半初始化的 skb 改 mark / pkt_type。
    if !datapath_ready() {
        return Ok(TC_ACT_OK);
    }
    let param = PARAM.load();
    let cb0 = unsafe { (*ctx.skb.skb).cb[0] };
    if cb0 == param.mark {
        ctx.skb.set_mark(param.mark);
    }
    // The redirected frame still carries the original destination MAC, so
    // the veth crossing classifies it PACKET_OTHERHOST and ip_rcv() would
    // drop it before sk_lookup. Force PACKET_HOST (honk does the same).
    let _ = ctx.skb.change_type(PACKET_HOST);
    Ok(TC_ACT_OK)
}

/// Swap the captured MACs back in (LAN framing of the original flow).
#[inline(always)]
fn restore_macs(ctx: &TcContext, track: &TrackEntry) {
    unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb,
            OFF_ETH_SRC,
            track.dmac.as_ptr() as *const _,
            6,
            0,
        );
        bpf_skb_store_bytes(
            ctx.skb.skb,
            OFF_ETH_DST,
            track.smac.as_ptr() as *const _,
            6,
            0,
        );
    }
}

/// Replies from the transparent listeners leaving `silkns` through `silk0`:
/// restore the original framing and hand the packet back to its capture
/// interface. This is where proxied traffic exits back to clients without
/// ever touching host IP forwarding.
#[inline(always)]
fn do_silk0_ingress(ctx: &TcContext) -> Verdict {
    // [方案七] 准入门控；退出时先清门再拆监听器，回程不再被改写。
    if !datapath_ready() {
        return Ok(TC_ACT_OK);
    }
    // silk0 是 veth，回程帧总是以太网帧。
    let pkt = match parse(ctx, LINK_L2) {
        Ok(p) => p,
        Err(_) => return Err(TC_ACT_UNSPEC),
    };

    // Replies travel in the reverse direction of the tracked flow.
    let key: FlowKey = pkt.flow_key().reverse();
    let Some(ptr) = FLOW_TRACK.get_ptr_mut(key) else {
        // Unknown reply: not ours to place.
        return Err(TC_ACT_UNSPEC);
    };
    let e = unsafe { &mut *ptr };
    let track: TrackEntry = *e;
    // [方案七] 回程也刷新 last_seen_ns：单向长流（只有 server→client
    // 数据，如推送 / 视频 / 长轮询）此前只靠正向包刷新，会在 120 s 后
    // 被 janitor 当成空闲删掉，回程随即丢帧。CLOSING 期间每个回程包都
    // 强制刷新，半关闭时 server 继续推数据就不会被 5 s 短窗口误删；
    // OPEN 仍按 30 s 节流，避免每包写放大。
    let now = unsafe { bpf_ktime_get_ns() };
    if track.tcp_state == TCP_STATE_CLOSING
        || now.wrapping_sub(track.last_seen_ns) > FLOW_TRACK_REFRESH_NS
    {
        e.last_seen_ns = now;
    }
    // [方案六] 回程流量计数（LAN 回客户端 / 本机注入 WAN RX 都算）。
    observability::count_reply(ctx.skb.len());
    // [方案十一] 回程按流记录的 verdict 记到对应节点的 rx。
    observability::node_rx(track.verdict, ctx.skb.len());

    // Restore LAN framing: swap captured MACs back in.
    // [方案九] L3 流没有 MAC 可恢复：redirect 到 L3 设备时内核
    // （__bpf_redirect_no_mac）会自己剥掉以太网头，只交付 IP 包。
    if track.link == LINK_L2 {
        restore_macs(ctx, &track);
    }

    let param = PARAM.load();
    if track.from_wan != 0 {
        // Host-originated: inject into the WAN RX path as PACKET_HOST so the
        // local stack delivers it to the originating socket.
        let _ = ctx.skb.change_type(PACKET_HOST);
        // Reply goes back in on the interface the flow left through (recorded
        // at capture), so wlan0 <-> mobile-data switches keep working.
        let wan_if = if track.ifindex != 0 { track.ifindex } else { param.wan_ifindex };
        let _ = unsafe { bpf_redirect(wan_if, BPF_F_INGRESS) };
    } else {
        // LAN client: TX onto the LAN interface as OTHERHOST (frame leaving).
        let _ = ctx.skb.change_type(PACKET_OTHERHOST);
        let _ = unsafe { bpf_redirect(track.ifindex, 0) };
    }
    Ok(crate::action::TC_ACT_REDIRECT)
}

pub fn lan_ingress_body(ctx: &TcContext) -> Verdict {
    do_lan_ingress(ctx, LINK_L2)
}

pub fn wan_egress_body(ctx: &TcContext) -> Verdict {
    do_wan_egress(ctx, LINK_L2)
}

/// [方案九] L3 入口：先按 honk 的方法确认帧里确实没有以太网头（被改型的
/// 设备可能仍带着），再按实际链路类型解析。
pub fn lan_ingress_l3_body(ctx: &TcContext) -> Verdict {
    let link = l3_link_type(ctx);
    do_lan_ingress(ctx, link)
}

pub fn wan_egress_l3_body(ctx: &TcContext) -> Verdict {
    let link = l3_link_type(ctx);
    do_wan_egress(ctx, link)
}

pub fn silk0peer_ingress_body(ctx: &TcContext) -> Verdict {
    do_silk0peer_ingress(ctx)
}

pub fn silk0_ingress_body(ctx: &TcContext) -> Verdict {
    do_silk0_ingress(ctx)
}
