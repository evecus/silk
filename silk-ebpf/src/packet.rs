//! Minimal L2-L4 packet parser for TC programs.
//!
//! Hand-rolled with `load_bytes` on fixed-size buffers so every context read
//! stays a bounded, constant-offset access the verifier can prove.

use crate::action::TC_ACT_UNSPEC;
use aya_ebpf::cty::c_long;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::{bpf_skb_load_bytes, bpf_skb_load_bytes_relative};
use silk_ebpf_common::{
    FlowKey, IPPROTO_AH, IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_ROUTING,
    IPPROTO_TCP, IPPROTO_UDP, LINK_L2, LINK_L3, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST,
    TCP_FLAG_SYN,
};

pub const ETH_HLEN: usize = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_VLAN: u16 = 0x8100;
/// 802.1ad（QinQ 外层）。
pub const ETH_P_QINQ: u16 = 0x88a8;
const VLAN_VID_MASK: u32 = 0x0fff;
/// `enum bpf_hdr_start_off::BPF_HDR_START_NET`。写成字面量，避免依赖
/// aya-ebpf-bindings 0.2 里枚举模块的具体生成路径。
const BPF_HDR_START_NET: u32 = 1;

/// [方案九] 挂在 L3 设备上的程序先确认帧里真的没有以太网头，移植自 honk
/// `transport::l3_link_h_len()`。一个先按以太网建起来、后来被改成
/// `ARPHRD_RAWIP` 的设备（某些 Android modem 驱动、L3 bond 上 AF_PACKET
/// 预留的 14 字节）仍然带着以太网头，所以只能信内核记录的 network header
/// 位置，不能只看包内容：
///   1. 线性区长度必须在 15..=65550 之间，且 bytes 12-13 等于 skb->protocol
///      （普通裸 IP 在这一步就被排除，不需要调 helper）；
///   2. 再用 `bpf_skb_load_bytes_relative(BPF_HDR_START_NET)` 探测 network
///      header 恰好位于偏移 14。
///
/// 返回 LINK_L2 或 LINK_L3。
#[inline(always)]
pub fn l3_link_type(ctx: &TcContext) -> u8 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let head = (data_end - data) as u32;
    if !(ETH_HLEN as u32 + 1..=ETH_HLEN as u32 + 1 + 0xffff).contains(&head)
        || data + ETH_HLEN > data_end
    {
        return LINK_L3;
    }
    // 直接包访问：data + 14 <= data_end 已证明，verifier 可接受。
    let ether_type = unsafe { *((data + 12) as *const u16) };
    let proto = unsafe { (*ctx.skb.skb).protocol } as u16;
    if ether_type != proto {
        return LINK_L3;
    }
    network_header_at_eth_hlen(ctx, head)
}

// helper 只读到线性区末尾：在同一个偏移上，1 字节读成功说明 network header
// 距线性区开头不超过 14 字节，2 字节读失败说明至少 14 字节，二者同时成立
// 即恰好 14。`#[inline(never)]` 让探测缓冲区不挤进调用方的栈帧。
#[inline(never)]
fn network_header_at_eth_hlen(ctx: &TcContext, head: u32) -> u8 {
    let skb = ctx.skb.skb as *const _;
    let offset = head - ETH_HLEN as u32 - 1;
    let mut bytes = [0u8; 2];
    let to = bytes.as_mut_ptr() as *mut _;
    if unsafe { bpf_skb_load_bytes_relative(skb, offset, to, 1, BPF_HDR_START_NET) } != 0
        || unsafe { bpf_skb_load_bytes_relative(skb, offset, to, 2, BPF_HDR_START_NET) } == 0
    {
        return LINK_L3;
    }
    LINK_L2
}

/// [方案九] 硬件卸载的 802.1Q 标签（`skb->vlan_tci`，VID != 0）。TC 在父
/// 接口上看到它时 `vlan_do_receive` 还没把帧交给 VLAN 子接口；把它转进
/// silkns 会以 OTHERHOST 被丢掉，回程也会从父接口不带标签地发出去、落到
/// 错误的 VLAN。交给 VLAN 子接口自己的 hook 处理（honk `is_vlan_tagged`）。
/// VID 0 只是优先级标签，照常处理。
#[inline(always)]
pub fn is_vlan_tagged(ctx: &TcContext, link: u8) -> bool {
    link == LINK_L2 && unsafe { (*ctx.skb.skb).vlan_tci } & VLAN_VID_MASK != 0
}

/// Bounds-checked, fixed-size load. aya's `TcContext::load_bytes` computes
/// `min(len, skb.len - offset)` at runtime, which the verifier rejects with
/// "invalid zero-sized read" when the range can include 0. Checking the
/// bounds explicitly keeps the helper call at a constant size.
#[inline(always)]
fn load(ctx: &TcContext, off: usize, buf: &mut [u8]) -> Result<(), c_long> {
    if (off + buf.len()) as u32 > ctx.skb.len() {
        return Err(TC_ACT_UNSPEC);
    }
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            off as u32,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
        )
    };
    if ret != 0 {
        return Err(ret);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct Pkt {
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub l4_proto: u8,
    /// V4-mapped form, network byte order.
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    /// Network byte order.
    pub sport: u16,
    pub dport: u16,
    /// 非首片（fragment offset != 0）：L4 端口字段读到的是载荷，不可用于
    /// 判决，只能走地址级规则或继承首片记录。
    pub is_fragment: bool,
    /// 首片（offset == 0 且 MF=1）：仍带完整 L4 头，判完之后要把结果
    /// 记进 FRAG_VERDICT 供后续片继承。
    pub is_first_fragment: bool,
    /// IP identification（IPv4 16 位 / IPv6 Fragment header 32 位）。
    pub frag_id: u32,
    /// [方案七] TCP 首部 flags 字节（L4 偏移 13）；非 TCP / 非首片为 0。
    pub tcp_flags: u8,
}

impl Pkt {
    /// IPv4 地址以 v4-mapped 形式存放；用它区分分片键是否应带 l4proto。
    #[inline(always)]
    pub fn is_v4(&self) -> bool {
        self.src_ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
    }

    /// 纯 SYN（不带 ACK）：一条新连接在声明自己的五元组。用来覆盖
    /// FLOW_TRACK 里同一五元组残留的旧 incarnation（旧 ifindex / MAC /
    /// verdict），对齐 honk 的 forward-SYN-only publication。
    #[inline(always)]
    pub fn is_new_syn(&self) -> bool {
        self.l4_proto == IPPROTO_TCP
            && self.tcp_flags & TCP_FLAG_SYN != 0
            && self.tcp_flags & TCP_FLAG_ACK == 0
    }

    /// FIN 或 RST：连接进入关闭流程，把流送入短回收窗口。
    #[inline(always)]
    pub fn is_fin_or_rst(&self) -> bool {
        self.l4_proto == IPPROTO_TCP
            && self.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST) != 0
    }

    #[inline(always)]
    pub fn flow_key(&self) -> FlowKey {
        FlowKey {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            sport: self.sport,
            dport: self.dport,
            proto: self.l4_proto,
            _pad: [0; 7],
        }
    }
}

/// [方案七] 基础设施流量直通判定，移植自 honk 的
/// `transport::dst_is_special()`（.agents/rules/datapath.md 明确要求
/// "Broadcast/multicast passes through eBPF" 与 "Internal traffic is never
/// proxied"）。
///
/// 必须在任何规则查表（含 DNS hijack）之前短路：用户态的
/// `add_private_direct()` 只能表达 IP 前缀，表达不了 L2 广播/组播 MAC、
/// 255.255.255.255 / 0.0.0.0；而 `decide()` 里 UDP/53 劫持又排在 CIDR
/// 之前，广播 DNS/DHCP 会被无条件送进代理。OpenWrt 上这会直接弄坏 LAN
/// DHCP/mDNS/SSDP。
///
/// own-link（veth 的 169.254.0.0/16 与 fd00:686f:6e6b::/64）也在这里硬
/// 保护：用户态 CIDR 是"先写私有直连、再写用户规则"，用户写一条更具体的
/// CIDR 就会用 LPM 覆盖它，让回程流量再次被捕获形成环路。
#[inline(always)]
pub fn dst_is_special(pkt: &Pkt) -> bool {
    // L2 广播 / 组播（ff:ff:...、01:00:5e:...、33:33:...）。
    if pkt.dmac[0] & 1 != 0 {
        return true;
    }
    if pkt.is_v4() {
        let ip = u32::from_be_bytes([
            pkt.dst_ip[12],
            pkt.dst_ip[13],
            pkt.dst_ip[14],
            pkt.dst_ip[15],
        ]);
        // 0.0.0.0 / 255.255.255.255 / 224.0.0.0/4 / 169.254.0.0/16
        ip == 0
            || ip == 0xffff_ffff
            || (ip & 0xf000_0000) == 0xe000_0000
            || (pkt.dst_ip[12] == 169 && pkt.dst_ip[13] == 254)
    } else {
        // ff00::/8（v6 组播）与 veth 的 ULA /64。
        pkt.dst_ip[0] == 0xff
            || pkt.dst_ip[0..8] == [0xfd, 0x00, 0x68, 0x6f, 0x6e, 0x6b, 0x00, 0x00]
    }
}

/// Parse the packet. Returns `Err(TC_ACT_UNSPEC)` (pass, unclassified) for
/// anything that is not plain IPv4/IPv6 TCP/UDP.
///
/// [方案九] `link` 指明捕获接口的链路类型：
/// * LINK_L2：以太网帧，L3 从偏移 14 开始。帧内 802.1Q / 802.1ad 标签
///   一律放过——旧实现会跳过标签继续解析并转进 silkns，但 silk0peer 上
///   没有 VLAN 设备，带标签的帧在那里被丢弃，回程也会从父接口不带标签
///   地发出。这类帧应由 VLAN 子接口上的 hook 处理。
/// * LINK_L3：裸 IP 设备，L3 从偏移 0 开始，协议取自 skb->protocol，
///   MAC 全 0（`dst_is_special` 的 L2 组播位因此天然为 0，只按 IP 判）。
#[inline(always)]
pub fn parse(ctx: &TcContext, link: u8) -> Result<Pkt, c_long> {
    let mut eth = [0u8; ETH_HLEN];
    let (eth_proto, l3_off) = if link == LINK_L3 {
        let proto = u16::from_be(unsafe { (*ctx.skb.skb).protocol } as u16);
        (proto, 0usize)
    } else {
        if load(ctx, 0, &mut eth).is_err() {
            return Err(TC_ACT_UNSPEC);
        }
        let proto = ((eth[12] as u16) << 8) | eth[13] as u16;
        if proto == ETH_P_VLAN || proto == ETH_P_QINQ {
            return Err(TC_ACT_UNSPEC);
        }
        (proto, ETH_HLEN)
    };

    match eth_proto {
        ETH_P_IP => parse_ipv4(ctx, l3_off, &eth),
        ETH_P_IPV6 => parse_ipv6(ctx, l3_off, &eth),
        _ => Err(TC_ACT_UNSPEC),
    }
}

#[inline(always)]
fn parse_ipv4(ctx: &TcContext, l3_off: usize, eth: &[u8; 14]) -> Result<Pkt, c_long> {
    let mut ihl_buf = [0u8; 20];
    if load(ctx, l3_off, &mut ihl_buf).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let ihl = (ihl_buf[0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return Err(TC_ACT_UNSPEC);
    }
    let l4_proto = ihl_buf[9];
    if l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP {
        return Err(TC_ACT_UNSPEC);
    }
    // IPv4 分片字段：bytes 4-5 = identification，6-7 = flags + offset。
    let frag_field = ((ihl_buf[6] as u16) << 8) | ihl_buf[7] as u16;
    let frag_off = frag_field & 0x1fff;
    let more_fragments = frag_field & 0x2000 != 0;
    let frag_id = ((ihl_buf[4] as u32) << 8) | ihl_buf[5] as u32;
    // [方案七] 非首片没有 L4 头：IPv4 头后面直接是载荷，端口字段读到的
    // 是垃圾。以前这里无条件 load 16 字节，最后一个短分片（载荷 < 16 B）
    // 会因 bounds check 失败返回 TC_ACT_UNSPEC 被直接放过，绕过
    // FRAG_VERDICT 的 BLOCK / 代理继承（honk 在 parse 失败路径上仍会
    // `condemned()` 判 SHOT）。现在非首片干脆不读 L4，端口置 0，
    // 让 tc.rs 的 fragment::inherited() 一定能拿到判决。
    // 16 bytes covers ports (0..4) and the TCP flags byte at offset 13.
    let mut l4 = [0u8; 16];
    if frag_off == 0 && load(ctx, l3_off + ihl, &mut l4).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let tcp_flags = if l4_proto == IPPROTO_TCP && frag_off == 0 {
        l4[13]
    } else {
        0
    };
    Ok(Pkt {
        smac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
        dmac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
        l4_proto,
        src_ip: FlowKey::to_v6_mapped([ihl_buf[12], ihl_buf[13], ihl_buf[14], ihl_buf[15]]),
        dst_ip: FlowKey::to_v6_mapped([ihl_buf[16], ihl_buf[17], ihl_buf[18], ihl_buf[19]]),
        sport: ((l4[0] as u16) << 8) | l4[1] as u16,
        dport: ((l4[2] as u16) << 8) | l4[3] as u16,
        is_fragment: frag_off != 0,
        is_first_fragment: frag_off == 0 && more_fragments,
        frag_id,
        tcp_flags,
    })
}

/// IPv6：固定 40 字节基头 + 最多 5 层扩展头的有限遍历。旧实现把扩展头
/// 当作 L4 头，端口会读错，且完全不认识 Fragment header —— 这是原报告里
/// 「IPv6 无扩展头」的局限。循环次数是编译期常量，verifier 可证明有界；
/// 每层只读固定 8 字节，长度按类型用常量公式算。
#[inline(always)]
fn parse_ipv6(ctx: &TcContext, l3_off: usize, eth: &[u8; 14]) -> Result<Pkt, c_long> {
    let mut hdr = [0u8; 40];
    if load(ctx, l3_off, &mut hdr).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip.copy_from_slice(&hdr[8..24]);
    dst_ip.copy_from_slice(&hdr[24..40]);

    let mut next = hdr[6];
    let mut off = l3_off + 40;
    let mut frag_id = 0u32;
    let mut is_fragment = false;
    let mut is_first_fragment = false;

    for _ in 0..5 {
        if next == IPPROTO_TCP || next == IPPROTO_UDP {
            break;
        }
        let mut ext = [0u8; 8];
        if load(ctx, off, &mut ext).is_err() {
            return Err(TC_ACT_UNSPEC);
        }
        let ext_len: usize = match next {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => (ext[1] as usize + 1) * 8,
            IPPROTO_AH => (ext[1] as usize + 2) * 4,
            IPPROTO_FRAGMENT => {
                // bytes 2-3: offset(13) + res(2) + M(1); bytes 4-7: id.
                let fo = (((ext[2] as u16) << 8) | ext[3] as u16) >> 3;
                let more = ext[3] & 1 != 0;
                frag_id = u32::from_be_bytes([ext[4], ext[5], ext[6], ext[7]]);
                is_fragment = fo != 0;
                is_first_fragment = fo == 0 && more;
                if is_fragment {
                    // [方案七] 非首片停在 Fragment header 后面：接下来是载荷，
                    // 不是 L4 头。记下真实的 next header 就停止遍历，否则会
                    // 把载荷当 TCP/UDP 头读，短分片还会因越界直接被放过。
                    next = ext[0];
                }
                8
            }
            // ESP / ICMPv6 / 未知扩展头：保持原有「未分类放过」行为。
            _ => return Err(TC_ACT_UNSPEC),
        };
        if ext_len < 8 {
            return Err(TC_ACT_UNSPEC);
        }
        if is_fragment {
            break;
        }
        off += ext_len;
        next = ext[0];
    }
    let l4_proto = next;

    // 非首片：端口与 TCP flags 都不可用，交给 FRAG_VERDICT 继承首片判决。
    if is_fragment {
        return Ok(Pkt {
            smac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
            dmac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
            l4_proto,
            src_ip,
            dst_ip,
            sport: 0,
            dport: 0,
            is_fragment: true,
            is_first_fragment: false,
            frag_id,
            tcp_flags: 0,
        });
    }
    if l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP {
        return Err(TC_ACT_UNSPEC);
    }
    let mut l4 = [0u8; 16];
    if load(ctx, off, &mut l4).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let tcp_flags = if l4_proto == IPPROTO_TCP { l4[13] } else { 0 };
    Ok(Pkt {
        smac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
        dmac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
        l4_proto,
        src_ip,
        dst_ip,
        sport: ((l4[0] as u16) << 8) | l4[1] as u16,
        dport: ((l4[2] as u16) << 8) | l4[3] as u16,
        is_fragment,
        is_first_fragment,
        frag_id,
        tcp_flags,
    })
}
