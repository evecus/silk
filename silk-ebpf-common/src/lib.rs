//! Kernel/userspace shared ABI types for silk.
//!
//! Mirrors honk's `honk-ebpf-common` discipline: every type here is `#[repr(C)]`
//! and must move together with the eBPF crate and the userspace map writers.
#![cfg_attr(not(feature = "std"), no_std)]

/// Skb mark reserved for traffic entering the proxy namespace (`silkns`).
/// The `silkns` policy routing rule `fwmark TPROXY_MARK table 100` sends these
/// packets to the local transparent listener table.
pub const TPROXY_MARK: u32 = 0x2027;

/// Socket mark for control-plane dials (SOCKS5, DNS upstream). Seen on
/// egress as skb->mark, letting the datapath pass the proxy's own traffic.
pub const CONTROL_MARK: u32 = 0x6d696e69;

/// 已由本数据面判为 DIRECT 的 skb 打上的高位标记。同一个 skb 若再次进入
/// 另一个 capture hook（LAN ingress -> 内核转发 -> WAN egress），看到该位
/// 就直接放行，不再重复判决，沿用 honk 的 CLASSIFIED_MARK 思路。取高位是
/// 为了避开 Android netd 把低 16 位 fwmark 当 netId 用的约定。
pub const CLASSIFIED_MARK: u32 = 0x1000_0000;

/// 每个地址族最多几个并行 UDP 监听 socket。sk_lookup 用五元组哈希取模把
/// 一条流固定到同一个槽位；eBPF 与用户态共用此常量，SockMap 容量按
/// `2 + 2 * UDP_LISTENER_MAX` 展开。
pub const UDP_LISTENER_MAX: u32 = 4;

/// LISTEN_SOCKETS 槽位布局，内核与用户态共用，避免两处各写一份而漂移。
pub const KEY_TCP4: u32 = 0;
pub const KEY_TCP6: u32 = 1;
pub const KEY_UDP4_BASE: u32 = 2;
pub const KEY_UDP6_BASE: u32 = KEY_UDP4_BASE + UDP_LISTENER_MAX;
pub const LISTEN_SLOTS: u32 = 2 + 2 * UDP_LISTENER_MAX;

/// Routing verdicts shared by every decision surface.
///
/// DIRECT and BLOCK are fully handled in the kernel. Every other verdict
/// enters userspace: `VERDICT_NODE_BASE + i` selects outbound node `i` (the
/// index in the config's `nodes` list), while the bare `VERDICT_PROXY` means
/// "userspace, no node chosen" (DNS hijack; userspace picks the default).
pub const VERDICT_DIRECT: u8 = 1;
pub const VERDICT_PROXY: u8 = 2;
pub const VERDICT_BLOCK: u8 = 3;
/// First node verdict: node `i` is `VERDICT_NODE_BASE + i`.
pub const VERDICT_NODE_BASE: u8 = 4;

/// True when the verdict sends the flow into userspace (any node).
#[inline(always)]
pub const fn verdict_is_proxy(v: u8) -> bool {
    v == VERDICT_PROXY || v >= VERDICT_NODE_BASE
}

/// Per-cgroup (cgroup v2) policy for host-originated traffic. The map value
/// is either `CGROUP_MODE_BYPASS` (the cgroup's traffic is never captured,
/// always direct) or a node verdict (`>= VERDICT_NODE_BASE`): everything
/// except local/private destinations is then forced through that node,
/// whatever the CIDR/domain/port rules say (block wins).
pub const CGROUP_MODE_BYPASS: u8 = 1;
/// Deepest cgroup hierarchy level searched for a matching ancestor rule.
pub const CGROUP_MAX_DEPTH: i32 = 12;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Immutable parameters written by userspace before programs attach.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Param {
    /// Host-side end of the veth pair bridging into `silkns`.
    pub silk0_ifindex: u32,
    /// LAN capture interface (0 = disabled).
    pub lan_ifindex: u32,
    /// WAN capture interface (0 = disabled).
    pub wan_ifindex: u32,
    /// Verdict applied when no rule matches (VERDICT_*).
    pub default_verdict: u8,
    /// Set when UDP port 53 should be steered into the userspace DNS engine.
    pub dns_hijack: u8,
    /// Non-zero when any cgroup rule is configured (skips the per-packet
    /// cgroup lookup otherwise).
    pub cgroup_rules: u8,
    /// 1 = 启用每流判决缓存（FLOW_DECISION）；0 = 每包重判，便于排查规则问题。
    pub flow_cache: u8,
    /// 每族并行 UDP 监听 socket 数（1..=UDP_LISTENER_MAX）。sk_lookup 用它
    /// 作五元组哈希的模数，必须与用户态实际发布的槽位数一致。
    pub udp_workers: u8,
}

impl Param {
    pub const DEFAULT: Param = Param {
        silk0_ifindex: 0,
        lan_ifindex: 0,
        wan_ifindex: 0,
        default_verdict: VERDICT_PROXY,
        dns_hijack: 1,
        cgroup_rules: 0,
        flow_cache: 1,
        udp_workers: UDP_LISTENER_MAX as u8,
    };
}

/// Five-tuple flow key, addresses always stored as 16 bytes
/// (IPv4 uses the v4-mapped form `::ffff:a.b.c.d`, network byte order).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    /// Network byte order.
    pub sport: u16,
    /// Network byte order.
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 7],
}

impl FlowKey {
    pub const fn zeroed() -> FlowKey {
        FlowKey {
            src_ip: [0; 16],
            dst_ip: [0; 16],
            sport: 0,
            dport: 0,
            proto: 0,
            _pad: [0; 7],
        }
    }

    pub fn reverse(&self) -> FlowKey {
        FlowKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            sport: self.dport,
            dport: self.sport,
            proto: self.proto,
            _pad: [0; 7],
        }
    }

    /// Map an IPv4 address into the v4-mapped IPv6 form (network byte order in/out).
    pub fn to_v6_mapped(v4: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[10] = 0xff;
        out[11] = 0xff;
        out[12..16].copy_from_slice(&v4);
        out
    }
}

/// Track entry published by the capture hooks (`lan_ingress`, `wan_egress`)
/// for every flow steered into the proxy. Consumed by `silk0_ingress` to
/// restore the original framing on replies.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrackEntry {
    /// Interface the flow was captured on (LAN TX / WAN RX-inject).
    pub ifindex: u32,
    /// 0 = flow originated from LAN (reply: restore MACs, TX).
    /// 1 = host-originated (reply: inject into WAN RX with BPF_F_INGRESS).
    pub from_wan: u8,
    /// The kernel verdict that sent this flow to userspace (VERDICT_NODE_BASE
    /// + node index, or VERDICT_PROXY). Userspace reads it to pick the node.
    pub verdict: u8,
    pub _pad: [u8; 2],
    /// Captured framing: LAN client MAC (src) and router MAC (dst).
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
}

impl TrackEntry {
    pub const fn zeroed() -> TrackEntry {
        TrackEntry {
            ifindex: 0,
            from_wan: 0,
            verdict: 0,
            _pad: [0; 2],
            smac: [0; 6],
            dmac: [0; 6],
        }
    }
}

/// Per-IP verdict resolved by the userspace DNS engine from domain rules.
/// DNS 条目是运行时持续发布的，故意不参与规则换代：换规则后由
/// `publish_domain_ip` 发现 verdict 变化时递增 ROUTE_GENERATION，让每流
/// 缓存整体失效即可。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainRouteEntry {
    /// VERDICT_* value.
    pub verdict: u8,
    pub _pad: [u8; 7],
}

/// 静态规则表（PORT_ROUTE / CIDR_V4 / CIDR_V6）的 value。
///
/// `generation == 0` 是通配（启动时的初始规则永远生效）；正数只在
/// ROUTE_GENERATION 等于它时生效。这是 honk "ArrayOfMaps 两代原子切换"的
/// 轻量替代：用户态先把整套新规则以新世代写入（此时数据面仍读旧世代，
/// 看不见新条目、旧条目照旧服务），全部写完后再用一次 map update 翻转
/// ROUTE_GENERATION，瞬间切换。无需重载 hook，也不存在半新半旧的中间态。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RouteEntry {
    pub verdict: u8,
    pub _pad: [u8; 3],
    pub generation: u32,
}

impl RouteEntry {
    pub const fn new(verdict: u8, generation: u32) -> RouteEntry {
        RouteEntry {
            verdict,
            _pad: [0; 3],
            generation,
        }
    }
}

/// 每流判决缓存的 value：首包判一次写进去，后续包按五元组命中即用，
/// 直到 ROUTE_GENERATION 变化（规则热重载）或被 LRU 驱逐。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowDecisionEntry {
    pub verdict: u8,
    pub _pad: [u8; 3],
    pub generation: u32,
}

impl FlowDecisionEntry {
    pub const fn new(verdict: u8, generation: u32) -> FlowDecisionEntry {
        FlowDecisionEntry {
            verdict,
            _pad: [0; 3],
            generation,
        }
    }
}

// Pod impls are only needed on the userspace side (aya map writes).
// The BPF side (aya-ebpf) has no Pod trait requirement for btf_maps.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for Param {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FlowKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TrackEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DomainRouteEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RouteEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FlowDecisionEntry {}
