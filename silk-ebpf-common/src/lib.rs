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
    pub _pad: u8,
}

impl Param {
    pub const DEFAULT: Param = Param {
        silk0_ifindex: 0,
        lan_ifindex: 0,
        wan_ifindex: 0,
        default_verdict: VERDICT_PROXY,
        dns_hijack: 1,
        cgroup_rules: 0,
        _pad: 0,
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
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainRouteEntry {
    /// VERDICT_* value.
    pub verdict: u8,
    pub _pad: [u8; 7],
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
