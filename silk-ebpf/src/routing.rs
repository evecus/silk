//! Kernel routing decision: the whole point of the datapath.
//!
//! Decision order (first match wins), all resolved inside the kernel so
//! direct traffic never leaves the TC hook:
//!   1. DNS hijack   — UDP dst port 53 (steered to the userspace DNS engine)
//!   2. DOMAIN_ROUTE — per-IP verdicts published by the DNS engine
//!   3. CIDR tries   — longest prefix match on the destination
//!   4. PORT_ROUTE   — destination port table
//!   5. PARAM.default_verdict

use crate::maps::{CIDR_V4, CIDR_V6, DOMAIN_ROUTE, PARAM, PORT_ROUTE};
use crate::packet::Pkt;
use aya_ebpf::maps::lpm_trie::Key;
use silk_ebpf_common::{IPPROTO_UDP, VERDICT_BLOCK, VERDICT_PROXY};

/// Full per-packet decision. Fragmented packets cannot be routed on L4 and
/// fall through to the address-only surfaces (2/3/5), like dae.
#[inline(always)]
pub fn decide(pkt: &Pkt) -> u8 {
    let param = PARAM.load();

    // 1. DNS hijack: the userspace DNS engine answers and publishes
    //    DOMAIN_ROUTE entries so later data packets route by domain.
    if param.dns_hijack != 0 && pkt.l4_proto == IPPROTO_UDP && pkt.dport == 53 && !pkt.is_fragment {
        return VERDICT_PROXY;
    }

    // 2. Domain-derived verdict for this destination address.
    if let Some(entry) = DOMAIN_ROUTE.get_ptr(pkt.dst_ip) {
        let v = unsafe { (*entry).verdict };
        if v != 0 {
            return v;
        }
    }

    // 3. CIDR longest prefix match.
    if pkt.dst_ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&pkt.dst_ip[12..16]);
        if let Some(v) = CIDR_V4.get(Key::new(32, v4)) {
            return *v;
        }
    } else {
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(&pkt.dst_ip);
        if let Some(v) = CIDR_V6.get(Key::new(128, v6)) {
            return *v;
        }
    }

    // 4. Port table (only meaningful for unfragmented packets).
    if !pkt.is_fragment {
        if let Some(v) = PORT_ROUTE.get_ptr(pkt.dport) {
            return unsafe { *v };
        }
    }

    // 5. Default.
    param.default_verdict
}

/// Local / private / link-local / multicast destinations (never forced to the
/// proxy). `ip` is the 16-byte form, IPv4 v4-mapped.
#[inline(always)]
fn is_local_or_private(ip: &[u8; 16]) -> bool {
    if ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        let a = ip[12];
        let b = ip[13];
        return a == 10
            || a == 127
            || (a == 172 && (b & 0xf0) == 16)
            || (a == 192 && b == 168)
            || (a == 169 && b == 254)
            || (a == 100 && (b & 0xc0) == 64)
            || a >= 224;
    }
    (ip[0] & 0xfe) == 0xfc                       // fc00::/7
        || (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) // fe80::/10
        || ip[0] == 0xff                          // ff00::/8
        || (ip[0..15] == [0u8; 15] && ip[15] == 1) // ::1
}

/// Decision for a cgroup forced to a node (`node` is VERDICT_NODE_BASE + i):
/// whatever the normal surfaces say, public destinations go through that
/// node. BLOCK still blocks, the DNS hijack (bare VERDICT_PROXY) stays, and
/// local or private destinations keep their normal verdict.
#[inline(always)]
pub fn decide_forced(pkt: &Pkt, node: u8) -> u8 {
    let v = decide(pkt);
    if v == VERDICT_BLOCK || v == VERDICT_PROXY {
        return v;
    }
    if is_local_or_private(&pkt.dst_ip) {
        return v;
    }
    node
}
