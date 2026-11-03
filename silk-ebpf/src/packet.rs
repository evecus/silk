//! Minimal L2-L4 packet parser for TC programs.
//!
//! Hand-rolled with `load_bytes` on fixed-size buffers so every context read
//! stays a bounded, constant-offset access the verifier can prove.

use crate::action::TC_ACT_UNSPEC;
use aya_ebpf::cty::c_long;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;
use silk_ebpf_common::{FlowKey, IPPROTO_TCP, IPPROTO_UDP};

pub const ETH_HLEN: usize = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_VLAN: u16 = 0x8100;

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
    pub is_fragment: bool,
}

impl Pkt {
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

/// Parse the packet. Returns `Err(TC_ACT_UNSPEC)` (pass, unclassified) for
/// anything that is not plain Ethernet IPv4/IPv6 TCP/UDP first-fragment.
#[inline(always)]
pub fn parse(ctx: &TcContext) -> Result<Pkt, c_long> {
    let mut eth = [0u8; ETH_HLEN];
    if load(ctx, 0, &mut eth).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let eth_proto = ((eth[12] as u16) << 8) | eth[13] as u16;
    let mut l3_off = ETH_HLEN;
    let eth_proto = if eth_proto == ETH_P_VLAN {
        // Single 802.1Q tag: 4 bytes, then the real ethertype.
        let mut t = [0u8; 4];
        if load(ctx, l3_off, &mut t).is_err() {
            return Err(TC_ACT_UNSPEC);
        }
        l3_off += 4;
        ((t[2] as u16) << 8) | t[3] as u16
    } else {
        eth_proto
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
    // frag_off field: bytes 6-7 of the IPv4 header, big endian.
    let frag_off = (((ihl_buf[6] as u16) << 8) | ihl_buf[7] as u16) & 0x1fff;
    // 16 bytes covers ports (0..4) and the flags byte at offset 13.
    let mut l4 = [0u8; 16];
    if load(ctx, l3_off + ihl, &mut l4).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let is_fragment = frag_off != 0;
    Ok(Pkt {
        smac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
        dmac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
        l4_proto,
        src_ip: FlowKey::to_v6_mapped([ihl_buf[12], ihl_buf[13], ihl_buf[14], ihl_buf[15]]),
        dst_ip: FlowKey::to_v6_mapped([ihl_buf[16], ihl_buf[17], ihl_buf[18], ihl_buf[19]]),
        sport: ((l4[0] as u16) << 8) | l4[1] as u16,
        dport: ((l4[2] as u16) << 8) | l4[3] as u16,
        is_fragment,
    })
}

#[inline(always)]
fn parse_ipv6(ctx: &TcContext, l3_off: usize, eth: &[u8; 14]) -> Result<Pkt, c_long> {
    // Fixed 40-byte base header; no extension headers.
    let mut hdr = [0u8; 40];
    if load(ctx, l3_off, &mut hdr).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    let l4_proto = hdr[6];
    if l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP {
        return Err(TC_ACT_UNSPEC);
    }
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip.copy_from_slice(&hdr[8..24]);
    dst_ip.copy_from_slice(&hdr[24..40]);
    let mut l4 = [0u8; 16];
    if load(ctx, l3_off + 40, &mut l4).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    Ok(Pkt {
        smac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
        dmac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
        l4_proto,
        src_ip,
        dst_ip,
        sport: ((l4[0] as u16) << 8) | l4[1] as u16,
        dport: ((l4[2] as u16) << 8) | l4[3] as u16,
        is_fragment: false,
    })
}
