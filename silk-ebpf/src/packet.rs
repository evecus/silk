//! Minimal L2-L4 packet parser for TC programs.
//!
//! Hand-rolled with `load_bytes` on fixed-size buffers so every context read
//! stays a bounded, constant-offset access the verifier can prove.

use crate::action::TC_ACT_UNSPEC;
use aya_ebpf::cty::c_long;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;
use silk_ebpf_common::{
    FlowKey, IPPROTO_AH, IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_ROUTING,
    IPPROTO_TCP, IPPROTO_UDP,
};

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
    /// 非首片（fragment offset != 0）：L4 端口字段读到的是载荷，不可用于
    /// 判决，只能走地址级规则或继承首片记录。
    pub is_fragment: bool,
    /// 首片（offset == 0 且 MF=1）：仍带完整 L4 头，判完之后要把结果
    /// 记进 FRAG_VERDICT 供后续片继承。
    pub is_first_fragment: bool,
    /// IP identification（IPv4 16 位 / IPv6 Fragment header 32 位）。
    pub frag_id: u32,
}

impl Pkt {
    /// IPv4 地址以 v4-mapped 形式存放；用它区分分片键是否应带 l4proto。
    #[inline(always)]
    pub fn is_v4(&self) -> bool {
        self.src_ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
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
    // IPv4 分片字段：bytes 4-5 = identification，6-7 = flags + offset。
    let frag_field = ((ihl_buf[6] as u16) << 8) | ihl_buf[7] as u16;
    let frag_off = frag_field & 0x1fff;
    let more_fragments = frag_field & 0x2000 != 0;
    let frag_id = ((ihl_buf[4] as u32) << 8) | ihl_buf[5] as u32;
    // 16 bytes covers ports (0..4) and the flags byte at offset 13.
    let mut l4 = [0u8; 16];
    if load(ctx, l3_off + ihl, &mut l4).is_err() {
        return Err(TC_ACT_UNSPEC);
    }
    Ok(Pkt {
        smac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
        dmac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
        l4_proto,
        src_ip: FlowKey::to_v6_mapped([ihl_buf[12], ihl_buf[13], ihl_buf[14], ihl_buf[15]]),
        dst_ip: FlowKey::to_v6_mapped([ihl_buf[16], ihl_buf[17], ihl_buf[18], ihl_buf[19]]),
        sport: ((l4[0] as u16) << 8) | l4[1] as u16,
        dport: ((l4[2] as u16) << 8) | l4[3] as u16,
        // 非首片没有 L4 头，端口字段读到的是载荷；首片仍带完整 L4 头。
        is_fragment: frag_off != 0,
        is_first_fragment: frag_off == 0 && more_fragments,
        frag_id,
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
                8
            }
            // ESP / ICMPv6 / 未知扩展头：保持原有「未分类放过」行为。
            _ => return Err(TC_ACT_UNSPEC),
        };
        if ext_len < 8 {
            return Err(TC_ACT_UNSPEC);
        }
        off += ext_len;
        next = ext[0];
    }
    let l4_proto = next;
    if l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP {
        return Err(TC_ACT_UNSPEC);
    }
    let mut l4 = [0u8; 16];
    if load(ctx, off, &mut l4).is_err() {
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
        is_fragment,
        is_first_fragment,
        frag_id,
    })
}
