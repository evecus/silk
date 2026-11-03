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

use crate::action::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC, Verdict};
use crate::maps::{cgroup_mode, is_control_plane_socket, FLOW_TRACK, PARAM};
use crate::packet::{parse, Pkt};
use crate::routing::{decide, decide_forced};
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::{bpf_redirect, bpf_skb_store_bytes};
use silk_ebpf_common::{
    verdict_is_proxy, CGROUP_MODE_BYPASS, FlowKey, TPROXY_MARK, TrackEntry, VERDICT_BLOCK,
    VERDICT_DIRECT, VERDICT_NODE_BASE,
};

const PACKET_HOST: u32 = 0;
const PACKET_OTHERHOST: u32 = 1;
const BPF_F_INGRESS: u64 = 1;

// Ethernet MAC field offsets (network_types::eth::EthHdr layout).
const OFF_ETH_DST: u32 = 0;
const OFF_ETH_SRC: u32 = 6;

/// Common capture path shared by lan_ingress and wan_egress.
#[inline(always)]
fn do_capture(ctx: &TcContext, from_wan: u8) -> Verdict {
    if is_control_plane_socket(ctx.skb.skb) {
        // Control plane's own dials (SOCKS5, DNS upstream) must never loop.
        return Ok(TC_ACT_OK);
    }
    // Per-process policy: only host-originated packets carry a socket (and so
    // a cgroup); forwarded LAN traffic never matches.
    let mut forced_node = 0u8;
    if from_wan == 1 && PARAM.load().cgroup_rules != 0 {
        let mode = cgroup_mode(ctx.skb.skb);
        if mode == CGROUP_MODE_BYPASS {
            return Ok(TC_ACT_OK);
        }
        if mode >= VERDICT_NODE_BASE {
            forced_node = mode;
        }
    }

    let pkt = parse(ctx)?;

    let verdict = if forced_node != 0 {
        decide_forced(&pkt, forced_node)
    } else {
        decide(&pkt)
    };
    if verdict == VERDICT_DIRECT {
        Ok(TC_ACT_OK)
    } else if verdict == VERDICT_BLOCK {
        Err(TC_ACT_SHOT)
    } else if verdict_is_proxy(verdict) {
        redirect_to_proxy(ctx, &pkt, from_wan, verdict)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// Record framing and steer the packet into the proxy namespace.
#[inline(always)]
fn redirect_to_proxy(ctx: &TcContext, pkt: &Pkt, from_wan: u8, verdict: u8) -> Verdict {
    let param = PARAM.load();
    if param.silk0_ifindex == 0 {
        return Err(TC_ACT_UNSPEC);
    }

    // Reply path authority: mark + tracked framing. silk0peer_ingress restores
    // the mark from cb[0] because the link crossing may scrub skb->mark.
    ctx.skb.set_mark(TPROXY_MARK);
    unsafe {
        (*ctx.skb.skb).cb[0] = TPROXY_MARK;
    }

    let key = pkt.flow_key();
    let entry = TrackEntry {
        ifindex: unsafe { (*ctx.skb.skb).ifindex },
        from_wan,
        verdict,
        _pad: [0; 2],
        smac: pkt.smac,
        dmac: pkt.dmac,
    };
    let _ = FLOW_TRACK.insert(key, entry, 0);

    // bpf_redirect_peer would bypass the backlog but is egress-only; TC
    // egress capture uses plain bpf_redirect, ingress capture may use either.
    let _ = unsafe { bpf_redirect(param.silk0_ifindex, 0) };
    Ok(crate::action::TC_ACT_REDIRECT)
}

/// LAN forwarded traffic capture (ingress on the LAN interface).
#[inline(always)]
fn do_lan_ingress(ctx: &TcContext) -> Verdict {
    do_capture(ctx, 0)
}

/// Host-originated traffic capture (egress on the WAN interface).
#[inline(always)]
fn do_wan_egress(ctx: &TcContext) -> Verdict {
    do_capture(ctx, 1)
}

/// Packets arriving in `silkns` on `silk0peer`: restore the mark scrubbed by
/// the link crossing, then let the `silkns` policy routing (fwmark ->
/// local table) plus the sk_lookup program deliver to the transparent
/// listeners.
#[inline(always)]
fn do_silk0peer_ingress(ctx: &TcContext) -> Verdict {
    let cb0 = unsafe { (*ctx.skb.skb).cb[0] };
    if cb0 == TPROXY_MARK {
        ctx.skb.set_mark(TPROXY_MARK);
    }
    // The redirected frame still carries the original destination MAC, so
    // the veth crossing classifies it PACKET_OTHERHOST and ip_rcv() would
    // drop it before sk_lookup. Force PACKET_HOST (honk does the same).
    let _ = ctx.skb.change_type(PACKET_HOST);
    Ok(TC_ACT_OK)
}

/// Replies from the transparent listeners leaving `silkns` through `silk0`:
/// restore the original framing and hand the packet back to its capture
/// interface. This is where proxied traffic exits back to clients without
/// ever touching host IP forwarding.
#[inline(always)]
fn do_silk0_ingress(ctx: &TcContext) -> Verdict {
    let pkt = match parse(ctx) {
        Ok(p) => p,
        Err(_) => return Err(TC_ACT_UNSPEC),
    };

    // Replies travel in the reverse direction of the tracked flow.
    let key: FlowKey = pkt.flow_key().reverse();
    let Some(track) = FLOW_TRACK.get_ptr(key) else {
        // Unknown reply: not ours to place.
        return Err(TC_ACT_UNSPEC);
    };
    let track: TrackEntry = unsafe { *track };

    // Restore LAN framing: swap captured MACs back in.
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
    do_lan_ingress(ctx)
}

pub fn wan_egress_body(ctx: &TcContext) -> Verdict {
    do_wan_egress(ctx)
}

pub fn silk0peer_ingress_body(ctx: &TcContext) -> Verdict {
    do_silk0peer_ingress(ctx)
}

pub fn silk0_ingress_body(ctx: &TcContext) -> Verdict {
    do_silk0_ingress(ctx)
}
