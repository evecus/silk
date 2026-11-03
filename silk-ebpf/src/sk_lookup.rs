//! sk_lookup program running inside `silkns`.
//!
//! Proxy-bound packets arrive with the original remote destination, so normal
//! socket lookup fails. This program assigns the transparent listener socket
//! from LISTEN_SOCKETS, letting the kernel deliver the packet with the
//! original destination intact (getsockname on the listener shows it).

use crate::maps::{KEY_TCP4, KEY_TCP6, KEY_UDP4, KEY_UDP6, LISTEN_SOCKETS};
use aya_ebpf::programs::SkLookupContext;
use silk_ebpf_common::{IPPROTO_TCP, IPPROTO_UDP};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

#[unsafe(no_mangle)]
#[unsafe(link_section = "sk_lookup")]
pub fn tproxy_sk_lookup(ctx: *mut aya_ebpf::bindings::bpf_sk_lookup) -> u32 {
    let ctx = SkLookupContext::new(ctx);
    do_sk_lookup(&ctx)
}

#[inline(always)]
fn do_sk_lookup(ctx: &SkLookupContext) -> u32 {
    let lookup = unsafe { &*ctx.lookup };
    let key = match (lookup.family, lookup.protocol as u8) {
        (AF_INET, IPPROTO_TCP) => KEY_TCP4,
        (AF_INET6, IPPROTO_TCP) => KEY_TCP6,
        (AF_INET, IPPROTO_UDP) => KEY_UDP4,
        (AF_INET6, IPPROTO_UDP) => KEY_UDP6,
        _ => return SK_PASS,
    };
    match LISTEN_SOCKETS.redirect_sk_lookup(ctx, key, 0) {
        Ok(_) => SK_PASS,
        Err(_) => SK_DROP,
    }
}
