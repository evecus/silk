//! silk-ebpf: trimmed transparent-proxy datapath, design follows honk/dae.
#![no_std]
#![no_main]

mod action;
mod fragment;
mod maps;
mod observability;
mod packet;
mod routing;
mod sk_lookup;
mod tc;

use action::flatten;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::bindings::__sk_buff;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// TC entry points use the raw __sk_buff pointer, matching honk's convention
// to avoid verifier "Arg#0 type STRUCT not supported" issues on newer kernels.

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::lan_ingress_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::wan_egress_body(&TcContext::new(ctx)))
}

// [方案九] 裸 IP（L3）设备上的 capture 入口：PPP、WireGuard、tun，以及
// Android 的 rmnet_data* / ccmni*（ARPHRD_RAWIP）。用户态按接口的 ARPHRD
// 选择 `*_l3` 或普通入口挂载。
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::lan_ingress_l3_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::wan_egress_l3_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn silk0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::silk0peer_ingress_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn silk0_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::silk0_ingress_body(&TcContext::new(ctx)))
}
