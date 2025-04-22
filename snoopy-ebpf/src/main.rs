#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::programs::TcContext;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::debug;
use aya_log_ebpf::error;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[map(name = "INGRESS_COUNTER")]
static INGRESS_COUNTER: PerCpuArray<Counter> = PerCpuArray::<Counter>::with_max_entries(1, 0);

#[map(name = "EGRESS_COUNTER")]
static EGRESS_COUNTER: PerCpuArray<Counter> = PerCpuArray::<Counter>::with_max_entries(1, 0);

#[aya_ebpf::macros::classifier]
pub fn update_tc_ingress(ctx: TcContext) -> i32 {
    match try_update_tc_ingress(&ctx) {
        Ok(_) => {
            debug!(
                &ctx,
                "TC INGRESS: added packet with {} bytes",
                ctx.data_end() - ctx.data()
            );
        }
        Err(msg) => {
            error!(&ctx, "TC INGRESS: failed to add packet: {}", msg);
        }
    }

    aya_ebpf::bindings::TC_ACT_PIPE
}

pub fn try_update_tc_ingress(ctx: &TcContext) -> Result<(), &'static str> {
    let data = ctx.data() as u64;
    let data_end = ctx.data_end() as u64;
    let bytes = data_end - data;

    let counter = INGRESS_COUNTER
        .get_ptr_mut(0)
        .ok_or("failed to get pointer to first entry in INGRESS_COUNTER map")?;

    unsafe {
        (*counter).packets = (*counter).packets.wrapping_add(1);
        (*counter).bytes = (*counter).bytes.wrapping_add(bytes);
    }

    Ok(())
}

#[aya_ebpf::macros::xdp]
pub fn update_xdp_ingress(ctx: XdpContext) -> u32 {
    match try_update_xdp_ingress(&ctx) {
        Ok(_) => {
            debug!(
                &ctx,
                "XDP INGRESS: added packet with {} bytes",
                ctx.data_end() - ctx.data()
            );
        }
        Err(msg) => {
            error!(&ctx, "XDP INGRESS: failed to add packet: {}", msg);
        }
    }

    xdp_action::XDP_PASS
}

fn try_update_xdp_ingress(ctx: &XdpContext) -> Result<(), &'static str> {
    let data = ctx.data() as u64;
    let data_end = ctx.data_end() as u64;
    let bytes = data_end - data;

    let counter = INGRESS_COUNTER
        .get_ptr_mut(0)
        .ok_or("failed to get pointer to first entry in INGRESS_COUNTER map")?;

    unsafe {
        (*counter).packets = (*counter).packets.wrapping_add(1);
        (*counter).bytes = (*counter).bytes.wrapping_add(bytes);
    }

    Ok(())
}

#[aya_ebpf::macros::classifier]
pub fn update_tc_egress(ctx: TcContext) -> i32 {
    match try_update_tc_egress(&ctx) {
        Ok(_) => {
            debug!(
                &ctx,
                "TC EGRESS: added packet with {} bytes",
                ctx.data_end() - ctx.data()
            );
        }
        Err(msg) => {
            error!(&ctx, "TC EGRESS: failed to add packet: {}", msg);
        }
    };

    aya_ebpf::bindings::TC_ACT_PIPE
}

pub fn try_update_tc_egress(ctx: &TcContext) -> Result<(), &'static str> {
    let data = ctx.data() as u64;
    let data_end = ctx.data_end() as u64;
    let bytes = data_end - data;

    let counter = EGRESS_COUNTER
        .get_ptr_mut(0)
        .ok_or("failed to get pointer to first entry in EGRESS_COUNTER map")?;

    unsafe {
        (*counter).packets = (*counter).packets.wrapping_add(1);
        (*counter).bytes = (*counter).bytes.wrapping_add(bytes);
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
