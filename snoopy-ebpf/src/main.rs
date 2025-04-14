#![no_std]
#![no_main]

use aya_ebpf::{macros::map, maps::HashMap};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::*;
use snoopy_common::Counter;

#[map(name = "INGRESS_COUNTER")]
static INGRESS_COUNTER: HashMap<u8, Counter> = HashMap::<u8, Counter>::with_max_entries(1, 0);

#[map(name = "EGRESS_COUNTER")]
static EGRESS_COUNTER: HashMap<u8, Counter> = HashMap::<u8, Counter>::with_max_entries(1, 0);

#[classifier]
pub fn update_tc_ingress(ctx: TcContext) -> i32 {
    let Some(counter) = get_counter(&INGRESS_COUNTER) else {
        error!(&ctx, "failed to get counter");
        return aya_ebpf::bindings::TC_ACT_OK;
    };
    let data = ctx.data() as u64;
    let data_end = ctx.data_end() as u64;

    counter.packets = counter.packets.wrapping_add(1);
    counter.bytes = counter.bytes.wrapping_add(data_end - data);

    aya_ebpf::bindings::TC_ACT_OK
}

#[classifier]
pub fn update_tc_egress(ctx: TcContext) -> i32 {
    let Some(counter) = get_counter(&EGRESS_COUNTER) else {
        error!(&ctx, "failed to get counter");
        return aya_ebpf::bindings::TC_ACT_OK;
    };
    let data = ctx.data() as u64;
    let data_end = ctx.data_end() as u64;

    counter.packets = counter.packets.wrapping_add(1);
    counter.bytes = counter.bytes.wrapping_add(data_end - data);

    aya_ebpf::bindings::TC_ACT_OK
}

#[inline]
fn get_counter(map: &HashMap<u8, Counter>) -> Option<&mut Counter>{
    let key: u8 = 0;
    let counter = match map.get_ptr_mut(&key) {
        Some(counter) => counter,
        None => {
            match map.insert(&key, &Counter { packets: 0, bytes: 0 }, 0) {
                Ok(_) => {},
                Err(_) => {
                    return None;
                },
            };
            match map.get_ptr_mut(&key) {
                Some(counter) => counter,
                None => {
                    return None;
                },
            }
        },
    };

    unsafe {
        Some(&mut *counter)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
