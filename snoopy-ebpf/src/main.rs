#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::programs::TcContext;

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

// Both directions are counted with TC classifiers only. XDP was tried first
// for ingress before, but attaching an XDP program to a veth clears TSO on
// its peer (`tx-tcp-segmentation: off [fixed]`), so the host had to segment
// every packet sent into the pod, and on `lo` it ran as generic XDP on every
// loopback packet. A classifier sees the same bytes without either cost.
//
// There is no aya-log here: the only failure path is a lookup of index 0 in
// a 1-entry array, which cannot fail, and each loaded object paid a 128 KiB
// AYA_LOGS ring buffer for it.

#[aya_ebpf::macros::classifier]
pub fn update_tc_ingress(ctx: TcContext) -> i32 {
    count(&INGRESS_COUNTER, ctx.len() as u64);
    aya_ebpf::bindings::TC_ACT_PIPE
}

#[aya_ebpf::macros::classifier]
pub fn update_tc_egress(ctx: TcContext) -> i32 {
    count(&EGRESS_COUNTER, ctx.len() as u64);
    aya_ebpf::bindings::TC_ACT_PIPE
}

#[inline(always)]
fn count(map: &PerCpuArray<Counter>, bytes: u64) {
    if let Some(counter) = map.get_ptr_mut(0) {
        // SAFETY: per-CPU map slot; programs on one CPU never run concurrently.
        unsafe {
            (*counter).packets = (*counter).packets.wrapping_add(1);
            (*counter).bytes = (*counter).bytes.wrapping_add(bytes);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
