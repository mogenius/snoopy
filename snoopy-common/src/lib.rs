#![no_std]

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Counter {}
