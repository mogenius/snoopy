use std::collections::HashMap;
use std::ops::Add;

use anyhow::Context;
use aya::Pod;
use aya::programs::SchedClassifier;
use aya::programs::TcAttachType;
use aya::programs::Xdp;
use aya::programs::XdpFlags;
use aya::programs::tc;
use clap::Parser;
use env_logger::Target;
use pnet::datalink::NetworkInterface;
use pnet::datalink::{self};
use serde::Deserialize;
use serde::Serialize;

// Snoopy
#[derive(Debug, Default, Parser, Clone)]
#[command(version, about)]
struct Arguments {
    #[arg(long, default_value = "100")]
    pub network_device_poll_rate: u64,

    #[arg(long, default_value = "500")]
    pub metrics_rate: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }

    let args = Arguments::parse();

    env_logger::builder().target(Target::Stderr).init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut interface_update_interval = tokio::time::interval(std::time::Duration::from_millis(args.network_device_poll_rate));
    let mut network_interfaces = vec![];
    let mut ebpf_tasks = HashMap::new();

    loop {
        interface_update_interval.tick().await;
        let network_interface_updates = update_network_interfaces(&mut network_interfaces);
        for event in network_interface_updates.iter() {
            log::info!("received event: {}", serde_json::to_string(&event).unwrap());

            match event {
                InterfaceUpdate::Added { interface } => {
                    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
                    let cloned_interface = interface.clone();
                    let args = args.clone();
                    let handle = tokio::spawn(attach_to_interface(args, cloned_interface.name.clone(), kill_rx));
                    ebpf_tasks.insert(interface.name.clone(), (kill_tx, handle));
                }
                InterfaceUpdate::Removed { interface } => {
                    log::info!("interface was removed: {}", interface);
                    if let Some((_, (kill_tx, handle))) =
                        ebpf_tasks.remove_entry(interface.name.as_str())
                    {
                        let _ = kill_tx.send(());
                        if handle.await.is_err() {
                            log::error!("failed to join worker thread");
                        }
                    }
                }
                InterfaceUpdate::Changed { previous, new } => {
                    log::info!("interface changed: {} -> {}", previous, new);
                }
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

unsafe impl Pod for Counter {}

impl Add for Counter {
    type Output = Counter;

    fn add(self, rhs: Self) -> Self::Output {
        Counter {
            packets: self.packets + rhs.packets,
            bytes: self.bytes + rhs.bytes,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
struct InterfaceMetrics<'a> {
    interface: &'a str,
    ingress: Counter,
    egress: Counter,
    rx_bytes: u64,
    tx_bytes: u64,
}

async fn attach_to_interface(
    args: Arguments,
    iface: String,
    mut kill_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    log::info!("opening ebpf module for interface {iface}");

    let rx_bytes = std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_bytes"))
        .map(|data| data.trim().parse::<u64>().unwrap_or(0))
        .unwrap_or(0);
    let tx_bytes = std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/tx_bytes"))
        .map(|data| data.trim().parse::<u64>().unwrap_or(0))
        .unwrap_or(0);

    let ebpf_program = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snoopy"));
    let mut ebpf = aya::Ebpf::load(ebpf_program).with_context(|| "failed to load ebpf program")?;
    if let Err(error) = aya_log::EbpfLogger::init_with_logger(&mut ebpf, log::logger()) {
        // This can happen if you remove all log statements from your eBPF program.
        log::warn!("failed to initialize eBPF logger: {error}");
    }

    let _ = tc::qdisc_add_clsact(iface.as_str());

    // let ingress_program: &mut SchedClassifier = ebpf
    //     .program_mut("update_tc_ingress")
    //     .expect("could not find program with name `update_tc_ingress`")
    //     .try_into()?;
    // ingress_program.load()?;
    // ingress_program
    //     .attach(iface.as_str(), TcAttachType::Ingress)
    //     .context("failed to attach the TcAttachType::Ingress program")?;

    let ingress_program: &mut Xdp = ebpf.program_mut("update_xdp_ingress").unwrap().try_into()?;
    ingress_program.load()?;
    ingress_program.attach(iface.as_str(), XdpFlags::default())
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("update_tc_egress")
        .expect("could not find program with name `update_tc_egress`")
        .try_into()?;
    egress_program.load()?;
    egress_program
        .attach(iface.as_str(), TcAttachType::Egress)
        .context("failed to attach the TcAttachType::Egress program")?;

    tokio::task::spawn(async move {
        let mut last_ingress_counter = Counter::default();
        let mut last_egress_counter = Counter::default();
        let mut ingress_counter: Counter;
        let mut egress_counter: Counter;

        let ingress_map: aya::maps::PerCpuArray<_, Counter> = aya::maps::PerCpuArray::try_from(
            ebpf.map("INGRESS_COUNTER")
                .expect("could not find map with name `INGRESS_COUNTER`"),
        )
        .expect("failed to convert type of map");

        let egress_map: aya::maps::PerCpuArray<_, Counter> = aya::maps::PerCpuArray::try_from(
            ebpf.map("EGRESS_COUNTER")
                .expect("could not find map with name `EGRESS_COUNTER`"),
        )
        .expect("failed to convert type of map");

        let mut check_interval = tokio::time::interval(std::time::Duration::from_millis(args.metrics_rate));

        loop {
            tokio::select! {
                _ = &mut kill_rx => {
                    break;
                }
                _ = check_interval.tick() => {
                    ingress_counter = Counter::default();
                    for counter in ingress_map.iter().flatten() {
                        ingress_counter = ingress_counter + *counter.first().unwrap();
                    }
        
                    egress_counter = Counter::default();
                    for counter in egress_map.iter().flatten() {
                        egress_counter = egress_counter + *counter.first().unwrap();
                    }
        
                    if last_egress_counter != egress_counter || last_ingress_counter != ingress_counter {
                        let metrics = InterfaceMetrics {
                            interface: iface.as_str(),
                            ingress: ingress_counter,
                            egress: egress_counter,
                            rx_bytes,
                            tx_bytes,
                        };
        
                        println!("{}", serde_json::to_string(&metrics).unwrap());
                    }
        
                    last_ingress_counter = ingress_counter;
                    last_egress_counter = egress_counter;
                }
            }
        }

        log::info!("closed ebpf module for interface {iface}");
    });

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum InterfaceUpdate {
    Added {
        interface: NetworkInterface,
    },
    Removed {
        interface: NetworkInterface,
    },
    Changed {
        previous: NetworkInterface,
        new: NetworkInterface,
    },
}

fn update_network_interfaces(
    network_interfaces: &mut Vec<NetworkInterface>,
) -> Vec<InterfaceUpdate> {
    let new_interfaces = datalink::interfaces();
    let mut updates = vec![];

    for new_interface in new_interfaces.iter() {
        let previous_interface = network_interfaces
            .iter_mut()
            .find(|interface| new_interface.name.as_str() == interface.name);
        let previous_interface = match previous_interface {
            Some(previous_interface) => previous_interface,
            None => {
                updates.push(InterfaceUpdate::Added {
                    interface: new_interface.clone(),
                });
                continue;
            }
        };
        if new_interface != previous_interface {
            updates.push(InterfaceUpdate::Changed {
                previous: previous_interface.clone(),
                new: new_interface.clone(),
            });
            continue;
        }
    }
    for previous_interface in network_interfaces.iter() {
        if !new_interfaces
            .iter()
            .any(|interface| previous_interface.name == interface.name)
        {
            updates.push(InterfaceUpdate::Removed {
                interface: previous_interface.clone(),
            });
        }
    }

    let _ = std::mem::replace(network_interfaces, new_interfaces);

    updates
}
