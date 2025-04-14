use std::collections::HashMap;
use std::io::IsTerminal;

use anyhow::Context;
use aya::programs::{SchedClassifier, TcAttachType};
use aya::Pod;
use clap::Parser;
use pnet::datalink::{self, NetworkInterface};
use serde::{Deserialize, Serialize};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser)]
struct CliArgs {}

fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }

    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .event_format(tracing_subscriber::fmt::format().json())
        .with_ansi(std::io::stderr().is_terminal())
        .finish()
        .init();

    let _args = CliArgs::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        tracing::debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let (rx, _handle) = watch_network_interfaces();

    let mut ebpf_tasks = HashMap::new();
    loop {
        let event = match rx.recv() {
            Ok(event) => event,
            Err(error) => {
                tracing::error!(
                    message = "failed to receive interface update",
                    "error" = error.to_string()
                );
                continue;
            }
        };

        tracing::info!(
            message = "received event",
            "event" = serde_json::to_string(&event).unwrap()
        );

        match event {
            InterfaceUpdate::Added { interface } => {
                let (kill_tx, kill_rx) = crossbeam::channel::bounded::<()>(0);
                let cloned_interface = interface.clone();
                let handle = std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .build()
                        .unwrap();
                    if let Err(error) = rt.block_on(attach_ebpf_to_interface(&cloned_interface.name, kill_rx)) {
                        tracing::error!(
                            "failed to attach ebpf to interface '{}': {}",
                            cloned_interface.name,
                            error.to_string()
                        );
                    };
                });
                ebpf_tasks.insert(interface.name, (kill_tx, handle));
            }
            InterfaceUpdate::Removed { interface } => {
                tracing::info!("interface was removed: {}", interface);
                if let Some((_, (kill_tx, handle))) =
                    ebpf_tasks.remove_entry(interface.name.as_str())
                {
                    let _ = kill_tx.send(());
                    if let Err(error) = handle.join() {
                        tracing::error!("failed to join worker thread: {:?}", error);
                    }
                }
            }
            InterfaceUpdate::Changed { previous, new } => {
                tracing::info!("interface changed: {} -> {}", previous, new);
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

unsafe impl Pod for Counter {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
struct InterfaceMetrics<'a> {
    interface: &'a str,
    ingress: Counter,
    egress: Counter,
    rx_bytes: u64,
    tx_bytes: u64,
}

async fn attach_ebpf_to_interface(
    iface: &str,
    kill_rx: crossbeam::channel::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!("opening ebpf module for interface {}", iface);

    let rx_bytes = std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_bytes"))
        .map(|data| data.trim().parse::<u64>().unwrap_or(0))
        .unwrap_or(0);
    let tx_bytes = std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/tx_bytes"))
        .map(|data| data.trim().parse::<u64>().unwrap_or(0))
        .unwrap_or(0);

    let ebpf_program = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snoopy"));
    let mut ebpf = aya::Ebpf::load(ebpf_program).with_context(|| "failed to load ebpf program")?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        tracing::warn!("failed to initialize eBPF logger: {}", e);
    }
    let ingress_program: &mut SchedClassifier = ebpf
        .program_mut("update_tc_ingress")
        .expect("could not find program with name `update_tc_ingress`")
        .try_into()?;
    ingress_program.load()?;
    ingress_program
        .attach(iface, TcAttachType::Ingress)
        .context("failed to attach the TcAttachType::Ingress program")?;

    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("update_tc_egress")
        .expect("could not find program with name `update_tc_egress`")
        .try_into()?;
    egress_program.load()?;
    egress_program
        .attach(iface, TcAttachType::Egress)
        .context("failed to attach the TcAttachType::Egress program")?;

    let ingress_map: aya::maps::HashMap<_, u8, Counter> = aya::maps::HashMap::try_from(
        ebpf.map("INGRESS_COUNTER")
            .expect("could not find map with name `INGRESS_COUNTER`"),
    )
    .expect("failed to convert type of map");

    let egress_map: aya::maps::HashMap<_, u8, Counter> = aya::maps::HashMap::try_from(
        ebpf.map("EGRESS_COUNTER")
            .expect("could not find map with name `EGRESS_COUNTER`"),
    )
    .expect("failed to convert type of map");

    let mut last_ingress_counter = Counter::default();
    let mut last_egress_counter = Counter::default();
    let mut ingress_counter = Counter::default();
    let mut egress_counter = Counter::default();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if kill_rx.try_recv().is_ok() {
            break;
        }

        if let Ok(counter) = ingress_map.get(&0, 0) {
            ingress_counter = counter;
        };

        if let Ok(counter) = egress_map.get(&0, 0) {
            egress_counter = counter;
        };

        if last_egress_counter != egress_counter || last_ingress_counter != ingress_counter {
            let metrics = InterfaceMetrics {
                interface: iface,
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

    tracing::info!("closing ebpf module for interface {}", iface);

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

fn watch_network_interfaces() -> (
    crossbeam::channel::Receiver<InterfaceUpdate>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = crossbeam::channel::bounded::<InterfaceUpdate>(0);

    let handle = std::thread::spawn(move || {
        let interval = std::time::Duration::from_millis(100);
        let mut previous_interfaces = datalink::interfaces();
        for interface in &previous_interfaces {
            if let Err(error) = tx.send(InterfaceUpdate::Added {
                interface: interface.to_owned(),
            }) {
                tracing::error!(
                    message = "failed to send interface update",
                    "error" = error.to_string()
                );
            }
        }
        loop {
            std::thread::sleep(interval);
            let new_interfaces = datalink::interfaces();
            for new_interface in &new_interfaces {
                let previous_interface = previous_interfaces
                    .iter()
                    .find(|interface| new_interface.name.as_str() == interface.name);
                let previous_interface = match previous_interface {
                    Some(previous_interface) => previous_interface,
                    None => {
                        if let Err(error) = tx.send(InterfaceUpdate::Added {
                            interface: new_interface.to_owned(),
                        }) {
                            tracing::error!(
                                message = "failed to send interface update",
                                "error" = error.to_string()
                            );
                        }
                        continue;
                    }
                };
                if new_interface != previous_interface {
                    if let Err(error) = tx.send(InterfaceUpdate::Changed {
                        previous: previous_interface.to_owned(),
                        new: new_interface.to_owned(),
                    }) {
                        tracing::error!(
                            message = "failed to send interface update",
                            "error" = error.to_string()
                        );
                    }
                    continue;
                }
            }
            for previous_interface in &previous_interfaces {
                if !new_interfaces
                    .iter()
                    .any(|interface| previous_interface.name == interface.name)
                {
                    if let Err(error) = tx.send(InterfaceUpdate::Removed {
                        interface: previous_interface.to_owned(),
                    }) {
                        tracing::error!(
                            message = "failed to send interface update",
                            "error" = error.to_string()
                        );
                    }
                }
            }
            previous_interfaces = new_interfaces;
        }
    });

    (rx, handle)
}
