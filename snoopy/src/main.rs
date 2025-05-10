use std::collections::HashMap;
use std::io::Write;
use std::ops::Add;
use std::path::Path;
use std::str::FromStr;

use anyhow::Context;
use anyhow::anyhow;
use aya::Pod;
use aya::programs::SchedClassifier;
use aya::programs::TcAttachType;
use aya::programs::Xdp;
use aya::programs::XdpFlags;
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
    /// Polling rate for updating the network devices list
    pub network_device_poll_rate: u64,

    #[arg(long, default_value = "500")]
    /// Rate at which network metrics are collected from BPF modules and printed to stdout
    pub metrics_rate: u64,
}

#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::builder()
        .target(Target::Stderr)
        .format(|buf, record| {
            writeln!(
                buf,
                "{{\"level\": \"{}\", \"target\": \"{}\", \"message\":{}}}",
                record.level(),
                record.target(),
                serde_json::to_string(&record.args().to_string()).unwrap()
            )
        })
        .init();

    let args = Arguments::parse();

    if !Path::new("/sys/kernel/btf").exists() {
        return Err(anyhow!("This Kernel does not support BTF"));
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "remove limit on locked memory failed, ret is: {}",
            ret
        ));
    }

    let mut interface_update_interval = tokio::time::interval(std::time::Duration::from_millis(
        args.network_device_poll_rate,
    ));
    let mut network_interfaces = vec![];
    let mut ebpf_tasks = HashMap::new();

    loop {
        interface_update_interval.tick().await;
        let network_interface_updates = update_network_interfaces(&mut network_interfaces);
        for event in network_interface_updates.iter() {
            println!("{}", serde_json::to_string(&event).unwrap());

            match event {
                InterfaceUpdate::InterfaceAdded { interface } => {
                    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
                    let args = args.clone();
                    match initialize_ebpf_for_interface(interface.name.clone()).await {
                        Ok((ebpf, ingress_impl, egress_impl)) => {
                            let handle = tokio::spawn(attach_to_interface(
                                args,
                                interface.name.clone(),
                                ebpf,
                                ingress_impl,
                                egress_impl,
                                kill_rx,
                            ));
                            ebpf_tasks.insert(interface.name.clone(), (kill_tx, handle));
                        }
                        Err(error) => {
                            log::error!("failed to initialize ebpf module for {interface}: {error}")
                        }
                    }
                }
                InterfaceUpdate::InterfaceRemoved { interface } => {
                    log::info!("interface was removed: {interface:?}");
                    if let Some((_, (kill_tx, handle))) =
                        ebpf_tasks.remove_entry(interface.name.as_str())
                    {
                        let _ = kill_tx.send(());
                        if handle.await.is_err() {
                            log::error!("failed to join worker thread");
                        }
                    }
                }
                InterfaceUpdate::InterfaceChanged { previous, new } => {
                    log::info!("interface changed: {previous:?} -> {new:?}");
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
    ingress_implementation: IngressImplementation,
    egress_implementation: EgressImplementation,
    ingress: Counter,
    egress: Counter,
}

#[derive(Debug, Copy, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressImplementation {
    #[default]
    None,
    Classifier,
    Xdp,
}

impl FromStr for IngressImplementation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "classifier" => Ok(IngressImplementation::Classifier),
            "xdp" => Ok(IngressImplementation::Xdp),
            _ => Err(anyhow::anyhow!("Invalid Ingress Implementation: {s}")),
        }
    }
}

#[derive(Debug, Copy, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressImplementation {
    #[default]
    None,
    Classifier,
}

impl FromStr for EgressImplementation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "classifier" => Ok(EgressImplementation::Classifier),
            _ => Err(anyhow::anyhow!("Invalid Egress Implementation: {s}")),
        }
    }
}

async fn initialize_ebpf_for_interface(
    iface: String,
) -> anyhow::Result<(aya::Ebpf, IngressImplementation, EgressImplementation)> {
    let ebpf_program = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snoopy"));
    let mut ebpf = aya::Ebpf::load(ebpf_program).with_context(|| "failed to load ebpf program")?;

    if let Err(error) = aya_log::EbpfLogger::init_with_logger(&mut ebpf, log::logger()) {
        // This can happen if you remove all log statements from your eBPF program.
        log::warn!("failed to initialize eBPF logger: {error}");
    }

    if let Err(error) = aya::programs::tc::qdisc_add_clsact(iface.as_str()) {
        match error.kind() {
            std::io::ErrorKind::AlreadyExists => {}
            _ => log::warn!(
                "failed to call aya::programs::tc::qdisc_add_clsact on {iface:?}: {error}"
            ),
        }
    }

    let ingress_impl = attach_ingress_counter(&mut ebpf, iface.as_str());
    let egress_impl = attach_egress_counter(&mut ebpf, iface.as_str());

    Ok((ebpf, ingress_impl, egress_impl))
}

async fn attach_to_interface(
    args: Arguments,
    iface: String,
    ebpf: aya::Ebpf,
    ingress_impl: IngressImplementation,
    egress_impl: EgressImplementation,
    mut kill_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let mut last_ingress_counter = Counter::default();
    let mut last_egress_counter = Counter::default();

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

    let mut check_interval =
        tokio::time::interval(std::time::Duration::from_millis(args.metrics_rate));

    loop {
        tokio::select! {
            _ = &mut kill_rx => {
                break;
            }
            _ = check_interval.tick() => handle_metrics_update(
                iface.as_str(),
                ingress_impl,
                egress_impl,
                &mut last_ingress_counter,
                &mut last_egress_counter,
                &ingress_map,
                &egress_map
            )
        }
    }

    log::info!("closed ebpf module for interface {iface}");
}

/// Attempt to attach any of the available implementations for counting ingress traffic
/// and returns the chosen implementation.
fn attach_ingress_counter(ebpf: &mut aya::Ebpf, iface: &str) -> IngressImplementation {
    if attach_ingress_xdp_counter(ebpf, iface).is_ok() {
        return IngressImplementation::Xdp;
    }

    if attach_ingress_classifier_counter(ebpf, iface).is_ok() {
        return IngressImplementation::Classifier;
    }

    IngressImplementation::None
}

/// ingress counter implementation using `XDP`
fn attach_ingress_xdp_counter(ebpf: &mut aya::Ebpf, iface: &str) -> anyhow::Result<()> {
    let ingress_program: &mut Xdp = ebpf.program_mut("update_xdp_ingress").unwrap().try_into()?;
    ingress_program.load()?;
    ingress_program
        .attach(iface, XdpFlags::default())
        .map_err(|err| anyhow!("failed to attach the XDP program with default flags: {err}"))?;

    Ok(())
}

/// ingress counter implementation using `Classifier` also known as `Tc`
fn attach_ingress_classifier_counter(ebpf: &mut aya::Ebpf, iface: &str) -> anyhow::Result<()> {
    let ingress_program: &mut SchedClassifier = ebpf
        .program_mut("update_tc_ingress")
        .expect("could not find program with name `update_tc_ingress`")
        .try_into()?;
    ingress_program.load()?;
    ingress_program
        .attach(iface, TcAttachType::Ingress)
        .map_err(|err| anyhow!("failed to attach the TcAttachType::Ingress program: {err}"))?;

    Ok(())
}

/// Attempt to attach any of the available implementations for counting egress traffic
/// and returns the chosen implementation.
fn attach_egress_counter(ebpf: &mut aya::Ebpf, iface: &str) -> EgressImplementation {
    if attach_egress_classifier_counter(ebpf, iface).is_ok() {
        return EgressImplementation::Classifier;
    }

    EgressImplementation::None
}

/// egress counter implementation using `Classifier` also known as `Tc`
fn attach_egress_classifier_counter(ebpf: &mut aya::Ebpf, iface: &str) -> anyhow::Result<()> {
    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("update_tc_egress")
        .expect("could not find program with name `update_tc_egress`")
        .try_into()?;
    egress_program.load()?;
    egress_program
        .attach(iface, TcAttachType::Egress)
        .map_err(|err| anyhow!("failed to attach the TcAttachType::Egress program: {err}"))?;

    Ok(())
}

fn handle_metrics_update(
    iface: &str,
    ingress_implementation: IngressImplementation,
    egress_implementation: EgressImplementation,
    last_ingress_counter: &mut Counter,
    last_egress_counter: &mut Counter,
    ingress_map: &aya::maps::PerCpuArray<&aya::maps::MapData, Counter>,
    egress_map: &aya::maps::PerCpuArray<&aya::maps::MapData, Counter>,
) {
    let mut ingress_counter = Counter::default();
    for counter in ingress_map.get(&0, 0).unwrap().iter() {
        ingress_counter = ingress_counter + *counter;
    }

    let mut egress_counter = Counter::default();
    for counter in egress_map.get(&0, 0).unwrap().iter() {
        egress_counter = egress_counter + *counter;
    }

    if *last_egress_counter != egress_counter || *last_ingress_counter != ingress_counter {
        let metrics = InterfaceMetrics {
            interface: iface,
            ingress_implementation,
            egress_implementation,
            ingress: ingress_counter,
            egress: egress_counter,
        };
        println!("{}", serde_json::to_string(&metrics).unwrap());
        // eprintln!(
        //     "{iface:?} DOWNLOAD({:?}) UPLOAD({:?})",
        //     human_bytes::human_bytes(ingress_counter.bytes as f64),
        //     human_bytes::human_bytes(egress_counter.bytes as f64),
        // );
    }

    let _ = std::mem::replace(last_ingress_counter, ingress_counter);
    let _ = std::mem::replace(last_egress_counter, egress_counter);
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum InterfaceUpdate {
    InterfaceAdded {
        interface: NetworkInterface,
    },
    InterfaceRemoved {
        interface: NetworkInterface,
    },
    InterfaceChanged {
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
                updates.push(InterfaceUpdate::InterfaceAdded {
                    interface: new_interface.clone(),
                });
                continue;
            }
        };

        if new_interface != previous_interface {
            updates.push(InterfaceUpdate::InterfaceChanged {
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
            updates.push(InterfaceUpdate::InterfaceRemoved {
                interface: previous_interface.clone(),
            });
        }
    }

    let _ = std::mem::replace(network_interfaces, new_interfaces);

    updates
}
