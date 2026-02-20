use std::collections::HashMap;
use std::io::Write;
use std::ops::Add;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
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
use serde_with::{serde_as, DisplayFromStr};
use tokio::io::unix::AsyncFd;

// Netlink multicast groups for interface and address change notifications
const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x800;

type EbpfTasks = HashMap<String, (tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>)>;

// Snoopy
#[derive(Debug, Default, Parser, Clone)]
#[command(version, about)]
struct Arguments {
    #[arg(long, default_value = "1000", hide = true)]
    /// Deprecated: interface changes are now detected via netlink events, this value is ignored
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

    // Bind the netlink socket before reading the initial interface list so that
    // any changes occurring during startup are buffered and not missed.
    let netlink_socket = create_netlink_socket()?;
    let mut network_interfaces = vec![];
    let mut ebpf_tasks: EbpfTasks = HashMap::new();

    // Initial population: treat every currently-present interface as Added.
    handle_updates(
        update_network_interfaces(&mut network_interfaces),
        &args,
        &mut ebpf_tasks,
    )
    .await;

    loop {
        // Block until the kernel sends a netlink notification (interface or
        // address change), then drain all buffered messages before diffing.
        let mut guard = netlink_socket.readable().await?;
        guard.clear_ready();
        drain_netlink_messages(netlink_socket.get_ref());

        handle_updates(
            update_network_interfaces(&mut network_interfaces),
            &args,
            &mut ebpf_tasks,
        )
        .await;
    }
}

async fn handle_updates(events: Vec<InterfaceUpdate>, args: &Arguments, ebpf_tasks: &mut EbpfTasks) {
    for event in events.iter() {
        println!("{}", serde_json::to_string(&event).unwrap());

        match event {
            InterfaceUpdate::InterfaceAdded { interface } => {
                let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
                let args = args.clone();
                match initialize_ebpf_for_interface(interface.name.clone()).await {
                    Ok((ebpf, ingress_impl, egress_impl)) => {
                        println!(
                            "{}",
                            serde_json::to_string(&InterfaceBpfInitialized {
                                interface: interface.name.as_str(),
                                ingress_implementation: ingress_impl,
                                egress_implementation: egress_impl,
                            })
                            .unwrap()
                        );
                        let handle = tokio::spawn(attach_to_interface(
                            args,
                            interface.name.clone(),
                            ebpf,
                            kill_rx,
                        ));
                        ebpf_tasks.insert(interface.name.clone(), (kill_tx, handle));
                    }
                    Err(error) => {
                        println!(
                            "{}",
                            serde_json::to_string(&InterfaceBpfInitializationFailed {
                                interface: interface.name.as_str(),
                                error: error.to_string().as_str(),
                            })
                            .unwrap()
                        );
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

fn create_netlink_socket() -> anyhow::Result<AsyncFd<OwnedFd>> {
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return Err(anyhow::anyhow!(
            "failed to create netlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let addr = libc::sockaddr_nl {
        nl_family: libc::AF_NETLINK as libc::sa_family_t,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
    };
    let ret = unsafe {
        libc::bind(
            raw_fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(raw_fd) };
        return Err(anyhow::anyhow!(
            "failed to bind netlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    Ok(AsyncFd::new(owned_fd)?)
}

/// Drains all buffered netlink messages from the socket. We only need the
/// wake-up signal, not the message contents — pnet's `datalink::interfaces()`
/// gives us the authoritative current state afterwards.
fn drain_netlink_messages(fd: &OwnedFd) {
    let mut buf = [0u8; 4096];
    loop {
        let ret = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if ret <= 0 {
            break;
        }
    }
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Counter {
    #[serde_as(as = "DisplayFromStr")]
    pub packets: u64,

    #[serde_as(as = "DisplayFromStr")]
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
struct InterfaceBpfInitialized<'a> {
    interface: &'a str,
    ingress_implementation: IngressImplementation,
    egress_implementation: EgressImplementation,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
struct InterfaceBpfInitializationFailed<'a> {
    interface: &'a str,
    error: &'a str,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
struct InterfaceMetrics<'a> {
    interface: &'a str,
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

    let old_map: HashMap<&str, &NetworkInterface> =
        network_interfaces.iter().map(|i| (i.name.as_str(), i)).collect();

    let new_map: HashMap<&str, &NetworkInterface> =
        new_interfaces.iter().map(|i| (i.name.as_str(), i)).collect();

    for new_interface in new_interfaces.iter() {
        match old_map.get(new_interface.name.as_str()) {
            None => updates.push(InterfaceUpdate::InterfaceAdded {
                interface: new_interface.clone(),
            }),
            Some(old_interface) if new_interface != *old_interface => {
                updates.push(InterfaceUpdate::InterfaceChanged {
                    previous: (*old_interface).clone(),
                    new: new_interface.clone(),
                })
            }
            _ => {}
        }
    }

    for old_interface in network_interfaces.iter() {
        if !new_map.contains_key(old_interface.name.as_str()) {
            updates.push(InterfaceUpdate::InterfaceRemoved {
                interface: old_interface.clone(),
            });
        }
    }

    *network_interfaces = new_interfaces;

    updates
}
