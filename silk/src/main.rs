//! silk: a minimal transparent proxy reusing the honk/dae kernel
//! datapath design — eBPF steers in the kernel, direct traffic never
//! reaches userspace, only proxy-bound flows enter this process.

// Some datapath helpers are only reachable from the `ebpf` feature build.
#![cfg_attr(not(feature = "ebpf"), allow(dead_code))]
// Flow tables are plain nested std types; aliases would not clarify them.
#![allow(clippy::type_complexity)]

mod bpf_raw;
mod cgroup;
mod config;
mod datapath;
mod dns;
mod hysteria2;
mod listener;
mod names;
mod ns;
mod outbound;
mod relay;
mod rules;
mod ruleset;
mod sniffer;
mod socks5;
mod vless;
mod wan_watch;

use anyhow::{Context, Result};
use clap::Parser;
use rules::{SharedRules, StaticMaps};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "silk")]
struct Args {
    /// Config file path (YAML). Used by the default run mode.
    #[arg(short, long, default_value = "/etc/silk/config.yaml")]
    config: String,

    /// Convert a source ruleset (list or sing-box JSON) to a binary ruleset
    /// (no file suffix) and exit.
    /// Usage: silk --convert-ruleset in.json /etc/silk/cn-domain
    #[arg(long, num_args = 2, value_names = ["INPUT", "OUTPUT"])]
    convert_ruleset: Option<Vec<String>>,
}

/// Resolve a node's server address. Done before any eBPF hook is attached so
/// the lookup cannot loop through our own datapath.
async fn resolve_server(node: &config::NodeConfig) -> Result<SocketAddr> {
    let server = node.server().trim();
    tokio::net::lookup_host(server)
        .await
        .with_context(|| format!("resolve {} node {} ({server})", node.type_name(), node.name()))?
        .next()
        .with_context(|| format!("node {}: no address for {server}", node.name()))
}

/// `general.lan` / `general.wan`: unset, empty or "none" disables capture.
fn capture_interface(spec: &Option<String>) -> Result<Option<(String, u32)>> {
    match spec.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => datapath::resolve_interface(s),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if let Some(pair) = args.convert_ruleset {
        let input = std::path::Path::new(&pair[0]);
        let output = std::path::Path::new(&pair[1]);
        ruleset::convert_source_to_ars(input, output)?;
        return Ok(());
    }
    let raw =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let config = config::parse(&raw).with_context(|| format!("config {}", args.config))?;
    let node_names = config.node_names();

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("silk must run as root (TC, sk_lookup, netns, transparent sockets)");
    }

    // Resolve every node's server before any eBPF hook is attached.
    let mut servers: Vec<SocketAddr> = Vec::new();
    for node in &config.nodes {
        servers.push(resolve_server(node).await?);
    }

    // 1. Proxy namespace + veth bridge.
    ns::create_silkns()?;
    datapath::setup_links(&config)?;

    // 2. eBPF: load, write globals, attach hooks, expose maps.
    let lan = capture_interface(&config.general.lan)?;
    // Follow the active uplink (Wi-Fi <-> mobile data, wired <-> wireless)
    // instead of pinning to the interface that was up at startup.
    // `wan: dynamic` works everywhere; `wan: auto` is dynamic on Android only
    // (desktop Linux keeps the fixed default-route interface).
    let wan_spec = config.general.wan.as_deref().map(str::trim);
    let dynamic_wan = wan_spec == Some("dynamic")
        || (ns::is_android() && wan_spec == Some("auto"));
    let wan = if dynamic_wan { None } else { capture_interface(&config.general.wan)? };
    if !dynamic_wan {
        datapath::setup_android_control_route(wan.as_ref().map(|(n, _)| n.as_str()));
    }
    let mut dp = datapath::load_and_attach(&config, lan.clone(), wan.clone())?;

    // 3. Routing: static surfaces now, domain surface via the DNS engine.
    // "list" rules import their ruleset files before the engines see them.
    let rules_list = config::expand_rules(&config)?;
    {
        let m = dp.maps.as_mut().expect("maps");
        m.add_private_direct()?;
        m.populate_cidr_ports(&rules_list, &node_names)?;
        let n = m.add_local_direct()?;
        tracing::info!(local_addrs = n, "local addresses routed direct");
    }
    let rules_engine = rules::Rules::new(&config.general.default, &rules_list, &node_names)?;
    tracing::info!(
        domain_rules = rules_engine.domain_rule_count,
        "domain matcher ready (source Vec + binary FST)"
    );
    let rules: SharedRules = Arc::new(Mutex::new(rules_engine));
    let maps: Arc<Mutex<StaticMaps>> = Arc::new(Mutex::new(dp.take_maps()));
    datapath::install_control_marker(&dp)?;

    // 4. Transparent listeners inside silkns, published to the sockmap.
    let listeners = listener::create(&mut dp, true).context("create transparent listeners")?;

    // 5. Nodes + engines. direct/block never get here (the kernel settles
    //    them); only node-bound flows reach the relays below.
    let nodes = Arc::new(outbound::Nodes::build(&config, &servers)?);
    if nodes.is_empty() {
        tracing::info!("no nodes configured; everything is handled in the kernel");
    }
    let default_verdict = rules::Verdict::parse(&config.general.default, &node_names)?;
    let upstream: SocketAddr = config.dns.upstream.parse().context("parse dns upstream")?;
    let remote_upstream: Option<SocketAddr> = match config.dns.remote.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(s.parse().context("parse dns remote")?),
        _ => None,
    };
    if !config.cgroups.is_empty() {
        cgroup::start(&config.cgroup_rules(), &node_names, maps.clone()).await?;
    }

    let names = Arc::new(names::NameCache::new());
    let dns = Arc::new(dns::DnsEngine::new(
        upstream,
        remote_upstream,
        rules.clone(),
        nodes.clone(),
        names.clone(),
    ));
    let tcp_ctx = Arc::new(relay::TcpCtx {
        nodes: nodes.clone(),
        default: default_verdict,
        maps: maps.clone(),
        rules: rules.clone(),
        names: names.clone(),
        sniff: config.sniff.enable,
        dial_by_domain: config.sniff.dial_by_domain,
    });
    tracing::info!(
        sniff = config.sniff.enable,
        dial_by_domain = config.sniff.dial_by_domain,
        "tcp sniffing"
    );

    tracing::info!(?lan, ?wan, default = %config.general.default, nodes = ?node_names, "datapath up; relaying");

    // 5b. Dynamic WAN capture (listeners and rules are ready now).
    let wan_watcher = if dynamic_wan {
        let w = Arc::new(std::sync::Mutex::new(wan_watch::WanWatcher::new(dp.ebpf.clone())));
        w.lock().unwrap_or_else(|e| e.into_inner()).sync();
        let h = wan_watch::spawn(w.clone());
        Some((w, h))
    } else {
        None
    };

    // 6. Relay loops.
    let mut tcp_task = tokio::spawn(relay::run_tcp(listeners.tcp4, tcp_ctx));
    let mut udp_task = tokio::spawn(relay::run_udp(
        listeners.udp4,
        nodes.clone(),
        default_verdict,
        dns.clone(),
        maps.clone(),
    ));

    // 7. Run until a signal (or a relay crash), then tear everything down:
    // netlink-attached TC filters, the veth bridge and the proxy namespace
    // all outlive the process and must be removed explicitly.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut relay_result: Option<Result<()>> = None;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; cleaning up");
        }
        _ = sigterm.recv() => {
            tracing::info!("terminated; cleaning up");
        }
        r = &mut tcp_task => {
            relay_result = Some(match r {
                Ok(v) => v,
                Err(e) => Err(anyhow::Error::new(e)),
            });
            tracing::warn!("tcp relay ended; cleaning up");
        }
        r = &mut udp_task => {
            relay_result = Some(match r {
                Ok(v) => v,
                Err(e) => Err(anyhow::Error::new(e)),
            });
            tracing::warn!("udp relay ended; cleaning up");
        }
    }
    tcp_task.abort();
    udp_task.abort();
    if let Some((w, h)) = &wan_watcher {
        h.abort();
        w.lock().unwrap_or_else(|e| e.into_inner()).detach_all();
    }

    ns::cleanup(
        lan.as_ref().map(|(n, _)| n.as_str()),
        wan.as_ref().map(|(n, _)| n.as_str()),
        datapath::SILK0_HOST,
    );
    if let Some(r) = relay_result {
        r?;
    }
    Ok(())
}
