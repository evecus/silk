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
mod dnsup;
mod fakeip;
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
mod store;
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
/// the lookup cannot loop through our own datapath. A hostname goes through
/// `dns.default` when one is configured, else (or if that fails) the system
/// resolver.
async fn resolve_server(node: &config::NodeConfig, resolver: &dnsup::HostResolver) -> Result<SocketAddr> {
    let server = node.server().trim();
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if resolver.is_configured()
        && let Some((host, port)) = server.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        let host = host.trim_matches(['[', ']']);
        match resolver.resolve(host).await {
            Ok(ip) => return Ok(SocketAddr::new(ip, port)),
            Err(e) => tracing::warn!(
                node = node.name(),
                error = %format!("{e:#}"),
                "dns.default could not resolve the node server; trying the system resolver"
            ),
        }
    }
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

/// `RUST_LOG`, when set, wins over `general.log`.
fn init_logging(level: config::LogLevel) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.directive())),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(pair) = args.convert_ruleset {
        init_logging(config::LogLevel::Info);
        let input = std::path::Path::new(&pair[0]);
        let output = std::path::Path::new(&pair[1]);
        ruleset::convert_source_to_ars(input, output)?;
        return Ok(());
    }
    let raw =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let config = config::parse(&raw).with_context(|| format!("config {}", args.config))?;
    init_logging(config.general.log);
    let node_names = config.node_names();

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("silk must run as root (TC, sk_lookup, netns, transparent sockets)");
    }

    // Resolve every node's server before any eBPF hook is attached.
    let dns_spec = dnsup::DnsSpec::from_config(&config.dns)?;
    let host_resolver = Arc::new(dnsup::HostResolver::new(dns_spec.default.clone()));
    let mut servers: Vec<SocketAddr> = Vec::new();
    for node in &config.nodes {
        servers.push(resolve_server(node, &host_resolver).await?);
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

    // 2b. Persistent state (DNS cache + fake-IP mappings). A store that
    //     cannot be opened degrades to memory only instead of stopping silk.
    let store: Option<Arc<store::Store>> = match config.dns.store.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => match store::Store::open(std::path::Path::new(p)) {
            Ok(s) => {
                tracing::info!(path = p, "state store open");
                Some(s)
            }
            Err(e) => {
                tracing::warn!(path = p, error = %format!("{e:#}"), "state store unavailable; running without persistence");
                None
            }
        },
        _ => None,
    };

    // 2c. Fake-IP pool (mappings restored from the store).
    let fake_pool: Option<Arc<fakeip::FakeIpPool>> = if config.dns.fakeip.enable {
        let f = &config.dns.fakeip;
        let mut pool = fakeip::FakeIpPool::new(&f.range, &f.include, &f.exclude, store.clone())?;
        if !f.range6.trim().is_empty() {
            pool = pool.with_v6(&f.range6)?;
        }
        Some(Arc::new(pool))
    } else {
        None
    };

    // 3. Routing: static surfaces now, domain surface via the DNS engine.
    // "list" rules import their ruleset files before the engines see them.
    let rules_list = config::expand_rules(&config)?;
    {
        let m = dp.maps.as_mut().expect("maps");
        m.add_private_direct()?;
        m.populate_cidr_ports(&rules_list, &node_names)?;
        if let Some(pool) = &fake_pool {
            // The kernel only needs to know the range goes to userspace; the
            // relay picks the node from the domain. Use the default node
            // when there is one, else the first.
            let v = match rules::Verdict::parse(&config.general.default, &node_names)? {
                v @ rules::Verdict::Node(_) => v,
                _ => rules::Verdict::Node(0),
            };
            m.add_cidr(pool.cidr(), v)?;
            tracing::info!(range = pool.cidr(), "fake-ip range routed to userspace");
            if let Some(c6) = pool.cidr6() {
                m.add_cidr(c6, v)?;
                tracing::info!(range6 = c6, "fake-ip v6 range routed to userspace");
            }
        }
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
    tracing::info!(
        upstream = %dns_spec.upstream,
        remote = ?dns_spec.remote.as_ref().map(|u| u.to_string()),
        "dns upstreams"
    );
    if !config.cgroup_rules().is_empty() {
        cgroup::start(&config.cgroup_rules(), &node_names, maps.clone()).await?;
    }

    let names = Arc::new(names::NameCache::new());
    let dns = Arc::new(dns::DnsEngine::new(
        dns_spec,
        host_resolver.clone(),
        rules.clone(),
        nodes.clone(),
        names.clone(),
        fake_pool.clone().map(|p| (p, config.dns.fakeip.ttl)),
        store.clone(),
    ));
    dns.restore(&maps).await;
    let tcp_ctx = Arc::new(relay::TcpCtx {
        nodes: nodes.clone(),
        default: default_verdict,
        maps: maps.clone(),
        rules: rules.clone(),
        names: names.clone(),
        sniff: config.sniff.enable,
        dial_by_domain: config.sniff.dial_by_domain,
        fakeip: fake_pool.clone(),
    });
    let udp_ctx = Arc::new(relay::UdpCtx {
        nodes: nodes.clone(),
        default: default_verdict,
        maps: maps.clone(),
        rules: rules.clone(),
        fakeip: fake_pool.clone(),
        sniff: config.sniff.enable,
        dial_by_domain: config.sniff.dial_by_domain,
    });
    tracing::info!(
        sniff = config.sniff.enable,
        dial_by_domain = config.sniff.dial_by_domain,
        fakeip = fake_pool.is_some(),
        "sniffing"
    );

    // Write DNS-cache / fake-IP changes back every 30 s, and once more on
    // `stop` (shutdown). Nothing is written to a store that is not open.
    let stop_saver = Arc::new(tokio::sync::Notify::new());
    let saver = store.is_some().then(|| {
        let (dns, pool, stop) = (dns.clone(), fake_pool.clone(), stop_saver.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                let stopping = tokio::select! {
                    _ = tick.tick() => false,
                    _ = stop.notified() => true,
                };
                dns.flush().await;
                if let Some(p) = pool.clone()
                    && let Ok(Err(e)) = tokio::task::spawn_blocking(move || p.flush()).await
                {
                    tracing::warn!(error = %format!("{e:#}"), "fakeip store write");
                }
                if stopping {
                    break;
                }
            }
        })
    });

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
    let mut udp_task = tokio::spawn(relay::run_udp(listeners.udp4, udp_ctx, dns.clone()));

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
    // Relays are stopped, so the state is final: flush it before teardown.
    stop_saver.notify_one();
    if let Some(h) = saver
        && tokio::time::timeout(std::time::Duration::from_secs(10), h).await.is_err()
    {
        tracing::warn!("state store flush timed out");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn node(server: &str) -> config::NodeConfig {
        let yaml = format!(
            "general: {{default: direct}}\ndns: {{upstream: '127.0.0.1:53'}}\nnodes:\n  - {{type: socks, server: '{server}', name: n}}\n"
        );
        config::parse(&yaml).unwrap().nodes.remove(0)
    }

    /// A UDP resolver answering every A query with 10.1.2.3.
    async fn fake_resolver() -> u16 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut b).await {
                let mut end = 12;
                while b[end] != 0 {
                    end += 1 + b[end] as usize;
                }
                end += 5;
                if n < end {
                    continue;
                }
                let mut r = b[..end].to_vec();
                r[2] = 0x81;
                r[3] = 0x80;
                r[6..8].copy_from_slice(&[0, 1]);
                r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3]);
                let _ = sock.send_to(&r, from).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn node_server_domain_resolves_through_dns_default() {
        let port = fake_resolver().await;
        let spec = dnsup::Upstream::parse(&format!("127.0.0.1:{port}")).unwrap();
        let resolver = dnsup::HostResolver::new(Some(spec));
        let a = resolve_server(&node("proxy.example.com:443"), &resolver).await.unwrap();
        assert_eq!(a, "10.1.2.3:443".parse().unwrap());
        // IP literals never touch the resolver
        let a = resolve_server(&node("203.0.113.9:1080"), &resolver).await.unwrap();
        assert_eq!(a, "203.0.113.9:1080".parse().unwrap());
        let a = resolve_server(&node("[2001:db8::1]:1080"), &resolver).await.unwrap();
        assert_eq!(a, "[2001:db8::1]:1080".parse().unwrap());
    }

    #[tokio::test]
    async fn node_server_falls_back_to_system_resolver() {
        // dns.default unreachable (nothing listens) -> system resolver; "localhost" always resolves
        let dead = dnsup::Upstream::parse("127.0.0.1:9").unwrap();
        let resolver = dnsup::HostResolver::new(Some(dead));
        let a = resolve_server(&node("localhost:443"), &resolver).await.unwrap();
        assert!(a.ip().is_loopback() && a.port() == 443);
        // and with no dns.default at all
        let a = resolve_server(&node("localhost:443"), &dnsup::HostResolver::new(None)).await.unwrap();
        assert!(a.ip().is_loopback());
    }
}
