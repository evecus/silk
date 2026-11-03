//! Datapath bring-up: sysctls, `silkns` veth bridge, aya load/attach, map
//! population. Link/routes management shells out to `ip` on purpose — the
//! interesting parts (programs, maps, listeners) are all in-process.

use crate::config::Config;
use crate::ns::{run_cmd, run_ip_netns, with_silkns, NETNS_NAME};
use crate::rules::StaticMaps;
use aya::maps::{MapData, SockMap};
use anyhow::{Context, Result};
use silk_ebpf_common::{CONTROL_MARK, TPROXY_MARK};

#[cfg(feature = "ebpf")]
use aya::maps::{lpm_trie::LpmTrie, HashMap};
#[cfg(feature = "ebpf")]
use aya::programs::{SchedClassifier, SkLookup, TcAttachType};
#[cfg(feature = "ebpf")]
use silk_ebpf_common::Param;
#[cfg(feature = "ebpf")]
use std::os::fd::{AsFd, AsRawFd};

#[cfg(feature = "ebpf")]
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(C, align(32))]
        struct Aligned<const N: usize>([u8; N]);
        static ALIGNED: Aligned<{ include_bytes!($path).len() }> = Aligned(*include_bytes!($path));
        &ALIGNED.0
    }};
}

pub const SILK0_HOST: &str = "silk0";
pub const SILK0_PEER: &str = "silk0peer";
/// honk's link addressing, /32 each side plus a ULA /64 for v6.
const SILK0_V4: &str = "169.254.0.1/32";
const SILK0PEER_V4: &str = "169.254.0.11/32";
const SILK0_V6: &str = "fd00:686f:6e6b::1/64";
const SILK0PEER_V6: &str = "fd00:686f:6e6b::2/64";
const SILK0_V6_GW: &str = "fd00:686f:6e6b::1";

pub struct Datapath {
    /// Taken over by the control plane at startup (None afterwards).
    pub maps: Option<StaticMaps>,
    pub listen_sockets: SockMap<MapData>,
    pub sk_storage_fd: std::os::fd::RawFd,
    /// Owns SK_IDENTITY; dropping it would close `sk_storage_fd`.
    #[allow(dead_code)]
    _sk_storage: MapData,
    /// Keep the loader alive: detached programs pin their links.
    pub ebpf: std::sync::Arc<std::sync::Mutex<aya::Ebpf>>,
}

impl Datapath {
    pub fn take_maps(&mut self) -> StaticMaps {
        self.maps.take().expect("maps already taken")
    }
}

static CONTROL: std::sync::OnceLock<(std::os::fd::RawFd, u32)> = std::sync::OnceLock::new();

/// Global control-socket marker used by dial helpers without a Datapath
/// handle (SOCKS5 client, DNS upstream). Installed at startup.
pub fn install_control_marker(dp: &Datapath) -> Result<()> {
    CONTROL
        .set((dp.sk_storage_fd, CONTROL_MARK))
        .map_err(|_| anyhow::anyhow!("control marker already installed"))
}

/// Mark a control-plane socket so the datapath never loops on it.
pub fn mark_global_control(fd: std::os::fd::RawFd) -> Result<()> {
    let (map_fd, mark) = CONTROL.get().context("control marker not installed")?;
    crate::bpf_raw::set_socket_mark(fd, *mark)?;
    crate::bpf_raw::mark_control_socket(*map_fd, fd)
}

/// Resolve an interface name or "auto" (default-route device) to
/// (name, ifindex). aya attaches by name; eBPF PARAM wants the ifindex.
pub fn resolve_interface(spec: &str) -> Result<Option<(String, u32)>> {
    if spec.is_empty() || spec == "none" {
        return Ok(None);
    }
    let name = if spec == "auto" {
        default_route_interface().context("auto: no default route")?
    } else {
        spec.to_string()
    };
    let c = std::ffi::CString::new(name.clone())?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("interface {name} not found");
    }
    Ok(Some((name, idx)))
}

fn default_route_interface() -> Result<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let dev = text
        .split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .context("no dev in default route")?;
    Ok(dev.to_string())
}


/// Host reachability to the veth peer subnet via `silk0`.
/// Android: high-priority rule + table 101, and stamp common per-iface tables.
fn setup_host_proxy_routes() {
    const TABLE: &str = "101";
    const PRIO: &str = "50";
    let _ = run_cmd(&["ip", "route", "replace", "169.254.0.11/32", "dev", SILK0_HOST, "table", "main"]);
    let _ = run_cmd(&["ip", "route", "replace", "169.254.0.0/16", "dev", SILK0_HOST, "table", "main"]);
    let _ = run_cmd(&["ip", "route", "flush", "table", TABLE]);
    let _ = run_cmd(&[
        "ip", "route", "replace", "169.254.0.0/16", "dev", SILK0_HOST, "src", "169.254.0.1", "table", TABLE,
    ]);
    let _ = run_cmd(&["ip", "rule", "del", "to", "169.254.0.0/16", "lookup", TABLE]);
    if let Err(e) = run_cmd(&[
        "ip", "rule", "add", "to", "169.254.0.0/16", "lookup", TABLE, "priority", PRIO,
    ]) {
        tracing::warn!(error = %e, "ip rule for 169.254/16 failed (ok on plain desktop)");
    }
    for table in ["wlan0", "ccmni0", "ccmni1", "rmnet_data0", "rmnet_data1"] {
        let _ = run_cmd(&[
            "ip", "route", "replace", "169.254.0.0/16", "dev", SILK0_HOST, "src", "169.254.0.1", "table", table,
        ]);
        let _ = run_cmd(&[
            "ip", "route", "replace", "169.254.0.11/32", "dev", SILK0_HOST, "src", "169.254.0.1", "table", table,
        ]);
    }
    if crate::ns::is_android() {
        tracing::info!("android host routes: table {TABLE} prio {PRIO} via {SILK0_HOST}");
    }
}

/// Android routes by fwmark: netd's rules match the low 16 bits (0xffff) as a
/// netId. CONTROL_MARK's low 16 bits (0x6e69) are not a real netId, so control
/// sockets (node dials, DNS upstream) fall through to `from all unreachable`
/// and fail with ENETUNREACH. Send exactly-CONTROL_MARK traffic to the table
/// of the WAN interface instead.
pub fn setup_android_control_route(wan: Option<&str>) {
    if !crate::ns::is_android() {
        return;
    }
    let Some(wan) = wan else { return };
    let mark = format!("{:#x}/0xffffffff", CONTROL_MARK);
    let table = android_table_for(wan).unwrap_or_else(|| wan.to_string());
    for fam in [None, Some("-6")] {
        let mut del: Vec<&str> = vec!["ip"];
        let mut add: Vec<&str> = vec!["ip"];
        if let Some(f) = fam {
            del.push(f);
            add.push(f);
        }
        del.extend(["rule", "del", "fwmark", &mark, "priority", "40"]);
        add.extend(["rule", "add", "fwmark", &mark, "lookup", &table, "priority", "40"]);
        while run_cmd(&del).is_ok() {}
        if let Err(e) = run_cmd(&add) {
            tracing::warn!(error = %e, family = ?fam, "android control-socket rule failed");
        }
    }
    tracing::info!(%table, %wan, "android: control sockets (mark {mark}) routed via wan table");
}

/// Find the routing table Android assigned to `iface` (name or number, exactly
/// as `ip` prints it, so it can be fed back to `ip rule ... lookup`).
fn android_table_for(iface: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "table", "all"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if !line.starts_with("default") {
            continue;
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        let on_dev = w.windows(2).any(|p| p[0] == "dev" && p[1] == iface);
        if !on_dev {
            continue;
        }
        if let Some(i) = w.iter().position(|x| *x == "table")
            && let Some(t) = w.get(i + 1)
        {
            return Some((*t).to_string());
        }
    }
    None
}

pub fn setup_links(config: &Config) -> Result<()> {
    // Kernel prerequisites for a transparent gateway.
    let _ = run_cmd(&["sysctl", "-w", "net.ipv4.ip_forward=1"]);
    let _ = run_cmd(&["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"]);
    for ifc in ["all", "default"] {
        let _ = run_cmd(&[
            "sysctl",
            "-w",
            &format!("net.ipv4.conf.{ifc}.rp_filter=0"),
        ]);
    }
    {
        let ifc = config.general.lan.as_deref().filter(|s| !s.is_empty() && *s != "auto" && *s != "none").unwrap_or("all");
        let _ = run_cmd(&["sysctl", "-w", &format!("net.ipv4.conf.{ifc}.rp_filter=0")]);
    }

    // Fresh veth pair every start.
    let _ = run_cmd(&["ip", "link", "del", SILK0_HOST]);
    let _ = run_cmd(&["ip", "link", "del", SILK0_PEER]);
    // Linux: create with the peer directly in the named netns. Android's `ip`
    // rejects netns names, so it skips straight to host-create + move-by-pid.
    let direct_ok = !crate::ns::is_android()
        && match run_cmd(&[
            "ip", "link", "add", SILK0_HOST, "type", "veth", "peer", "name", SILK0_PEER,
            "netns", NETNS_NAME,
        ]) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "veth create with netns name failed; trying host-then-move");
                let _ = run_cmd(&["ip", "link", "del", SILK0_HOST]);
                let _ = run_cmd(&["ip", "link", "del", SILK0_PEER]);
                false
            }
        };
    if !direct_ok {
        run_cmd(&[
            "ip", "link", "add", SILK0_HOST, "type", "veth", "peer", "name", SILK0_PEER,
        ])
        .context("ip link add veth (host)")?;
        crate::ns::move_link_to_silkns(SILK0_PEER)?;
    }

    // Confirm peer landed in the named netns (catches desync early).
    run_ip_netns(&["link", "show", SILK0_PEER]).with_context(|| {
        format!("{SILK0_PEER} missing in netns {NETNS_NAME} after veth create")
    })?;

    run_cmd(&["ip", "addr", "add", SILK0_V4, "dev", SILK0_HOST])?;
    let _ = run_cmd(&["ip", "addr", "add", SILK0_V6, "dev", SILK0_HOST]);
    run_cmd(&["ip", "link", "set", SILK0_HOST, "up"])?;
    let _ = run_cmd(&["tc", "qdisc", "add", "dev", SILK0_HOST, "clsact"]);

    let silk0_mac = link_mac(SILK0_HOST)?;
    run_ip_netns(&["link", "set", "lo", "up"])?;
    run_ip_netns(&["addr", "add", SILK0PEER_V4, "dev", SILK0_PEER])?;
    let _ = run_ip_netns(&["addr", "add", SILK0PEER_V6, "dev", SILK0_PEER]);
    run_ip_netns(&["link", "set", SILK0_PEER, "up"])?;

    // Like honk: no reverse-path filtering and accept "local" sources inside
    // silkns / on silk0, otherwise redirected packets can be dropped by the
    // kernel before the transparent listeners see them. Best-effort.
    for key in [
        "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.all.accept_local=1",
        "net.ipv4.conf.all.route_localnet=1",
        "net.ipv4.conf.silk0peer.rp_filter=0",
        "net.ipv4.conf.silk0peer.accept_local=1",
        "net.ipv4.conf.silk0peer.route_localnet=1",
        "net.ipv4.conf.lo.accept_local=1",
        "net.ipv4.conf.lo.route_localnet=1",
    ] {
        let _ = crate::ns::exec_in_silkns(&["sysctl", "-w", key]);
    }
    for key in [
        "net.ipv4.conf.silk0.rp_filter=0",
        "net.ipv4.conf.silk0.accept_local=1",
        "net.ipv4.conf.all.rp_filter=0",
    ] {
        let _ = run_cmd(&["sysctl", "-w", key]);
    }

    // Android policy routing often ignores main-table routes (table wlan0 first).
    setup_host_proxy_routes();

    let _ = crate::ns::exec_in_silkns(&["tc", "qdisc", "add", "dev", SILK0_PEER, "clsact"]);

    // Control-plane replies leave silkns via silk0peer. Addresses are /32, so
    // the gateway is not in any subnet: `onlink` accepts it, and the static
    // neighbor entry below makes it resolvable without ARP. `replace` keeps
    // restarts idempotent.
    run_ip_netns(&[
        "route",
        "replace",
        "default",
        "via",
        "169.254.0.1",
        "dev",
        SILK0_PEER,
        "onlink",
    ])?;
    let _ = run_ip_netns(&[
        "-6",
        "route",
        "replace",
        "default",
        "via",
        SILK0_V6_GW,
        "dev",
        SILK0_PEER,
        "onlink",
    ]);
    run_ip_netns(&[
        "neigh",
        "replace",
        "169.254.0.1",
        "lladdr",
        &silk0_mac,
        "dev",
        SILK0_PEER,
        "nud",
        "permanent",
    ])?;

    // Marked packets deliver to local transparent sockets. A "local default"
    // route must sit on a device — use lo, which is up at this point.
    // `replace` keeps restarts against a stale netns idempotent.
    let mark = tproxy_mark(config);
    let _ = run_ip_netns(&["rule", "del", "fwmark", &format!("{mark:#x}"), "table", "100"]);
    run_ip_netns(&["rule", "add", "fwmark", &format!("{mark:#x}"), "table", "100"])?;
    run_ip_netns(&[
        "route",
        "replace",
        "local",
        "default",
        "dev",
        "lo",
        "table",
        "100",
    ])?;
    let _ = run_ip_netns(&["-6", "rule", "del", "fwmark", &format!("{mark:#x}"), "table", "100"]);
    let _ = run_ip_netns(&[
        "-6",
        "rule",
        "add",
        "fwmark",
        &format!("{mark:#x}"),
        "table",
        "100",
    ]);
    let _ = run_ip_netns(&[
        "-6",
        "route",
        "replace",
        "local",
        "default",
        "dev",
        "lo",
        "table",
        "100",
    ]);
    Ok(())
}

fn link_mac(name: &str) -> Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mac = text
        .split_whitespace()
        .skip_while(|w| *w != "link/ether")
        .nth(1)
        .context("no mac")?;
    Ok(mac.to_string())
}

pub fn tproxy_mark(config: &Config) -> u32 {
    config.general.tproxy_mark.unwrap_or(TPROXY_MARK)
}

#[allow(dead_code)]
fn ifindex_in_silkns(name: &str) -> Result<u32> {
    with_silkns(|| {
        let c = std::ffi::CString::new(name)?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            anyhow::bail!("{name} not found in silkns");
        }
        Ok(idx)
    })
}

/// Load the eBPF object, write globals, attach all hooks, and hand back the
/// map handles the control plane drives.
#[cfg(feature = "ebpf")]
pub fn load_and_attach(
    config: &Config,
    lan: Option<(String, u32)>,
    wan: Option<(String, u32)>,
) -> Result<Datapath> {
    let silk0 = unsafe { libc::if_nametoindex(std::ffi::CString::new(SILK0_HOST)?.as_ptr()) };
    let param = Param {
        silk0_ifindex: silk0,
        lan_ifindex: lan.as_ref().map(|(_, i)| *i).unwrap_or(0),
        wan_ifindex: wan.as_ref().map(|(_, i)| *i).unwrap_or(0),
        default_verdict: crate::rules::Verdict::parse(&config.general.default, &config.node_names())?.to_u8(),
        dns_hijack: 1,
        cgroup_rules: u8::from(!config.cgroups.is_empty()),
        _pad: 0,
    };

    let mut ebpf = aya::EbpfLoader::new()
        .set_global("PARAM", &param, true)
        // SK_IDENTITY (sk_storage) has no aya 0.13 wrapper; we only need its
        // fd for raw bpf() syscalls, which Map::Unsupported still provides.
        .allow_unsupported_maps()
        .load(include_bytes_aligned!(
            "../../silk-ebpf/target/bpfel-unknown-none/release/silk-ebpf"
        ))
        .context("load silk-ebpf object (build silk-ebpf first)")?;

    for prog in ["lan_ingress", "wan_egress", "silk0_ingress", "silk0peer_ingress"] {
        let p: &mut SchedClassifier = ebpf
            .program_mut(prog)
            .context("program missing")?
            .try_into()?;
        p.load()?;
    }
    let sk_lookup: &mut SkLookup = ebpf
        .program_mut("tproxy_sk_lookup")
        .context("tproxy_sk_lookup missing")?
        .try_into()?;
    sk_lookup.load()?;

    // Host-side hooks. TCX rejects already-attached names across restarts of
    // the same pinned name, but a fresh process gets fresh links.
    if let Some((lan_name, _)) = &lan {
        let p: &mut SchedClassifier = ebpf.program_mut("lan_ingress").unwrap().try_into()?;
        p.attach(lan_name, TcAttachType::Ingress)
            .context("attach lan_ingress")?;
    }
    if let Some((wan_name, _)) = &wan {
        let p: &mut SchedClassifier = ebpf.program_mut("wan_egress").unwrap().try_into()?;
        p.attach(wan_name, TcAttachType::Egress)
            .context("attach wan_egress")?;
    }
    let p: &mut SchedClassifier = ebpf.program_mut("silk0_ingress").unwrap().try_into()?;
    p.attach(SILK0_HOST, TcAttachType::Ingress)
        .context("attach silk0_ingress")?;

    // Proxy-namespace hooks must be attached from inside silkns.
    // Verify the peer exists *in the same ns* as SILKNS before aya attach —
    // ENODEV here almost always means netns desync or missing link.
    with_silkns(|| {
        let idx = {
            let c = std::ffi::CString::new(SILK0_PEER)?;
            unsafe { libc::if_nametoindex(c.as_ptr()) }
        };
        if idx == 0 {
            // Debug listing for Android bring-up.
            let _ = std::process::Command::new("ip")
                .args(["link"])
                .status();
            anyhow::bail!(
                "{SILK0_PEER} not present inside silkns at attach time (if_nametoindex=0).                  Check that veth peer was moved into the same netns held by SILKNS."
            );
        }
        tracing::info!(ifindex = idx, "silkns peer present; attaching silk0peer_ingress");
        // clsact may have been added via `ip -n`; re-ensure for this netns view.
        let _ = run_cmd(&["tc", "qdisc", "add", "dev", SILK0_PEER, "clsact"]);
        let p: &mut SchedClassifier =
            ebpf.program_mut("silk0peer_ingress").unwrap().try_into()?;
        p.attach(SILK0_PEER, TcAttachType::Ingress)
            .context("attach silk0peer_ingress")?;
        let s: &mut SkLookup = ebpf.program_mut("tproxy_sk_lookup").unwrap().try_into()?;
        let netns = crate::ns::silkns_fd()?;
        s.attach(&netns).context("attach tproxy_sk_lookup (silkns)")?;
        Ok(())
    })?;

    let maps = StaticMaps {
        domain_route: HashMap::try_from(take_map(&mut ebpf, "DOMAIN_ROUTE")?)?,
        port_route: HashMap::try_from(take_map(&mut ebpf, "PORT_ROUTE")?)?,
        cgroup_rules: HashMap::try_from(take_map(&mut ebpf, "CGROUP_RULES")?)?,
        flow_track: HashMap::try_from(take_map(&mut ebpf, "FLOW_TRACK")?)?,
        cidr_v4: LpmTrie::try_from(take_map(&mut ebpf, "CIDR_V4")?)?,
        cidr_v6: LpmTrie::try_from(take_map(&mut ebpf, "CIDR_V6")?)?,
    };
    let listen_sockets = SockMap::try_from(take_map(&mut ebpf, "LISTEN_SOCKETS")?)?;
    let sk_storage = map_data(take_map(&mut ebpf, "SK_IDENTITY")?);
    let sk_storage_fd = sk_storage.fd().as_fd().as_raw_fd();


    Ok(Datapath {
        maps: Some(maps),
        listen_sockets,
        sk_storage_fd,
        _sk_storage: sk_storage,
        ebpf: std::sync::Arc::new(std::sync::Mutex::new(ebpf)),
    })
}

fn take_map(ebpf: &mut aya::Ebpf, name: &str) -> Result<aya::maps::Map> {
    ebpf.take_map(name).context(format!("map {name} missing"))
}

/// Every `Map` variant wraps `MapData`; unwrap it for raw-fd access.
fn map_data(map: aya::maps::Map) -> aya::maps::MapData {
    use aya::maps::Map;
    match map {
        Map::Array(d)
        | Map::BloomFilter(d)
        | Map::CpuMap(d)
        | Map::DevMap(d)
        | Map::DevMapHash(d)
        | Map::HashMap(d)
        | Map::LpmTrie(d)
        | Map::LruHashMap(d)
        | Map::PerCpuArray(d)
        | Map::PerCpuHashMap(d)
        | Map::PerCpuLruHashMap(d)
        | Map::PerfEventArray(d)
        | Map::ProgramArray(d)
        | Map::Queue(d)
        | Map::RingBuf(d)
        | Map::SockHash(d)
        | Map::SockMap(d)
        | Map::Stack(d)
        | Map::StackTraceMap(d)
        | Map::Unsupported(d)
        | Map::XskMap(d) => d,
    }
}

#[cfg(not(feature = "ebpf"))]
pub fn load_and_attach(
    _config: &Config,
    _lan: Option<(String, u32)>,
    _wan: Option<(String, u32)>,
) -> Result<Datapath> {
    anyhow::bail!(
        "built without the `ebpf` feature; build with:\n  \
         cd silk-ebpf && cargo build --release -Zbuild-std=core --target bpfel-unknown-none\n  \
         cargo build --release --features ebpf"
    )
}

/// Insert a listener fd into LISTEN_SOCKETS.
impl Datapath {
    pub fn publish_listener(&mut self, key: u32, fd: std::os::fd::RawFd) -> Result<()> {
        self.listen_sockets.set(key, &fd, 0)?;
        Ok(())
    }

    /// Mark a control-plane socket so the datapath never loops on it.
    #[allow(dead_code)]
    pub fn mark_control(&self, fd: std::os::fd::RawFd) -> Result<()> {
        mark_global_control(fd)
    }
}
