//! Configuration model (YAML, parsed with `serde_yaml_ng`).
//!
//! Outbounds are a named node list; `general.default`, rule verdicts and
//! cgroup policies refer to nodes by name (or to the built-ins `direct` /
//! `block`, which the kernel handles without ever entering userspace).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

pub const VERDICT_NAME_DIRECT: &str = "direct";
pub const VERDICT_NAME_BLOCK: &str = "block";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub general: General,
    /// Outbound nodes. Names are unique and referenced by `general.default`,
    /// `rules` and `cgroups`. The same `type` may appear several times.
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    pub dns: Dns,
    /// Optional; protocol sniffing + dial-by-domain for proxied TCP flows.
    #[serde(default)]
    pub sniff: Sniff,
    /// Optional per-process policy by cgroup v2 path (host traffic only),
    /// grouped by mode: `bypass | <node name>: [path, ...]`.
    #[serde(default)]
    pub cgroups: BTreeMap<String, Vec<String>>,
    /// `"kind,value,verdict"` lines, first match wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// One per-cgroup policy. `path` is absolute (under /sys/fs/cgroup) or
/// relative to the cgroup v2 root; the rule covers the whole subtree and the
/// deepest matching rule wins.
#[derive(Debug, Clone)]
pub struct CgroupRule {
    pub path: String,
    /// "bypass" (alias "direct") or a node name.
    pub mode: String,
}

impl Config {
    /// Node names in config order (the index is the node id).
    pub fn node_names(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.name().trim().to_string()).collect()
    }

    /// Cgroup rules with bare service names expanded
    /// (`qbittorrent` -> `system.slice/qbittorrent.service`).
    pub fn cgroup_rules(&self) -> Vec<CgroupRule> {
        self.cgroups
            .iter()
            .flat_map(|(mode, paths)| {
                paths.iter().map(move |p| CgroupRule {
                    path: expand_cgroup_path(p),
                    mode: mode.trim().to_string(),
                })
            })
            .collect()
    }
}

fn expand_cgroup_path(key: &str) -> String {
    let key = key.trim();
    if key.contains('/') {
        return key.to_string();
    }
    let has_unit_suffix = [".service", ".scope", ".slice", ".socket", ".mount"]
        .iter()
        .any(|s| key.ends_with(s));
    if has_unit_suffix {
        format!("system.slice/{key}")
    } else {
        format!("system.slice/{key}.service")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sniff {
    /// Peek at the first bytes of every proxied TCP flow for a TLS SNI or
    /// HTTP Host, and at the first datagram of every proxied UDP flow for a
    /// QUIC Initial SNI; re-run the domain rules on the name and dial by it.
    #[serde(default = "yes")]
    pub enable: bool,
    /// Dial the proxy exit with the domain (sniffed, or remembered from the
    /// DNS answer) instead of the bare IP, so the exit resolves it itself.
    #[serde(default = "yes")]
    pub dial_by_domain: bool,
}

impl Default for Sniff {
    fn default() -> Self {
        Sniff {
            enable: true,
            dial_by_domain: true,
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    /// LAN capture interface (gateway mode): "auto", a name, or omitted /
    /// empty to disable LAN capture.
    #[serde(default)]
    pub lan: Option<String>,
    /// WAN capture interface (host mode), same forms as `lan`.
    #[serde(default)]
    pub wan: Option<String>,
    /// Skb mark steering traffic into the proxy namespace.
    #[serde(default)]
    pub tproxy_mark: Option<u32>,
    /// Verdict when no rule matches: "direct" | "block" | a node name.
    #[serde(default = "default_verdict")]
    pub default: String,
    /// Log level: off | error | warn | info | debug | trace (default info).
    /// The `RUST_LOG` environment variable, when set, overrides it.
    #[serde(default)]
    pub log: LogLevel,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// The `tracing` filter directive for this level.
    pub fn directive(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

fn default_verdict() -> String {
    VERDICT_NAME_DIRECT.into()
}

/// One outbound node. `type` picks the protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum NodeConfig {
    /// SOCKS5 (`socks` is an alias).
    #[serde(rename = "socks", alias = "socks5")]
    Socks(Socks5),
    #[serde(rename = "hysteria2", alias = "hy2")]
    Hysteria2(Hysteria2),
    #[serde(rename = "vless")]
    Vless(Box<Vless>),
}

impl NodeConfig {
    pub fn name(&self) -> &str {
        match self {
            NodeConfig::Socks(c) => &c.name,
            NodeConfig::Hysteria2(c) => &c.name,
            NodeConfig::Vless(c) => &c.name,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            NodeConfig::Socks(_) => "socks",
            NodeConfig::Hysteria2(_) => "hysteria2",
            NodeConfig::Vless(_) => "vless",
        }
    }

    pub fn server(&self) -> &str {
        match self {
            NodeConfig::Socks(c) => &c.server,
            NodeConfig::Hysteria2(c) => &c.server,
            NodeConfig::Vless(c) => &c.server,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5 {
    pub name: String,
    /// "host:port"
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2 {
    pub name: String,
    /// "host:port" or "ip:port". Resolved via system DNS at startup.
    #[serde(default)]
    pub server: String,
    /// Auth credential (Hysteria-Auth header).
    #[serde(default, deserialize_with = "de_string")]
    pub password: String,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    /// Skip server certificate verification.
    #[serde(default)]
    pub insecure: bool,
    /// Local upload bandwidth ("100 Mbps", "80"); empty/"auto" = congestion control.
    #[serde(default, deserialize_with = "de_string")]
    pub up: String,
    /// Local download bandwidth; advertised to the server via Hysteria-CC-RX.
    #[serde(default, deserialize_with = "de_string")]
    pub down: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vless {
    pub name: String,
    /// VLESS server "host:port" or "ip:port" (hostname resolved via system
    /// DNS at startup, before the eBPF hooks are attached).
    #[serde(default)]
    pub server: String,
    /// VLESS user id (UUID).
    #[serde(default)]
    pub uuid: String,
    /// Transport: "tcp" | "ws" | "xhttp".
    #[serde(default = "default_network")]
    pub network: String,
    /// Wrap the transport in TLS (server must speak TLS on this port).
    #[serde(default)]
    pub tls: bool,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    /// Skip server certificate verification (self-signed servers).
    #[serde(default)]
    pub insecure: bool,
    /// WebSocket path (network = "ws"); defaults to "/".
    #[serde(default)]
    pub ws_path: String,
    /// WebSocket Host header; defaults to the SNI.
    #[serde(default)]
    pub ws_host: String,
    /// 流控 addon: "xtls-rprx-vision"（network = "tcp" 且 tls/reality）。
    #[serde(default)]
    pub flow: String,
    /// REALITY x25519 公钥（base64url, 43 字符）。设置后启用 REALITY。
    #[serde(default)]
    pub reality_public_key: String,
    /// REALITY shortId（hex, ≤16 字符）。
    #[serde(default)]
    pub reality_short_id: String,
    /// uTLS 浏览器指纹: chrome | firefox | safari | ios | android | edge |
    /// 360 | qq | random | randomized（空 = 标准 rustls ClientHello）。
    #[serde(default)]
    pub client_fingerprint: String,
    /// 显式 TLS ALPN（逗号分隔，如 "h2,http/1.1"）。
    #[serde(default)]
    pub alpn: String,
    /// xhttp Host 头 / 伪装域名；默认 SNI。
    #[serde(default)]
    pub xhttp_host: String,
    /// xhttp 路径（network = "xhttp"），可带 query："/xhttp?token=abc"。
    #[serde(default)]
    pub xhttp_path: String,
    /// xhttp 上行模式: auto（默认；reality→stream-one, 其他→packet-up）|
    /// stream-one | packet-up | stream-up。
    #[serde(default)]
    pub xhttp_mode: String,
}

fn default_network() -> String {
    "tcp".into()
}

/// Accept a YAML string, number or bool for a string field (`up: 80`,
/// `password: 123456`), so unquoted scalars do not fail to parse.
fn de_string<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Scalar {
        S(String),
        I(i64),
        U(u64),
        F(f64),
        B(bool),
    }
    Ok(match Option::<Scalar>::deserialize(d)? {
        None => String::new(),
        Some(Scalar::S(s)) => s,
        Some(Scalar::I(v)) => v.to_string(),
        Some(Scalar::U(v)) => v.to_string(),
        Some(Scalar::F(v)) => v.to_string(),
        Some(Scalar::B(v)) => v.to_string(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Domestic resolver, queried directly (control-plane marked socket).
    /// `1.1.1.1` / `udp://1.1.1.1` (UDP, port 53), `tcp://1.1.1.1` (53),
    /// `tls://1.1.1.1` (DoT, 853) or `https://1.1.1.1/dns-query` (DoH, 443);
    /// a `:port` overrides the default. Only UDP may omit the scheme.
    pub upstream: String,
    /// Optional overseas resolver (same forms as `upstream`), queried THROUGH
    /// the proxy node a domain routes to (the default node for unmatched
    /// domains). Unset = every domain is resolved by `upstream`.
    #[serde(default)]
    pub remote: Option<String>,
    /// Resolver for hostnames: node servers (`server: node.example.com:443`)
    /// and DNS upstreams written as domains (`tls://dns.alidns.com`). Must be
    /// a plain UDP/TCP resolver given as an IP (`223.5.5.5`). Unset: falls
    /// back to `upstream` when that is such a resolver; node server names are
    /// otherwise resolved by the system resolver.
    #[serde(default)]
    pub default: Option<String>,
    /// Optional redb file persisting the DNS cache and the fake-IP mappings
    /// across restarts. Unset = memory only.
    #[serde(default)]
    pub store: Option<String>,
    /// Optional fake-IP mode (off by default).
    #[serde(default)]
    pub fakeip: FakeIp,
}

/// Fake-IP: domains routed to a proxy node get an address from `range`
/// instead of a real answer; the relay maps it back to the name and dials
/// the exit by domain. Direct / blocked domains are unaffected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeIp {
    #[serde(default)]
    pub enable: bool,
    /// IPv4 CIDR, prefix length 8..=30.
    #[serde(default = "default_fakeip_range")]
    pub range: String,
    /// Optional IPv6 range mirroring `range` (e.g. `fd00:198:18::/96`).
    /// Empty = AAAA for faked names stays an empty NOERROR (IPv4 only).
    /// The prefix needs at least as many host bits as `range` (a /15 range
    /// needs 17, so the prefix is at most /111).
    #[serde(default)]
    pub range6: String,
    /// TTL (seconds) of fake answers.
    #[serde(default = "default_fakeip_ttl")]
    pub ttl: u32,
    /// Domain suffixes that always get real answers (on top of the built-in
    /// local-name list).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Optional whitelist: when non-empty only these suffixes get fake
    /// addresses.
    #[serde(default)]
    pub include: Vec<String>,
}

impl Default for FakeIp {
    fn default() -> Self {
        FakeIp {
            enable: false,
            range: default_fakeip_range(),
            range6: String::new(),
            ttl: default_fakeip_ttl(),
            exclude: Vec::new(),
            include: Vec::new(),
        }
    }
}

fn default_fakeip_range() -> String {
    "198.18.0.0/15".into()
}

fn default_fakeip_ttl() -> u32 {
    1
}

/// One routing rule, written as a `"kind,value,verdict"` line.
///
/// The list is evaluated in order and the first match on its surface wins.
/// Domain rules additionally drive the per-IP DOMAIN_ROUTE map published by
/// the DNS engine.
#[derive(Debug, Clone)]
pub struct Rule {
    /// "cidr" | "domain" | "port" | "source" | "binary"
    pub kind: String,
    /// CIDR, domain suffix, port, or a ruleset file path for source/binary.
    pub value: String,
    /// "direct" | "block" | a node name
    pub verdict: String,
}

impl Rule {
    pub fn parse(line: &str) -> Result<Rule> {
        let line = line.trim();
        let (kind, rest) = line
            .split_once(',')
            .with_context(|| format!("rule {line:?}: expected \"kind,value,verdict\""))?;
        // The verdict is the last field; the value may itself contain commas.
        let (value, verdict) = rest
            .rsplit_once(',')
            .with_context(|| format!("rule {line:?}: expected \"kind,value,verdict\""))?;
        let rule = Rule {
            kind: kind.trim().to_ascii_lowercase(),
            value: value.trim().to_string(),
            verdict: verdict.trim().to_string(),
        };
        if rule.value.is_empty() || rule.verdict.is_empty() {
            bail!("rule {line:?}: empty value or verdict");
        }
        Ok(rule)
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Rule, D::Error> {
        let s = String::deserialize(d)?;
        Rule::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Parse and validate a config document.
pub fn parse(text: &str) -> Result<Config> {
    let config: Config = serde_yaml_ng::from_str(text).context("parse yaml")?;
    validate(&config)?;
    Ok(config)
}

/// Expand `source` rules into concrete cidr/domain rules.
///
/// - `source`: plain list **or** sing-box JSON. Domains stay as ordinary
///   domain rules (Vec match at runtime — **no FST built at startup**).
///   A file carrying the ARST magic is rewritten to `binary` (FST).
/// - `binary`: passed through; the ARST magic is verified when it is loaded.
pub fn expand_rules(config: &Config) -> Result<Vec<Rule>> {
    let mut out = Vec::new();
    for rule in &config.rules {
        if rule.kind != "source" && rule.kind != "list" {
            out.push(rule.clone());
            continue;
        }

        let raw = std::fs::read(&rule.value)
            .with_context(|| format!("read ruleset {}", rule.value))?;

        if raw.len() >= 4 && &raw[0..4] == b"ARST" {
            out.push(Rule {
                kind: "binary".into(),
                value: rule.value.clone(),
                verdict: rule.verdict.clone(),
            });
            tracing::info!("imported binary ruleset {}", rule.value);
            continue;
        }

        let compiled = crate::ruleset::parse_source_bytes(&raw)
            .with_context(|| format!("parse source ruleset {}", rule.value))?;
        let n = compiled.domains.len()
            + compiled.domain_suffixes.len()
            + compiled.ipv4_cidrs.len()
            + compiled.ipv6_cidrs.len();
        out.extend(crate::ruleset::compiled_to_rules(&compiled, &rule.verdict));
        tracing::info!(
            path = %rule.value,
            entries = n,
            "imported source ruleset (no FST; use --convert-ruleset for binary)"
        );
    }
    Ok(out)
}

/// Whether `name` is a verdict the kernel resolves on its own.
pub fn is_builtin_verdict(name: &str) -> bool {
    name.eq_ignore_ascii_case(VERDICT_NAME_DIRECT) || name.eq_ignore_ascii_case(VERDICT_NAME_BLOCK)
}

/// Static validation: node definitions and every verdict reference.
pub fn validate(config: &Config) -> Result<()> {
    if config.nodes.len() > (u8::MAX - silk_ebpf_common::VERDICT_NODE_BASE) as usize {
        bail!("too many nodes (max {})", u8::MAX - silk_ebpf_common::VERDICT_NODE_BASE);
    }

    if config.dns.fakeip.enable {
        if config.nodes.is_empty() {
            bail!("dns.fakeip needs at least one node");
        }
        let range = config.dns.fakeip.range.trim();
        let (_, plen) = crate::rules::parse_v4_cidr(range)
            .with_context(|| format!("dns.fakeip.range {range:?} must be an IPv4 CIDR"))?;
        if !(8..=30).contains(&plen) {
            bail!("dns.fakeip.range {range}: prefix length must be 8..=30");
        }
        let range6 = config.dns.fakeip.range6.trim();
        if !range6.is_empty() {
            let (_, plen6) = crate::rules::parse_v6_cidr(range6)
                .with_context(|| format!("dns.fakeip.range6 {range6:?} must be an IPv6 CIDR"))?;
            let max6 = 128 - (32 - plen as u32);
            if plen6 < 8 || plen6 as u32 > max6 {
                bail!("dns.fakeip.range6 {range6}: prefix length must be 8..={max6} for range {range}");
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    for n in &config.nodes {
        let name = n.name().trim();
        if name.is_empty() {
            bail!("a {} node has an empty name", n.type_name());
        }
        if is_builtin_verdict(name) || name.eq_ignore_ascii_case("bypass") {
            bail!("node name {name:?} is reserved");
        }
        if name.contains(',') {
            bail!("node name {name:?} must not contain ','");
        }
        if !seen.insert(name.to_string()) {
            bail!("duplicate node name {name:?}");
        }
        if n.server().trim().is_empty() {
            bail!("node {name:?} ({}): server is empty", n.type_name());
        }
        if let NodeConfig::Vless(v) = n {
            if v.uuid.trim().is_empty() {
                bail!("node {name:?} (vless): uuid is empty");
            }
            let network = v.network.trim().to_lowercase();
            if network != "tcp" && network != "ws" && network != "xhttp" {
                bail!("node {name:?} (vless): network must be \"tcp\", \"ws\" or \"xhttp\" (got {network:?})");
            }
            let flow = v.flow.trim();
            if !flow.is_empty() && flow != "xtls-rprx-vision" {
                bail!("node {name:?} (vless): flow must be \"xtls-rprx-vision\" (got {flow:?})");
            }
            if !flow.is_empty() && network != "tcp" {
                bail!("node {name:?} (vless): flow requires network \"tcp\"");
            }
            if !flow.is_empty() && !v.tls && v.reality_public_key.trim().is_empty() {
                bail!("node {name:?} (vless): flow requires tls or reality_public_key");
            }
            if !v.reality_public_key.trim().is_empty() && network == "ws" {
                bail!("node {name:?} (vless): reality does not support network \"ws\"");
            }
            let mode = v.xhttp_mode.trim().to_lowercase();
            if network != "xhttp" && !mode.is_empty() {
                bail!("node {name:?} (vless): xhttp_mode set but network is not \"xhttp\"");
            }
            if network == "xhttp"
                && !mode.is_empty()
                && mode != "auto"
                && mode != "stream-one"
                && mode != "packet-up"
                && mode != "stream-up"
            {
                bail!("node {name:?} (vless): xhttp_mode must be auto, stream-one, packet-up or stream-up (got {mode:?})");
            }
            if network == "xhttp"
                && !v.reality_public_key.trim().is_empty()
                && (mode == "packet-up" || mode == "stream-up")
            {
                bail!("node {name:?} (vless): reality only supports xhttp stream-one (got {mode:?})");
            }
        }
    }

    let check = |what: &str, verdict: &str| -> Result<()> {
        let v = verdict.trim();
        if is_builtin_verdict(v) || seen.contains(v) {
            Ok(())
        } else {
            bail!("{what}: unknown verdict/node {v:?} (expected direct, block or a node name)")
        }
    };
    check("general.default", &config.general.default)?;
    for r in &config.rules {
        check(&format!("rule {},{}", r.kind, r.value), &r.verdict)?;
    }
    let mut cg_paths: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for (mode, paths) in &config.cgroups {
        let m = mode.trim();
        if !(m.eq_ignore_ascii_case("bypass") || seen.contains(m)) {
            bail!("cgroups[{m}]: unknown mode/node (expected bypass or a node name)");
        }
        for p in paths {
            if p.trim().is_empty() {
                bail!("cgroups[{m}]: empty cgroup path");
            }
            // The same cgroup under two modes would be ambiguous.
            if let Some(prev) = cg_paths.insert(expand_cgroup_path(p), m) {
                bail!("cgroups: {p:?} is listed under both {prev:?} and {m:?}");
            }
        }
    }

    // Parses upstream / remote / default (schemes, ports, hostnames).
    crate::dnsup::DnsSpec::from_config(&config.dns)?;

    if config
        .dns
        .remote
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        && config.nodes.is_empty()
    {
        bail!("dns.remote is set but no nodes are configured");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
general:
  lan: auto
  wan: auto
  default: hy2
  tproxy_mark: 0x2027
nodes:
  - type: socks
    server: 127.0.0.1:1080
    name: socks
    username: ""
    password: ""
  - type: hysteria2
    server: example.com:443
    name: hy2
    password: "xxxx"
    up: 80 Mbps
    down: 300 Mbps
  - type: vless
    name: vless
    server: example.com:443
    uuid: 00000000-0000-0000-0000-000000000000
    network: ws
    tls: true
    ws_path: /
dns:
  upstream: 223.5.5.5:53
  remote: 8.8.8.8:53
sniff:
  enable: true
  dial_by_domain: true
cgroups:
  bypass:
    - system.slice/frps.service
  hy2:
    - qbittorrent
rules:
  - cidr,10.0.0.0/8,direct
  - domain,cn,direct
  - source,/etc/silk/geosite-google.json,hy2
  - binary,/etc/silk/cn-domain,vless
  - port,25,block
"#;

    #[test]
    fn parses_sample() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.nodes.len(), 3);
        assert_eq!(c.general.tproxy_mark, Some(0x2027));
        assert_eq!(c.rules.len(), 5);
        assert_eq!(c.rules[3].kind, "binary");
        assert_eq!(c.rules[3].verdict, "vless");
        let cg = c.cgroup_rules();
        assert!(cg.iter().any(|r| r.path == "system.slice/qbittorrent.service" && r.mode == "hy2"));
        assert!(cg.iter().any(|r| r.path == "system.slice/frps.service" && r.mode == "bypass"));
    }

    #[test]
    fn cgroups_grouped_by_mode() {
        let base = "general: {default: direct}\ndns: {upstream: '1.1.1.1:53'}\nnodes:\n  - {type: socks, server: '127.0.0.1:1', name: hy2}\n";
        let ok = format!("{base}cgroups:\n  bypass:\n    - system.slice/frps.service\n    - user-1000.slice/session-c1.scope\n  hy2:\n    - qbittorrent\n    - machine.slice/docker-abc123.scope\n");
        let c = parse(&ok).unwrap();
        let cg = c.cgroup_rules();
        assert_eq!(cg.len(), 4);
        assert!(cg.iter().any(|r| r.path == "system.slice/frps.service" && r.mode == "bypass"));
        assert!(cg.iter().any(|r| r.path == "system.slice/qbittorrent.service" && r.mode == "hy2"));
        assert!(cg.iter().any(|r| r.path == "machine.slice/docker-abc123.scope" && r.mode == "hy2"));
        // unknown mode, duplicate path across modes, old path->mode form
        assert!(parse(&format!("{base}cgroups:\n  nope:\n    - a\n")).is_err());
        assert!(parse(&format!("{base}cgroups:\n  bypass: [qbittorrent]\n  hy2: [system.slice/qbittorrent.service]\n")).is_err());
        assert!(parse(&format!("{base}cgroups:\n  qbittorrent: hy2\n")).is_err());
    }

    #[test]
    fn log_level() {
        let t = |l: &str| parse(&format!("general: {{default: direct{l}}}\ndns: {{upstream: '1.1.1.1:53'}}\n"));
        assert_eq!(t("").unwrap().general.log, LogLevel::Info);
        for (s, v) in [("off", LogLevel::Off), ("error", LogLevel::Error), ("warn", LogLevel::Warn),
                       ("info", LogLevel::Info), ("debug", LogLevel::Debug), ("trace", LogLevel::Trace)] {
            assert_eq!(t(&format!(", log: {s}")).unwrap().general.log, v);
        }
        assert!(t(", log: verbose").is_err());
    }

    #[test]
    fn example_config_parses() {
        let c = parse(include_str!("../../config.example.yaml")).unwrap();
        assert_eq!(
            c.node_names(),
            ["socks", "hy2", "vless", "vless-xhttp", "vless-reality"]
        );
        assert_eq!(c.general.default, "hy2");
        // fake-IP and the store ship commented out.
        assert!(!c.dns.fakeip.enable);
        assert!(c.dns.store.is_none());
    }

    #[test]
    fn fakeip_config() {
        let on = SAMPLE.replace(
            "upstream:",
            "store: /tmp/silk.redb\n  fakeip: {enable: true, range: 198.18.0.0/16, ttl: 5, exclude: [ntp.org]}\n  upstream:",
        );
        let c = parse(&on).unwrap();
        assert_eq!(c.dns.store.as_deref(), Some("/tmp/silk.redb"));
        assert!(c.dns.fakeip.enable);
        assert_eq!(c.dns.fakeip.range, "198.18.0.0/16");
        assert_eq!(c.dns.fakeip.ttl, 5);
        assert_eq!(c.dns.fakeip.exclude, ["ntp.org"]);

        // defaults
        let d = parse("general: {default: direct}\ndns: {upstream: '1.1.1.1:53'}\n").unwrap();
        assert!(!d.dns.fakeip.enable);
        assert_eq!(d.dns.fakeip.range, "198.18.0.0/15");
        assert_eq!(d.dns.fakeip.ttl, 1);

        // enabled without any node is rejected, as is a bad range
        let no_nodes = "general: {default: direct}\ndns: {upstream: '1.1.1.1:53', fakeip: {enable: true}}\n";
        assert!(parse(no_nodes).is_err());
        assert!(parse(&on.replace("198.18.0.0/16", "198.18.0.0/31")).is_err());
        assert!(parse(&on.replace("198.18.0.0/16", "fc00::/7")).is_err());

        // range6: optional, IPv6 only, leaves room for the v4 slot offsets
        assert!(d.dns.fakeip.range6.is_empty());
        let with6 = |r6: &str| on.replace("range: 198.18.0.0/16,", &format!("range: 198.18.0.0/16, range6: '{r6}',"));
        assert_eq!(parse(&with6("fd00:198:18::/96")).unwrap().dns.fakeip.range6, "fd00:198:18::/96");
        assert!(parse(&with6("fd00::/112")).is_ok()); // a /16 range has 16 host bits
        assert!(parse(&with6("fd00::/113")).is_err());
        assert!(parse(&with6("198.18.0.0/16")).is_err());
    }

    #[test]
    fn verdict_roundtrip() {
        use crate::rules::Verdict;
        let names = vec!["a".to_string(), "b".to_string()];
        for (s, v) in [("direct", Verdict::Direct), ("block", Verdict::Block), ("a", Verdict::Node(0)), ("b", Verdict::Node(1))] {
            let parsed = Verdict::parse(s, &names).unwrap();
            assert_eq!(parsed, v);
            assert_eq!(Verdict::from_u8(parsed.to_u8()), Some(v));
        }
        assert!(Verdict::parse("c", &names).is_err());
        assert_eq!(Verdict::from_u8(silk_ebpf_common::VERDICT_PROXY), None);
    }

    #[test]
    fn unknown_verdict_rejected() {
        let bad = SAMPLE.replace("port,25,block", "port,25,nope");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn duplicate_node_rejected() {
        let bad = SAMPLE.replace("name: vless", "name: hy2");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn direct_only_needs_no_nodes() {
        let c = parse("general: {default: direct}\ndns: {upstream: '1.1.1.1:53'}\n").unwrap();
        assert!(c.nodes.is_empty());
    }

    #[test]
    fn rule_value_may_contain_comma() {
        let r = Rule::parse("source, /a,b.json ,hy2").unwrap();
        assert_eq!(r.value, "/a,b.json");
        assert_eq!(r.verdict, "hy2");
    }
}
