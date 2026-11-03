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
    /// Optional per-process policy by cgroup v2 path (host traffic only).
    /// `path: bypass | <node name>`.
    #[serde(default)]
    pub cgroups: BTreeMap<String, String>,
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
            .map(|(k, v)| CgroupRule {
                path: expand_cgroup_path(k),
                mode: v.trim().to_string(),
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
    /// HTTP Host, re-run the domain rules on it, and dial by name.
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
    pub upstream: String,
    /// Optional overseas resolver ("8.8.8.8:53"), queried THROUGH the proxy
    /// node a domain routes to (the default node for unmatched domains).
    /// Unset = every domain is resolved by `upstream`.
    #[serde(default)]
    pub remote: Option<String>,
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
    for (path, mode) in &config.cgroups {
        let m = mode.trim();
        if m.eq_ignore_ascii_case("bypass") || seen.contains(m) {
            continue;
        }
        bail!("cgroups[{path}]: unknown mode/node {m:?} (expected bypass or a node name)");
    }

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
  system.slice/frps.service: bypass
  qbittorrent: hy2
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
    fn example_config_parses() {
        let c = parse(include_str!("../../config.example.yaml")).unwrap();
        assert_eq!(c.node_names(), ["socks", "hy2", "vless"]);
        assert_eq!(c.general.default, "hy2");
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
