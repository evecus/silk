//! Routing rules engine + map writers.
//!
//! eBPF only understands three concrete surfaces (CIDR LPM, ports, per-IP
//! domain verdicts). Domain *strings* are matched here, once per DNS answer,
//! and the resulting verdict is published into DOMAIN_ROUTE.
//!
//! - Inline / `source` domain rules: plain Vec (no FST at startup).
//! - `binary` (`.ars`): FST sets for large lists.

use anyhow::{bail, Context, Result};
use aya::maps::lpm_trie::Key;
use aya::maps::{HashMap, MapData};
use fst::Set;
use silk_ebpf_common::{DomainRouteEntry, FlowKey, TrackEntry, VERDICT_BLOCK, VERDICT_DIRECT, VERDICT_NODE_BASE};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

/// Routing decision for a surface. `Direct` and `Block` are resolved in the
/// kernel; `Node(i)` sends the flow into userspace, where node `i` (index in
/// the config's `nodes` list) forwards it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Direct,
    Block,
    Node(u8),
}

impl Verdict {
    /// Parse "direct" | "block" | a node name (`nodes` = configured names in
    /// order).
    pub fn parse(s: &str, nodes: &[String]) -> Result<Verdict> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("direct") {
            return Ok(Verdict::Direct);
        }
        if s.eq_ignore_ascii_case("block") {
            return Ok(Verdict::Block);
        }
        match nodes.iter().position(|n| n == s) {
            Some(i) => Ok(Verdict::Node(i as u8)),
            None => anyhow::bail!("unknown verdict or node: {s}"),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Verdict::Direct => VERDICT_DIRECT,
            Verdict::Block => VERDICT_BLOCK,
            Verdict::Node(i) => VERDICT_NODE_BASE + i,
        }
    }

    /// Inverse of [`Verdict::to_u8`]. `None` for 0 and for the bare
    /// "userspace, no node" verdict (DNS hijack).
    pub fn from_u8(v: u8) -> Option<Verdict> {
        match v {
            VERDICT_DIRECT => Some(Verdict::Direct),
            VERDICT_BLOCK => Some(Verdict::Block),
            v if v >= VERDICT_NODE_BASE => Some(Verdict::Node(v - VERDICT_NODE_BASE)),
            _ => None,
        }
    }
}

/// One pre-built binary ruleset (ARST membership FSTs) tagged with a verdict.
struct BinaryDomainSet {
    exact: Option<Set<Arc<[u8]>>>,
    suffix: Option<Set<Arc<[u8]>>>,
    verdict: Verdict,
}

pub struct Rules {
    pub default: Verdict,
    /// Inline + source domain-suffix rules (label lists). No FST.
    domain_rules: Vec<(Vec<String>, Verdict)>,
    /// Binary domain sets (exact + suffix), each with a fixed verdict.
    binary_sets: Vec<BinaryDomainSet>,
    pub domain_rule_count: usize,
}

impl Rules {
    pub fn new(
        default_verdict: &str,
        rules: &[crate::config::Rule],
        nodes: &[String],
    ) -> Result<Rules> {
        let mut domain_rules = Vec::new();
        let mut binary_sets = Vec::new();
        let mut domain_rule_count = 0usize;

        for rule in rules {
            let verdict = Verdict::parse(&rule.verdict, nodes)?;
            match rule.kind.as_str() {
                "domain" => {
                    let labels = split_domain(&rule.value);
                    if !labels.is_empty() {
                        domain_rules.push((labels, verdict));
                        domain_rule_count += 1;
                    }
                }
                "binary" => {
                    let data = std::fs::read(&rule.value)
                        .with_context(|| format!("read binary ruleset {}", rule.value))?;
                    let loaded = load_ars_domains(&data)
                        .with_context(|| format!("parse binary ruleset {}", rule.value))?;
                    let n_exact = loaded.exact.as_ref().map(|s| s.len()).unwrap_or(0);
                    let n_suf = loaded.suffix.as_ref().map(|s| s.len()).unwrap_or(0);
                    domain_rule_count += n_exact + n_suf;
                    tracing::info!(
                        path = %rule.value,
                        exact = n_exact,
                        suffix = n_suf,
                        verdict = %rule.verdict,
                        "loaded binary domain ruleset"
                    );
                    binary_sets.push(BinaryDomainSet {
                        exact: loaded.exact,
                        suffix: loaded.suffix,
                        verdict,
                    });
                }
                "cidr" | "port" => {}
                other => anyhow::bail!("unknown rule kind: {other}"),
            }
        }

        Ok(Rules {
            default: Verdict::parse(default_verdict, nodes)?,
            domain_rules,
            binary_sets,
            domain_rule_count,
        })
    }

    /// Longest-suffix domain match. `None` when no domain rule matches.
    pub fn match_domain(&self, domain: &str) -> Option<Verdict> {
        let labels = split_domain(domain);
        if labels.is_empty() {
            return None;
        }

        let mut best: Option<(usize, Verdict)> = None;

        for (pattern, verdict) in &self.domain_rules {
            if pattern.is_empty() || pattern.len() > labels.len() {
                continue;
            }
            if pattern[..] == labels[labels.len() - pattern.len()..]
                && best.map(|(n, _)| pattern.len() > n).unwrap_or(true) {
                    best = Some((pattern.len(), *verdict));
                }
        }

        let label_refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();
        for bin in &self.binary_sets {
            if let Some(set) = &bin.exact {
                let key = exact_fst_key_from_labels(&label_refs);
                if set.contains(&key) {
                    let depth = labels.len();
                    if best.map(|(n, _)| depth >= n).unwrap_or(true) {
                        best = Some((depth, bin.verdict));
                    }
                }
            }
            if let Some(set) = &bin.suffix
                && let Some(depth) = match_suffix_fst_depth(set, &label_refs)
                    && best.map(|(n, _)| depth > n).unwrap_or(true) {
                        best = Some((depth, bin.verdict));
                    }
        }

        best.map(|(_, v)| v)
    }
}

fn split_domain(s: &str) -> Vec<String> {
    s.trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

fn match_suffix_fst_depth(set: &Set<Arc<[u8]>>, labels: &[&str]) -> Option<usize> {
    let mut buf = Vec::with_capacity(64);
    let mut best = None;
    for depth in 1..=labels.len() {
        buf.clear();
        let start = labels.len() - depth;
        for i in (start..labels.len()).rev() {
            buf.extend_from_slice(labels[i].as_bytes());
            buf.push(b'.');
        }
        if set.contains(&buf) {
            best = Some(depth);
        }
    }
    best
}

fn exact_fst_key_from_labels(labels: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (k, lab) in labels.iter().rev().enumerate() {
        if k > 0 {
            buf.push(b'.');
        }
        buf.extend_from_slice(lab.as_bytes());
    }
    buf
}

const ARS_MAGIC: &[u8; 4] = b"ARST";
const ARS_HEADER_LEN: usize = 14;
const ARS_SECTION_HEADER_LEN: usize = 9;
const ARS_DOMAIN_FST: u8 = 0x05;
const ARS_DOMAIN_SUFFIX_FST: u8 = 0x06;

struct LoadedArsDomains {
    exact: Option<Set<Arc<[u8]>>>,
    suffix: Option<Set<Arc<[u8]>>>,
}

fn load_ars_domains(data: &[u8]) -> Result<LoadedArsDomains> {
    if data.len() < ARS_HEADER_LEN {
        bail!("ars truncated header");
    }
    if &data[0..4] != ARS_MAGIC {
        bail!("bad ars magic (expected ARST)");
    }
    let version = data[4];
    if version != 0x01 {
        bail!("unsupported ars version {version}");
    }
    let section_count = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;
    let mut off = ARS_HEADER_LEN;
    let mut exact_bytes: Option<Vec<u8>> = None;
    let mut suffix_bytes: Option<Vec<u8>> = None;

    for _ in 0..section_count {
        if off + ARS_SECTION_HEADER_LEN > data.len() {
            bail!("ars truncated section header");
        }
        let ty = data[off];
        let byte_len = u32::from_le_bytes(data[off + 5..off + 9].try_into().unwrap()) as usize;
        off += ARS_SECTION_HEADER_LEN;
        if off + byte_len > data.len() {
            bail!("ars truncated section body");
        }
        let body = &data[off..off + byte_len];
        match ty {
            ARS_DOMAIN_FST => exact_bytes = Some(body.to_vec()),
            ARS_DOMAIN_SUFFIX_FST => suffix_bytes = Some(body.to_vec()),
            _ => {}
        }
        off += byte_len;
    }

    let exact = match exact_bytes {
        Some(b) if !b.is_empty() => {
            let arc: Arc<[u8]> = Arc::from(b);
            Some(Set::new(arc).map_err(|e| anyhow::anyhow!("ars domain fst: {e}"))?)
        }
        _ => None,
    };
    let suffix = match suffix_bytes {
        Some(b) if !b.is_empty() => {
            let arc: Arc<[u8]> = Arc::from(b);
            Some(Set::new(arc).map_err(|e| anyhow::anyhow!("ars suffix fst: {e}"))?)
        }
        _ => None,
    };
    Ok(LoadedArsDomains { exact, suffix })
}

/// Static surfaces (CIDR / ports) written once at startup.
pub struct StaticMaps {
    pub domain_route: HashMap<MapData, [u8; 16], DomainRouteEntry>,
    pub port_route: HashMap<MapData, u16, u8>,
    /// cgroup v2 id -> CGROUP_MODE_* (kept fresh by `cgroup.rs`).
    pub cgroup_rules: HashMap<MapData, u64, u8>,
    /// Capture-time flow records; userspace reads the node verdict from it.
    pub flow_track: HashMap<MapData, FlowKey, TrackEntry>,
    pub cidr_v4: aya::maps::lpm_trie::LpmTrie<MapData, [u8; 4], u8>,
    pub cidr_v6: aya::maps::lpm_trie::LpmTrie<MapData, [u8; 16], u8>,
}

impl StaticMaps {
    pub fn populate_cidr_ports(
        &mut self,
        rules: &[crate::config::Rule],
        nodes: &[String],
    ) -> Result<()> {
        for rule in rules {
            let verdict = Verdict::parse(&rule.verdict, nodes)?.to_u8();
            match rule.kind.as_str() {
                "cidr" => self.insert_cidr(&rule.value, verdict)?,
                "port" => {
                    let port: u16 = rule.value.parse().context("bad port in rule")?;
                    self.port_route.insert(port, verdict, 0)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Private/link-local/multicast ranges go direct unless the user's own
    /// rules say otherwise (call this BEFORE `populate_cidr_ports`).
    pub fn add_private_direct(&mut self) -> Result<()> {
        for c in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "224.0.0.0/4",
            "fe80::/10",
            "fc00::/7",
            "ff00::/8",
        ] {
            self.insert_cidr(c, VERDICT_DIRECT)?;
        }
        Ok(())
    }

    /// Traffic addressed to this host itself (replies to its own dials, ssh,
    /// frp, ...) must never be captured by the LAN ingress hook. Every local
    /// address gets a /32 (/128) direct entry. Returns how many were added.
    pub fn add_local_direct(&mut self) -> Result<usize> {
        let out = std::process::Command::new("ip")
            .args(["-o", "addr", "show"])
            .output()
            .context("run `ip -o addr show`")?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut n = 0;
        for line in text.lines() {
            let mut it = line.split_whitespace();
            while let Some(tok) = it.next() {
                if tok == "inet" || tok == "inet6" {
                    if let Some(addr) = it.next().and_then(|a| a.split('/').next()) {
                        let cidr = if tok == "inet" {
                            format!("{addr}/32")
                        } else {
                            format!("{addr}/128")
                        };
                        if self.insert_cidr(&cidr, VERDICT_DIRECT).is_ok() {
                            n += 1;
                        }
                    }
                    break;
                }
            }
        }
        Ok(n)
    }

    /// The kernel verdict recorded when the datapath captured this flow
    /// (`client` -> `orig`). `None` when no track entry exists (evicted) or
    /// it carries no node (DNS hijack).
    pub fn flow_verdict(&self, client: std::net::SocketAddr, orig: std::net::SocketAddr, udp: bool) -> Option<Verdict> {
        let key = FlowKey {
            src_ip: v6_mapped(client.ip()),
            dst_ip: v6_mapped(orig.ip()),
            // The kernel stores ports as read off the wire (network order).
            sport: client.port().to_be(),
            dport: orig.port().to_be(),
            proto: if udp { silk_ebpf_common::IPPROTO_UDP } else { silk_ebpf_common::IPPROTO_TCP },
            _pad: [0; 7],
        };
        let entry = self.flow_track.get(&key, 0).ok()?;
        Verdict::from_u8(entry.verdict)
    }

    fn insert_cidr(&mut self, value: &str, verdict: u8) -> Result<()> {
        if let Ok((v4, plen)) = parse_v4_cidr(value) {
            self.cidr_v4
                .insert(&Key::new(plen as u32, v4.octets()), verdict, 0)?;
        } else if let Ok((v6, plen)) = parse_v6_cidr(value) {
            self.cidr_v6
                .insert(&Key::new(plen as u32, v6.octets()), verdict, 0)?;
        } else {
            anyhow::bail!("bad CIDR: {value}");
        }
        Ok(())
    }

    /// Publish one DNS-answered address with the verdict its domain resolves
    /// to. Called by the DNS engine for every A/AAAA record.
    pub fn publish_domain_ip(&mut self, ip: std::net::IpAddr, verdict: Verdict) -> Result<()> {
        let key = v6_mapped(ip);
        let entry = DomainRouteEntry {
            verdict: verdict.to_u8(),
            _pad: [0; 7],
        };
        self.domain_route.insert(key, entry, 0)?;
        Ok(())
    }
}

/// 16-byte address form used by the maps (IPv4 is v4-mapped).
fn v6_mapped(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let mut k = [0u8; 16];
            k[10] = 0xff;
            k[11] = 0xff;
            k[12..16].copy_from_slice(&v4.octets());
            k
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

pub fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, plen) = s
        .split_once('/')
        .with_context(|| format!("bad CIDR: {s}"))?;
    Ok((Ipv4Addr::from_str(addr)?, plen.parse()?))
}

pub fn parse_v6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, plen) = s
        .split_once('/')
        .with_context(|| format!("bad CIDR: {s}"))?;
    Ok((Ipv6Addr::from_str(addr)?, plen.parse()?))
}

/// Shared handle handed to the DNS engine.
pub type SharedRules = Arc<tokio::sync::Mutex<Rules>>;
