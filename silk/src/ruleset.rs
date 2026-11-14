//! Text ruleset parsing (list / sing-box JSON) and binary (ARST) conversion.
//!
//! `source` rules load text at runtime **without** building an FST: domains
//! become plain suffix rules (Vec). Large sets should be converted offline to
//! a suffix-less binary file used by `binary` rules (ARST / FST).

use anyhow::{anyhow, bail, Context, Result};
use fst::SetBuilder;
use serde::Deserialize;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Default)]
pub struct CompiledRuleSet {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub ipv4_cidrs: Vec<(Ipv4Addr, u8)>,
    pub ipv6_cidrs: Vec<(Ipv6Addr, u8)>,
}

/// Parse a source file (sing-box JSON or plain list) into compiled entries.
pub fn parse_source_bytes(data: &[u8]) -> Result<CompiledRuleSet> {
    let text = std::str::from_utf8(data).context("source ruleset is not UTF-8")?;
    parse_source_text(text)
}

pub fn parse_source_text(text: &str) -> Result<CompiledRuleSet> {
    let t = text.trim_start();
    if t.starts_with('{') {
        compile_singbox_json(text)
    } else {
        compile_list_text(text)
    }
}

/// Plain list: one domain suffix or CIDR per line.
fn compile_list_text(text: &str) -> Result<CompiledRuleSet> {
    let mut out = CompiledRuleSet::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = line.strip_prefix("+.").unwrap_or(line);
        if value.contains('/') {
            push_cidr(&mut out, value);
        } else {
            push_suffix(&mut out, value.trim_start_matches('.'));
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct SingboxSourceFile {
    #[serde(default)]
    rules: Vec<SingboxRule>,
}

#[derive(Deserialize)]
struct SingboxRule {
    #[serde(default)]
    rules: Option<serde_json::Value>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    #[serde(default)]
    domain_regex: Vec<String>,
    #[serde(default)]
    ip_cidr: Vec<String>,
}

fn compile_singbox_json(src: &str) -> Result<CompiledRuleSet> {
    let file: SingboxSourceFile =
        serde_json::from_str(src).context("parse sing-box rule-set JSON")?;
    let mut out = CompiledRuleSet::default();
    for rule in &file.rules {
        if rule.rules.is_some() {
            tracing::warn!("skip sing-box logical rule (nested rules)");
            continue;
        }
        if rule.kind.is_some() {
            tracing::warn!("skip sing-box rule with `type` field");
            continue;
        }
        for d in &rule.domain {
            push_domain(&mut out, d);
        }
        for d in &rule.domain_suffix {
            push_suffix(&mut out, d.trim_start_matches('.'));
        }
        if !rule.domain_keyword.is_empty() {
            tracing::warn!(
                n = rule.domain_keyword.len(),
                "skip domain_keyword (not used by silk matcher)"
            );
        }
        if !rule.domain_regex.is_empty() {
            tracing::warn!(
                n = rule.domain_regex.len(),
                "skip domain_regex (not used by silk matcher)"
            );
        }
        for c in &rule.ip_cidr {
            push_cidr(&mut out, c);
        }
    }
    Ok(out)
}

fn push_domain(out: &mut CompiledRuleSet, s: &str) {
    let v = s.trim_matches('.').to_ascii_lowercase();
    if !v.is_empty() {
        out.domains.push(v);
    }
}

fn push_suffix(out: &mut CompiledRuleSet, s: &str) {
    let v = s.trim_matches('.').to_ascii_lowercase();
    if !v.is_empty() {
        out.domain_suffixes.push(v);
    }
}

fn push_cidr(out: &mut CompiledRuleSet, cidr: &str) {
    if let Ok((v4, p)) = parse_v4_cidr(cidr) {
        out.ipv4_cidrs.push((v4, p));
    } else if let Ok((v6, p)) = parse_v6_cidr(cidr) {
        out.ipv6_cidrs.push((v6, p));
    } else if let Ok(v4) = Ipv4Addr::from_str(cidr) {
        out.ipv4_cidrs.push((v4, 32));
    } else if let Ok(v6) = Ipv6Addr::from_str(cidr) {
        out.ipv6_cidrs.push((v6, 128));
    } else {
        tracing::warn!("skip invalid ip/cidr: {cidr}");
    }
}

fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, pref) = s.split_once('/').ok_or_else(|| anyhow!("missing /"))?;
    let a: Ipv4Addr = addr.parse()?;
    let p: u8 = pref.parse()?;
    if p > 32 {
        bail!("ipv4 prefix > 32");
    }
    Ok((a, p))
}

fn parse_v6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, pref) = s.split_once('/').ok_or_else(|| anyhow!("missing /"))?;
    let a: Ipv6Addr = addr.parse()?;
    let p: u8 = pref.parse()?;
    if p > 128 {
        bail!("ipv6 prefix > 128");
    }
    Ok((a, p))
}

// ---- ARST writer (domain FST + suffix FST + CIDR sections) ----

const MAGIC: [u8; 4] = *b"ARST";
const VERSION: u8 = 0x01;
const SEC_DOMAIN_FST: u8 = 0x05;
const SEC_SUFFIX_FST: u8 = 0x06;
const SEC_V4: u8 = 0x10;
const SEC_V6: u8 = 0x11;

fn domain_to_fst_key(domain: &str) -> String {
    let mut labels: Vec<&str> = domain.split('.').filter(|s| !s.is_empty()).collect();
    labels.reverse();
    labels.join(".")
}

fn suffix_to_fst_key(suffix: &str) -> String {
    let mut key = domain_to_fst_key(suffix);
    if !key.is_empty() {
        key.push('.');
    }
    key
}

fn build_set(keys: &[String]) -> Result<Vec<u8>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut sorted = keys.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut builder = SetBuilder::memory();
    for k in &sorted {
        builder
            .insert(k.as_bytes())
            .map_err(|e| anyhow!("fst insert: {e}"))?;
    }
    builder
        .into_inner()
        .map_err(|e| anyhow!("fst finish: {e}"))
}

fn encode_ipv4(list: &[(Ipv4Addr, u8)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(list.len() * 5);
    for (a, p) in list {
        buf.extend_from_slice(&a.octets());
        buf.push(*p);
    }
    buf
}

fn encode_ipv6(list: &[(Ipv6Addr, u8)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(list.len() * 17);
    for (a, p) in list {
        buf.extend_from_slice(&a.octets());
        buf.push(*p);
    }
    buf
}

/// Write compiled rules as ARST binary (compatible with `kind = "binary"`).
pub fn write_ars<W: Write>(compiled: &CompiledRuleSet, w: &mut W) -> Result<()> {
    let domain_keys: Vec<String> = compiled.domains.iter().map(|d| domain_to_fst_key(d)).collect();
    let suffix_keys: Vec<String> = compiled
        .domain_suffixes
        .iter()
        .map(|d| suffix_to_fst_key(d))
        .collect();
    let domain_fst = build_set(&domain_keys)?;
    let suffix_fst = build_set(&suffix_keys)?;
    let v4 = encode_ipv4(&compiled.ipv4_cidrs);
    let v6 = encode_ipv6(&compiled.ipv6_cidrs);

    let sections: Vec<(u8, usize, Vec<u8>)> = [
        (SEC_DOMAIN_FST, compiled.domains.len(), domain_fst),
        (SEC_SUFFIX_FST, compiled.domain_suffixes.len(), suffix_fst),
        (SEC_V4, compiled.ipv4_cidrs.len(), v4),
        (SEC_V6, compiled.ipv6_cidrs.len(), v6),
    ]
    .into_iter()
    .filter(|(_, _, data)| !data.is_empty())
    .collect();

    w.write_all(&MAGIC)?;
    w.write_all(&[VERSION])?;
    w.write_all(&[0x00])?;
    w.write_all(&(sections.len() as u32).to_le_bytes())?;
    w.write_all(&[0u8; 4])?;

    for (ty, count, data) in &sections {
        w.write_all(&[*ty])?;
        w.write_all(&(*count as u32).to_le_bytes())?;
        w.write_all(&(data.len() as u32).to_le_bytes())?;
        w.write_all(data)?;
    }
    Ok(())
}

/// Convert a source file (list or sing-box JSON) to a suffix-less ARST binary.
pub fn convert_source_to_ars(input: &Path, output: &Path) -> Result<()> {
    // Binary rulesets are extension-less files (recognised by their ARST
    // magic, not by name): drop a trailing `.ars` if one was given.
    let output = &strip_ars_suffix(output);
    let raw = std::fs::read(input).with_context(|| format!("read {input:?}"))?;
    let compiled = parse_source_bytes(&raw)?;
    let mut out = std::fs::File::create(output).with_context(|| format!("create {output:?}"))?;
    write_ars(&compiled, &mut out)?;
    tracing::info!(
        ?input,
        ?output,
        domains = compiled.domains.len(),
        suffixes = compiled.domain_suffixes.len(),
        v4 = compiled.ipv4_cidrs.len(),
        v6 = compiled.ipv6_cidrs.len(),
        "wrote binary ruleset"
    );
    Ok(())
}

/// `cn-domain.ars` -> `cn-domain`; anything else is returned unchanged.
fn strip_ars_suffix(p: &Path) -> std::path::PathBuf {
    match p.extension().and_then(|e| e.to_str()) {
        Some(e) if e.eq_ignore_ascii_case("ars") => p.with_extension(""),
        _ => p.to_path_buf(),
    }
}

/// Expand one compiled source set into concrete config rules with a verdict.
pub fn compiled_to_rules(compiled: &CompiledRuleSet, verdict: &str) -> Vec<crate::config::Rule> {
    let mut out = Vec::new();
    for d in &compiled.domains {
        // exact domain stored as suffix of itself (same match behavior for single host)
        out.push(crate::config::Rule {
            kind: "domain".into(),
            value: d.clone(),
            verdict: verdict.to_string(),
        });
    }
    for d in &compiled.domain_suffixes {
        out.push(crate::config::Rule {
            kind: "domain".into(),
            value: d.clone(),
            verdict: verdict.to_string(),
        });
    }
    for (a, p) in &compiled.ipv4_cidrs {
        out.push(crate::config::Rule {
            kind: "cidr".into(),
            value: format!("{a}/{p}"),
            verdict: verdict.to_string(),
        });
    }
    for (a, p) in &compiled.ipv6_cidrs {
        out.push(crate::config::Rule {
            kind: "cidr".into(),
            value: format!("{a}/{p}"),
            verdict: verdict.to_string(),
        });
    }
    out
}
