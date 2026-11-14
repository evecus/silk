//! [方案三] 编译式路由的降级版。
//!
//! honk 把任意布尔规则表达式编译成 eBPF 指令（freplace + ArrayOfMaps 两代
//! 原子切换）。silk 的规则面本来就很扁（CIDR LPM / 端口表 / DNS 发布的
//! per-IP verdict），写一套指令编译器收益不抵复杂度。这里保留它最有价值
//! 的一半语义：**把配置在用户态一次性编译成扁平快照，再以两代共存 +
//! 一次翻转完成无停机热重载**，由 `StaticMaps::commit_rules` 执行。
//!
//! 数据面侧对应 `silk-ebpf/src/routing.rs` 的 `live_verdict()`：只有世代
//! 匹配（或 0 = 通配）的条目才生效。

use crate::rules::{parse_v4_cidr, parse_v6_cidr, ConfigKeys, Verdict};
use anyhow::{Context, Result};

/// 编译后的静态规则快照。元素是 `(prefix_len, addr_bytes, verdict)` /
/// `(port, verdict)`，与 eBPF map 的 key/value 一一对应。
pub struct CompiledRules {
    pub cidr_v4: Vec<(u32, [u8; 4], u8)>,
    pub cidr_v6: Vec<(u32, [u8; 16], u8)>,
    pub ports: Vec<(u16, u8)>,
    /// 本次快照涉及的 key，供下一次提交打墓碑。
    pub keys: ConfigKeys,
}

impl CompiledRules {
    /// 把 `config.rules` 求值成扁平表。
    ///
    /// 只编译 cidr / port：domain 规则本来就是由 DNS 引擎在用户态按域名
    /// 匹配后发布成 DOMAIN_ROUTE（IP -> verdict），不进静态表。`source` /
    /// `binary` 规则集由 `config::expand_rules` 先展开成普通规则行。
    pub fn compile(config: &crate::config::Config, nodes: &[String]) -> Result<CompiledRules> {
        let rules = crate::config::expand_rules(config)?;
        let mut out = CompiledRules {
            cidr_v4: Vec::new(),
            cidr_v6: Vec::new(),
            ports: Vec::new(),
            keys: ConfigKeys::default(),
        };
        for rule in &rules {
            let verdict = Verdict::parse(&rule.verdict, nodes)?.to_u8();
            match rule.kind.as_str() {
                "cidr" => {
                    if let Ok((v4, plen)) = parse_v4_cidr(&rule.value) {
                        let k = (plen as u32, v4.octets());
                        out.cidr_v4.push((k.0, k.1, verdict));
                        if !out.keys.cidr_v4.contains(&k) {
                            out.keys.cidr_v4.push(k);
                        }
                    } else if let Ok((v6, plen)) = parse_v6_cidr(&rule.value) {
                        let k = (plen as u32, v6.octets());
                        out.cidr_v6.push((k.0, k.1, verdict));
                        if !out.keys.cidr_v6.contains(&k) {
                            out.keys.cidr_v6.push(k);
                        }
                    } else {
                        anyhow::bail!("bad CIDR: {}", rule.value);
                    }
                }
                "port" => {
                    let port: u16 = rule.value.parse().context("bad port in rule")?;
                    out.ports.push((port, verdict));
                    if !out.keys.ports.contains(&port) {
                        out.keys.ports.push(port);
                    }
                }
                // domain / source / binary 由 DNS 引擎与 Rules 处理。
                _ => {}
            }
        }
        Ok(out)
    }

    pub fn rule_count(&self) -> usize {
        self.cidr_v4.len() + self.cidr_v6.len() + self.ports.len()
    }
}

/// SIGHUP：重新读配置、重新编译、两阶段提交。解析或写入失败时保持旧世代
/// 不变（fail-closed 到"沿用现有规则"），不会把半套规则推进数据面。
pub async fn reload(
    path: &str,
    nodes: &[String],
    maps: &std::sync::Arc<tokio::sync::Mutex<crate::rules::StaticMaps>>,
) {
    let compiled = match load(path, nodes) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                path,
                "rule reload: config/parse failed; keeping current rules"
            );
            return;
        }
    };
    let n = compiled.rule_count();
    let mut m = maps.lock().await;
    match m.commit_rules(&compiled) {
        Ok(()) => tracing::info!(path, rules = n, generation = ?m.generation(), "rule reload applied"),
        Err(e) => tracing::warn!(
            error = %format!("{e:#}"),
            "rule reload: map commit failed; keeping old generation"
        ),
    }
}

fn load(path: &str, nodes: &[String]) -> Result<CompiledRules> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let config = crate::config::parse(&raw).with_context(|| format!("config {path}"))?;
    CompiledRules::compile(&config, nodes)
}
