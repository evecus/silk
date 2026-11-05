//! Per-process policy by cgroup v2: resolve configured cgroup paths to ids
//! and keep the CGROUP_RULES map fresh.
//!
//! The eBPF side matches `bpf_skb_ancestor_cgroup_id()` against this map, so
//! one rule on a parent cgroup covers every descendant and the deepest rule
//! wins. A cgroup id is the inode number of its directory; a service restart
//! recreates the directory with a new id, so ids are re-resolved every few
//! seconds and stale ones are removed.
//!
//! A rule's map value is `CGROUP_MODE_BYPASS` (never captured) or the node
//! verdict (`VERDICT_NODE_BASE + i`) the cgroup's public traffic is forced to.

use crate::config::CgroupRule;
use crate::rules::StaticMaps;
use anyhow::{Context, Result};
use silk_ebpf_common::CGROUP_MODE_BYPASS;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

const REFRESH: std::time::Duration = std::time::Duration::from_secs(3);

struct Entry {
    path: PathBuf,
    mode: u8,
    /// Id currently published for this rule.
    id: Option<u64>,
}

pub struct CgroupWatcher {
    entries: Vec<Entry>,
}

/// The cgroup v2 mount: `/sys/fs/cgroup` (unified) or `.../unified` (hybrid).
fn cgroup_root() -> Result<PathBuf> {
    for p in ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"] {
        if Path::new(p).join("cgroup.controllers").exists() {
            return Ok(PathBuf::from(p));
        }
    }
    anyhow::bail!("cgroup v2 is not mounted (no cgroup.controllers under /sys/fs/cgroup)")
}

impl CgroupWatcher {
    pub fn new(rules: &[CgroupRule], nodes: &[String]) -> Result<Self> {
        let root = cgroup_root()?;
        let mut entries = Vec::new();
        for r in rules {
            let mode = if r.mode.eq_ignore_ascii_case("bypass") || r.mode.eq_ignore_ascii_case("direct") {
                CGROUP_MODE_BYPASS
            } else {
                match crate::rules::Verdict::parse(&r.mode, nodes) {
                    Ok(crate::rules::Verdict::Node(i)) => crate::rules::Verdict::Node(i).to_u8(),
                    _ => anyhow::bail!(
                        "cgroup {}: unknown mode `{}` (expected bypass or a node name)",
                        r.path,
                        r.mode
                    ),
                }
            };
            let p = Path::new(&r.path);
            let path = if p.starts_with(&root) {
                p.to_path_buf()
            } else {
                root.join(r.path.trim_start_matches('/'))
            };
            entries.push(Entry { path, mode, id: None });
        }
        Ok(CgroupWatcher { entries })
    }

    /// Re-resolve every rule and reconcile the map. Missing paths (service
    /// not running yet) are retried on the next round.
    pub async fn sync(&mut self, maps: &Arc<Mutex<StaticMaps>>) {
        let mut maps = maps.lock().await;
        for i in 0..self.entries.len() {
            let now = std::fs::metadata(&self.entries[i].path)
                .ok()
                .filter(|m| m.is_dir())
                .map(|m| m.ino());
            let old = self.entries[i].id;
            if now == old {
                continue;
            }
            let mode = self.entries[i].mode;
            let shared = |id: u64, this: usize, es: &[Entry]| {
                es.iter()
                    .enumerate()
                    .any(|(j, e)| j != this && e.id == Some(id))
            };
            if let Some(old_id) = old
                && !shared(old_id, i, &self.entries) {
                    let _ = maps.cgroup_rules.remove(&old_id);
                }
            match now {
                Some(id) => match maps.cgroup_rules.insert(id, mode, 0) {
                    Ok(()) => {
                        tracing::info!(
                            path = %self.entries[i].path.display(),
                            id,
                            mode = if mode == CGROUP_MODE_BYPASS { "bypass" } else { "node" },
                            verdict = mode,
                            "cgroup rule active"
                        );
                        self.entries[i].id = Some(id);
                    }
                    Err(e) => {
                        tracing::warn!(path = %self.entries[i].path.display(), error = %e, "cgroup rule insert");
                        self.entries[i].id = None;
                    }
                },
                None => {
                    tracing::info!(path = %self.entries[i].path.display(), "cgroup gone; rule inactive");
                    self.entries[i].id = None;
                }
            }
        }
    }
}

/// Initial sync, then keep refreshing in the background.
pub async fn start(
    rules: &[CgroupRule],
    nodes: &[String],
    maps: Arc<Mutex<StaticMaps>>,
) -> Result<()> {
    let mut w = CgroupWatcher::new(rules, nodes).context("cgroup rules")?;
    w.sync(&maps).await;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REFRESH).await;
            w.sync(&maps).await;
        }
    });
    Ok(())
}
