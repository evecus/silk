//! Persistent state in one redb file: the fake-IP mappings and the DNS
//! response cache. Both live in memory first; callers write changes back in
//! batches (`*_apply`), so a commit — and its fsync — happens per flush, not
//! per DNS query.

use anyhow::{Context, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

const META: TableDefinition<&str, &str> = TableDefinition::new("meta");
/// ip -> (domain, allocation sequence)
const FAKEIP: TableDefinition<u32, (&str, u64)> = TableDefinition::new("fakeip");
/// (qname, qtype) -> (expiry as unix seconds, raw DNS response)
const DNS: TableDefinition<(&str, u16), (u64, &[u8])> = TableDefinition::new("dns_cache");

const META_FAKEIP_RANGE: &str = "fakeip_range";

pub struct Store {
    db: Database,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRow {
    pub ip: u32,
    pub domain: String,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRow {
    pub qname: String,
    pub qtype: u16,
    pub expiry_unix: u64,
    pub response: Vec<u8>,
}

impl Store {
    /// Open (or create) the database at `path`. redb repairs a file left by
    /// an unclean shutdown itself; the file is locked against a second silk.
    pub fn open(path: &Path) -> Result<Arc<Store>> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let db = Database::create(path).with_context(|| format!("open {}", path.display()))?;
        // Create the tables up front so reads never see a missing one.
        let txn = db.begin_write()?;
        {
            txn.open_table(META)?;
            txn.open_table(FAKEIP)?;
            txn.open_table(DNS)?;
        }
        txn.commit()?;
        Ok(Arc::new(Store { db }))
    }

    // ── fake-IP ──────────────────────────────────────────────────────────

    /// The stored mappings, oldest allocation first. A different `range`
    /// than the one they were made for invalidates them: the table is
    /// cleared and an empty list returned.
    pub fn fakeip_load(&self, range: &str) -> Result<Vec<FakeRow>> {
        let stored = {
            let r = self.db.begin_read()?;
            let t = r.open_table(META)?;
            t.get(META_FAKEIP_RANGE)?.map(|v| v.value().to_string())
        };
        if stored.as_deref() != Some(range) {
            let w = self.db.begin_write()?;
            {
                w.delete_table(FAKEIP)?;
                w.open_table(FAKEIP)?;
                w.open_table(META)?.insert(META_FAKEIP_RANGE, range)?;
            }
            w.commit()?;
            return Ok(Vec::new());
        }
        let r = self.db.begin_read()?;
        let t = r.open_table(FAKEIP)?;
        let mut rows = Vec::new();
        for item in t.iter()? {
            let (k, v) = item?;
            let (domain, seq) = v.value();
            rows.push(FakeRow {
                ip: k.value(),
                domain: domain.to_string(),
                seq,
            });
        }
        rows.sort_unstable_by_key(|r| r.seq);
        Ok(rows)
    }

    /// Upsert `puts` and delete `dels` in one transaction.
    pub fn fakeip_apply(&self, puts: &[FakeRow], dels: &[u32]) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(FAKEIP)?;
            for ip in dels {
                t.remove(*ip)?;
            }
            for row in puts {
                t.insert(row.ip, (row.domain.as_str(), row.seq))?;
            }
        }
        w.commit()?;
        Ok(())
    }

    // ── DNS cache ────────────────────────────────────────────────────────

    /// Cached responses that have not expired at `now_unix`.
    pub fn dns_load(&self, now_unix: u64) -> Result<Vec<DnsRow>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(DNS)?;
        let mut rows = Vec::new();
        for item in t.iter()? {
            let (k, v) = item?;
            let (qname, qtype) = k.value();
            let (expiry_unix, response) = v.value();
            if expiry_unix > now_unix {
                rows.push(DnsRow {
                    qname: qname.to_string(),
                    qtype,
                    expiry_unix,
                    response: response.to_vec(),
                });
            }
        }
        Ok(rows)
    }

    /// Upsert `puts` and delete `dels` in one transaction.
    pub fn dns_apply(&self, puts: &[DnsRow], dels: &[(String, u16)]) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(DNS)?;
            for (qname, qtype) in dels {
                t.remove((qname.as_str(), *qtype))?;
            }
            for row in puts {
                t.insert(
                    (row.qname.as_str(), row.qtype),
                    (row.expiry_unix, row.response.as_slice()),
                )?;
            }
        }
        w.commit()?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn temp_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "silk-store-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("state.redb")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fakeip_roundtrip_order_and_range_change() {
        let path = temp_path("fakeip");
        let range = "198.18.0.0/15";
        {
            let s = Store::open(&path).unwrap();
            assert!(s.fakeip_load(range).unwrap().is_empty());
            let row = |ip, d: &str, seq| FakeRow { ip, domain: d.into(), seq };
            s.fakeip_apply(&[row(5, "b.test", 2), row(9, "a.test", 1), row(7, "gone.test", 3)], &[])
                .unwrap();
            // overwrite one slot, delete another
            s.fakeip_apply(&[row(9, "c.test", 4)], &[7]).unwrap();
        }
        let s = Store::open(&path).unwrap(); // reopen: data survives
        let rows = s.fakeip_load(range).unwrap();
        let got: Vec<_> = rows.iter().map(|r| (r.ip, r.domain.as_str(), r.seq)).collect();
        assert_eq!(got, [(5, "b.test", 2), (9, "c.test", 4)]);
        // another range discards them, and the new range sticks
        assert!(s.fakeip_load("198.51.100.0/24").unwrap().is_empty());
        assert!(s.fakeip_load("198.51.100.0/24").unwrap().is_empty());
        assert!(s.fakeip_load(range).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn dns_roundtrip_skips_expired() {
        let path = temp_path("dns");
        let s = Store::open(&path).unwrap();
        let row = |n: &str, t, exp, b: &[u8]| DnsRow {
            qname: n.into(),
            qtype: t,
            expiry_unix: exp,
            response: b.to_vec(),
        };
        s.dns_apply(
            &[row("a.test", 1, 2000, b"AAA"), row("a.test", 28, 2000, b"V6"), row("old.test", 1, 500, b"X"), row("b.test", 1, 3000, b"BBB")],
            &[],
        )
        .unwrap();
        s.dns_apply(&[], &[("b.test".into(), 1)]).unwrap();
        let mut rows = s.dns_load(1000).unwrap();
        rows.sort_by(|a, b| (a.qname.as_str(), a.qtype).cmp(&(b.qname.as_str(), b.qtype)));
        assert_eq!(rows, [row("a.test", 1, 2000, b"AAA"), row("a.test", 28, 2000, b"V6")]);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
