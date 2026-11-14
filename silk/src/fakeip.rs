//! Fake-IP allocator. The ring is IPv4; an optional IPv6 range mirrors it
//! slot for slot (`range6` base + slot offset), so a name's A and AAAA fake
//! answers always refer to the same slot and eviction / persistence stay
//! single-keyed.
//!
//! The DNS engine hands out an address from `range` for every domain whose
//! effective verdict is a proxy node; the kernel steers that range into the
//! proxy namespace, and the relay maps the destination address back to the
//! domain to route and dial by name. Domains that resolve to `direct` keep
//! real answers, so direct traffic still never reaches userspace.
//!
//! Differences from a never-evicting pool: the range is a ring. When the
//! cursor reaches an occupied slot, the slot is recycled if it has been idle
//! for `MIN_IDLE`; only a pool full of busy entries evicts the oldest.
//! Mappings are written back to a redb [`Store`] in batches (`flush`) and
//! restored at startup, so clients holding a fake address across a restart
//! keep working.

use crate::store::{FakeRow, Store};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A slot untouched for this long may be recycled by the allocator.
const MIN_IDLE: Duration = Duration::from_secs(600);
/// How many occupied slots the allocator inspects before force-evicting.
const SCAN_LIMIT: u64 = 1024;

/// Suffixes that never get a fake address (local names, reverse zones).
const BUILTIN_EXCLUDE: &[&str] = &[
    "local",
    "lan",
    "localdomain",
    "localhost",
    "home.arpa",
    "in-addr.arpa",
    "ip6.arpa",
];

pub struct FakeIpPool {
    start: u32,
    end: u32,
    cidr: String,
    /// Optional IPv6 mirror of the ring.
    v6: Option<V6Range>,
    include: Vec<String>,
    exclude: Vec<String>,
    store: Option<Arc<Store>>,
    /// Serializes `flush` so a slow periodic write can never land after a
    /// newer shutdown write.
    flush_lock: Mutex<()>,
    inner: Mutex<Inner>,
}

/// IPv6 range: slot `n` (IPv4 as u32) maps to `base + (n - (start - 1))`.
struct V6Range {
    base: u128,
    cidr: String,
}

struct Inner {
    by_domain: HashMap<String, u32>,
    by_ip: HashMap<u32, Slot>,
    /// Next ring position to try.
    next: u32,
    seq: u64,
    /// Slots changed since the last flush (inserted, overwritten or evicted).
    dirty: HashSet<u32>,
}

struct Slot {
    domain: String,
    seq: u64,
    last_used: Instant,
}

impl FakeIpPool {
    /// `cidr` is an IPv4 prefix (e.g. `198.18.0.0/15`). `include` is an
    /// optional whitelist of domain suffixes (empty = every domain);
    /// `exclude` adds to the built-in never-fake list.
    pub fn new(
        cidr: &str,
        include: &[String],
        exclude: &[String],
        store: Option<Arc<Store>>,
    ) -> Result<Self> {
        let (net, plen) = crate::rules::parse_v4_cidr(cidr.trim())
            .with_context(|| format!("fakeip range {cidr:?}"))?;
        if !(8..=30).contains(&plen) {
            bail!("fakeip range {cidr}: prefix length must be 8..=30");
        }
        let mask = u32::MAX << (32 - plen as u32);
        let base = u32::from(net) & mask;
        let (start, end) = (base + 1, (base | !mask) - 1);
        let norm = |v: &[String]| -> Vec<String> {
            v.iter().filter_map(|s| normalize_suffix(s)).collect()
        };
        let mut exclude = norm(exclude);
        exclude.extend(BUILTIN_EXCLUDE.iter().map(|s| s.to_string()));
        let pool = FakeIpPool {
            start,
            end,
            cidr: format!("{}/{plen}", Ipv4Addr::from(base)),
            v6: None,
            include: norm(include),
            exclude,
            store,
            flush_lock: Mutex::new(()),
            inner: Mutex::new(Inner {
                by_domain: HashMap::new(),
                by_ip: HashMap::new(),
                next: start,
                seq: 0,
                dirty: HashSet::new(),
            }),
        };
        pool.load();
        Ok(pool)
    }

    /// Mirror the ring into an IPv6 prefix (e.g. `fd00:198:18::/96`). The
    /// prefix must leave at least as many host bits as the IPv4 range has,
    /// because the slot offset is added to its base.
    pub fn with_v6(mut self, cidr6: &str) -> Result<Self> {
        let (net, plen) = crate::rules::parse_v6_cidr(cidr6.trim())
            .with_context(|| format!("fakeip range6 {cidr6:?}"))?;
        let host_bits = (self.end - self.start + 3).trailing_zeros(); // v4 host bits (usable = 2^n - 2)
        if plen < 8 || plen as u32 > 128 - host_bits {
            bail!("fakeip range6 {cidr6}: prefix length must be 8..={}", 128 - host_bits);
        }
        let mask = u128::MAX << (128 - plen as u32);
        let base = u128::from(net) & mask;
        self.v6 = Some(V6Range {
            base,
            cidr: format!("{}/{plen}", Ipv6Addr::from(base)),
        });
        Ok(self)
    }

    /// The normalized CIDR of the range (what the kernel CIDR map needs).
    pub fn cidr(&self) -> &str {
        &self.cidr
    }

    /// The normalized IPv6 CIDR, when `range6` is configured.
    pub fn cidr6(&self) -> Option<&str> {
        self.v6.as_ref().map(|v| v.cidr.as_str())
    }

    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    /// IPv6 fake address of the slot holding `v4`.
    pub fn v6_of(&self, v4: Ipv4Addr) -> Option<Ipv6Addr> {
        let v6 = self.v6.as_ref()?;
        let off = u32::from(v4).checked_sub(self.start - 1)?;
        Some(Ipv6Addr::from(v6.base + off as u128))
    }

    /// IPv4 slot address for an IPv6 fake address inside the range.
    fn v4_of(&self, ip: Ipv6Addr) -> Option<u32> {
        let v6 = self.v6.as_ref()?;
        let off = u128::from(ip).checked_sub(v6.base)?;
        let n = (self.start as u128 - 1).checked_add(off)?;
        (n >= self.start as u128 && n <= self.end as u128).then_some(n as u32)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_ip.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v) => {
                let n = u32::from(v);
                n >= self.start && n <= self.end
            }
            IpAddr::V6(v) => self.v4_of(v).is_some(),
        }
    }

    /// Whether `domain` may get a fake address (filters only; the caller
    /// still checks that the routing verdict is a node).
    pub fn should_fake(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() || d.parse::<IpAddr>().is_ok() {
            return false;
        }
        if self.exclude.iter().any(|s| suffix_match(&d, s)) {
            return false;
        }
        self.include.is_empty() || self.include.iter().any(|s| suffix_match(&d, s))
    }

    /// The domain a fake address was handed out for. Refreshes its idle timer.
    pub fn domain_of(&self, ip: IpAddr) -> Option<String> {
        let n = match ip.to_canonical() {
            IpAddr::V4(v4) => u32::from(v4),
            IpAddr::V6(v6) => self.v4_of(v6)?,
        };
        let mut g = self.inner.lock().unwrap();
        let slot = g.by_ip.get_mut(&n)?;
        slot.last_used = Instant::now();
        Some(slot.domain.clone())
    }

    /// Allocate (or reuse) the fake address for `domain`.
    pub fn allocate(&self, domain: &str) -> Option<Ipv4Addr> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        if let Some(&n) = g.by_domain.get(&domain) {
            if let Some(slot) = g.by_ip.get_mut(&n) {
                slot.last_used = now;
            }
            return Some(Ipv4Addr::from(n));
        }

        let span = (self.end - self.start) as u64 + 1;
        let first = g.next;
        let mut pos = first;
        let mut chosen = None;
        for _ in 0..span.min(SCAN_LIMIT) {
            let free = match g.by_ip.get(&pos) {
                None => true,
                Some(s) => now.duration_since(s.last_used) >= MIN_IDLE,
            };
            if free {
                chosen = Some(pos);
                break;
            }
            pos = self.succ(pos);
        }
        // Everything inspected is busy: evict the oldest allocation (FIFO).
        let n = chosen.unwrap_or(first);
        if let Some(old) = g.by_ip.remove(&n) {
            g.by_domain.remove(&old.domain);
        }
        g.seq += 1;
        let seq = g.seq;
        g.by_ip.insert(
            n,
            Slot {
                domain: domain.clone(),
                seq,
                last_used: now,
            },
        );
        g.by_domain.insert(domain, n);
        g.next = self.succ(n);
        g.dirty.insert(n);
        Some(Ipv4Addr::from(n))
    }

    /// Allocate (or reuse) the IPv6 fake address for `domain`: the mirror of
    /// its IPv4 slot. `None` when `range6` is not configured.
    pub fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        self.v6.as_ref()?;
        self.v6_of(self.allocate(domain)?)
    }

    fn succ(&self, n: u32) -> u32 {
        if n >= self.end { self.start } else { n + 1 }
    }

    // ── persistence ──────────────────────────────────────────────────────

    fn load(&self) {
        let Some(store) = &self.store else { return };
        let rows = match store.fakeip_load(&self.cidr) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "fakeip store unreadable; starting empty");
                return;
            }
        };
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let mut loaded = 0usize;
        // Oldest first, so the cursor ends up after the newest allocation.
        for row in rows {
            if row.ip < self.start || row.ip > self.end || row.domain.is_empty() {
                continue;
            }
            g.seq = g.seq.max(row.seq);
            g.by_domain.insert(row.domain.clone(), row.ip);
            g.by_ip.insert(
                row.ip,
                Slot {
                    domain: row.domain,
                    seq: row.seq,
                    last_used: now,
                },
            );
            g.next = self.succ(row.ip);
            loaded += 1;
        }
        tracing::info!(count = loaded, "fakeip mappings restored");
    }

    /// Write the slots changed since the last flush to the store (one
    /// transaction). Blocking: call from `spawn_blocking` or a sync context.
    pub fn flush(&self) -> Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let _serial = self.flush_lock.lock().unwrap();
        let (puts, dels) = {
            let mut g = self.inner.lock().unwrap();
            if g.dirty.is_empty() {
                return Ok(());
            }
            let dirty = std::mem::take(&mut g.dirty);
            let mut puts = Vec::new();
            let mut dels = Vec::new();
            for ip in dirty {
                match g.by_ip.get(&ip) {
                    Some(s) => puts.push(FakeRow {
                        ip,
                        domain: s.domain.clone(),
                        seq: s.seq,
                    }),
                    None => dels.push(ip),
                }
            }
            (puts, dels)
        };
        if let Err(e) = store.fakeip_apply(&puts, &dels) {
            // Keep them for the next attempt.
            let mut g = self.inner.lock().unwrap();
            g.dirty.extend(puts.iter().map(|r| r.ip).chain(dels));
            return Err(e);
        }
        Ok(())
    }
}

/// Lowercase, strip `*.` / `+.` / leading dots. `None` for an empty entry.
fn normalize_suffix(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let s = s
        .trim_start_matches("*.")
        .trim_start_matches("+.")
        .trim_start_matches('.')
        .trim_end_matches('.');
    (!s.is_empty()).then(|| s.to_string())
}

fn suffix_match(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(cidr: &str) -> FakeIpPool {
        FakeIpPool::new(cidr, &[], &[], None).unwrap()
    }

    #[test]
    fn allocates_stably_and_maps_back() {
        let p = pool("198.18.0.0/15");
        let a = p.allocate("Example.COM.").unwrap();
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(p.allocate("example.com"), Some(a));
        let b = p.allocate("other.org").unwrap();
        assert_ne!(a, b);
        assert!(p.contains(IpAddr::V4(a)));
        assert!(!p.contains("8.8.8.8".parse().unwrap()));
        assert_eq!(p.domain_of(IpAddr::V4(b)).as_deref(), Some("other.org"));
        assert_eq!(p.domain_of("198.19.255.250".parse().unwrap()), None);
    }

    #[test]
    fn range_bounds_skip_network_and_broadcast() {
        let p = pool("198.18.0.0/15");
        assert!(!p.contains("198.18.0.0".parse().unwrap()));
        assert!(!p.contains("198.19.255.255".parse().unwrap()));
        assert!(p.contains("198.19.255.254".parse().unwrap()));
        assert_eq!(p.cidr(), "198.18.0.0/15");
    }

    #[test]
    fn full_pool_evicts_oldest_and_stays_consistent() {
        // /29 → 6 usable addresses, all busy: the 7th evicts the first.
        let p = pool("10.9.9.0/29");
        let ips: Vec<_> = (0..6).map(|i| p.allocate(&format!("d{i}.test")).unwrap()).collect();
        assert_eq!(p.len(), 6);
        let n = p.allocate("new.test").unwrap();
        assert_eq!(n, ips[0]);
        assert_eq!(p.len(), 6);
        assert_eq!(p.domain_of(IpAddr::V4(n)).as_deref(), Some("new.test"));
        // The evicted domain gets a fresh address (evicting the next oldest).
        let again = p.allocate("d0.test").unwrap();
        assert_eq!(again, ips[1]);
        assert_eq!(p.domain_of(IpAddr::V4(ips[1])).as_deref(), Some("d0.test"));
    }

    #[test]
    fn v6_mirrors_v4_slots() {
        let p = pool("198.18.0.0/15").with_v6("fd00:198:18::/96").unwrap();
        assert_eq!(p.cidr6(), Some("fd00:198:18::/96"));
        let a4 = p.allocate("a.example").unwrap();
        let a6 = p.allocate_v6("a.example").unwrap();
        assert_eq!(a6, "fd00:198:18::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(p.v6_of(a4), Some(a6));
        let b6 = p.allocate_v6("b.example").unwrap();
        assert_eq!(b6, "fd00:198:18::2".parse::<Ipv6Addr>().unwrap());
        assert!(p.contains(IpAddr::V6(a6)));
        assert_eq!(p.domain_of(IpAddr::V6(a6)).as_deref(), Some("a.example"));
        assert_eq!(p.domain_of(IpAddr::V4(p.allocate("b.example").unwrap())).as_deref(), Some("b.example"));
        // outside the mirrored slots / other prefixes
        assert!(!p.contains("fd00:198:18::".parse().unwrap()));
        assert!(!p.contains("fd00:198:19::1".parse().unwrap()));
        assert!(!p.contains("2001:db8::1".parse().unwrap()));
        assert!(!p.contains("fd00:198:18::3:0".parse().unwrap())); // offset past the last slot
        assert_eq!(p.domain_of("fd00:198:18::ffff".parse().unwrap()), None); // unallocated
        // without range6 nothing changes
        let q = pool("198.18.0.0/15");
        assert_eq!(q.allocate_v6("x.example"), None);
        assert!(!q.contains("fd00:198:18::1".parse().unwrap()));
    }

    #[test]
    fn v6_range_validation() {
        // /15 v4 leaves 17 host bits, so the v6 prefix may be at most /111
        assert!(pool("198.18.0.0/15").with_v6("fd00::/112").is_err());
        assert!(pool("198.18.0.0/15").with_v6("fd00::/111").is_ok());
        assert!(pool("198.18.0.0/15").with_v6("198.18.0.0/16").is_err());
        assert!(pool("198.18.0.0/15").with_v6("nonsense").is_err());
        // v6 eviction mirrors v4
        let p = pool("10.9.9.0/29").with_v6("fd00:9::/64").unwrap();
        let ips: Vec<_> = (0..6).map(|i| p.allocate_v6(&format!("d{i}.test")).unwrap()).collect();
        let n = p.allocate_v6("new.test").unwrap();
        assert_eq!(n, ips[0]);
        assert_eq!(p.domain_of(IpAddr::V6(n)).as_deref(), Some("new.test"));
    }

    #[test]
    fn filters() {
        let p = FakeIpPool::new(
            "198.18.0.0/15",
            &[],
            &["+.ntp.org".into(), "stun.example.com".into()],
            None,
        )
        .unwrap();
        assert!(p.should_fake("www.google.com"));
        assert!(!p.should_fake("pool.ntp.org"));
        assert!(!p.should_fake("ntp.org"));
        assert!(!p.should_fake("stun.example.com"));
        assert!(p.should_fake("xstun.example.com"));
        assert!(!p.should_fake("printer.lan"));
        assert!(!p.should_fake("1.2.3.4"));

        let w = FakeIpPool::new("198.18.0.0/15", &["google.com".into()], &[], None).unwrap();
        assert!(w.should_fake("www.google.com"));
        assert!(!w.should_fake("example.org"));
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(FakeIpPool::new("198.18.0.0/31", &[], &[], None).is_err());
        assert!(FakeIpPool::new("2001:db8::/32", &[], &[], None).is_err());
        assert!(FakeIpPool::new("nonsense", &[], &[], None).is_err());
    }

    #[test]
    fn persistence_roundtrip_keeps_mappings_and_cursor() {
        let path = crate::store::temp_path("pool");
        let a;
        let b;
        {
            let st = Store::open(&path).unwrap();
            let p = FakeIpPool::new("198.18.0.0/15", &[], &[], Some(st)).unwrap();
            a = p.allocate("a.example").unwrap();
            b = p.allocate("b.example").unwrap();
            p.flush().unwrap();
            p.flush().unwrap(); // nothing dirty: a no-op
        }
        let st = Store::open(&path).unwrap();
        let p = FakeIpPool::new("198.18.0.0/15", &[], &[], Some(st.clone())).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.allocate("a.example"), Some(a));
        assert_eq!(p.domain_of(IpAddr::V4(b)).as_deref(), Some("b.example"));
        let c = p.allocate("c.example").unwrap();
        assert!(c != a && c != b);
        assert_eq!(u32::from(c), u32::from(b) + 1, "cursor resumes after the newest slot");
        // A different range discards the stored mappings.
        let q = FakeIpPool::new("198.51.100.0/24", &[], &[], Some(st)).unwrap();
        assert_eq!(q.len(), 0);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn eviction_is_persisted_as_overwrite() {
        let path = crate::store::temp_path("evict");
        {
            let st = Store::open(&path).unwrap();
            let p = FakeIpPool::new("10.9.9.0/29", &[], &[], Some(st)).unwrap();
            for i in 0..6 {
                p.allocate(&format!("d{i}.test")).unwrap();
            }
            p.flush().unwrap();
            p.allocate("new.test").unwrap(); // evicts d0.test (same slot)
            p.flush().unwrap();
        }
        let st = Store::open(&path).unwrap();
        let p = FakeIpPool::new("10.9.9.0/29", &[], &[], Some(st)).unwrap();
        assert_eq!(p.len(), 6);
        assert!(p.domain_of("10.9.9.1".parse().unwrap()).as_deref() == Some("new.test"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
