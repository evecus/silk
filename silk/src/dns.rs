//! DNS engine: intercept UDP/53 flows, resolve through the configured
//! upstream (udp/tcp/tls/https, see `dnsup`) on control-plane sockets, publish per-IP verdicts into
//! DOMAIN_ROUTE, and answer the client through a `silkns` reply socket.

use crate::dnsup::{self, HostResolver, Upstream, Via};
use crate::fakeip::FakeIpPool;
use crate::listener::create_reply_socket;
use crate::names::NameCache;
use crate::outbound::Nodes;
use crate::rules::{SharedRules, StaticMaps, Verdict};
use crate::store::{DnsRow, Store};
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// In-memory cache size cap; expired entries go first, then everything.
const CACHE_MAX: usize = 20_000;

type CacheKey = (String, u16);

struct CacheEntry {
    resp: Vec<u8>,
    expiry: Instant,
    /// The same deadline as wall-clock seconds, for the persistent store.
    expiry_unix: u64,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<CacheKey, CacheEntry>,
    /// Keys changed since the last flush: present in `map` = upsert, absent
    /// = delete. Only tracked when a store is attached.
    dirty: HashSet<CacheKey>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct DnsEngine {
    /// Domestic resolver, queried directly on a control-plane socket.
    upstream: Upstream,
    /// Overseas resolver, queried through a proxy node.
    remote: Option<Upstream>,
    /// Resolves hostnames via `dns.default` (`tls://dns.example.com`).
    resolver: Arc<HostResolver>,
    nodes: Arc<Nodes>,
    rules: SharedRules,
    /// IP -> domain memory for dial-by-domain on proxied TCP flows.
    names: Arc<NameCache>,
    /// Fake-IP pool and the TTL of fake answers (None = real answers only).
    fakeip: Option<(Arc<FakeIpPool>, u32)>,
    /// query cache: (qname, qtype) -> response + expiry
    cache: Mutex<CacheInner>,
    /// Persistent copy of the cache (None = memory only).
    store: Option<Arc<Store>>,
    /// Serializes `flush` (periodic vs. shutdown).
    flush_lock: Mutex<()>,
}

impl DnsEngine {
    pub fn new(
        spec: dnsup::DnsSpec,
        resolver: Arc<HostResolver>,
        rules: SharedRules,
        nodes: Arc<Nodes>,
        names: Arc<NameCache>,
        fakeip: Option<(Arc<FakeIpPool>, u32)>,
        store: Option<Arc<Store>>,
    ) -> Self {
        DnsEngine {
            upstream: spec.upstream,
            remote: spec.remote,
            resolver,
            nodes,
            rules,
            names,
            fakeip,
            cache: Mutex::new(CacheInner::default()),
            store,
            flush_lock: Mutex::new(()),
        }
    }

    /// Reload the persisted cache. Call once, after the kernel maps exist and
    /// before any query is served: the kernel's DOMAIN_ROUTE is empty after a
    /// restart, so every restored answer's verdict is published again, from
    /// the *current* rules. Entries that would now be blocked or answered
    /// with a fake address are dropped.
    pub async fn restore(&self, maps: &Arc<Mutex<StaticMaps>>) {
        let Some(store) = self.store.clone() else { return };
        let now_unix = unix_now();
        let rows = match tokio::task::spawn_blocking(move || store.dns_load(now_unix)).await {
            Ok(Ok(rows)) => rows,
            Ok(Err(e)) => return tracing::warn!(error = %e, "dns cache store unreadable"),
            Err(e) => return tracing::warn!(error = %e, "dns cache restore task"),
        };
        let mut restored = 0usize;
        for row in rows {
            let (rule, default) = {
                let rules = self.rules.lock().await;
                (rules.match_domain(&row.qname), rules.default)
            };
            let key = (row.qname.clone(), row.qtype);
            let verdict = rule.unwrap_or(default);
            if rule == Some(Verdict::Block) || self.would_fake(&row.qname, row.qtype, verdict) {
                self.cache.lock().await.dirty.insert(key); // delete from the store
                continue;
            }
            self.apply_answer(&row.qname, rule, &row.response, maps).await;
            let remaining = row.expiry_unix.saturating_sub(now_unix);
            self.cache.lock().await.map.insert(
                key,
                CacheEntry {
                    resp: row.response,
                    expiry: Instant::now() + Duration::from_secs(remaining),
                    expiry_unix: row.expiry_unix,
                },
            );
            restored += 1;
        }
        tracing::info!(count = restored, "dns cache restored");
    }

    /// Write cache changes (and drop expired entries) to the store in one
    /// transaction. No-op without a store.
    pub async fn flush(&self) {
        let Some(store) = self.store.clone() else { return };
        let _serial = self.flush_lock.lock().await;
        let (puts, dels) = {
            let mut c = self.cache.lock().await;
            let now = Instant::now();
            let expired: Vec<CacheKey> = c
                .map
                .iter()
                .filter(|(_, e)| e.expiry <= now)
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired {
                c.map.remove(&k);
                c.dirty.insert(k);
            }
            let dirty = std::mem::take(&mut c.dirty);
            let mut puts = Vec::new();
            let mut dels = Vec::new();
            for k in dirty {
                match c.map.get(&k) {
                    Some(e) => puts.push(DnsRow {
                        qname: k.0,
                        qtype: k.1,
                        expiry_unix: e.expiry_unix,
                        response: e.resp.clone(),
                    }),
                    None => dels.push(k),
                }
            }
            (puts, dels)
        };
        if puts.is_empty() && dels.is_empty() {
            return;
        }
        match tokio::task::spawn_blocking(move || store.dns_apply(&puts, &dels)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "dns cache store write"),
            Err(e) => tracing::warn!(error = %e, "dns cache flush task"),
        }
    }

    async fn cache_put(&self, qname: &str, qtype: u16, resp: &[u8], ttl: u64) {
        let key = (qname.to_string(), qtype);
        let mut c = self.cache.lock().await;
        if c.map.len() >= CACHE_MAX {
            let now = Instant::now();
            let expired: Vec<CacheKey> =
                c.map.iter().filter(|(_, e)| e.expiry <= now).map(|(k, _)| k.clone()).collect();
            for k in expired {
                c.map.remove(&k);
                c.dirty.insert(k);
            }
            if c.map.len() >= CACHE_MAX {
                let all: Vec<CacheKey> = c.map.keys().cloned().collect();
                c.map.clear();
                c.dirty.extend(all);
            }
        }
        c.map.insert(
            key.clone(),
            CacheEntry {
                resp: resp.to_vec(),
                expiry: Instant::now() + Duration::from_secs(ttl),
                expiry_unix: unix_now() + ttl,
            },
        );
        if self.store.is_some() {
            c.dirty.insert(key);
        } else {
            c.dirty.clear();
        }
    }

    /// Per-answer side effects shared by a fresh resolve and a restore:
    /// remember address -> name for dial-by-domain, and publish the domain's
    /// verdict for every answer address into DOMAIN_ROUTE. Verdicts are
    /// published only for domains that matched a domain rule; anything else
    /// falls through to CIDR / port / default in the kernel (otherwise the
    /// default verdict would override CIDR rules).
    async fn apply_answer(
        &self,
        qname: &str,
        rule: Option<Verdict>,
        buf: &[u8],
        maps: &Arc<Mutex<StaticMaps>>,
    ) {
        if rule == Some(Verdict::Block) {
            return;
        }
        let ttl = answer_min_ttl(buf).unwrap_or(60).clamp(300, 7200);
        self.remember_names(qname, buf, ttl);
        if let Some(verdict) = rule {
            let mut maps = maps.lock().await;
            for ip in answer_ips(buf) {
                if let Err(e) = maps.publish_domain_ip(ip, verdict) {
                    tracing::warn!(%ip, error = %e, "publish domain route");
                }
            }
        }
    }

    /// Handle one hijacked DNS flow. `payload` is the client's query,
    /// `client` its source, `orig` the original destination (DNS server).
    /// The reply socket is bound to `orig` inside `silkns` so the answer
    /// looks like it came from the queried resolver.
    pub async fn handle_flow(
        &self,
        payload: &[u8],
        client: SocketAddr,
        orig: SocketAddr,
        maps: Arc<Mutex<crate::rules::StaticMaps>>,
    ) -> Result<()> {
        let qname = query_name(payload).unwrap_or_default();
        let qtype = query_type(payload).unwrap_or(0);
        tracing::debug!(%client, %orig, %qname, qtype, "dns query hijacked");

        // Resolve upstream and publish domain verdicts for every answer.
        let response = self.resolve(payload, &qname, qtype, &maps).await?;
        tracing::debug!(%qname, len = response.len(), "dns upstream answered");

        // Answer through a transparent socket bound to the queried resolver.
        let reply_sock = create_reply_socket(orig)?;
        reply_sock.send_to(&response, client).await?;
        tracing::debug!(%client, %orig, "dns reply sent");
        Ok(())
    }

    async fn resolve(
        &self,
        payload: &[u8],
        qname: &str,
        qtype: u16,
        maps: &Arc<Mutex<StaticMaps>>,
    ) -> Result<Vec<u8>> {
        if payload.len() < 12 {
            return Err(anyhow!("short DNS query"));
        }

        // 0. fake-IP: a domain that routes to a node never needs a real
        //    answer; the pool is the cache, so nothing is published or cached.
        if let Some(resp) = self.try_fake(payload, qname, qtype).await {
            return Ok(resp);
        }

        // 1. cache (a cached answer carries the old transaction id: patch it)
        {
            let cache = self.cache.lock().await;
            if let Some(CacheEntry { resp, expiry, .. }) = cache.map.get(&(qname.to_string(), qtype))
                && *expiry > Instant::now() && resp.len() >= 2 {
                    let mut out = resp.clone();
                    out[0] = payload[0];
                    out[1] = payload[1];
                    self.remember_names(qname, &out, 300);
                    return Ok(out);
                }
        }

        // 2. split DNS: the domain verdict picks the resolver.
        let (rule, default) = {
            let rules = self.rules.lock().await;
            (rules.match_domain(qname), rules.default)
        };
        let buf = match rule {
            Some(Verdict::Block) => nxdomain(payload),
            Some(Verdict::Direct) => self.query_direct(payload).await?,
            Some(Verdict::Node(n)) => self.query_proxied_or_direct(payload, n).await?,
            None => self.query_unmatched(payload, default, maps).await?,
        };

        // 3. remember names + publish the domain verdict.
        self.apply_answer(qname, rule, &buf, maps).await;

        // 4. cache by the minimum answer TTL (a zero TTL is never served).
        let ttl = answer_min_ttl(&buf).unwrap_or(60);
        if ttl > 0 {
            self.cache_put(qname, qtype, &buf, ttl).await;
        }
        Ok(buf)
    }

    /// Synthesize a fake answer when fake-IP is on, the name passes the
    /// filters and its effective verdict (rule, else `general.default`) is a
    /// node. A -> fake IPv4 address; AAAA -> the mirrored fake IPv6 address
    /// when `range6` is configured, else an empty NOERROR so clients use A.
    /// HTTPS/SVCB (their hints would carry real addresses / ECH keys that
    /// bypass the fake mapping) -> empty NOERROR.
    async fn try_fake(&self, payload: &[u8], qname: &str, qtype: u16) -> Option<Vec<u8>> {
        let (pool, ttl) = self.fakeip.as_ref()?;
        if !matches!(qtype, 1 | 28 | 64 | 65) || !pool.should_fake(qname) {
            return None;
        }
        let verdict = {
            let rules = self.rules.lock().await;
            rules.match_domain(qname).unwrap_or(rules.default)
        };
        if !self.would_fake(qname, qtype, verdict) {
            return None;
        }
        let ip = match qtype {
            1 => Some(std::net::IpAddr::V4(pool.allocate(qname)?)),
            28 if pool.has_v6() => Some(std::net::IpAddr::V6(pool.allocate_v6(qname)?)),
            _ => None,
        };
        let resp = fake_answer(payload, ip, *ttl)?;
        tracing::debug!(%qname, qtype, fake = ?ip, "dns fake answer");
        Some(resp)
    }

    /// Whether a query for `qname` whose effective verdict is `verdict` is
    /// answered with a fake address (or an empty fake-mode answer).
    fn would_fake(&self, qname: &str, qtype: u16, verdict: Verdict) -> bool {
        self.fakeip
            .as_ref()
            .is_some_and(|(pool, _)| matches!(qtype, 1 | 28 | 64 | 65) && pool.should_fake(qname))
            && matches!(verdict, Verdict::Node(_))
    }

    fn remember_names(&self, qname: &str, response: &[u8], ttl_secs: u64) {
        for ip in answer_ips(response) {
            self.names
                .insert(ip, qname, std::time::Duration::from_secs(ttl_secs));
        }
    }

    /// Domain routed to the proxy: resolve overseas through the outbound so
    /// the answer is neither poisoned nor geo-localised to China. Falls back
    /// to the domestic resolver when no remote is configured or it fails.
    async fn query_proxied_or_direct(&self, payload: &[u8], node: u8) -> Result<Vec<u8>> {
        if self.remote.is_some() {
            match self.query_remote(payload, node).await {
                Ok(buf) => return Ok(buf),
                Err(e) => tracing::warn!(error = %e, "remote dns failed; using domestic"),
            }
        }
        self.query_direct(payload).await
    }

    /// No domain rule matched. Follow `general.default`:
    /// - default is a node name and `remote` is configured → use remote
    ///   (fall back to domestic only if remote fails)
    /// - otherwise → use domestic upstream
    ///
    /// This avoids leaking foreign domain queries to the domestic resolver.
    async fn query_unmatched(
        &self,
        payload: &[u8],
        default: Verdict,
        _maps: &Arc<Mutex<StaticMaps>>,
    ) -> Result<Vec<u8>> {
        match default {
            Verdict::Node(n) if self.remote.is_some() => {
                match self.query_remote(payload, n).await {
                    Ok(buf) => Ok(buf),
                    Err(e) => {
                        tracing::warn!(error = %e, "remote dns failed; using domestic");
                        self.query_direct(payload).await
                    }
                }
            }
            _ => self.query_direct(payload).await,
        }
    }

    /// Domestic resolver: marked sockets, direct path.
    async fn query_direct(&self, payload: &[u8]) -> Result<Vec<u8>> {
        dnsup::exchange(&self.upstream, payload, Via::Direct, &self.resolver).await
    }

    /// Overseas resolver reached through proxy node `node` (UDP relay for
    /// `udp://`, a proxied TCP stream for tcp / tls / https).
    async fn query_remote(&self, payload: &[u8], node: u8) -> Result<Vec<u8>> {
        let remote = self.remote.as_ref().ok_or_else(|| anyhow!("no remote dns configured"))?;
        let outbound = self
            .nodes
            .get(node)
            .ok_or_else(|| anyhow!("dns remote needs proxy node #{node}"))?;
        dnsup::exchange(remote, payload, Via::Node(outbound.as_ref()), &self.resolver).await
    }
}

/// End offset of the single question of a plain IN query; `None` for
/// anything unusual (responses, other opcodes, several questions,
/// compressed names, non-IN class) so the caller falls back to real DNS.
fn question_end(q: &[u8]) -> Option<usize> {
    if q.len() < 12
        || q[2] & 0xf8 != 0 // QR=0 and opcode QUERY
        || u16::from_be_bytes([q[4], q[5]]) != 1
    {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *q.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos += len;
    }
    let end = pos + 4;
    (end <= q.len() && q[end - 2..end] == [0, 1]).then_some(end)
}

/// Answer `query` with one A record for `ip`, or an empty NOERROR when `ip`
/// is `None`. Only the question is echoed (EDNS is not).
fn fake_answer(query: &[u8], ip: Option<std::net::IpAddr>, ttl: u32) -> Option<Vec<u8>> {
    let end = question_end(query)?;
    let mut out = Vec::with_capacity(end + 16);
    out.extend_from_slice(&query[0..2]); // id
    out.push(0x80 | (query[2] & 0x01)); // QR, opcode 0, keep RD
    out.push(0x80); // RA, NOERROR
    out.extend_from_slice(&[0, 1]); // qdcount
    out.extend_from_slice(&[0, ip.is_some() as u8]); // ancount
    out.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    out.extend_from_slice(&query[12..end]);
    if let Some(ip) = ip {
        let (rtype, rdata): (u8, Vec<u8>) = match ip {
            std::net::IpAddr::V4(v) => (1, v.octets().to_vec()),
            std::net::IpAddr::V6(v) => (28, v.octets().to_vec()),
        };
        out.extend_from_slice(&[0xc0, 0x0c, 0, rtype, 0, 1]); // name ptr, A/AAAA, IN
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}

/// Synthesize an NXDOMAIN answer for a blocked domain (question echoed).
fn nxdomain(query: &[u8]) -> Vec<u8> {
    let mut end = 12usize;
    while let Some(&len) = query.get(end) {
        if len == 0 {
            end += 1;
            break;
        }
        end += 1 + len as usize;
    }
    end = (end + 4).min(query.len());
    let mut out = query[..end].to_vec();
    out[2] = 0x80 | (query[2] & 0x79); // QR, keep opcode + RD
    out[3] = 0x80 | 0x03; // RA, RCODE = NXDOMAIN
    for b in &mut out[6..12] {
        *b = 0; // an/ns/ar counts
    }
    out
}

fn query_name(msg: &[u8]) -> Option<String> {
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression in qname: unusual, bail
        }
        pos += 1;
        let label = msg.get(pos..pos + len as usize)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len as usize;
    }
    Some(labels.join("."))
}

fn query_type(msg: &[u8]) -> Option<u16> {
    let mut pos = 12usize;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            return Some(u16::from_be_bytes([
                *msg.get(pos + 1)?,
                *msg.get(pos + 2)?,
            ]));
        }
        pos += 1 + len as usize;
    }
}

/// A/AAAA record addresses in the answer section.
pub(crate) fn answer_ips(msg: &[u8]) -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    let Some(ancount) = msg.get(6..8).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return out;
    };
    if ancount == 0 {
        return out;
    }
    // Skip the question section.
    let mut pos = 12usize;
    loop {
        let Some(len) = msg.get(pos).copied() else { return out };
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len as usize;
    }
    pos += 4; // qtype + qclass

    for _ in 0..ancount {
        // name (possibly compressed)
        let Some(b) = msg.get(pos).copied() else { return out };
        pos += if b & 0xc0 != 0 { 2 } else { 1 + b as usize + 1 };
        let Some((rtype, rdlen)) = msg.get(pos..pos + 10).map(|b| {
            (u16::from_be_bytes([b[0], b[1]]), u16::from_be_bytes([b[8], b[9]]))
        }) else {
            return out;
        };
        let rdata = msg.get(pos + 10..pos + 10 + rdlen as usize).unwrap_or(&[]);
        match (rtype, rdata.len()) {
            (1, 4) => out.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (28, 16) => {
                out.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(rdata).unwrap(),
                )));
            }
            _ => {}
        }
        pos += 10 + rdlen as usize;
    }
    out
}

fn answer_min_ttl(msg: &[u8]) -> Option<u64> {
    // Same walk as answer_ips but collecting TTLs; compact duplicate logic
    // is fine for a reference engine.
    let ancount = u16::from_be_bytes([*msg.get(6)?, *msg.get(7)?]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len as usize;
    }
    pos += 4;
    let mut min = u64::MAX;
    for _ in 0..ancount {
        let b = *msg.get(pos)?;
        pos += if b & 0xc0 != 0 { 2 } else { 1 + b as usize + 1 };
        let hdr = msg.get(pos..pos + 10)?;
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]);
        let ttl = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        min = min.min(ttl as u64);
        pos += 10 + rdlen as usize;
    }
    (min != u64::MAX).then_some(min)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn engine(store: Option<Arc<Store>>) -> DnsEngine {
        let cfg = crate::config::parse("general: {default: direct}\ndns: {upstream: '1.1.1.1:53'}\n").unwrap();
        let nodes = Arc::new(Nodes::build(&cfg, &[]).unwrap());
        let rules: SharedRules =
            Arc::new(Mutex::new(crate::rules::Rules::new("direct", &[], &[]).unwrap()));
        DnsEngine::new(
            dnsup::DnsSpec {
                upstream: Upstream::parse("1.1.1.1:53").unwrap(),
                remote: None,
                default: None,
            },
            Arc::new(HostResolver::new(None)),
            rules,
            nodes,
            Arc::new(NameCache::new()),
            None,
            store,
        )
    }

    #[tokio::test]
    async fn cache_flush_persists_and_prunes_expired() {
        let path = crate::store::temp_path("engine");
        let store = Store::open(&path).unwrap();
        let eng = engine(Some(store.clone()));
        eng.cache_put("a.test", 1, b"RESP-A", 100).await;
        eng.cache_put("b.test", 1, b"RESP-B", 100).await;
        eng.flush().await;
        let mut rows = store.dns_load(unix_now()).unwrap();
        rows.sort_by(|x, y| x.qname.cmp(&y.qname));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].response, b"RESP-A");
        assert!(rows[0].expiry_unix >= unix_now() + 98);

        // b expires in memory -> the next flush deletes it from the store.
        eng.cache.lock().await.map.get_mut(&("b.test".to_string(), 1)).unwrap().expiry =
            Instant::now() - Duration::from_millis(1);
        eng.flush().await;
        let rows = store.dns_load(0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].qname, "a.test");
        assert!(!eng.cache.lock().await.map.contains_key(&("b.test".to_string(), 1)));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[tokio::test]
    async fn no_store_tracks_nothing() {
        let eng = engine(None);
        eng.cache_put("a.test", 1, b"X", 60).await;
        assert!(eng.cache.lock().await.dirty.is_empty());
        eng.flush().await; // no-op
        assert_eq!(eng.cache.lock().await.map.len(), 1);
    }

    #[test]
    fn fake_a_answer_parses_back() {
        let q = query("www.example.com", 1);
        let ip = Ipv4Addr::new(198, 18, 0, 7);
        let r = fake_answer(&q, Some(IpAddr::V4(ip)), 5).unwrap();
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x81, 0x81); // QR + RD kept
        assert_eq!(r[3] & 0x0f, 0); // NOERROR
        assert_eq!(query_name(&r).as_deref(), Some("www.example.com"));
        assert_eq!(answer_ips(&r), vec![IpAddr::V4(ip)]);
        assert_eq!(answer_min_ttl(&r), Some(5));
    }

    #[test]
    fn fake_aaaa_answer_parses_back() {
        let q = query("www.example.com", 28);
        let ip: std::net::Ipv6Addr = "fd00:198:18::7".parse().unwrap();
        let r = fake_answer(&q, Some(IpAddr::V6(ip)), 5).unwrap();
        assert_eq!(r[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(query_type(&r), Some(28));
        assert_eq!(answer_ips(&r), vec![IpAddr::V6(ip)]);
        assert_eq!(answer_min_ttl(&r), Some(5));
    }

    #[test]
    fn empty_noerror_for_aaaa() {
        let q = query("www.example.com", 28);
        let r = fake_answer(&q, None, 1).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0);
        assert_eq!(r[3] & 0x0f, 0);
        assert!(answer_ips(&r).is_empty());
        assert_eq!(query_type(&r), Some(28));
    }

    #[test]
    fn odd_queries_fall_back() {
        let mut resp = query("a.com", 1);
        resp[2] |= 0x80; // a response, not a query
        assert!(fake_answer(&resp, None, 1).is_none());
        let mut two = query("a.com", 1);
        two[5] = 2;
        assert!(fake_answer(&two, None, 1).is_none());
        let mut chaos = query("a.com", 1);
        let n = chaos.len();
        chaos[n - 1] = 3; // class CH
        assert!(fake_answer(&chaos, None, 1).is_none());
        assert!(fake_answer(&[0u8; 5], None, 1).is_none());
    }
}
