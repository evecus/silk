//! DNS engine: intercept UDP/53 flows, resolve through the configured
//! upstream on a control-plane socket, publish per-IP verdicts into
//! DOMAIN_ROUTE, and answer the client through a `silkns` reply socket.

use crate::listener::create_reply_socket;
use crate::names::NameCache;
use crate::outbound::Nodes;
use crate::rules::{SharedRules, StaticMaps, Verdict};
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub struct DnsEngine {
    /// Domestic resolver, queried directly on a control-plane socket.
    upstream: SocketAddr,
    /// Overseas resolver, queried through a proxy node.
    remote: Option<SocketAddr>,
    nodes: Arc<Nodes>,
    rules: SharedRules,
    /// IP -> domain memory for dial-by-domain on proxied TCP flows.
    names: Arc<NameCache>,
    /// query cache: (qname, qtype) -> (response, expiry instant)
    cache: Mutex<std::collections::HashMap<(String, u16), (Vec<u8>, std::time::Instant)>>,
}

impl DnsEngine {
    pub fn new(
        upstream: SocketAddr,
        remote: Option<SocketAddr>,
        rules: SharedRules,
        nodes: Arc<Nodes>,
        names: Arc<NameCache>,
    ) -> Self {
        DnsEngine {
            upstream,
            remote,
            nodes,
            rules,
            names,
            cache: Mutex::new(Default::default()),
        }
    }

    /// One fresh, marked, connected socket per query. A shared socket makes
    /// concurrent queries steal each other's answers.
    async fn new_upstream_socket(&self) -> Result<UdpSocket> {
        let family = if self.upstream.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            anyhow::bail!("socket: {}", std::io::Error::last_os_error());
        }
        // Own the fd immediately so every error path closes it.
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        crate::datapath::mark_global_control(fd)?;
        std_sock.set_nonblocking(true)?;
        let sock = UdpSocket::from_std(std_sock)?;
        sock.connect(self.upstream).await?;
        Ok(sock)
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

        // 1. cache (a cached answer carries the old transaction id: patch it)
        {
            let cache = self.cache.lock().await;
            if let Some((resp, expiry)) = cache.get(&(qname.to_string(), qtype))
                && *expiry > std::time::Instant::now() && resp.len() >= 2 {
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

        // 3a. remember which name each answer address belongs to, for
        //     dial-by-domain on proxied TCP flows.
        if rule != Some(Verdict::Block) {
            let ttl = answer_min_ttl(&buf).unwrap_or(60).clamp(300, 7200);
            self.remember_names(qname, &buf, ttl);
        }

        // 3. publish verdicts only for domains that matched a domain rule;
        //    anything else falls through to CIDR / port / default in the
        //    kernel (otherwise the default verdict would override CIDR rules).
        if let Some(verdict) = rule
            && verdict != Verdict::Block {
                let mut maps = maps.lock().await;
                for ip in answer_ips(&buf) {
                    if let Err(e) = maps.publish_domain_ip(ip, verdict) {
                        tracing::warn!(%ip, error = %e, "publish domain route");
                    }
                }
            }

        // 4. cache by the minimum answer TTL.
        let ttl = answer_min_ttl(&buf).unwrap_or(60);
        self.cache.lock().await.insert(
            (qname.to_string(), qtype),
            (buf.clone(), std::time::Instant::now() + std::time::Duration::from_secs(ttl)),
        );
        Ok(buf)
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

    /// Domestic resolver: fresh marked socket, direct path.
    async fn query_direct(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let sock = self.new_upstream_socket().await?;
        sock.send(payload).await?;
        let mut buf = vec![0u8; 4096];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let n = loop {
            let (n, _) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow!("DNS upstream timeout"))??;
            if n >= 2 && buf[0] == payload[0] && buf[1] == payload[1] {
                break n;
            }
        };
        buf.truncate(n);
        Ok(buf)
    }

    /// Overseas resolver reached through proxy node `node` (UDP relay).
    async fn query_remote(&self, payload: &[u8], node: u8) -> Result<Vec<u8>> {
        let remote = self.remote.ok_or_else(|| anyhow!("no remote dns configured"))?;
        let outbound = self
            .nodes
            .get(node)
            .ok_or_else(|| anyhow!("dns remote needs proxy node #{node}"))?;
        let session = outbound.udp_session().await?;
        session.send(payload, remote).await?;
        let mut buf = vec![0u8; 4096];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let n = loop {
            let n = tokio::time::timeout_at(deadline, session.recv(&mut buf))
                .await
                .map_err(|_| anyhow!("remote DNS timeout"))??;
            if n >= 2 && buf[0] == payload[0] && buf[1] == payload[1] {
                break n;
            }
        };
        buf.truncate(n);
        Ok(buf)
    }
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
fn answer_ips(msg: &[u8]) -> Vec<std::net::IpAddr> {
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
