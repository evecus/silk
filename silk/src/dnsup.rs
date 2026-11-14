//! DNS upstream transports: plain UDP, TCP, DNS-over-TLS and DNS-over-HTTPS.
//!
//! An upstream is written as a URL; the scheme picks the transport and every
//! transport has a default port, so the port is only needed when it differs:
//!
//! | spelling                       | transport | default port |
//! |--------------------------------|-----------|--------------|
//! | `1.1.1.1`, `udp://1.1.1.1`     | UDP       | 53           |
//! | `tcp://1.1.1.1`                | TCP       | 53           |
//! | `tls://1.1.1.1`                | DoT       | 853          |
//! | `https://1.1.1.1/dns-query`    | DoH       | 443          |
//!
//! Only UDP may omit the scheme. IPv6 literals work bare (`2606:4700::1111`)
//! or bracketed with a port (`[2606:4700::1111]:5353`). The DoH path defaults
//! to `/dns-query`. The host may be a domain (`tls://dns.alidns.com`): it is
//! resolved through the default resolver (`dns.default`, plain UDP/TCP to an IP).
//!
//! Every query opens a fresh connection. Direct queries use control-plane
//! marked sockets so the datapath never loops on them; proxied queries go
//! through the node the domain routes to (`Outbound::connect_tcp` /
//! `udp_session`).

use crate::outbound::{BoxStream, Outbound};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio_rustls::TlsConnector;

/// Per-step network timeout.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound for a whole exchange (resolve + connect + handshake + query).
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a default-resolved upstream address is reused.
const BOOTSTRAP_TTL: Duration = Duration::from_secs(300);
/// Largest DoH response body accepted.
const MAX_DOH_BODY: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl Kind {
    pub fn default_port(self) -> u16 {
        match self {
            Kind::Udp | Kind::Tcp => 53,
            Kind::Tls => 853,
            Kind::Https => 443,
        }
    }

    fn scheme(self) -> &'static str {
        match self {
            Kind::Udp => "udp",
            Kind::Tcp => "tcp",
            Kind::Tls => "tls",
            Kind::Https => "https",
        }
    }
}

/// One parsed DNS upstream. Parsing never touches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub kind: Kind,
    /// IP literal or domain, without brackets.
    pub host: String,
    pub port: u16,
    /// DoH request path (with query); empty for the other transports.
    pub path: String,
}

impl Upstream {
    /// Parse `1.1.1.1`, `udp://…`, `tcp://…`, `tls://…` or `https://…`.
    pub fn parse(s: &str) -> Result<Upstream> {
        let raw = s.trim();
        if raw.is_empty() {
            bail!("empty dns upstream");
        }
        let (kind, rest) = match raw.split_once("://") {
            None => (Kind::Udp, raw),
            Some((scheme, rest)) => {
                let kind = match scheme.to_ascii_lowercase().as_str() {
                    "udp" => Kind::Udp,
                    "tcp" => Kind::Tcp,
                    "tls" => Kind::Tls,
                    "https" => Kind::Https,
                    other => bail!(
                        "dns upstream {raw:?}: unsupported scheme {other:?} \
                         (use udp://, tcp://, tls:// or https://)"
                    ),
                };
                (kind, rest)
            }
        };
        let (authority, path) = if kind == Kind::Https {
            match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].to_string()),
                None => (rest, "/dns-query".to_string()),
            }
        } else {
            (rest.trim_end_matches('/'), String::new())
        };
        let (host, port) = split_host_port(authority, kind.default_port())
            .with_context(|| format!("dns upstream {raw:?}"))?;
        Ok(Upstream { kind, host, port, path })
    }

    /// The host as an IP address, when it is a literal.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

impl std::fmt::Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        write!(f, "{}://{host}:{}{}", self.kind.scheme(), self.port, self.path)
    }
}

fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    let (host, port) = if let Some(inner) = s.strip_prefix('[') {
        let end = inner.find(']').context("unclosed '[' in address")?;
        let host = &inner[..end];
        let rest = &inner[end + 1..];
        let port = match rest {
            "" => default_port,
            r => parse_port(r.strip_prefix(':').context("expected ':port' after ']'")?)?,
        };
        (host, port)
    } else if s.parse::<Ipv6Addr>().is_ok() {
        // A bare IPv6 literal has no port.
        (s, default_port)
    } else if let Some((h, p)) = s.rsplit_once(':') {
        (h, parse_port(p)?)
    } else {
        (s, default_port)
    };
    if host.is_empty() {
        bail!("missing host");
    }
    if host.chars().any(|c| c.is_whitespace() || c == '/' || c == '@') {
        bail!("invalid host {host:?}");
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn parse_port(p: &str) -> Result<u16> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => bail!("invalid port {p:?}"),
        Ok(n) => Ok(n),
    }
}

// ── default ────────────────────────────────────────────────────────────

/// Everything the `dns` section says about resolvers, parsed once.
#[derive(Debug, Clone)]
pub struct DnsSpec {
    pub upstream: Upstream,
    pub remote: Option<Upstream>,
    /// `dns.default`: resolver for hostnames (node servers, DNS upstreams
    /// written as domains): plain UDP/TCP to an IP.
    pub default: Option<Upstream>,
}

impl DnsSpec {
    pub fn from_config(dns: &crate::config::Dns) -> Result<DnsSpec> {
        let upstream = Upstream::parse(&dns.upstream).context("dns.upstream")?;
        let remote = match dns.remote.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => Some(Upstream::parse(s).context("dns.remote")?),
            _ => None,
        };
        let plain_ip = |u: &Upstream| matches!(u.kind, Kind::Udp | Kind::Tcp) && u.ip().is_some();
        let default = match dns.default.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                let b = Upstream::parse(s).context("dns.default")?;
                if !plain_ip(&b) {
                    bail!("dns.default {s:?} must be a plain udp/tcp resolver given as an IP address (e.g. 223.5.5.5)");
                }
                Some(b)
            }
            // Unset: the domestic resolver itself, when it qualifies.
            _ => plain_ip(&upstream).then(|| upstream.clone()),
        };
        if default.is_none() {
            for (name, u) in [("dns.upstream", Some(&upstream)), ("dns.remote", remote.as_ref())] {
                if let Some(u) = u
                    && u.ip().is_none()
                {
                    bail!(
                        "{name} {u} uses a hostname: set dns.default to a plain resolver IP \
                         (e.g. dns.default: 223.5.5.5) to resolve it"
                    );
                }
            }
        }
        Ok(DnsSpec { upstream, remote, default })
    }
}

/// Resolves hostnames (node servers, DNS upstreams written as domains)
/// through `dns.default`, caching the answer for a few minutes (and dropping
/// it when an exchange fails).
pub struct HostResolver {
    server: Option<Upstream>,
    cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

impl HostResolver {
    pub fn new(server: Option<Upstream>) -> Self {
        HostResolver {
            server,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.server.is_some()
    }

    fn invalidate(&self, host: &str) {
        self.cache.lock().unwrap().remove(host);
    }

    pub async fn resolve(&self, host: &str) -> Result<IpAddr> {
        if let Some((ip, at)) = self.cache.lock().unwrap().get(host)
            && at.elapsed() < BOOTSTRAP_TTL
        {
            return Ok(*ip);
        }
        let server = self
            .server
            .as_ref()
            .context("no dns.default to resolve the hostname")?;
        let addr = SocketAddr::new(server.ip().context("default must be an IP")?, server.port);
        let mut found = None;
        for qtype in [1u16, 28] {
            let q = build_query(host, qtype);
            let resp = match server.kind {
                Kind::Tcp => exchange_tcp(addr, &q, Via::Direct).await,
                _ => udp_exchange(addr, &q, Via::Direct).await,
            }
            .with_context(|| format!("default {server} for {host}"))?;
            if let Some(ip) = crate::dns::answer_ips(&resp).into_iter().next() {
                found = Some(ip);
                break;
            }
        }
        let ip = found.with_context(|| format!("default resolver has no address for {host}"))?;
        self.cache.lock().unwrap().insert(host.to_string(), (ip, Instant::now()));
        Ok(ip)
    }
}

fn build_query(host: &str, qtype: u16) -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.trim_end_matches('.').split('.') {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

// ── exchange ─────────────────────────────────────────────────────────────

/// How the query leaves this host.
#[derive(Clone, Copy)]
pub enum Via<'a> {
    /// Straight out on a control-plane marked socket.
    Direct,
    /// Through a proxy node.
    Node(&'a Outbound),
}

/// Send `query` to `up` and return the raw response.
pub async fn exchange(up: &Upstream, query: &[u8], via: Via<'_>, boot: &HostResolver) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("short DNS query");
    }
    let result = tokio::time::timeout(TOTAL_TIMEOUT, async {
        let ip = match up.ip() {
            Some(ip) => ip,
            None => boot.resolve(&up.host).await?,
        };
        let addr = SocketAddr::new(ip, up.port);
        match up.kind {
            Kind::Udp => {
                let resp = udp_exchange(addr, query, via).await?;
                // Truncated: retry the same server over TCP.
                if resp.get(2).is_some_and(|b| b & 0x02 != 0) {
                    return exchange_tcp(addr, query, via).await;
                }
                Ok(resp)
            }
            Kind::Tcp => exchange_tcp(addr, query, via).await,
            Kind::Tls => exchange_tls(addr, &up.host, query, via).await,
            Kind::Https => exchange_https(addr, up, query, via).await,
        }
    })
    .await
    .unwrap_or_else(|_| Err(anyhow!("dns upstream timeout")));
    if result.is_err() && up.ip().is_none() {
        // The address may have changed: resolve again next time.
        boot.invalidate(&up.host);
    }
    result.with_context(|| format!("dns upstream {up}"))
}

#[cfg(not(test))]
fn mark(fd: std::os::fd::RawFd) -> Result<()> {
    // Before the eBPF hooks attach (startup lookups of node servers) there is
    // no datapath to loop through, so an unmarked socket is fine.
    if crate::datapath::control_installed() {
        crate::datapath::mark_global_control(fd)?;
    }
    Ok(())
}

// Unit tests run without the datapath's control marker.
#[cfg(test)]
fn mark(_fd: std::os::fd::RawFd) -> Result<()> {
    Ok(())
}

async fn udp_exchange(addr: SocketAddr, query: &[u8], via: Via<'_>) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let n = match via {
        Via::Direct => {
            let family = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
            let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                bail!("socket: {}", std::io::Error::last_os_error());
            }
            // Own the fd immediately so every error path closes it.
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            mark(fd)?;
            std_sock.set_nonblocking(true)?;
            let sock = UdpSocket::from_std(std_sock)?;
            sock.connect(addr).await?;
            sock.send(query).await?;
            loop {
                let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
                    .await
                    .map_err(|_| anyhow!("dns udp timeout"))??;
                if n >= 12 && buf[..2] == query[..2] {
                    break n;
                }
            }
        }
        Via::Node(node) => {
            let session = node.udp_session().await?;
            session.send(query, addr, None).await?;
            loop {
                let n = tokio::time::timeout_at(deadline, session.recv(&mut buf))
                    .await
                    .map_err(|_| anyhow!("dns udp timeout"))??;
                if n >= 12 && buf[..2] == query[..2] {
                    break n;
                }
            }
        }
    };
    buf.truncate(n);
    Ok(buf)
}

/// A TCP stream to `addr`: marked and direct, or through the node.
async fn open_stream(addr: SocketAddr, via: Via<'_>) -> Result<BoxStream> {
    match via {
        Via::Direct => {
            let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            mark(sock.as_raw_fd())?;
            let s = tokio::time::timeout(TIMEOUT, sock.connect(addr))
                .await
                .map_err(|_| anyhow!("dns connect {addr}: timeout"))?
                .with_context(|| format!("dns connect {addr}"))?;
            s.set_nodelay(true).ok();
            Ok(Box::new(s))
        }
        Via::Node(node) => tokio::time::timeout(TIMEOUT, node.connect_tcp(addr, None))
            .await
            .map_err(|_| anyhow!("dns connect {addr} via node: timeout"))?,
    }
}

async fn exchange_tcp(addr: SocketAddr, query: &[u8], via: Via<'_>) -> Result<Vec<u8>> {
    let mut s = open_stream(addr, via).await?;
    framed_exchange(&mut s, query).await
}

async fn exchange_tls(addr: SocketAddr, sni: &str, query: &[u8], via: Via<'_>) -> Result<Vec<u8>> {
    let mut tls = tls_connect(addr, sni, via, false).await?;
    framed_exchange(&mut tls, query).await
}

/// RFC 7766 framing: 2-byte length prefix each way.
async fn framed_exchange<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, query: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(query.len()).context("dns query too large")?;
    let mut msg = Vec::with_capacity(query.len() + 2);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(query);
    s.write_all(&msg).await?;
    s.flush().await?;
    let mut hdr = [0u8; 2];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut hdr))
        .await
        .map_err(|_| anyhow!("dns read timeout"))??;
    let n = u16::from_be_bytes(hdr) as usize;
    if n < 12 {
        bail!("bad dns response length {n}");
    }
    let mut buf = vec![0u8; n];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow!("dns read timeout"))??;
    if buf[..2] != query[..2] {
        bail!("dns response id mismatch");
    }
    Ok(buf)
}

async fn tls_connect(
    addr: SocketAddr,
    sni: &str,
    via: Via<'_>,
    http: bool,
) -> Result<tokio_rustls::client::TlsStream<BoxStream>> {
    let stream = open_stream(addr, via).await?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow!("invalid TLS server name {sni:?}"))?;
    tokio::time::timeout(TIMEOUT, tls_connector(http).connect(name, stream))
        .await
        .map_err(|_| anyhow!("dns tls handshake timeout"))?
        .with_context(|| format!("dns tls handshake with {sni}"))
}

fn tls_connector(http: bool) -> TlsConnector {
    static PLAIN: OnceLock<TlsConnector> = OnceLock::new();
    static HTTP: OnceLock<TlsConnector> = OnceLock::new();
    let build = move || {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        #[cfg(test)]
        roots
            .add(rustls::pki_types::CertificateDer::from(
                include_bytes!("testdata/dns-test-cert.der").to_vec(),
            ))
            .unwrap();
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if http {
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        TlsConnector::from(Arc::new(cfg))
    };
    if http { HTTP.get_or_init(build) } else { PLAIN.get_or_init(build) }.clone()
}

/// RFC 8484 DoH: POST `application/dns-message` over HTTP/1.1.
async fn exchange_https(addr: SocketAddr, up: &Upstream, query: &[u8], via: Via<'_>) -> Result<Vec<u8>> {
    use hyper::header::{ACCEPT, CONTENT_TYPE, HOST};
    let tls = tls_connect(addr, &up.host, via, true).await?;
    let io = hyper_util::rt::TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .context("doh http handshake")?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let host = if up.host.contains(':') { format!("[{}]", up.host) } else { up.host.clone() };
    let authority = if up.port == 443 { host } else { format!("{host}:{}", up.port) };
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(up.path.as_str())
        .header(HOST, authority)
        .header(CONTENT_TYPE, "application/dns-message")
        .header(ACCEPT, "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(query)))
        .context("doh request")?;
    let result = async {
        let resp = tokio::time::timeout(TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_| anyhow!("doh request timeout"))?
            .context("doh request")?;
        if !resp.status().is_success() {
            bail!("doh server answered HTTP {}", resp.status());
        }
        let body = tokio::time::timeout(TIMEOUT, Limited::new(resp.into_body(), MAX_DOH_BODY).collect())
            .await
            .map_err(|_| anyhow!("doh body timeout"))?
            .map_err(|e| anyhow!("doh body: {e}"))?
            .to_bytes();
        if body.len() < 12 {
            bail!("doh response too short");
        }
        if body[..2] != query[..2] {
            bail!("doh response id mismatch");
        }
        Ok(body.to_vec())
    }
    .await;
    driver.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, UdpSocket as TokioUdp};

    fn up(s: &str) -> Upstream {
        Upstream::parse(s).unwrap()
    }

    #[test]
    fn default_ports_per_scheme() {
        assert_eq!(up("1.1.1.1"), Upstream { kind: Kind::Udp, host: "1.1.1.1".into(), port: 53, path: "".into() });
        assert_eq!(up("udp://1.1.1.1").port, 53);
        assert_eq!(up("tcp://1.1.1.1").port, 53);
        assert_eq!(up("tls://1.1.1.1").port, 853);
        let h = up("https://1.1.1.1/dns-query");
        assert_eq!((h.kind, h.port, h.path.as_str()), (Kind::Https, 443, "/dns-query"));
        assert_eq!(up("https://dns.example.com").path, "/dns-query");
    }

    #[test]
    fn explicit_ports_and_paths() {
        assert_eq!(up("1.1.1.1:5353").port, 5353);
        assert_eq!(up("udp://1.1.1.1:5353").port, 5353);
        assert_eq!(up("tcp://8.8.8.8:5353").port, 5353);
        assert_eq!(up("tls://dns.google:8853").port, 8853);
        let h = up("https://doh.example.com:8443/custom/q?x=1");
        assert_eq!((h.host.as_str(), h.port, h.path.as_str()), ("doh.example.com", 8443, "/custom/q?x=1"));
        // scheme is case-insensitive, host lowercased, whitespace trimmed
        assert_eq!(up("  TLS://DNS.Google  ").host, "dns.google");
        assert_eq!(up("tls://1.1.1.1/").port, 853);
    }

    #[test]
    fn ipv6_literals() {
        assert_eq!(up("2606:4700::1111").host, "2606:4700::1111");
        assert_eq!(up("2606:4700::1111").port, 53);
        assert_eq!(up("[2606:4700::1111]:5353").port, 5353);
        assert_eq!(up("[::1]").port, 53);
        assert_eq!(up("tls://[2606:4700::1111]").port, 853);
        assert_eq!(up("https://[2606:4700::1111]/dns-query").port, 443);
        assert_eq!(up("https://[2606:4700::1111]:8443/dns-query").port, 8443);
        assert_eq!(up("tls://[2606:4700::1111]:8853").ip(), Some("2606:4700::1111".parse().unwrap()));
        assert_eq!(up("tls://[2606:4700::1111]").to_string(), "tls://[2606:4700::1111]:853");
    }

    #[test]
    fn rejects_bad_specs() {
        for bad in [
            "", "  ", "quic://1.1.1.1", "tls://", "tcp://:53", "1.1.1.1:0", "1.1.1.1:99999",
            "1.1.1.1:abc", "[::1", "[::1]x", "tcp://1.1.1.1/path", "https://",
        ] {
            assert!(Upstream::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn display_roundtrips() {
        for s in ["udp://1.1.1.1:53", "tcp://1.1.1.1:53", "tls://dns.google:853", "https://dns.google:443/dns-query"] {
            assert_eq!(up(s).to_string(), s);
            assert_eq!(up(&up(s).to_string()), up(s));
        }
    }

    #[test]
    fn spec_default_rules() {
        let dns = |extra: &str| -> Result<DnsSpec> {
            let cfg = crate::config::parse(&format!(
                "general: {{default: direct}}\ndns: {{{extra}}}\n"
            ))
            .map(|c| c.dns);
            DnsSpec::from_config(&cfg?)
        };
        // plain IP upstream doubles as default
        let s = dns("upstream: 223.5.5.5").unwrap();
        assert_eq!(s.default, Some(up("223.5.5.5")));
        // IP-literal DoT/DoH need no default
        assert!(dns("upstream: 'tls://223.5.5.5'").unwrap().default.is_none());
        assert!(dns("upstream: 'https://223.5.5.5/dns-query'").unwrap().default.is_none());
        // hostname without a default is an error; with one it works
        assert!(dns("upstream: 'tls://dns.alidns.com'").is_err());
        let s = dns("upstream: 'tls://dns.alidns.com', default: 119.29.29.29").unwrap();
        assert_eq!(s.default, Some(up("119.29.29.29")));
        // default must be a plain IP resolver
        assert!(dns("upstream: 223.5.5.5, default: 'tls://1.1.1.1'").is_err());
        assert!(dns("upstream: 223.5.5.5, default: dns.google").is_err());
    }

    /// A canned A answer for whatever single question `q` asks.
    fn answer_for(q: &[u8]) -> Vec<u8> {
        let mut end = 12;
        while q[end] != 0 {
            end += 1 + q[end] as usize;
        }
        end += 5;
        let mut r = q[..end].to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6..8].copy_from_slice(&[0, 1]);
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 9, 9, 9]);
        r
    }

    fn query() -> Vec<u8> {
        build_query("www.example.com", 1)
    }

    fn assert_answer(resp: &[u8]) {
        assert_eq!(crate::dns::answer_ips(resp), vec![IpAddr::from([9, 9, 9, 9])]);
    }

    fn boot() -> HostResolver {
        HostResolver::new(None)
    }

    async fn framed_server<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).await.unwrap();
        let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
        s.read_exact(&mut q).await.unwrap();
        let a = answer_for(&q);
        s.write_all(&(a.len() as u16).to_be_bytes()).await.unwrap();
        s.write_all(&a).await.unwrap();
        s.flush().await.unwrap();
        // keep the connection open until the client hangs up
        let _ = s.read(&mut [0u8; 1]).await;
    }

    fn tls_acceptor(alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
        let cert = rustls::pki_types::CertificateDer::from(include_bytes!("testdata/dns-test-cert.der").to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(include_bytes!("testdata/dns-test-key.der").to_vec()),
        );
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn udp_exchange_roundtrip() {
        let srv = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let port = srv.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            let (n, from) = srv.recv_from(&mut b).await.unwrap();
            // a stray packet with the wrong id must be ignored
            let mut wrong = answer_for(&b[..n]);
            wrong[0] ^= 0xff;
            srv.send_to(&wrong, from).await.unwrap();
            srv.send_to(&answer_for(&b[..n]), from).await.unwrap();
        });
        let r = exchange(&up(&format!("127.0.0.1:{port}")), &query(), Via::Direct, &boot()).await.unwrap();
        assert_answer(&r);
    }

    #[tokio::test]
    async fn udp_truncated_retries_over_tcp() {
        // UDP and TCP listeners on the same port number.
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = TokioUdp::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            let (n, from) = udp.recv_from(&mut b).await.unwrap();
            let mut tc = answer_for(&b[..n]);
            tc[2] |= 0x02; // TC
            tc.truncate(n); // no answers
            tc[6..8].copy_from_slice(&[0, 0]);
            udp.send_to(&tc, from).await.unwrap();
        });
        tokio::spawn(async move {
            let (s, _) = tcp.accept().await.unwrap();
            framed_server(s).await;
        });
        let r = exchange(&up(&format!("127.0.0.1:{port}")), &query(), Via::Direct, &boot()).await.unwrap();
        assert_answer(&r);
    }

    #[tokio::test]
    async fn tcp_exchange_roundtrip() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            framed_server(s).await;
        });
        let r = exchange(&up(&format!("tcp://127.0.0.1:{port}")), &query(), Via::Direct, &boot()).await.unwrap();
        assert_answer(&r);
    }

    #[tokio::test]
    async fn tls_exchange_roundtrip() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let acc = tls_acceptor(&[]);
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            framed_server(acc.accept(s).await.unwrap()).await;
        });
        let r = exchange(&up(&format!("tls://127.0.0.1:{port}")), &query(), Via::Direct, &boot()).await.unwrap();
        assert_answer(&r);
    }

    #[tokio::test]
    async fn tls_rejects_untrusted_certificate() {
        // A server whose name does not match the dialed IP/SNI must fail.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let acc = tls_acceptor(&[]);
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let _ = acc.accept(s).await;
        });
        // 127.0.0.2 is not in the certificate's SANs
        let r = exchange(&up(&format!("tls://127.0.0.2:{port}")), &query(), Via::Direct, &boot()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn https_exchange_roundtrip() {
        use http_body_util::BodyExt;
        use hyper::service::service_fn;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let acc = tls_acceptor(&[b"http/1.1"]);
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let tls = acc.accept(s).await.unwrap();
            let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                assert_eq!(req.method(), hyper::Method::POST);
                assert_eq!(req.uri().path(), "/custom");
                assert_eq!(req.headers()["content-type"], "application/dns-message");
                let q = req.into_body().collect().await.unwrap().to_bytes();
                Ok::<_, std::convert::Infallible>(
                    hyper::Response::builder()
                        .header("content-type", "application/dns-message")
                        .body(Full::new(Bytes::from(answer_for(&q))))
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
        let r = exchange(&up(&format!("https://127.0.0.1:{port}/custom")), &query(), Via::Direct, &boot())
            .await
            .unwrap();
        assert_answer(&r);
    }

    #[tokio::test]
    async fn https_non_200_is_an_error() {
        use hyper::service::service_fn;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let acc = tls_acceptor(&[b"http/1.1"]);
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let tls = acc.accept(s).await.unwrap();
            let svc = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, std::convert::Infallible>(
                    hyper::Response::builder().status(503).body(Full::new(Bytes::new())).unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
        let e = exchange(&up(&format!("https://127.0.0.1:{port}")), &query(), Via::Direct, &boot())
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("503"), "{e:#}");
    }

    #[tokio::test]
    async fn hostname_resolves_through_default() {
        // default: a UDP server answering every A query with 127.0.0.1
        let boot_srv = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let boot_port = boot_srv.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            loop {
                let Ok((n, from)) = boot_srv.recv_from(&mut b).await else { return };
                let mut a = answer_for(&b[..n]);
                let l = a.len();
                a[l - 4..].copy_from_slice(&[127, 0, 0, 1]);
                let _ = boot_srv.send_to(&a, from).await;
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            framed_server(s).await;
        });
        let boot = HostResolver::new(Some(up(&format!("127.0.0.1:{boot_port}"))));
        let r = exchange(&up(&format!("tcp://dns.test:{port}")), &query(), Via::Direct, &boot).await.unwrap();
        assert_answer(&r);
        assert_eq!(boot.cache.lock().unwrap().get("dns.test").map(|e| e.0), Some(IpAddr::from([127, 0, 0, 1])));
        // a failed exchange drops the cached address
        let e = exchange(&up("tcp://dns.test:1"), &query(), Via::Direct, &boot).await;
        assert!(e.is_err());
        assert!(boot.cache.lock().unwrap().get("dns.test").is_none());
        // no default configured: clear error
        let e = exchange(&up("tcp://dns.test:53"), &query(), Via::Direct, &HostResolver::new(None)).await.unwrap_err();
        assert!(format!("{e:#}").contains("default"), "{e:#}");
    }
}
