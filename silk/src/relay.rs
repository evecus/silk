//! Transparent relay: consumes the `silkns` listeners.
//!
//! TCP: accepted conns carry the original destination (IP_TRANSPARENT +
//! sk_lookup assignment); relay to the flow's node (SOCKS5 / Hysteria2 / VLESS) over a
//! control-plane marked dial socket, copying both directions.
//!
//! UDP: each datagram carries its original destination via IP_RECVORIGDSTADDR.
//! Flows to port 53 are handed to the DNS engine; other flows go through the
//! outbound's UDP relay. Replies are sent from a per-flow socket bound to the
//! original destination inside `silkns`, so the datapath's silk0_ingress
//! restores the captured framing and hands them back to the client.

use crate::fakeip::FakeIpPool;
use crate::listener::{create_reply_socket, orig_dst_tcp};
use crate::names::NameCache;
use crate::outbound::{BoxStream, Nodes, UdpUpstream};
use crate::rules::{SharedRules, StaticMaps, Verdict};
use crate::sniffer;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Shared state for TCP flows.
pub struct TcpCtx {
    pub nodes: Arc<Nodes>,
    /// Verdict for flows the kernel record does not place on a node.
    pub default: Verdict,
    pub maps: Arc<Mutex<StaticMaps>>,
    pub rules: SharedRules,
    pub names: Arc<NameCache>,
    /// Peek at the first bytes for a TLS SNI / HTTP Host.
    pub sniff: bool,
    /// Dial the proxy exit by name instead of by IP.
    pub dial_by_domain: bool,
    /// Fake-IP pool: destinations inside it map back to a domain.
    pub fakeip: Option<Arc<FakeIpPool>>,
}

/// How long to wait for the client's first bytes. Clients speak first on TLS
/// and HTTP, so this only costs time for server-first protocols, which the
/// negative cache in `sniffer` then stops probing.
const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const SNIFF_MAX: usize = 4096;
const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_tcp(listener: tokio::net::TcpListener, ctx: Arc<TcpCtx>) -> Result<()> {
    loop {
        let (conn, client) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(conn, client, ctx).await {
                tracing::debug!(error = %e, "tcp flow ended");
            }
        });
    }
}

async fn handle_tcp(mut conn: TcpStream, client: SocketAddr, ctx: Arc<TcpCtx>) -> Result<()> {
    let orig = orig_dst_tcp(&conn)?;

    // 1. The name: a fake address maps straight back to its domain (no
    //    sniffing needed); otherwise sniff the client's first bytes
    //    (TLS SNI / HTTP Host).
    let mut early: Vec<u8> = Vec::new();
    let mut domain: Option<String> = None;
    let mut fake = false;
    if let Some(pool) = &ctx.fakeip
        && pool.contains(orig.ip())
    {
        match pool.domain_of(orig.ip()) {
            Some(d) => {
                domain = Some(d);
                fake = true;
            }
            None => {
                // Stale address (evicted, or handed out before a restart
                // without a store): nothing to dial.
                tracing::debug!(%orig, "fake ip without mapping; dropping");
                return Ok(());
            }
        }
    } else if ctx.sniff && sniffer::sniff_allowed(orig) {
        let (bytes, sniffed) = sniff_client(&mut conn, orig).await?;
        early = bytes;
        domain = sniffed;
    }

    // 2. A sniffed name re-runs the domain rules: the kernel only saw an IP.
    //    A node verdict here overrides the node the kernel picked.
    let mut sniffed_node: Option<Verdict> = None;
    if let Some(d) = &domain {
        let verdict = ctx.rules.lock().await.match_domain(d);
        match verdict {
            Some(Verdict::Block) => {
                tracing::debug!(%orig, domain = %d, "sniffed domain blocked");
                return Ok(());
            }
            Some(Verdict::Direct) => {
                if fake {
                    // Direct names are never given fake addresses; this is a
                    // mapping that outlived a rule change.
                    anyhow::bail!("fake ip {orig} maps to direct domain {d}");
                }
                tracing::debug!(%orig, domain = %d, "sniffed domain routed direct");
                let up = dial_direct(orig).await?;
                return relay(conn, up, early).await;
            }
            Some(v @ Verdict::Node(_)) => sniffed_node = Some(v),
            None => {}
        }
    }

    // 3. Node path: sniffed rule > the node the kernel recorded at capture >
    //    the default. Prefer the sniffed name for dialling; fall back to the
    //    name the DNS engine remembered for this address (unique names only).
    let kernel_node = match sniffed_node {
        Some(_) => None,
        None => ctx.maps.lock().await.flow_verdict(client, orig, false),
    };
    let (node_idx, outbound) = ctx.nodes.pick(sniffed_node.or(kernel_node), ctx.default)?;
    let outbound = outbound.clone();
    // A fake address cannot be dialled: the name is mandatory for it.
    let dial_name = if fake {
        domain.clone()
    } else if ctx.dial_by_domain {
        domain.clone().or_else(|| ctx.names.lookup(orig.ip()))
    } else {
        None
    };
    tracing::debug!(%orig, name = ?dial_name, node = ctx.nodes.name(node_idx), "tcp proxy dial");
    let upstream: BoxStream = outbound.connect_tcp(orig, dial_name.as_deref()).await?;
    relay(conn, upstream, early).await
}

/// Read the client's opening bytes until a name is found, the data is not
/// sniffable, or the window closes. Returns everything read (to be replayed
/// to the upstream) and the sniffed name.
async fn sniff_client(conn: &mut TcpStream, orig: SocketAddr) -> Result<(Vec<u8>, Option<String>)> {
    let mut buf = vec![0u8; SNIFF_MAX];
    let mut n = 0usize;
    let mut domain = None;
    let mut timed_out = false;
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    while n < buf.len() {
        match tokio::time::timeout_at(deadline, conn.read(&mut buf[n..])).await {
            Err(_) => {
                timed_out = true;
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => break,
            Ok(Ok(k)) => {
                n += k;
                let r = sniffer::sniff_tcp_ex(&buf[..n], true, false);
                if let Some(d) = r.domain {
                    domain = sniffer::clean_domain(&d);
                    break;
                }
                if !sniffer::tcp_needs_more(&buf[..n]) {
                    break;
                }
            }
        }
    }
    buf.truncate(n);
    sniffer::note_sniff_result(orig, domain.is_some(), timed_out && n == 0);
    Ok((buf, domain))
}

/// Direct dial from userspace (control-plane marked, so the datapath lets it
/// through) to the address the client originally wanted.
async fn dial_direct(dst: SocketAddr) -> Result<TcpStream> {
    let sock = if dst.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    crate::datapath::mark_global_control(sock.as_raw_fd())?;
    tokio::time::timeout(DIRECT_DIAL_TIMEOUT, sock.connect(dst))
        .await
        .map_err(|_| anyhow::anyhow!("direct dial {dst}: timeout"))?
        .with_context(|| format!("direct dial {dst}"))
}

/// Replay the sniffed prefix upstream, then copy both directions.
async fn relay<U>(conn: TcpStream, upstream: U, early: Vec<u8>) -> Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = conn.into_split();
    let (mut ur, mut uw) = tokio::io::split(upstream);
    if !early.is_empty() {
        uw.write_all(&early).await?;
    }
    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);
    tokio::select! {
        r = c2u => { r?; let _ = cw.shutdown().await; }
        r = u2c => { r?; let _ = uw.shutdown().await; }
    }
    Ok(())
}

struct UdpFlow {
    /// Outbound UDP relay channel.
    upstream: UdpUpstream,
    /// Reply socket bound to the original destination inside `silkns`.
    reply: UdpSocket,
    client: SocketAddr,
    /// Name the exit should resolve instead of the captured address
    /// (a fake IP's domain, or a QUIC-sniffed SNI).
    domain: Option<String>,
}

/// Shared state for UDP flows.
pub struct UdpCtx {
    pub nodes: Arc<Nodes>,
    pub default: Verdict,
    pub maps: Arc<Mutex<StaticMaps>>,
    pub rules: SharedRules,
    pub fakeip: Option<Arc<FakeIpPool>>,
    /// Sniff the SNI of a QUIC Initial in a new flow's first datagram
    /// (`sniff.enable`, like TCP).
    pub sniff: bool,
    /// Dial the exit with a sniffed name (fake-IP flows always do).
    pub dial_by_domain: bool,
}

pub async fn run_udp(
    sock: std::net::UdpSocket,
    ctx: Arc<UdpCtx>,
    dns: Arc<crate::dns::DnsEngine>,
) -> Result<()> {
    // Dedicated blocking recv thread: the transparent socket is read with
    // recvmsg(RECVORIGDSTADDR), which has no tokio equivalent. Datagrams are
    // forwarded to the async dispatcher over a channel.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<UdpEvent>();
    std::thread::Builder::new().name("udp-recv".into()).spawn({
        use std::os::fd::AsRawFd;
        move || loop {
            let mut buf = vec![0u8; 65535];
            match unsafe { recv_orig_dst_blocking(sock.as_raw_fd(), &mut buf) } {
                Ok((n, client, orig)) => {
                    let payload = buf[..n].to_vec();
                    if tx
                        .send(UdpEvent {
                            payload,
                            client,
                            orig,
                        })
                        .is_err()
                    {
                        break; // dispatcher gone: shut down
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "udp recvmsg");
                }
            }
        }
    })?;

    let flows: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpFlow>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    while let Some(ev) = rx.recv().await {
        let UdpEvent {
            payload,
            client,
            orig,
        } = ev;
        let key = (client, orig);

        tracing::debug!(%client, %orig, len = payload.len(), "udp datagram in silkns");
        if orig.port() == 53 {
            let dns = dns.clone();
            let maps = ctx.maps.clone();
            tokio::spawn(async move {
                if let Err(e) = dns.handle_flow(&payload, client, orig, maps).await {
                    tracing::warn!(error = %e, "dns flow");
                }
            });
            continue;
        }

        let flow = {
            let mut table = flows.lock().await;
            if let Some(f) = table.get(&key) {
                f.clone()
            } else {
                let flow = match create_udp_flow(&ctx, key, &payload).await {
                    Ok(Some(f)) => Arc::new(f),
                    // Blocked, or a stale fake address: drop the datagram.
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(error = %e, "udp flow setup");
                        continue;
                    }
                };
                table.insert(key, flow.clone());
                // One pump per flow: reads the SOCKS5 relay endpoint and
                // emits replies from the silkns reply socket. Exits on idle.
                let pump_flow = flow.clone();
                let table_ref = flows.clone();
                tokio::spawn(async move {
                    let idle = pump_udp_replies(pump_flow).await;
                    table_ref.lock().await.remove(&key);
                    if let Err(e) = idle {
                        tracing::debug!(error = %e, "udp pump ended");
                    }
                });
                flow
            }
        };

        // Forward through the outbound relay channel.
        if let Err(e) = flow.upstream.send(&payload, orig, flow.domain.as_deref()).await {
            tracing::warn!(error = %e, "udp upstream send");
        }
    }
    Ok(())
}

/// Set up the relay for a new UDP flow; `first` is its first datagram.
/// `Ok(None)` = drop (blocked name, or a fake address without a mapping).
async fn create_udp_flow(
    ctx: &UdpCtx,
    key: (SocketAddr, SocketAddr),
    first: &[u8],
) -> Result<Option<UdpFlow>> {
    let (client, orig) = key;

    // 1. The name: a fake address maps back to its domain; otherwise try the
    //    QUIC Initial's SNI (a no-op for any other datagram).
    let mut domain: Option<String> = None;
    let mut fake = false;
    if let Some(pool) = &ctx.fakeip
        && pool.contains(orig.ip())
    {
        match pool.domain_of(orig.ip()) {
            Some(d) => {
                domain = Some(d);
                fake = true;
            }
            None => {
                tracing::debug!(%client, %orig, "udp: fake ip without mapping; dropping");
                return Ok(None);
            }
        }
    } else if ctx.sniff {
        domain = sniffer::sniff_quic(first).and_then(|d| sniffer::clean_domain(&d));
        if let Some(d) = &domain {
            tracing::debug!(%client, %orig, domain = %d, "quic sni sniffed");
        }
    }

    // 2. A name re-runs the domain rules: the kernel only saw an IP.
    let mut named_node: Option<Verdict> = None;
    if let Some(d) = &domain {
        let verdict = ctx.rules.lock().await.match_domain(d);
        match verdict {
            Some(Verdict::Block) => {
                tracing::debug!(%client, %orig, domain = %d, "udp domain blocked");
                return Ok(None);
            }
            Some(Verdict::Direct) => {
                if fake {
                    anyhow::bail!("fake ip {orig} maps to direct domain {d}");
                }
                tracing::debug!(%client, %orig, domain = %d, "udp domain routed direct");
                return Ok(Some(UdpFlow {
                    upstream: UdpUpstream::direct(orig).await?,
                    reply: create_reply_socket(orig)?,
                    client,
                    domain: None,
                }));
            }
            Some(v @ Verdict::Node(_)) => named_node = Some(v),
            None => {}
        }
    }

    // 3. Node: the name's rule > the node the kernel recorded > the default.
    let kernel_node = match named_node {
        Some(_) => None,
        None => ctx.maps.lock().await.flow_verdict(client, orig, true),
    };
    let (node_idx, outbound) = ctx.nodes.pick(named_node.or(kernel_node), ctx.default)?;
    // Only a name we are sure of is dialled; no DNS-memory guess for UDP.
    let dial_name = if fake || ctx.dial_by_domain { domain } else { None };
    tracing::debug!(%client, %orig, name = ?dial_name, node = ctx.nodes.name(node_idx), "udp proxy flow");
    Ok(Some(UdpFlow {
        upstream: outbound.udp_session().await?,
        reply: create_reply_socket(orig)?,
        client,
        domain: dial_name,
    }))
}

async fn pump_udp_replies(flow: Arc<UdpFlow>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            flow.upstream.recv(&mut buf),
        )
        .await??;
        // Emit from the original-destination socket: src = orig, dst = client,
        // routed out of silkns via silk0peer and restored by silk0_ingress.
        flow.reply.send_to(&buf[..n], flow.client).await?;
    }
}

struct UdpEvent {
    payload: Vec<u8>,
    client: SocketAddr,
    orig: SocketAddr,
}

/// recvmsg wrapper extracting IP_RECVORIGDSTADDR ancillary data. Runs on the
/// dedicated blocking recv thread; `fd` must be a blocking socket.
unsafe fn recv_orig_dst_blocking(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    // SAFETY: single-threaded FFI on the recv thread; buffers outlive the call.
    unsafe {
        let mut iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 128];
        let mut from: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_name = &mut from as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        // musl: msg_controllen is socklen_t (u32); glibc often size_t — cast for both.
        msg.msg_controllen = cmsg_buf.len() as _;

        let n = loop {
            let rc = libc::recvmsg(fd, &mut msg, 0);
            if rc >= 0 {
                break rc as usize;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted
                || err.kind() == std::io::ErrorKind::WouldBlock
            {
                continue;
            }
            anyhow::bail!("recvmsg: {err}");
        };

        let client = sockaddr_to_addr(&from).context("client addr")?;
        let mut orig = None;
        let mut cpos = cmsg_buf.as_mut_ptr();
        let end = cmsg_buf.as_mut_ptr().add(msg.msg_controllen as usize);
        while cpos < end {
            let ch = cpos as *const libc::cmsghdr;
            let level = (*ch).cmsg_level;
            let ctype = (*ch).cmsg_type;
            if (level == libc::IPPROTO_IP && ctype == libc::IP_RECVORIGDSTADDR)
                || (level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_RECVORIGDSTADDR)
            {
                let data =
                    cpos.add(std::mem::size_of::<libc::cmsghdr>()) as *const libc::sockaddr_storage;
                orig = sockaddr_to_addr(&*data);
                break;
            }
            // cmsg_len is size_t on glibc but socklen_t (u32) on musl.
            #[allow(clippy::unnecessary_cast)]
            let clen = (*ch).cmsg_len as usize;
            cpos = cpos.add(cmsg_align(clen));
        }
        let orig = orig.context("no orig dst ancillary")?;
        Ok((n, client, orig))
    }
}

/// CMSG_ALIGN is a libc macro, not a function — replicate it here.
fn cmsg_align(len: usize) -> usize {
    (len + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1)
}

fn sockaddr_to_addr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let a: &libc::sockaddr_in = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin_port)))
        }
        libc::AF_INET6 => {
            let a: &libc::sockaddr_in6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin6_port)))
        }
        _ => None,
    }
}
