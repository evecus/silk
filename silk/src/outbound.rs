//! Outbound abstraction: SOCKS5, Hysteria2 or VLESS behind one TCP/UDP dial
//! surface, plus the named node table the datapath verdicts index into.

use crate::hysteria2::Hysteria2Client;
use crate::socks5::Socks5Client;
use crate::vless::VlessClient;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};

/// A bidirectional byte stream to the proxy exit.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}
pub type BoxStream = Box<dyn ByteStream>;

/// The configured nodes, in config order. A kernel verdict
/// `VERDICT_NODE_BASE + i` selects `nodes[i]`.
pub struct Nodes {
    list: Vec<(String, Arc<Outbound>)>,
}

impl Nodes {
    pub fn get(&self, idx: u8) -> Option<&Arc<Outbound>> {
        self.list.get(idx as usize).map(|(_, o)| o)
    }

    pub fn name(&self, idx: u8) -> &str {
        self.list
            .get(idx as usize)
            .map(|(n, _)| n.as_str())
            .unwrap_or("?")
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Resolve the node for a flow: the chosen verdict if it names a node,
    /// else the default node, else error.
    pub fn pick(&self, chosen: Option<crate::rules::Verdict>, default: crate::rules::Verdict) -> Result<(u8, &Arc<Outbound>)> {
        use crate::rules::Verdict;
        for v in [chosen, Some(default)].into_iter().flatten() {
            if let Verdict::Node(i) = v
                && let Some(o) = self.get(i) {
                    return Ok((i, o));
                }
        }
        // Nothing names a node (e.g. the kernel record was evicted and the
        // default is `direct`): fall back to the first node.
        match self.list.first() {
            Some((_, o)) => Ok((0, o)),
            None => anyhow::bail!("proxy flow but no node configured"),
        }
    }

    /// Build every configured node. `servers[i]` is the pre-resolved address
    /// of node `i` (resolved before the eBPF hooks attach, so lookups never
    /// loop through the datapath).
    pub fn build(config: &crate::config::Config, servers: &[SocketAddr]) -> Result<Nodes> {
        use crate::config::NodeConfig;
        let mut list = Vec::new();
        for (node, &server) in config.nodes.iter().zip(servers) {
            let name = node.name().trim().to_string();
            let outbound = match node {
                NodeConfig::Socks(c) => Outbound::Socks5(Arc::new(Socks5Client {
                    server,
                    username: c.username.clone(),
                    password: c.password.clone(),
                })),
                NodeConfig::Hysteria2(c) => Outbound::Hysteria2(Arc::new(
                    Hysteria2Client::new(
                        server,
                        c.password.clone(),
                        c.sni.clone(),
                        c.insecure,
                        &c.up,
                        &c.down,
                    )
                    .with_context(|| format!("node {name}: hysteria2"))?,
                )),
                NodeConfig::Vless(c) => Outbound::Vless(Arc::new(
                    VlessClient::new(server, c).with_context(|| format!("node {name}: vless"))?,
                )),
            };
            tracing::info!(node = %name, kind = node.type_name(), %server, "node ready");
            list.push((name, Arc::new(outbound)));
        }
        Ok(Nodes { list })
    }
}

pub enum Outbound {
    Socks5(Arc<Socks5Client>),
    Hysteria2(Arc<Hysteria2Client>),
    Vless(Arc<VlessClient>),
}

impl Outbound {
    /// Open a TCP connection to `dst` through the outbound. With `domain`
    /// the exit is asked to connect to `domain:port(dst)` (and resolve it
    /// itself) instead of the bare IP.
    pub async fn connect_tcp(&self, dst: SocketAddr, domain: Option<&str>) -> Result<BoxStream> {
        match self {
            Outbound::Socks5(c) => Ok(Box::new(c.connect_tcp(dst, domain).await?)),
            Outbound::Hysteria2(c) => Ok(Box::new(c.connect_tcp(dst, domain).await?)),
            Outbound::Vless(c) => c.connect_tcp(dst, domain).await,
        }
    }

    /// Establish a UDP relay channel. The returned handle carries both
    /// directions; drop it to tear the flow down.
    pub async fn udp_session(&self) -> Result<UdpUpstream> {
        match self {
            Outbound::Socks5(c) => {
                let (control, sock) = c.associate_udp().await?;
                Ok(UdpUpstream::Socks5 {
                    _control: control,
                    sock,
                })
            }
            Outbound::Hysteria2(c) => Ok(UdpUpstream::Hy2(c.udp_session().await?)),
            Outbound::Vless(c) => Ok(UdpUpstream::Vless(c.udp_session().await?)),
        }
    }
}

pub enum UdpUpstream {
    Socks5 {
        /// ASSOCIATE control connection; dropped with the flow.
        _control: TcpStream,
        sock: UdpSocket,
    },
    Hy2(crate::hysteria2::UdpSession),
    Vless(crate::vless::VlessUdpSession),
}

impl UdpUpstream {
    /// Send one datagram to `dst` through the outbound.
    pub async fn send(&self, payload: &[u8], dst: SocketAddr) -> Result<()> {
        match self {
            UdpUpstream::Socks5 { sock, .. } => {
                let mut pkt = vec![0u8, 0, 0];
                push_udp_addr(&mut pkt, dst);
                pkt.extend_from_slice(payload);
                sock.send(&pkt).await?;
                Ok(())
            }
            UdpUpstream::Hy2(s) => s.send(payload, dst).await,
            UdpUpstream::Vless(s) => s.send(payload, dst).await,
        }
    }

    /// Receive one relayed datagram into `buf`, returning its length.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match self {
            UdpUpstream::Socks5 { sock, .. } => {
                let n = sock.recv(buf).await?;
                if n < 4 {
                    anyhow::bail!("short UDP relay packet");
                }
                let atyp = buf[3];
                let hdr_len = match atyp {
                    1 => 10,
                    4 => 22,
                    other => anyhow::bail!("UDP relay ATYP {other}"),
                };
                if n < hdr_len {
                    anyhow::bail!("short UDP relay header");
                }
                buf.copy_within(hdr_len..n, 0);
                Ok(n - hdr_len)
            }
            UdpUpstream::Hy2(s) => s.recv(buf).await,
            UdpUpstream::Vless(s) => s.recv(buf).await,
        }
    }
}

fn push_udp_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            buf.push(1);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}
