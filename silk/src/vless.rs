//! VLESS outbound (protocol aligned with Xray / ant's client).
//!
//! Transports: `tcp` | `ws` | `xhttp`; TLS layer optional (rustls, uTLS
//! fingerprint, or self-implemented REALITY TLS 1.3), plus the
//! `xtls-rprx-vision` flow control (padding + direct copy) on plain TCP.
//!
//! * tcp: header written directly, response header read eagerly. With
//!   `flow: xtls-rprx-vision` the stream is wrapped in a [`vision::VisionConn`].
//! * ws: the VLESS header is merged into the first upstream write and the
//!   response header is skipped lazily on the first read (same as ant /
//!   sing-box). Waiting for the response eagerly would deadlock, since
//!   servers only answer once they got payload.
//! * xhttp: stream-one (single POST, HTTP/1.1 over plain/rustls/uTLS/REALITY)
//!   or packet-up / stream-up (hyper, h2 under TLS / h1 plain). The VLESS
//!   header is merged into the first write.
//!
//! Request: version(1) + uuid(16) + addon_len(1) + addon + cmd(1) + port(2 BE) + atyp + addr
//! Response: version(1) + addon_len(1) + addon
//!
//! Every socket this module dials is control-plane marked so the eBPF
//! datapath never loops on it.

mod reality;
mod utls;
mod vision;
mod ws;
mod xhttp;
mod xhttp_h2;

use crate::config::Vless as VlessConfig;
use crate::datapath::mark_global_control;
use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;

use crate::outbound::BoxStream;

const VLESS_VERSION: u8 = 0;
const VLESS_CMD_TCP: u8 = 1;
const VLESS_CMD_UDP: u8 = 2;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// TLS + WS handshake timeout (matches ant / sing-box TCPTimeout).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Dial a control-plane marked TCP connection. Shared with the xhttp h2
/// connector (which dials from inside hyper, outside `VlessClient`).
pub(crate) async fn dial_marked(server: SocketAddr) -> Result<TcpStream> {
    let sock = if server.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Err(e) = mark_global_control(sock.as_raw_fd()) {
        // Only expected in tests / before the eBPF marker is installed;
        // production always installs it before the outbound is built.
        tracing::warn!("vless: control mark unavailable, dialing unmarked: {e:#}");
    }
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, sock.connect(server))
        .await
        .map_err(|_| anyhow!("vless dial {server} timeout"))?
        .with_context(|| format!("vless dial {server}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub struct VlessClient {
    server: SocketAddr,
    uuid: [u8; 16],
    /// "tcp" | "ws" | "xhttp"
    network: String,
    /// TLS (rustls, uTLS or REALITY) is enabled.
    tls: bool,
    sni: String,
    ws_path: String,
    ws_host: String,
    /// Flow control addon ("xtls-rprx-vision"), TCP only.
    flow: Option<String>,
    /// uTLS browser fingerprint (None = plain rustls ClientHello).
    utls: Option<utls::UtlsFingerprint>,
    utls_verify: utls::UtlsVerify,
    /// rustls config for plain TLS (non-REALITY), http/1.1 / user ALPN.
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// rustls config for xhttp packet-up / stream-up (ALPN forced to h2).
    xhttp_h2_tls: Option<Arc<rustls::ClientConfig>>,
    /// REALITY dial settings (implies TLS).
    reality: Option<reality::RealityDialConfig>,
    xhttp: Option<xhttp::XhttpConfig>,
    xhttp_resolved: XhttpResolved,
    xhttp_host: String,
}

/// xhttp 上行模式（对齐 ant / Xray）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum XhttpResolved {
    StreamOne,
    PacketUp,
    StreamUp,
}

impl XhttpResolved {
    fn as_str(self) -> &'static str {
        match self {
            XhttpResolved::StreamOne => "stream-one",
            XhttpResolved::PacketUp => "packet-up",
            XhttpResolved::StreamUp => "stream-up",
        }
    }
}

impl VlessClient {
    pub fn new(server: SocketAddr, cfg: &VlessConfig) -> Result<Self> {
        let uuid = parse_uuid(cfg.uuid.trim())
            .with_context(|| format!("invalid vless uuid {:?}", cfg.uuid))?;
        let network = cfg.network.trim().to_lowercase();
        if network != "tcp" && network != "ws" && network != "xhttp" {
            bail!("vless: unsupported network {network:?} (supported: tcp, ws, xhttp)");
        }
        let server_host = cfg
            .server
            .rsplit_once(':')
            .map(|(h, _)| {
                h.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            })
            .unwrap_or_else(|| server.ip().to_string());
        let sni = if cfg.sni.trim().is_empty() {
            server_host.clone()
        } else {
            cfg.sni.trim().to_string()
        };
        let ws_path = {
            let mut p = if cfg.ws_path.trim().is_empty() {
                "/".to_string()
            } else {
                cfg.ws_path.trim().to_string()
            };
            if !p.starts_with('/') {
                p.insert(0, '/');
            }
            p
        };
        let ws_host = if cfg.ws_host.trim().is_empty() {
            sni.clone()
        } else {
            cfg.ws_host.trim().to_string()
        };
        let xhttp_host = if cfg.xhttp_host.trim().is_empty() {
            sni.clone()
        } else {
            cfg.xhttp_host.trim().to_string()
        };

        // ── 流控（flow addon）─────────────────────────────────────────────
        let flow = match cfg.flow.trim() {
            "" => None,
            "xtls-rprx-vision" => Some("xtls-rprx-vision".to_string()),
            other => bail!("vless: unsupported flow {other:?} (supported: xtls-rprx-vision)"),
        };

        // ── uTLS 指纹 ─────────────────────────────────────────────────────
        let fingerprint_str = cfg.client_fingerprint.trim().to_string();
        let utls = if fingerprint_str.is_empty() {
            None
        } else {
            match utls::UtlsFingerprint::parse(&fingerprint_str) {
                Some(fp) => Some(fp),
                None => bail!(
                    "vless: unknown client_fingerprint {fingerprint_str:?} (supported: chrome/firefox/safari/edge/ios/android/360/qq/random)"
                ),
            }
        };
        let utls_verify = utls::UtlsVerify {
            skip_cert_verify: cfg.insecure,
            fingerprint: None,
        };

        // ── 用户显式 ALPN（逗号分隔）──────────────────────────────────────
        let alpn: Vec<String> = cfg
            .alpn
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // ── REALITY ────────────────────────────────────────────────────────
        let reality_key = cfg
            .reality_public_key
            .trim()
            .to_string();
        let reality = if reality_key.is_empty() {
            None
        } else {
            Some(reality::RealityDialConfig {
                public_key: reality_key,
                short_id: cfg.reality_short_id.trim().to_string(),
                server_name: Some(sni.clone()),
                server: cfg.server.trim().to_string(),
                alpn: alpn.clone(),
            })
        };
        if reality.is_some() && network == "ws" {
            bail!("vless: reality does not support network ws");
        }
        if utls.is_some() && reality.is_some() {
            tracing::warn!(
                "vless: client_fingerprint is ignored under reality (reality handshake is self-implemented TLS 1.3)"
            );
        }

        // ── xhttp 配置 ─────────────────────────────────────────────────────
        let xhttp = if network == "xhttp" {
            let mut x = xhttp::XhttpConfig::default();
            if !cfg.xhttp_path.trim().is_empty() {
                x.path = cfg.xhttp_path.trim().to_string();
            }
            Some(x)
        } else {
            None
        };
        let xhttp_resolved = if network == "xhttp" {
            match cfg.xhttp_mode.trim().to_lowercase().as_str() {
                "" | "auto" => {
                    if reality.is_some() {
                        XhttpResolved::StreamOne
                    } else {
                        XhttpResolved::PacketUp
                    }
                }
                "stream-one" => XhttpResolved::StreamOne,
                "packet-up" => XhttpResolved::PacketUp,
                "stream-up" => XhttpResolved::StreamUp,
                other => bail!(
                    "vless: unsupported xhttp_mode {other:?} (supported: auto, stream-one, packet-up, stream-up)"
                ),
            }
        } else {
            XhttpResolved::StreamOne
        };
        if network == "xhttp" && reality.is_some() && xhttp_resolved != XhttpResolved::StreamOne {
            bail!(
                "vless: reality does not support xhttp mode {} (only stream-one)",
                xhttp_resolved.as_str()
            );
        }

        // ── 流控与传输方式的组合校验 ──────────────────────────────────────
        if let Some(f) = &flow {
            if network != "tcp" {
                bail!("vless: flow {f:?} requires network tcp");
            }
            if !cfg.tls && reality.is_none() {
                bail!("vless: flow {f:?} requires tls or reality");
            }
        }

        // ── TLS 配置 ───────────────────────────────────────────────────────
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok(); // already installed is fine

        // ws 升级是 HTTP/1.1；xhttp stream-one 也是 HTTP/1.1 POST。
        let force_http11 = network == "ws" || xhttp_resolved == XhttpResolved::StreamOne;
        let mut tls_alpn: Vec<String> = if !alpn.is_empty() {
            alpn.clone()
        } else if utls.is_some() {
            vec!["h2".to_string(), "http/1.1".to_string()]
        } else {
            Vec::new()
        };
        if force_http11 {
            tls_alpn = vec!["http/1.1".to_string()];
        }
        let to_wire = |v: &[String]| v.iter().map(|s| s.as_bytes().to_vec()).collect::<Vec<_>>();

        let tls_config = if cfg.tls && reality.is_none() {
            let builder = rustls::ClientConfig::builder();
            let mut config = if cfg.insecure {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SkipVerify))
                    .with_no_client_auth()
            } else {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            };
            config.alpn_protocols = to_wire(&tls_alpn);
            Some(Arc::new(config))
        } else {
            if cfg.insecure && !cfg.tls {
                tracing::warn!("vless: insecure set but tls is disabled — no effect");
            }
            None
        };

        // packet-up / stream-up 走 hyper：TLS 时 ALPN 强制 h2（HTTP/2 流式语义）。
        let xhttp_h2_tls = if network == "xhttp"
            && cfg.tls
            && reality.is_none()
            && matches!(
                xhttp_resolved,
                XhttpResolved::PacketUp | XhttpResolved::StreamUp
            ) {
            let builder = rustls::ClientConfig::builder();
            let mut config = if cfg.insecure {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SkipVerify))
                    .with_no_client_auth()
            } else {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            };
            config.alpn_protocols = vec![b"h2".to_vec()];
            Some(Arc::new(config))
        } else {
            None
        };

        Ok(Self {
            server,
            uuid,
            network,
            tls: cfg.tls || reality.is_some(),
            sni,
            ws_path,
            ws_host,
            flow,
            utls,
            utls_verify,
            tls_config,
            xhttp_h2_tls,
            reality,
            xhttp,
            xhttp_resolved,
            xhttp_host,
        })
    }

    /// Open a TCP connection to `dst` through the VLESS outbound. With
    /// `domain` the exit is asked to connect to `domain:port(dst)` (and
    /// resolve it itself) instead of the bare IP.
    pub async fn connect_tcp(&self, dst: SocketAddr, domain: Option<&str>) -> Result<BoxStream> {
        let header = build_vless_header(
            &self.uuid,
            domain,
            dst,
            VLESS_CMD_TCP,
            self.flow.as_deref(),
        );
        if self.network != "tcp" {
            // Header merged into the first ws frame / first xhttp write;
            // response header is skipped lazily (servers answer only after
            // payload).
            return self.transport_with_header(header).await;
        }

        let tcp = self.dial().await?;
        let layer = self.transport_tcp_layer(tcp).await?;
        if self.flow.is_some() {
            // 流控：padding 混淆 + direct 零拷贝（VisionConn 处理一切）。
            let mut vconn = vision::VisionConn::new(layer, self.uuid);
            vconn.write_all(&header).await.context("vless write request")?;
            vconn.flush().await.context("vless flush request")?;
            read_vless_response(&mut vconn).await?;
            Ok(Box::new(vconn))
        } else {
            let mut io: BoxStream = match layer {
                vision::TlsLayer::Rustls(s) => Box::new(s),
                vision::TlsLayer::Tls13(s) => Box::new(s),
                vision::TlsLayer::Plain(s) => Box::new(s),
            };
            io.write_all(&header).await.context("vless write request")?;
            read_vless_response(&mut io).await?;
            Ok(io)
        }
    }

    /// Establish a UDP relay session (VLESS command=UDP, one stream per
    /// destination — silk gives every UDP flow its own session).
    pub async fn udp_session(self: &Arc<Self>) -> Result<VlessUdpSession> {
        Ok(VlessUdpSession {
            client: self.clone(),
            write: tokio::sync::Mutex::new(None),
            read: tokio::sync::Mutex::new(None),
        })
    }

    /// TCP → rustls TLS / uTLS / REALITY / plain，包装成 Vision 的外层。
    async fn transport_tcp_layer(&self, tcp: TcpStream) -> Result<vision::TlsLayer> {
        if let Some(rc) = &self.reality {
            Ok(vision::TlsLayer::Tls13(
                reality::reality_connect(tcp, rc).await?,
            ))
        } else if self.tls {
            if let Some(fp) = &self.utls {
                Ok(vision::TlsLayer::Tls13(
                    utls::connect_utls(
                        tcp,
                        &self.sni,
                        fp,
                        &self.utls_verify,
                        &["h2".to_string(), "http/1.1".to_string()],
                    )
                    .await?,
                ))
            } else {
                Ok(vision::TlsLayer::Rustls(Box::new(
                    self.wrap_tls(tcp).await?,
                )))
            }
        } else {
            Ok(vision::TlsLayer::Plain(tcp))
        }
    }

    /// xhttp stream-one 的外层传输：REALITY > rustls/uTLS > plain
    /// （对齐 ant 的 connect_xhttp_transport）。
    async fn xhttp_stream_transport(&self) -> Result<BoxStream> {
        let tcp = self.dial().await?;
        if let Some(rc) = &self.reality {
            return Ok(Box::new(
                reality::reality_connect(tcp, rc)
                    .await
                    .context("vless reality handshake")?,
            ));
        }
        if self.tls {
            if let Some(fp) = &self.utls {
                return Ok(Box::new(
                    utls::connect_utls(
                        tcp,
                        &self.sni,
                        fp,
                        &self.utls_verify,
                        &["http/1.1".to_string()],
                    )
                    .await?,
                ));
            }
            return Ok(Box::new(self.wrap_tls(tcp).await?));
        }
        Ok(Box::new(tcp))
    }

    /// Underlying transport for ws / xhttp（VLESS 头并入首个写块），
    /// 以及 tcp 网络（头由调用方直接写入）。
    async fn transport_with_header(&self, header: Vec<u8>) -> Result<BoxStream> {
        match self.network.as_str() {
            "ws" => {
                let tcp = self.dial().await?;
                let io: BoxStream = if self.tls {
                    if let Some(fp) = &self.utls {
                        Box::new(
                            utls::connect_utls(
                                tcp,
                                &self.sni,
                                fp,
                                &self.utls_verify,
                                &["http/1.1".to_string()],
                            )
                            .await?,
                        )
                    } else {
                        Box::new(self.wrap_tls(tcp).await?)
                    }
                } else {
                    Box::new(tcp)
                };
                let ws = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws::WsStream::connect(io, self))
                    .await
                    .map_err(|_| {
                        anyhow!(
                            "vless ws handshake timed out after {}s",
                            HANDSHAKE_TIMEOUT.as_secs()
                        )
                    })?
                    .context("vless ws handshake")?;
                Ok(Box::new(ws.with_header(header)))
            }
            "xhttp" => {
                let x = self.xhttp.as_ref().context("vless xhttp not configured")?;
                let pipe: BoxStream = match self.xhttp_resolved {
                    XhttpResolved::StreamOne => {
                        // stream-one：单条 POST 双向流；REALITY / uTLS / rustls
                        // / plain 任意外层（ALPN http/1.1）。
                        let transport = self.xhttp_stream_transport().await?;
                        Box::new(xhttp::connect_over_stream(transport, x).await?)
                    }
                    XhttpResolved::PacketUp | XhttpResolved::StreamUp => {
                        // packet-up / stream-up：hyper 客户端；TLS 时 ALPN h2。
                        let tls = self.xhttp_h2_tls.as_ref().map(|cfg| xhttp_h2::XhttpH2Tls {
                            config: cfg.clone(),
                            server_name: self.sni.clone(),
                            utls: self.utls,
                            verify: self.utls_verify.clone(),
                        });
                        let stream = tokio::time::timeout(
                            HANDSHAKE_TIMEOUT,
                            xhttp_h2::connect(
                                &self.server.ip().to_string(),
                                self.server.port(),
                                &self.xhttp_host,
                                &x.path,
                                self.xhttp_resolved.as_str(),
                                &x.headers,
                                tls,
                            ),
                        )
                        .await
                        .map_err(|_| anyhow!("vless xhttp handshake timed out"))?
                        .context("vless xhttp handshake")?;
                        Box::new(stream)
                    }
                };
                Ok(Box::new(VlessStreamIo::with_header(
                    pipe,
                    Bytes::from(header),
                )))
            }
            // tcp 网络：transport_with_header 只用于 UDP 会话（无流控）。
            _ => {
                let tcp = self.dial().await?;
                let layer = self.transport_tcp_layer(tcp).await?;
                let mut io: BoxStream = match layer {
                    vision::TlsLayer::Rustls(s) => Box::new(s),
                    vision::TlsLayer::Tls13(s) => Box::new(s),
                    vision::TlsLayer::Plain(s) => Box::new(s),
                };
                if !header.is_empty() {
                    io.write_all(&header).await.context("vless write request")?;
                    read_vless_response(&mut io).await?;
                }
                Ok(io)
            }
        }
    }

    /// Underlying transport: TCP → (TLS/uTLS/REALITY) → (WS upgrade, ws network only).
    async fn transport(&self) -> Result<BoxStream> {
        self.transport_with_header(Vec::new()).await
    }

    async fn dial(&self) -> Result<TcpStream> {
        dial_marked(self.server).await
    }

    async fn wrap_tls(&self, tcp: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let cfg = self
            .tls_config
            .as_ref()
            .context("vless tls enabled but no tls config")?;
        let name = ServerName::try_from(self.sni.clone())
            .map_err(|_| anyhow!("invalid vless sni {:?}", self.sni))?;
        let conn = TlsConnector::from(cfg.clone()).connect(name, tcp);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, conn)
            .await
            .map_err(|_| {
                anyhow!(
                    "vless tls handshake timed out after {}s",
                    HANDSHAKE_TIMEOUT.as_secs()
                )
            })?
            .context("vless tls handshake")
    }
}

/// 把 VLESS 请求头并入首个上行写块（xhttp 用：pipe 建立后头随首个
/// POST/stream body 一起发出），并在读方向惰性跳过 VLESS 响应头。
pub(crate) struct VlessStreamIo {
    inner: BoxStream,
    pending_header: Option<Bytes>,
    pending_write: Option<Bytes>,
    /// Bytes of the *user* payload reported as written once `pending_write`
    /// (header + payload combined) has been fully flushed.
    pending_reported: usize,
    raw_buf: Vec<u8>,
    read_buf: Bytes,
    response_header_skipped: bool,
}

impl VlessStreamIo {
    pub(crate) fn with_header(inner: BoxStream, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
            raw_buf: Vec::new(),
            read_buf: Bytes::new(),
            response_header_skipped: false,
        }
    }
}

impl AsyncRead for VlessStreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf = this.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        if !this.response_header_skipped {
            // Accumulate until the full [ver][addon_len][addon] header is here.
            loop {
                if this.raw_buf.len() >= 2 {
                    if this.raw_buf[0] != VLESS_VERSION {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("vless: bad response version {}", this.raw_buf[0]),
                        )));
                    }
                    let hdr_len = 2 + this.raw_buf[1] as usize;
                    if this.raw_buf.len() >= hdr_len {
                        this.response_header_skipped = true;
                        let payload = Bytes::copy_from_slice(&this.raw_buf[hdr_len..]);
                        this.raw_buf.clear();
                        if !payload.is_empty() {
                            this.read_buf = payload;
                            let n = buf.remaining().min(this.read_buf.len());
                            buf.put_slice(&this.read_buf[..n]);
                            this.read_buf = this.read_buf.slice(n..);
                        }
                        break;
                    }
                }
                let mut tmp = [0u8; 512];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.raw_buf.extend_from_slice(filled);
                    }
                }
            }
        }

        if !this.read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // 1. Finish a partially-written combined buffer first.
        if let Some(pending) = this.pending_write.take() {
            return match Pin::new(&mut this.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = this.pending_reported;
                    this.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    this.pending_reported = 0;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    this.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. First write: merge header + data into one upstream write.
        if let Some(header) = this.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            return match Pin::new(&mut this.inner).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(data.len())),
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(combined.slice(n..));
                    this.pending_reported = data.len();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending_write = Some(combined);
                    this.pending_reported = data.len();
                    Poll::Pending
                }
            };
        }

        // 3. Plain passthrough.
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Lazily established VLESS UDP stream (command=UDP). The relay gives every
/// (client, destination) pair its own session, so a single stream carrying
/// u16be-length framed datagrams in both directions is sufficient.
pub struct VlessUdpSession {
    client: Arc<VlessClient>,
    write: tokio::sync::Mutex<Option<tokio::io::WriteHalf<BoxStream>>>,
    read: tokio::sync::Mutex<Option<tokio::io::ReadHalf<BoxStream>>>,
}

impl VlessUdpSession {
    /// Send one datagram to `dst`. Opens the VLESS UDP stream on first use.
    pub async fn send(&self, payload: &[u8], dst: SocketAddr) -> Result<()> {
        let mut guard = self.write.lock().await;
        if guard.is_none() {
            let header = build_vless_header(&self.client.uuid, None, dst, VLESS_CMD_UDP, None);
            let mut io = self.client.transport().await?;
            io.write_all(&header).await.context("vless udp write request")?;
            // tcp：响应头现在就读掉；ws / xhttp 的响应头由传输适配层
            // （WsStream / VlessStreamIo）在首个读里惰性剥离，这里再读
            // 反而会吃掉真正的数据。
            if self.client.network == "tcp" {
                read_vless_response(&mut io).await?;
            }
            let (r, w) = tokio::io::split(io);
            *self.read.lock().await = Some(r);
            *guard = Some(w);
        }
        if payload.is_empty() || payload.len() > u16::MAX as usize {
            bail!("vless udp payload size out of range: {}", payload.len());
        }
        let w = guard.as_mut().unwrap();
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        w.write_all(&frame).await.context("vless udp write")
    }

    /// Receive one relayed datagram into `buf`, returning its length.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.read.lock().await;
            if let Some(r) = guard.as_mut() {
                let mut lenb = [0u8; 2];
                r.read_exact(&mut lenb).await.context("vless udp len")?;
                let n = u16::from_be_bytes(lenb) as usize;
                if n == 0 {
                    return Ok(0);
                }
                if n > buf.len() {
                    bail!("vless udp datagram {} exceeds buffer {}", n, buf.len());
                }
                r.read_exact(&mut buf[..n]).await.context("vless udp body")?;
                return Ok(n);
            }
            drop(guard);
            // The stream opens on the first send; wait for it.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        bail!("uuid must contain 32 hex digits, got {}", hex.len());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("bad uuid byte {}", i))?;
    }
    Ok(out)
}

/// Build the VLESS request header. `domain` (a name the exit should resolve)
/// is sent as ATYP_DOMAIN instead of the bare IP. `flow` (流控 addon) is
/// encoded as a protobuf field: 0x0a + len + "xtls-rprx-vision".
fn build_vless_header(
    uuid: &[u8; 16],
    domain: Option<&str>,
    dst: SocketAddr,
    cmd: u8,
    flow: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22 + 260);
    buf.push(VLESS_VERSION);
    buf.extend_from_slice(uuid);
    match flow {
        Some(f) if !f.is_empty() => {
            // protobuf: field 1 (addon), wire type 2 (length-delimited)
            buf.push(2 + f.len() as u8);
            buf.push(0x0a);
            buf.push(f.len() as u8);
            buf.extend_from_slice(f.as_bytes());
        }
        _ => buf.push(0), // addon len
    }
    buf.push(cmd);
    buf.extend_from_slice(&dst.port().to_be_bytes());
    if let Some(d) = domain
        .filter(|d| !d.is_empty() && d.len() <= 255 && d.parse::<IpAddr>().is_err())
    {
        buf.push(ATYP_DOMAIN);
        buf.push(d.len() as u8);
        buf.extend_from_slice(d.as_bytes());
        return buf;
    }
    match dst.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf
}

/// Read the VLESS response header `[ver 1B][addon_len 1B][addon]`.
async fn read_vless_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver)
        .await
        .context("vless read response version")?;
    if ver[0] != VLESS_VERSION {
        bail!("vless unexpected response version {}", ver[0]);
    }
    let mut alen = [0u8; 1];
    r.read_exact(&mut alen)
        .await
        .context("vless read addon len")?;
    if alen[0] > 0 {
        let mut addon = vec![0u8; alen[0] as usize];
        r.read_exact(&mut addon)
            .await
            .context("vless read addon")?;
    }
    Ok(())
}

/// Length of the VLESS response header at the start of `buf`, or None if
/// incomplete / invalid (ws path: skipped lazily from the first frame).
pub(crate) fn vless_response_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != VLESS_VERSION {
        return None;
    }
    let n = 2 + buf[1] as usize;
    (buf.len() >= n).then_some(n)
}

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parsing() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u, [0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee]);
        assert!(parse_uuid("nope").is_err());
    }

    #[test]
    fn header_domain_and_ip() {
        let uuid = [7u8; 16];
        let h = build_vless_header(&uuid, Some("example.com"), "1.2.3.4:443".parse().unwrap(), VLESS_CMD_TCP, None);
        // ver + uuid + addon + cmd + port + atyp + len + name
        assert_eq!(h[0], 0);
        assert_eq!(&h[1..17], &uuid);
        assert_eq!(h[17], 0, "addon len");
        assert_eq!(h[18], VLESS_CMD_TCP);
        assert_eq!(&h[19..21], &443u16.to_be_bytes());
        assert_eq!(h[21], ATYP_DOMAIN);
        assert_eq!(h[22], 11);
        assert_eq!(&h[23..], b"example.com");

        // IP-looking "domain" falls through to the bare address.
        let h = build_vless_header(&uuid, Some("1.2.3.4"), "1.2.3.4:80".parse().unwrap(), VLESS_CMD_TCP, None);
        assert_eq!(h[21], ATYP_IPV4);
        assert_eq!(&h[22..], &[1, 2, 3, 4]);

        let h = build_vless_header(&uuid, None, "[::1]:80".parse().unwrap(), VLESS_CMD_UDP, None);
        assert_eq!(h[18], VLESS_CMD_UDP);
        assert_eq!(h[21], ATYP_IPV6);
    }

    #[test]
    fn header_flow_addon() {
        let uuid = [9u8; 16];
        let h = build_vless_header(&uuid, Some("example.com"), "1.2.3.4:443".parse().unwrap(), VLESS_CMD_TCP, Some("xtls-rprx-vision"));
        // addon: [len][0x0a][flen]["xtls-rprx-vision"]
        let flow = b"xtls-rprx-vision";
        assert_eq!(h[17] as usize, 2 + flow.len(), "addon len");
        assert_eq!(h[18], 0x0a, "protobuf field 1, wire type 2");
        assert_eq!(h[19] as usize, flow.len());
        assert_eq!(&h[20..20 + flow.len()], flow);
        // cmd follows the addon
        assert_eq!(h[20 + flow.len()], VLESS_CMD_TCP);
    }

    #[test]
    fn response_len_parser() {
        assert_eq!(vless_response_len(&[0, 0]), Some(2));
        assert_eq!(vless_response_len(&[0, 3, 1, 2, 3]), Some(5));
        assert_eq!(vless_response_len(&[0, 3, 1]), None, "incomplete");
        assert_eq!(vless_response_len(&[1, 0]), None, "bad version");
        assert_eq!(vless_response_len(&[0]), None);
    }

    fn test_cfg(port: u16, network: &str, tls: bool) -> VlessConfig {
        VlessConfig {
            name: "test".into(),
            server: format!("127.0.0.1:{port}"),
            uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            network: network.into(),
            tls,
            sni: "example.com".into(),
            insecure: true,
            ws_path: "/ws".into(),
            ws_host: String::new(),
            flow: String::new(),
            reality_public_key: String::new(),
            reality_short_id: String::new(),
            client_fingerprint: String::new(),
            alpn: String::new(),
            xhttp_host: String::new(),
            xhttp_path: String::new(),
            xhttp_mode: String::new(),
        }
    }

    /// VLESS over plain TCP: header written directly, response header read
    /// eagerly, payload relayed both ways. Header layout:
    /// ver(1)+uuid(16)+addon(1)+cmd(1)+port(2)+atyp(1)+len(1)+domain(11) = 34.
    #[tokio::test]
    async fn vless_tcp_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut s, _) = listener.accept().await.unwrap();
            // 34-byte VLESS request header; the payload ("hello") only
            // follows after the server's response header.
            let mut req = vec![0u8; 34];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0, "vless version");
            assert_eq!(
                &req[1..17],
                &[0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc,
                  0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee]
            );
            assert_eq!(req[17], 0, "addon len");
            assert_eq!(req[18], VLESS_CMD_TCP);
            assert_eq!(req[21], ATYP_DOMAIN);
            s.write_all(&[0u8, 0u8]).await.unwrap();
            s.write_all(b"world").await.unwrap();
            let mut payload = vec![0u8; 5];
            s.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
        });

        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = VlessClient::new(server_addr, &test_cfg(port, "tcp", false)).unwrap();
        let mut s = client
            .connect_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// VLESS over plain WS: header merged into the first (masked) frame,
    /// response header stripped from the first incoming frame.
    #[tokio::test]
    async fn vless_ws_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut s, _) = listener.accept().await.unwrap();
            // Read the upgrade request head.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&req).to_lowercase();
            assert!(head.starts_with("get /ws http/1.1"), "head: {head}");
            assert!(head.contains("upgrade: websocket"), "head: {head}");
            assert!(head.contains("sec-websocket-key: "), "head: {head}");
            assert!(head.contains("host: example.com"), "head: {head}");
            s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: ignored-by-this-client\r\n\
                  \r\n",
            )
            .await
            .unwrap();

            // First client frame: VLESS header (34) + "hello" = 39 payload.
            let frame_len = 2 + 4 + 39; // FIN|opcode + mask|len7 + mask key
            let mut frame = vec![0u8; frame_len];
            s.read_exact(&mut frame).await.unwrap();
            let (op, fin, payload) = decode_client_frame(&frame);
            assert_eq!(op, 0x2, "binary");
            assert!(fin);
            assert_eq!(payload[0], 0, "vless version");
            assert_eq!(&payload[34..], b"hello");

            // Reply: unmasked binary frame with VLESS response header.
            let mut reply = vec![0x82u8, 7];
            reply.extend_from_slice(&[0u8, 0u8]);
            reply.extend_from_slice(b"world");
            s.write_all(&reply).await.unwrap();
        });

        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = VlessClient::new(server_addr, &test_cfg(port, "ws", false)).unwrap();
        let mut s = client
            .connect_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// Unmask a client frame the way a server would.
    fn decode_client_frame(frame: &[u8]) -> (u8, bool, Vec<u8>) {
        let opcode = frame[0] & 0x0f;
        let fin = frame[0] & 0x80 != 0;
        assert!(frame[1] & 0x80 != 0, "client frames must be masked");
        let len7 = (frame[1] & 0x7f) as usize;
        let (len, mut pos) = match len7 {
            126 => (u16::from_be_bytes([frame[2], frame[3]]) as usize, 4),
            127 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&frame[2..10]);
                (u64::from_be_bytes(b) as usize, 10)
            }
            l => (l, 2),
        };
        let key = [frame[pos], frame[pos + 1], frame[pos + 2], frame[pos + 3]];
        pos += 4;
        let payload: Vec<u8> = frame[pos..pos + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        (opcode, fin, payload)
    }

    /// TLS config paths build (SkipVerify / webpki roots); no handshake here.
    #[test]
    fn vless_tls_config_builds() {
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let c = VlessClient::new(server_addr, &test_cfg(1, "tcp", true)).unwrap();
        assert!(c.tls_config.is_some());
        // insecure=false also builds (webpki roots).
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.insecure = false;
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert!(c.tls_config.is_some());
        // Plain tcp: no TLS config.
        let c = VlessClient::new(server_addr, &test_cfg(1, "tcp", false)).unwrap();
        assert!(c.tls_config.is_none());
        // ws forces http/1.1 ALPN.
        let c = VlessClient::new(server_addr, &test_cfg(1, "ws", true)).unwrap();
        assert_eq!(c.tls_config.unwrap().alpn_protocols, vec![b"http/1.1".to_vec()]);
        // Unknown network fails fast.
        assert!(VlessClient::new(server_addr, &test_cfg(1, "grpc", false)).is_err());
    }

    /// REALITY 配置装配：公钥/short id/sni/alpn，network=ws 拒绝，
    /// reality 覆盖 plain rustls 配置。
    #[test]
    fn vless_reality_config_builds() {
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.reality_public_key =
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into();
        cfg.reality_short_id = "0123456789abcdef".into();
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert!(c.reality.is_some());
        assert!(c.tls, "reality implies tls");
        assert!(c.tls_config.is_none(), "reality replaces rustls config");
        assert_eq!(
            c.reality.as_ref().unwrap().server_name.as_deref(),
            Some("example.com")
        );

        // reality + ws → error
        let mut cfg = test_cfg(1, "ws", true);
        cfg.reality_public_key =
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());
    }

    /// 非法 REALITY 公钥在握手时失败（reality_connect 解码），不影响配置装配。
    #[test]
    fn vless_reality_bad_key_deferred() {
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.reality_public_key = "not-base64!".into();
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert!(c.reality.is_some(), "config builds; handshake will fail");
        assert!(reality::decode_x25519_pubkey("not-base64!").is_err());
    }

    /// 流控配置：合法 flow 装配；flow + ws / flow 无 TLS 拒绝。
    #[test]
    fn vless_flow_config() {
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.flow = "xtls-rprx-vision".into();
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert_eq!(c.flow.as_deref(), Some("xtls-rprx-vision"));

        // flow requires tcp
        let mut cfg = test_cfg(1, "ws", true);
        cfg.flow = "xtls-rprx-vision".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());

        // flow requires tls
        let mut cfg = test_cfg(1, "tcp", false);
        cfg.flow = "xtls-rprx-vision".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());

        // unknown flow
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.flow = "xtls-rprx-xudp".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());
    }

    /// uTLS 指纹解析与 xhttp 模式解析。
    #[test]
    fn vless_utls_and_xhttp_mode() {
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut cfg = test_cfg(1, "tcp", true);
        cfg.client_fingerprint = "chrome".into();
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert!(c.utls.is_some());

        let mut cfg = test_cfg(1, "tcp", true);
        cfg.client_fingerprint = "nope".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());

        // xhttp 默认 packet-up（无 reality）
        let cfg = test_cfg(1, "xhttp", true);
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert_eq!(c.xhttp_resolved, XhttpResolved::PacketUp);
        assert!(c.xhttp_h2_tls.is_some(), "h2 tls config built");
        assert_eq!(
            c.xhttp_h2_tls.unwrap().alpn_protocols,
            vec![b"h2".to_vec()]
        );

        // xhttp stream-one + uTLS：rustls http/1.1 配置就绪（wrap_tls 用）
        let mut cfg = test_cfg(1, "xhttp", true);
        cfg.xhttp_mode = "stream-one".into();
        cfg.client_fingerprint = "firefox".into();
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert_eq!(c.xhttp_resolved, XhttpResolved::StreamOne);
        assert!(c.tls_config.is_some());
        assert_eq!(
            c.tls_config.unwrap().alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
        assert!(c.xhttp_h2_tls.is_none());

        // reality + xhttp → auto 解析为 stream-one；显式 packet-up 拒绝
        let mut cfg = test_cfg(1, "xhttp", true);
        cfg.reality_public_key =
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into();
        let c = VlessClient::new(server_addr, &cfg).unwrap();
        assert_eq!(c.xhttp_resolved, XhttpResolved::StreamOne);
        let mut cfg = test_cfg(1, "xhttp", true);
        cfg.reality_public_key =
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into();
        cfg.xhttp_mode = "packet-up".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());

        // 未知 xhttp_mode
        let mut cfg = test_cfg(1, "xhttp", true);
        cfg.xhttp_mode = "grpc".into();
        assert!(VlessClient::new(server_addr, &cfg).is_err());
    }

    /// xhttp path 归一化 + path/query 拆分（对齐 ant 的测试）。
    #[test]
    fn xhttp_path_normalization() {
        assert_eq!(xhttp_h2::split_path_query("/ws?token=abc").0, "/ws/");
        assert_eq!(
            xhttp_h2::split_path_query("/xhttp?token=abc").1,
            "token=abc"
        );
    }

    /// 读取一个 HTTP/1.1 请求头（到 \r\n\r\n），返回 (原始头, 已读缓冲)。
    async fn read_http_head(
        s: &mut tokio::net::TcpStream,
    ) -> (String, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut req = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            if let Some(p) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&req[..p + 4]).to_string();
                return (head, req.split_off(p + 4));
            }
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before head end");
            req.extend_from_slice(&buf[..n]);
        }
    }

    /// 从 socket 累积读取直到 `pattern` 出现在 `body` 中。
    async fn read_until(s: &mut tokio::net::TcpStream, body: &mut Vec<u8>, pattern: &[u8]) {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 2048];
        while !body.windows(pattern.len()).any(|w| w == pattern) {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before pattern");
            body.extend_from_slice(&buf[..n]);
        }
    }

    /// 单 chunk 的 chunked body：去掉第一行大小行，返回后续字节。
    fn first_chunk(body: &[u8]) -> &[u8] {
        let p = body.windows(2).position(|w| w == b"\r\n").unwrap();
        &body[p + 2..]
    }

    /// 校验 VLESS 请求头（34B：ver+uuid+addon+cmd+port+atyp+len+domain）
    /// 紧贴在 payload 的 "hello" 之前。
    fn assert_vless_header_before_hello(payload: &[u8]) {
        let hp = payload
            .windows(5)
            .position(|w| w == b"hello")
            .expect("hello not in payload");
        assert!(hp >= 34, "34-byte vless header must precede hello");
        assert_eq!(payload[hp - 34], 0, "vless version");
        // ver(1)+uuid(16)+addon(1)+cmd(1)+port(2)+atyp(1)+len(1)+domain(11)
        assert_eq!(payload[hp - 16], VLESS_CMD_TCP);
    }

    /// VLESS over xhttp stream-one（明文 HTTP）：单条 POST 双向流。
    /// 请求头并入首个 body 块，响应头从首个响应 chunk 中剥离。
    #[tokio::test]
    async fn vless_xhttp_stream_one_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut s, _) = listener.accept().await.unwrap();
            let (head, rest) = read_http_head(&mut s).await;
            let head_l = head.to_lowercase();
            assert!(head_l.starts_with("post /xhttp http/1.1"), "head: {head}");
            assert!(
                head_l.contains("transfer-encoding: chunked"),
                "head: {head}"
            );
            // 提前应答（合法 HTTP）：chunked 响应体 = VLESS 响应头 + payload。
            s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            let mut chunk = format!("{:x}\r\n", 7).into_bytes();
            chunk.extend_from_slice(&[0u8, 0u8]);
            chunk.extend_from_slice(b"world");
            chunk.extend_from_slice(b"\r\n0\r\n\r\n");
            s.write_all(&chunk).await.unwrap();

            // 读客户端 chunked body（rest 可能已含 body 的前几个字节），
            // 去帧后校验 VLESS 请求头。
            let mut body = rest;
            read_until(&mut s, &mut body, b"hello").await;
            assert_vless_header_before_hello(first_chunk(&body));
        });

        let mut cfg = test_cfg(port, "xhttp", false);
        cfg.xhttp_path = "/xhttp".into();
        cfg.xhttp_mode = "stream-one".into();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = VlessClient::new(server_addr, &cfg).unwrap();
        let mut s = client
            .connect_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// VLESS over xhttp packet-up（明文 HTTP）：GET 长轮询下行 + POST 上行。
    #[tokio::test]
    async fn vless_xhttp_packet_up_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            // 连接 1：GET 下载（长轮询）。
            let (mut d, _) = listener.accept().await.unwrap();
            let (head, _) = read_http_head(&mut d).await;
            assert!(
                head.to_lowercase().starts_with("get /xhttp/"),
                "head: {head}"
            );
            // Content-Length 响应：VLESS 响应头 + payload。
            // Connection: close — 让 hyper 不复用该连接跑 POST 上行，
            // 否则上传会走同一条连接，第二个 accept 永远等不到。
            d.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            d.write_all(&[0u8, 0u8]).await.unwrap();
            d.write_all(b"world").await.unwrap();

            // 连接 2：POST 上行（packet，chunked），body = VLESS 请求头 + "hello"。
            let (mut u, _) = listener.accept().await.unwrap();
            let (head, rest) = read_http_head(&mut u).await;
            let head_l = head.to_lowercase();
            assert!(
                head_l.starts_with("post /xhttp/") && head_l.contains("/0 "),
                "head: {head}"
            );
            let mut body = rest;
            read_until(&mut u, &mut body, b"hello").await;
            assert_vless_header_before_hello(first_chunk(&body));
        });

        let mut cfg = test_cfg(port, "xhttp", false);
        cfg.xhttp_path = "/xhttp".into();
        cfg.xhttp_mode = "packet-up".into();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = VlessClient::new(server_addr, &cfg).unwrap();
        let mut s = client
            .connect_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }
}
