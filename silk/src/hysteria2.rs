//! Hysteria2 outbound (protocol frames aligned with the official
//! hysteria2 / sing-box implementation; raw HTTP/3 auth without the `h3`
//! crate, following ant's client).
//!
//! Every socket this module dials is control-plane marked so the eBPF
//! datapath never loops on it.

mod hy2_codec;
mod hy2_h3;

use crate::datapath::mark_global_control;
use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use hy2_codec::{Defragger, HysUdpPacket, encode_varint, fragment_packet};
use hy2_h3::{
    H3_FRAME_DATA, H3_FRAME_HEADERS, open_h3_control_streams, parse_headers_from_qpack,
    put_literal_header, random_padding, read_h3_frame, read_varint_async, write_h3_frame,
};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::io;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Fixed 10s, matching sing-box / reflex.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_COOLDOWN: Duration = Duration::from_secs(3);
const HYSTERIA_STATUS_OK: u16 = 233;

/// QUIC initial stream receive window (sing-box hysteria/protocol.go).
const QUIC_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
/// QUIC connection-level max receive window (sing-box).
const QUIC_MAX_CONNECTION_RECEIVE_WINDOW: u64 = 20 * 1024 * 1024;
/// Brutal approximation: RTT estimate used to pre-size the BBR initial window.
const BRUTAL_APPROX_INITIAL_RTT_MS: u64 = 100;
/// DoS guards on response fields (official protocol maxima).
const MAX_MESSAGE_LENGTH: u64 = 2048;
const MAX_PADDING_LENGTH: u64 = 4096;

/// Parse a bandwidth string (`"100 Mbps"`, `"50mbps"`, `"80"`) to integer
/// Mbps; 0 means "auto / unset" (use plain congestion control).
fn parse_bandwidth_mbps(s: &str) -> u64 {
    let t = s.trim().to_lowercase();
    if t.is_empty() || t == "auto" {
        return 0;
    }
    let num: String = t
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num.parse::<f64>().map(|v| v as u64).unwrap_or(0)
}

/// Results negotiated during the Hysteria2 auth handshake.
#[derive(Debug, Clone)]
struct AuthInfo {
    udp_enabled: bool,
    /// Effective tx bandwidth (bps); 0 = no Brutal-style pacing.
    tx_bps: u64,
}

pub struct Hysteria2Client {
    server: SocketAddr,
    password: String,
    sni: String,
    udp_mtu: usize,
    up_mbps: u64,
    down_mbps: u64,
    endpoint: Endpoint,
    state: tokio::sync::Mutex<ConnState>,
    next_session_id: AtomicU32,
}

struct ConnState {
    conn: Option<Arc<Hy2Conn>>,
    last_fail: Option<(std::time::Instant, String)>,
}

struct Hy2Conn {
    quic: Connection,
    support_udp: bool,
    /// session_id → per-session inbound channel + fragment reassembler.
    sessions: Arc<StdMutex<std::collections::HashMap<u32, UdpSessionEntry>>>,
    udp_mtu: usize,
}

struct UdpSessionEntry {
    /// Outbound leg of the datagram router. Dispatched with `try_send`
    /// (drop-on-full) so a slow consumer cannot stall the shared reader.
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    defrag: Defragger,
}

impl Hysteria2Client {
    pub fn new(
        server: SocketAddr,
        password: String,
        sni: String,
        insecure: bool,
        up: &str,
        down: &str,
    ) -> Result<Self> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok(); // already installed is fine

        let sni = if sni.is_empty() {
            server.ip().to_string()
        } else {
            sni
        };
        let opts = QuicOpts {
            insecure,
            up_mbps: parse_bandwidth_mbps(up),
            down_mbps: parse_bandwidth_mbps(down),
        };
        let client_config = build_quic_config(&opts)?;

        // Control-plane marked UDP socket for the QUIC endpoint: the datapath
        // must never capture our own tunnel traffic.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            bail!("socket: {}", std::io::Error::last_os_error());
        }
        mark_global_control(fd)?;
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_sock,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            server,
            password,
            sni,
            udp_mtu: 1200,
            up_mbps: opts.up_mbps,
            down_mbps: opts.down_mbps,
            endpoint,
            state: tokio::sync::Mutex::new(ConnState {
                conn: None,
                last_fail: None,
            }),
            next_session_id: AtomicU32::new(1),
        })
    }

    async fn ensure_conn(&self) -> Result<Arc<Hy2Conn>> {
        let mut guard = self.state.lock().await;
        if let Some(ref c) = guard.conn {
            if c.quic.close_reason().is_none() {
                return Ok(c.clone());
            }
            guard.conn = None;
        }

        if let Some((when, msg)) = &guard.last_fail {
            let elapsed = when.elapsed();
            if elapsed < RECONNECT_COOLDOWN {
                bail!(
                    "hysteria2 unavailable (retry in {}ms): {}",
                    (RECONNECT_COOLDOWN - elapsed).as_millis(),
                    msg
                );
            }
        }

        match self.connect_once().await {
            Ok(conn) => {
                guard.conn = Some(conn.clone());
                guard.last_fail = None;
                Ok(conn)
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!("hysteria2 connect failed: {msg}");
                guard.last_fail = Some((std::time::Instant::now(), msg.clone()));
                Err(anyhow!(msg))
            }
        }
    }

    async fn connect_once(&self) -> Result<Arc<Hy2Conn>> {
        tracing::debug!(server = %self.server, sni = %self.sni, "hysteria2 connecting");

        let connecting = self
            .endpoint
            .connect(self.server, &self.sni)
            .context("quic connect start")?;

        let quic = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| anyhow!("quic handshake timeout ({}s)", HANDSHAKE_TIMEOUT.as_secs()))?
            .context("quic handshake")?;

        // ── Accept server uni streams (H3 control / SETTINGS) ───────────────
        // quic-go/http3 opens its control stream immediately after the
        // handshake. If the client never reads it, server-side flow control
        // fills up and the server stops processing requests.
        {
            let conn_bg = quic.clone();
            tokio::spawn(async move {
                for _ in 0..8 {
                    match tokio::time::timeout(Duration::from_secs(5), conn_bg.accept_uni()).await {
                        Ok(Ok(mut stream)) => {
                            let c = conn_bg.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let _ = stream.read(&mut buf).await;
                                c.closed().await;
                                drop(stream);
                            });
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            });
        }

        let auth = self.auth(&quic).await?;
        tracing::debug!(
            "hysteria2 authenticated (udp={}, tx_bps={})",
            auth.udp_enabled,
            auth.tx_bps
        );

        let mtu = self
            .udp_mtu
            .min(quic.max_datagram_size().unwrap_or(self.udp_mtu));

        let conn = Arc::new(Hy2Conn {
            quic: quic.clone(),
            support_udp: auth.udp_enabled,
            sessions: Arc::new(StdMutex::new(std::collections::HashMap::new())),
            udp_mtu: mtu,
        });

        // ── Single datagram reader / router ─────────────────────────────────
        {
            let conn_rx = conn.clone();
            tokio::spawn(async move {
                loop {
                    match conn_rx.quic.read_datagram().await {
                        Ok(pkt) => route_incoming_datagram(&conn_rx, pkt),
                        Err(e) => {
                            tracing::warn!("hy2 datagram loop end: {e}");
                            break;
                        }
                    }
                }
            });
        }

        Ok(conn)
    }

    /// Hysteria2 auth handshake: raw HTTP/3 POST https://hysteria/auth.
    async fn auth(&self, conn: &Connection) -> Result<AuthInfo> {
        open_h3_control_streams(conn)
            .await
            .context("open h3 control streams")?;

        let (mut send, mut recv) = conn.open_bi().await.context("open auth bi stream")?;

        // Client-advertised downlink (tells the server how much we can receive).
        let rx_bps: u64 = self.down_mbps * 1_000_000;

        let mut qpack = BytesMut::new();
        qpack.extend_from_slice(&[0x00, 0x00]); // Required Insert Count=0, Delta Base=0
        put_literal_header(&mut qpack, b":method", b"POST");
        put_literal_header(&mut qpack, b":scheme", b"https");
        put_literal_header(&mut qpack, b":authority", b"hysteria");
        put_literal_header(&mut qpack, b":path", b"/auth");
        put_literal_header(&mut qpack, b"hysteria-auth", self.password.as_bytes());
        put_literal_header(&mut qpack, b"hysteria-cc-rx", rx_bps.to_string().as_bytes());
        put_literal_header(
            &mut qpack,
            b"hysteria-padding",
            random_padding(256, 2048).as_bytes(),
        );

        let mut frame = BytesMut::new();
        write_h3_frame(&mut frame, 0x01, &qpack); // H3 HEADERS
        send.write_all(&frame)
            .await
            .map_err(|e| anyhow!("hy2 auth send: {e}"))?;
        send.finish().map_err(|e| anyhow!("hy2 auth finish: {e}"))?;

        // Read the response; quic-go may interleave DATA frames, skip them.
        let headers = loop {
            let (frame_type, payload) = read_h3_frame(&mut recv)
                .await
                .context("hy2 auth read frame")?;
            match frame_type {
                H3_FRAME_HEADERS => {
                    break parse_headers_from_qpack(&payload).context("hy2 auth qpack")?;
                }
                H3_FRAME_DATA => continue,
                other => bail!("hy2 auth: unexpected H3 frame type 0x{other:02x}"),
            }
        };

        let get_header = |name: &str| -> Option<&str> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };

        let status: u16 = get_header(":status")
            .unwrap_or("")
            .parse()
            .map_err(|_| anyhow!("hy2 auth: invalid :status"))?;
        if status != HYSTERIA_STATUS_OK {
            bail!("hy2 auth failed: status {status}");
        }

        let udp_enabled = get_header("hysteria-udp")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let tx_bps = {
            let local_tx = self.up_mbps * 1_000_000;
            let server_rx: u64 = match get_header("hysteria-cc-rx") {
                Some(v) if v.eq_ignore_ascii_case("auto") => u64::MAX,
                Some(v) => v.parse().unwrap_or(0),
                None => 0,
            };
            if local_tx == 0 {
                0
            } else if server_rx == 0 {
                local_tx
            } else {
                local_tx.min(server_rx)
            }
        };

        Ok(AuthInfo {
            udp_enabled,
            tx_bps,
        })
    }

    async fn open_tcp_stream(&self, target: &str) -> Result<Hy2TcpStream> {
        let conn = self.ensure_conn().await?;
        let (mut send, mut recv) = conn.quic.open_bi().await.context("open bi stream")?;

        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 0x401);
        encode_varint(&mut buf, target.len() as u64);
        buf.extend_from_slice(target.as_bytes());
        let pad = random_padding(64, 512);
        encode_varint(&mut buf, pad.len() as u64);
        buf.extend_from_slice(pad.as_bytes());
        send.write_all(&buf)
            .await
            .map_err(|e| anyhow!("hy2 tcp write header: {e}"))?;

        let status = recv.read_u8().await.context("read tcp status")?;
        let msg_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(msg_len <= MAX_MESSAGE_LENGTH, "hy2 response: msg too long");
        if msg_len > 0 {
            let mut msg = vec![0u8; msg_len as usize];
            recv.read_exact(&mut msg).await.context("read tcp msg")?;
            if status != 0 {
                bail!(
                    "hysteria2 tcp open failed status={status} msg={}",
                    String::from_utf8_lossy(&msg)
                );
            }
        } else if status != 0 {
            bail!("hysteria2 tcp open failed status={status}");
        }
        let pad_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(
            pad_len <= MAX_PADDING_LENGTH,
            "hy2 response: padding too long"
        );
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len as usize];
            recv.read_exact(&mut pad_buf)
                .await
                .context("read tcp resp padding")?;
        }

        Ok(Hy2TcpStream { send, recv })
    }

    /// Dial a TCP connection through the hysteria2 server.
    pub async fn connect_tcp(&self, dst: SocketAddr, domain: Option<&str>) -> Result<Hy2TcpStream> {
        let addr = match domain {
            Some(d) if !d.is_empty() => format!("{d}:{}", dst.port()),
            _ => dst.to_string(),
        };
        self.open_tcp_stream(&addr).await
    }

    /// Open a UDP relay session (QUIC-datagram based).
    pub async fn udp_session(self: &Arc<Self>) -> Result<UdpSession> {
        let conn = self.ensure_conn().await?;
        if !conn.support_udp {
            bail!("hysteria2 server does not support UDP");
        }
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(64);
        conn.sessions.lock().unwrap().insert(
            session_id,
            UdpSessionEntry {
                tx,
                defrag: Defragger::default(),
            },
        );
        Ok(UdpSession {
            conn,
            session_id,
            pkt_id: AtomicU16::new(0),
            rx: tokio::sync::Mutex::new(rx),
        })
    }
}

struct QuicOpts {
    insecure: bool,
    up_mbps: u64,
    down_mbps: u64,
}

/// Route one inbound QUIC datagram to its UDP session (synchronous, no await).
fn route_incoming_datagram(conn: &Hy2Conn, pkt: Bytes) {
    let mut buf: BytesMut = pkt.into();
    let Ok(decoded) = HysUdpPacket::decode(&mut buf) else {
        return;
    };
    let mut sessions = conn.sessions.lock().unwrap();
    let Some(entry) = sessions.get_mut(&decoded.session_id) else {
        tracing::debug!("hy2 udp session not found: {}", decoded.session_id);
        return;
    };
    if let Some(full) = entry.defrag.feed(decoded) {
        let src = parse_addr_str(&full.addr).unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let _ = entry.tx.try_send((full.data, src));
    }
}

fn parse_addr_str(s: &str) -> Option<SocketAddr> {
    s.parse().ok().or_else(|| {
        let (h, p) = s.rsplit_once(':')?;
        let port: u16 = p.parse().ok()?;
        let ip: std::net::IpAddr = h.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    })
}

pub struct UdpSession {
    conn: Arc<Hy2Conn>,
    session_id: u32,
    pkt_id: AtomicU16,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl UdpSession {
    /// `domain` replaces the IP in the wire address so the server resolves it.
    pub async fn send(&self, data: &[u8], dst: SocketAddr, domain: Option<&str>) -> Result<()> {
        let addr_str = match domain {
            Some(d) => format!("{d}:{}", dst.port()),
            None => dst.to_string(),
        };
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        let max_pkt = self
            .conn
            .quic
            .max_datagram_size()
            .unwrap_or(self.conn.udp_mtu)
            .min(self.conn.udp_mtu);
        for frag in fragment_packet(self.session_id, pkt_id, &addr_str, max_pkt, data) {
            self.conn
                .quic
                .send_datagram(frag)
                .map_err(|e| anyhow!("send datagram: {e}"))?;
        }
        Ok(())
    }

    /// Receive one relayed datagram, copying it into `buf`; returns its length.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.rx.lock().await;
        let (data, _src) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("hy2 udp session closed"))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.conn.sessions.lock().unwrap().remove(&self.session_id);
    }
}

pub struct Hy2TcpStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for Hy2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        <RecvStream as AsyncRead>::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for Hy2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        <SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        <SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        <SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Build the QUIC client config (TLS + transport + congestion control).
fn build_quic_config(opts: &QuicOpts) -> Result<ClientConfig> {
    let crypto = if opts.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let mut crypto = crypto;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.enable_sni = true;

    let mut transport = TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u64(QUIC_STREAM_RECEIVE_WINDOW).unwrap());
    transport.receive_window(quinn::VarInt::from_u64(QUIC_MAX_CONNECTION_RECEIVE_WINDOW).unwrap());
    transport.send_window(QUIC_MAX_CONNECTION_RECEIVE_WINDOW);
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        if opts.up_mbps > 0 {
            let brutal_cwnd =
                (opts.up_mbps * 1_000_000 / 8 / 1000 * BRUTAL_APPROX_INITIAL_RTT_MS).max(1024);
            tracing::debug!(
                "hy2: BBR with Brutal-like initial window ({} bytes, up={}Mbps)",
                brutal_cwnd,
                opts.up_mbps
            );
            let mut bbr = quinn::congestion::BbrConfig::default();
            bbr.initial_window(brutal_cwnd);
            Arc::new(bbr)
        } else {
            Arc::new(quinn::congestion::BbrConfig::default())
        };
    transport.congestion_controller_factory(cc_factory);

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("build quic client config")?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// TLS cert verifier that accepts any certificate (insecure=true only).
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
