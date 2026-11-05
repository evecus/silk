//! Minimal SOCKS5 client: TCP CONNECT and UDP ASSOCIATE (RFC 1928).
//! Dial sockets are pre-marked by the caller so the datapath passes them.

use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub struct Socks5Client {
    pub server: SocketAddr,
    pub username: String,
    pub password: String,
}

impl Socks5Client {
    /// SOCKS5 CONNECT, returns the established stream.
    pub async fn connect_tcp(&self, dst: SocketAddr, domain: Option<&str>) -> Result<TcpStream> {
        let mut stream = self.dial().await?;
        handshake(&mut stream, self).await?;
        // Request: VER=5 CMD=CONNECT RSV=0 ATYP/ADDR/PORT
        let mut req = vec![5u8, 1, 0];
        match domain {
            // ATYP 3: length-prefixed domain name (<= 255 bytes).
            Some(d) if !d.is_empty() && d.len() <= 255 => {
                req.push(3);
                req.push(d.len() as u8);
                req.extend_from_slice(d.as_bytes());
                req.extend_from_slice(&dst.port().to_be_bytes());
            }
            _ => push_addr(&mut req, dst),
        }
        stream.write_all(&req).await?;
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;
        if reply[1] != 0 {
            return Err(anyhow!("SOCKS5 CONNECT failed, code {}", reply[1]));
        }
        skip_addr(&mut stream).await?;
        Ok(stream)
    }

    /// SOCKS5 UDP ASSOCIATE: control connection plus the relay endpoint.
    /// Caller must keep `control` alive for the lifetime of the UDP flow.
    pub async fn associate_udp(self: &Arc<Self>) -> Result<(TcpStream, UdpSocket)> {
        let mut control = self.dial().await?;
        handshake(&mut control, self).await?;
        // BIND addr 0.0.0.0:0 — server picks the relay endpoint.
        let req = [5u8, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        control.write_all(&req).await?;
        let mut reply = [0u8; 4];
        control.read_exact(&mut reply).await?;
        if reply[1] != 0 {
            return Err(anyhow!("SOCKS5 UDP ASSOCIATE failed, code {}", reply[1]));
        }
        let bnd = read_addr(&mut control).await?;

        let udp = self.new_udp_socket()?;
        let relay = match bnd {
            SocketAddr::V4(a) if a.ip().is_unspecified() => {
                SocketAddr::new(self.server.ip(), a.port())
            }
            other => other,
        };
        // "Connect" fixes the peer so send/recv stay on the relay endpoint.
        udp.connect(relay).await?;
        Ok((control, udp))
    }

    pub fn new_udp_socket(&self) -> Result<UdpSocket> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            anyhow::bail!("socket: {}", std::io::Error::last_os_error());
        }
        crate::datapath::mark_global_control(fd)?;
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        Ok(UdpSocket::from_std(std_sock)?)
    }

    pub fn new_tcp_socket(&self) -> Result<TcpSocket> {
        let sock = TcpSocket::new_v4()?;
        crate::datapath::mark_global_control(sock.as_raw_fd())?;
        Ok(sock)
    }

    async fn dial(&self) -> Result<TcpStream> {
        let sock = self.new_tcp_socket()?;
        sock.connect(self.server)
            .await
            .context("dial SOCKS5 server")
    }
}

async fn handshake(stream: &mut TcpStream, client: &Socks5Client) -> Result<()> {
    let methods: &[u8] = if client.username.is_empty() {
        &[5, 1, 0] // no-auth
    } else {
        &[5, 2, 0, 2] // no-auth + user/pass
    };
    stream.write_all(methods).await?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await?;
    if chosen[0] != 5 {
        return Err(anyhow!("bad SOCKS5 version {}", chosen[0]));
    }
    match chosen[1] {
        0 => {}
        2 => {
            let mut auth = Vec::with_capacity(3 + client.username.len() + client.password.len());
            auth.push(1);
            auth.push(client.username.len() as u8);
            auth.extend_from_slice(client.username.as_bytes());
            auth.push(client.password.len() as u8);
            auth.extend_from_slice(client.password.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0 {
                return Err(anyhow!("SOCKS5 auth failed"));
            }
        }
        other => return Err(anyhow!("SOCKS5 server chose method {other}")),
    }
    Ok(())
}

fn push_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
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

async fn read_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        1 => {
            let mut o = [0u8; 6];
            stream.read_exact(&mut o).await?;
            let ip = std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]);
            Ok(SocketAddr::new(ip.into(), u16::from_be_bytes([o[4], o[5]])))
        }
        4 => {
            let mut o = [0u8; 18];
            stream.read_exact(&mut o).await?;
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&o[0..16]).unwrap());
            Ok(SocketAddr::new(ip.into(), u16::from_be_bytes([o[16], o[17]])))
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let host = String::from_utf8_lossy(&name).to_string();
            let addr = tokio::net::lookup_host((host.as_str(), u16::from_be_bytes(port)))
                .await
                .context("resolve BND.ADDR")?
                .next()
                .context("empty BND.ADDR")?;
            Ok(addr)
        }
        other => Err(anyhow!("bad ATYP {other}")),
    }
}

async fn skip_addr(stream: &mut TcpStream) -> Result<()> {
    read_addr(stream).await.map(|_| ())
}
