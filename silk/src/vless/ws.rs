//! Minimal WebSocket client transport (RFC 6455), following ant's ws.rs
//! design but hand-rolled to keep silk dependency-free:
//!
//! * [`WsStream::connect`] performs the HTTP/1.1 upgrade over an already
//!   established (and, if wanted, TLS-wrapped) byte stream.
//! * [`WsStream`] adapts the connection to `AsyncRead + AsyncWrite`:
//!   - every write becomes one masked binary frame;
//!   - an optional protocol header is merged into the first frame;
//!   - the VLESS response header is stripped from the first incoming frame;
//!   - Ping → Pong answered automatically, Close → EOF.

use super::{vless_response_len, VlessClient};
use crate::outbound::BoxStream;
use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// One parsed frame: (bytes consumed, opcode, fin, payload).
type ParsedFrame = (usize, u8, bool, Vec<u8>);

/// DoS guards (frame / handshake response caps).
const MAX_FRAME: usize = 16 * 1024 * 1024;
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;
const READ_CHUNK: usize = 16 * 1024;

pub struct WsStream {
    io: BoxStream,
    /// Unparsed bytes from the wire.
    raw: BytesMut,
    /// Completed message payload waiting to be delivered.
    msg: BytesMut,
    /// Accumulator for fragmented messages.
    frag: BytesMut,
    eof: bool,
    /// Strip the VLESS response header from the first message.
    response_skipped: bool,
    /// Protocol header merged into the first written frame.
    pending_header: Option<Vec<u8>>,
    /// Fully framed bytes (header+mask+payload) not yet fully written,
    /// plus the offset already accepted by the inner stream.
    out_pending: Option<(Vec<u8>, usize)>,
}

impl WsStream {
    /// Perform the HTTP/1.1 upgrade over `io` using the client's ws options.
    pub async fn connect(mut io: BoxStream, c: &VlessClient) -> Result<Self> {
        let port = c.server.port();
        let default_port = if c.tls { 443 } else { 80 };
        let authority = if port == default_port {
            c.ws_host.clone()
        } else {
            format!("{}:{}", c.ws_host, port)
        };
        // Random 16-byte key, base64 encoded (the accept reply is not
        // verified — a proxy only talks to its own server).
        let key_bytes: [u8; 16] = rand::random();
        let key = b64_encode(&key_bytes);
        let req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             User-Agent: Go-http-client/1.1\r\n\
             \r\n",
            c.ws_path, authority, key
        );
        io.write_all(req.as_bytes())
            .await
            .context("ws write handshake")?;
        io.flush().await.context("ws flush handshake")?;

        // Read until the end of the response head.
        let mut raw = BytesMut::new();
        let head_len = loop {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if raw.len() > MAX_HANDSHAKE_RESPONSE {
                bail!("ws handshake response too large");
            }
            let mut buf = [0u8; 1024];
            let n = io.read(&mut buf).await.context("ws read handshake")?;
            if n == 0 {
                bail!("ws handshake: connection closed");
            }
            raw.extend_from_slice(&buf[..n]);
        };
        let head = &raw[..head_len];
        let first_line = head
            .split(|b| *b == b'\n')
            .next()
            .unwrap_or(b"")
            .to_vec();
        let status = String::from_utf8_lossy(&first_line).trim().to_string();
        if !status.contains(" 101") {
            bail!("ws handshake failed: {status}");
        }
        Ok(Self {
            io,
            raw: raw.split_off(head_len),
            msg: BytesMut::new(),
            frag: BytesMut::new(),
            eof: false,
            response_skipped: false,
            pending_header: None,
            out_pending: None,
        })
    }

    /// Prepend `header` to the first written payload (same frame).
    pub fn with_header(mut self, header: Vec<u8>) -> Self {
        self.pending_header = Some(header);
        self
    }

    /// Try to parse one frame from `raw`. Returns None if more bytes are
    /// needed, Some(Err(..)) on protocol violations.
    fn parse_frame(raw: &[u8]) -> Option<Result<ParsedFrame>> {
        if raw.len() < 2 {
            return None;
        }
        let b0 = raw[0];
        let b1 = raw[1];
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7f) as usize;
        let mut pos = 2;
        let len = match len7 {
            126 => {
                if raw.len() < pos + 2 {
                    return None;
                }
                let l = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
                pos += 2;
                l
            }
            127 => {
                if raw.len() < pos + 8 {
                    return None;
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&raw[pos..pos + 8]);
                pos += 8;
                match usize::try_from(u64::from_be_bytes(b)) {
                    Ok(l) => l,
                    Err(_) => return Some(Err(anyhow::anyhow!("ws frame too large"))),
                }
            }
            l => l,
        };
        if len > MAX_FRAME {
            return Some(Err(anyhow::anyhow!("ws frame too large: {len}")));
        }
        let mask = if masked {
            if raw.len() < pos + 4 {
                return None;
            }
            let m = [raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]];
            pos += 4;
            Some(m)
        } else {
            None
        };
        if raw.len() < pos + len {
            return None;
        }
        let mut payload = raw[pos..pos + len].to_vec();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        Some(Ok((pos + len, opcode, fin, payload)))
    }

    /// Queue a masked control frame for transmission (best effort).
    fn queue_control(&mut self, opcode: u8, payload: &[u8]) {
        if self.out_pending.is_none() {
            self.out_pending = Some((encode_frame(opcode, payload), 0));
        }
        // Busy: drop the control reply; servers re-ping.
    }

    /// Write as much of `out_pending` as the inner stream accepts.
    fn poll_flush_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        while let Some((frame, off)) = self.out_pending.as_mut() {
            match Pin::new(&mut self.io).poll_write(cx, &frame[*off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "ws write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    *off += n;
                    if *off >= frame.len() {
                        self.out_pending = None;
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Encode one client frame (FIN, masked with a fresh random key).
fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.push(0x80 | opcode);
    let len = payload.len();
    if len < 126 {
        f.push(0x80 | len as u8);
    } else if len <= 0xffff {
        f.push(0x80 | 126);
        f.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let key: [u8; 4] = rand::random();
    f.extend_from_slice(&key);
    for (i, b) in payload.iter().enumerate() {
        f.push(b ^ key[i % 4]);
    }
    f
}

fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[((n >> 18) & 63) as usize] as char);
        out.push(TBL[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TBL[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.msg.is_empty() {
                let n = buf.remaining().min(this.msg.len());
                let chunk = this.msg.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                // Nothing filled: EOF per the AsyncRead contract.
                return Poll::Ready(Ok(()));
            }

            match Self::parse_frame(&this.raw) {
                Some(Ok((consumed, opcode, fin, payload))) => {
                    this.raw.advance(consumed);
                    match opcode {
                        OP_CLOSE => {
                            this.eof = true;
                            this.queue_control(
                                OP_CLOSE,
                                &payload[..payload.len().min(125)],
                            );
                        }
                        OP_PING => {
                            this.queue_control(OP_PONG, &payload[..payload.len().min(125)]);
                        }
                        OP_PONG => {}
                        OP_BINARY | OP_TEXT | OP_CONT => {
                            if this.frag.len() + payload.len() > MAX_FRAME {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "ws message too large",
                                )));
                            }
                            this.frag.extend_from_slice(&payload);
                            if fin {
                                this.msg = std::mem::take(&mut this.frag);
                                if !this.response_skipped {
                                    this.response_skipped = true;
                                    match vless_response_len(&this.msg) {
                                        Some(skip) => {
                                            this.msg.advance(skip);
                                        }
                                        None => {
                                            return Poll::Ready(Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                "bad vless response header over ws",
                                            )));
                                        }
                                    }
                                }
                            }
                        }
                        _ => {} // unknown opcode: ignore
                    }
                }
                Some(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e,
                    )));
                }
                None => {
                    // Need more bytes from the wire.
                    let mut tmp = vec![0u8; READ_CHUNK];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.io).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                this.eof = true;
                            } else {
                                this.raw.extend_from_slice(rb.filled());
                            }
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // Drain queued control frames first.
        match this.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        // Merge the VLESS header into the very first payload frame.
        let frame = if let Some(header) = this.pending_header.take() {
            let mut payload = BytesMut::with_capacity(header.len() + data.len());
            payload.put_slice(&header);
            payload.put_slice(data);
            encode_frame(OP_BINARY, &payload)
        } else {
            encode_frame(OP_BINARY, data)
        };
        match Pin::new(&mut this.io).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) if n >= frame.len() => Poll::Ready(Ok(data.len())),
            Poll::Ready(Ok(n)) => {
                this.out_pending = Some((frame, n));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.out_pending = Some((frame, 0));
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unmask a client frame the way a server would.
    fn decode_client_frame(frame: &[u8]) -> (u8, bool, Vec<u8>) {
        let opcode = frame[0] & 0x0f;
        let fin = frame[0] & 0x80 != 0;
        assert!(frame[1] & 0x80 != 0, "client frames must be masked");
        let len7 = (frame[1] & 0x7f) as usize;
        let (len, mut pos) = match len7 {
            126 => (
                u16::from_be_bytes([frame[2], frame[3]]) as usize,
                4,
            ),
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

    #[test]
    fn frame_roundtrip() {
        let f = encode_frame(OP_BINARY, b"hello world");
        let (op, fin, payload) = decode_client_frame(&f);
        assert_eq!(op, OP_BINARY);
        assert!(fin);
        assert_eq!(payload, b"hello world");

        // 16-bit length
        let big = vec![0xabu8; 300];
        let f = encode_frame(OP_BINARY, &big);
        let (op, _, payload) = decode_client_frame(&f);
        assert_eq!(op, OP_BINARY);
        assert_eq!(payload, big);
    }

    #[test]
    fn parse_server_frame() {
        let parse = |raw: &[u8]| WsStream::parse_frame(raw);
        // Unmasked server frame: FIN binary "abc".
        let raw = [0x82u8, 0x03, b'a', b'b', b'c'];
        let (n, op, fin, payload) = parse(&raw).unwrap().unwrap();
        assert_eq!(n, 5);
        assert_eq!(op, OP_BINARY);
        assert!(fin);
        assert_eq!(payload, b"abc");

        // Incomplete → None.
        assert!(parse(&raw[..4]).is_none());

        // Masked server frame (non-compliant servers): unmasked correctly.
        let raw = [0x82u8, 0x80 | 3, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2, b'c' ^ 3];
        let (_, _, _, payload) = parse(&raw).unwrap().unwrap();
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn b64_matches_std_encoding() {
        // RFC 4648 test vectors.
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }
}
