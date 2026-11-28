//! Raw bpf(2) helpers for operations aya does not expose or that are simpler
//! at the syscall level: sk_storage marking of control-plane sockets.

use anyhow::Result;
use std::os::fd::{AsRawFd, RawFd};

const BPF_MAP_UPDATE_ELEM: i64 = 2;

/// Kernel contract for BPF_MAP_TYPE_SK_STORAGE updates
/// (net/core/bpf_sk_storage.c: bpf_fd_sk_storage_update_elem):
/// `key` points to an int holding the target socket fd, `value` points to a
/// buffer of the map's value_size, and `flags` takes plain map flags —
/// BPF_ANY (0) creates the storage or overwrites it. The program-side
/// BPF_SK_STORAGE_GET_F_CREATE flag is NOT valid in this path; the kernel
/// rejects any flags > BPF_EXIST with EINVAL.
pub fn mark_control_socket(sk_storage_map_fd: RawFd, sock_fd: RawFd) -> Result<()> {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let key: i32 = sock_fd;
    let value: u32 = 1; // SK_IDENTITY stores u32
    let attr = Attr {
        map_fd: sk_storage_map_fd as u32,
        pad: 0,
        key: &key as *const i32 as u64,
        value: &value as *const u32 as u64,
        flags: 0, // BPF_ANY
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const Attr,
            std::mem::size_of::<Attr>(),
        )
    };
    if rc < 0 {
        return Err(anyhow::anyhow!(
            "sk_storage update failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Set SO_MARK on a socket so egress skbs carry CONTROL_MARK.
pub fn set_socket_mark(fd: RawFd, mark: u32) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "SO_MARK failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn fd_as_raw<F: AsRawFd>(f: &F) -> RawFd {
    f.as_raw_fd()
}

// ---------------------------------------------------------------------------
// connect(2) that bypasses bionic's libnetd_client hook.
//
// On Android, libc `connect()` is routed through netd's fwmarkd. For sockets
// carrying our control-plane SO_MARK that path fails with ENETUNREACH (TCP
// dials and connected UDP sockets alike), while hook-free calls such as
// sendto/sendmsg are fine. The datapath needs the mark to reach the kernel's
// route lookup untouched, so every control-marked socket connects with the raw
// syscall. On desktop Linux the syscall is identical to libc's connect().
// ---------------------------------------------------------------------------

/// Raw `connect` syscall on `fd` (non-blocking sockets return EINPROGRESS).
pub fn raw_connect(fd: RawFd, addr: &std::net::SocketAddr) -> std::io::Result<()> {
    let rc = unsafe {
        match addr {
            std::net::SocketAddr::V4(a) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: a.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) },
                    sin_zero: [0; 8],
                };
                libc::syscall(
                    libc::SYS_connect,
                    fd as libc::c_long,
                    &sin as *const libc::sockaddr_in as libc::c_long,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::c_long,
                )
            }
            std::net::SocketAddr::V6(a) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: a.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
                    sin6_scope_id: a.scope_id(),
                };
                libc::syscall(
                    libc::SYS_connect,
                    fd as libc::c_long,
                    &sin6 as *const libc::sockaddr_in6 as libc::c_long,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::c_long,
                )
            }
        }
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Drop-in for `TcpSocket::connect` that uses [`raw_connect`].
pub async fn tcp_connect(
    sock: tokio::net::TcpSocket,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let fd = sock.into_raw_fd();
    // Own the fd right away so every error path closes it.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    match raw_connect(fd, &addr) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }
    let stream = tokio::net::TcpStream::from_std(std_stream)?;
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(stream)
}

/// Drop-in for `UdpSocket::connect` that uses [`raw_connect`].
pub fn udp_connect(sock: &tokio::net::UdpSocket, addr: std::net::SocketAddr) -> std::io::Result<()> {
    raw_connect(sock.as_raw_fd(), &addr)
}
