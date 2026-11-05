//! Transparent TCP/UDP listeners created inside `silkns` and published into
//! the LISTEN_SOCKETS sockmap that the sk_lookup program assigns packets to.

use crate::ns::with_silkns;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

pub const IP_TRANSPARENT: i32 = 19;
pub const IPV6_TRANSPARENT: i32 = 75;
pub const IP_RECVORIGDSTADDR: i32 = 20;
pub const IPV6_RECVORIGDSTADDR: i32 = 74;

pub struct Listeners {
    pub tcp4: tokio::net::TcpListener,
    /// Blocking socket: consumed by a dedicated recv thread (see relay).
    pub udp4: std::net::UdpSocket,
    #[allow(dead_code)]
    pub tcp6: Option<tokio::net::TcpListener>,
    #[allow(dead_code)]
    pub udp6: Option<std::net::UdpSocket>,
}

/// Create transparent listeners inside `silkns` and register their fds in the
/// sockmap. Returns the tokio handles for the control plane.
pub fn create(dp: &mut crate::datapath::Datapath, has_v6: bool) -> Result<Listeners> {
    let (tcp4_fd, udp4_fd) = with_silkns(|| Ok((tcp_listen4()?, udp_listen4()?)))?;
    let (tcp6_fd, udp6_fd) = if has_v6 {
        with_silkns(|| Ok((Some(tcp_listen6()?), Some(udp_listen6()?))))?
    } else {
        (None, None)
    };

    // TCP fds go to tokio and must be non-blocking. UDP fds stay blocking:
    // they are read by a dedicated thread (recvmsg with RECVORIGDSTADDR has
    // no tokio equivalent).
    for fd in std::iter::once(tcp4_fd).chain(tcp6_fd.iter().map(|f| f.as_raw_fd())) {
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    }

    dp.publish_listener(0, tcp4_fd)?;
    dp.publish_listener(2, udp4_fd)?;
    if let Some(fd) = tcp6_fd.as_ref().map(|f| f.as_raw_fd()) {
        dp.publish_listener(1, fd)?;
    }
    if let Some(fd) = udp6_fd.as_ref().map(|f| f.as_raw_fd()) {
        dp.publish_listener(3, fd)?;
    }

    let tcp4 = tokio::net::TcpListener::from_std(from_raw_tcp(tcp4_fd))?;
    let udp4 = from_raw_udp(udp4_fd);
    let tcp6 = match tcp6_fd {
        Some(fd) => Some(tokio::net::TcpListener::from_std(from_raw_tcp(fd))?),
        None => None,
    };
    let udp6 = udp6_fd.map(from_raw_udp);
    Ok(Listeners {
        tcp4,
        udp4,
        tcp6,
        udp6,
    })
}

fn set_transparent(fd: std::os::fd::RawFd, v6: bool) -> Result<()> {
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, IP_TRANSPARENT)
    };
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        anyhow::bail!("IP_TRANSPARENT: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn tcp_listen4() -> Result<std::os::fd::RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!("socket: {}", std::io::Error::last_os_error());
    }
    set_transparent(fd, false)?;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1i32 as *const _ as *const libc::c_void,
            4,
        )
    };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if rc != 0 {
        anyhow::bail!("bind tcp4: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, 256) } != 0 {
        anyhow::bail!("listen: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn tcp_listen6() -> Result<std::os::fd::RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!("socket6: {}", std::io::Error::last_os_error());
    }
    set_transparent(fd, true)?;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &1i32 as *const _ as *const libc::c_void,
            4,
        )
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1i32 as *const _ as *const libc::c_void,
            4,
        )
    };
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };
    if rc != 0 {
        anyhow::bail!("bind tcp6: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, 256) } != 0 {
        anyhow::bail!("listen6: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn udp_listen4() -> Result<std::os::fd::RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        anyhow::bail!("socket: {}", std::io::Error::last_os_error());
    }
    set_transparent(fd, false)?;
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            4,
        )
    };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if rc != 0 {
        anyhow::bail!("bind udp4: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn udp_listen6() -> Result<std::os::fd::RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        anyhow::bail!("socket6: {}", std::io::Error::last_os_error());
    }
    set_transparent(fd, true)?;
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            4,
        )
    };
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };
    if rc != 0 {
        anyhow::bail!("bind udp6: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn from_raw_tcp(fd: std::os::fd::RawFd) -> std::net::TcpListener {
    unsafe { std::net::TcpListener::from_raw_fd(fd) }
}

fn from_raw_udp(fd: std::os::fd::RawFd) -> std::net::UdpSocket {
    unsafe { std::net::UdpSocket::from_raw_fd(fd) }
}

use std::os::fd::FromRawFd;

/// Address of the original destination for an accepted transparent TCP conn.
pub fn orig_dst_tcp(conn: &tokio::net::TcpStream) -> Result<SocketAddr> {
    conn.local_addr().context("getsockname orig dst")
}

/// Create a UDP socket inside `silkns` bound to an original destination, so
/// datagrams sent from it look like replies from the original target.
pub fn create_reply_socket(orig: SocketAddr) -> Result<tokio::net::UdpSocket> {
    let fd = with_silkns(|| {
        // The sockaddr must outlive the bind() call: declare the storage
        // here, not inside the match arms (a pointer to an arm-local would
        // dangle and bind() then fails with EAFNOSUPPORT at random).
        let sin: libc::sockaddr_in;
        let sin6: libc::sockaddr_in6;
        let (family, ptr, len) = match orig {
            SocketAddr::V4(a) => {
                sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: a.port().to_be(),
                    // s_addr is a memory-layout field: octets() is already
                    // network order.
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(a.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                (
                    libc::AF_INET,
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            }
            SocketAddr::V6(a) => {
                sin6 = sockaddr6_from(&a);
                (
                    libc::AF_INET6,
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32,
                )
            }
        };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            anyhow::bail!("reply socket: {}", std::io::Error::last_os_error());
        }
        set_transparent(fd, family == libc::AF_INET6)?;
        // Two concurrent flows may target the same orig dst; this socket is
        // send-only, so reuse is safe and prevents EADDRINUSE.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &1i32 as *const _ as *const libc::c_void,
                4,
            )
        };
        if unsafe { libc::bind(fd, ptr, len) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            anyhow::bail!("bind reply socket: {err}");
        }
        Ok(fd)
    })?;
    unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    Ok(tokio::net::UdpSocket::from_std(from_raw_udp(fd))?)
}

fn sockaddr6_from(a: &std::net::SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: a.port().to_be(),
        sin6_flowinfo: a.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: a.ip().octets(),
        },
        sin6_scope_id: a.scope_id(),
    }
}
