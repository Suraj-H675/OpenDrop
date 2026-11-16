//! Explicit Linux Wi-Fi-only TCP CONNECTOR, independent of the TLS SERVER
//! and logical FILE RECEIVER roles. One connection per owner gesture.
//! No DNS, default-route fallback, wildcard binding or background retries.
use libc::{self, c_void, sockaddr, sockaddr_in, socklen_t};
use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DirectWifiRoute {
    pub interface: String,
    pub source: Ipv4Addr,
    pub peer: SocketAddrV4,
}

impl DirectWifiRoute {
    pub(super) fn validate(&self, test_loopback: bool) -> io::Result<()> {
        let interface = CString::new(self.interface.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        if self.interface.is_empty()
            || self.interface.len() >= libc::IFNAMSIZ
            || self.peer.port() == 0
            || !self
                .interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || (!test_loopback
                && (self.source == *self.peer.ip()
                    || !is_private(self.source)
                    || !is_private(*self.peer.ip())))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not private direct peer",
            ));
        }
        let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        if !test_loopback
            && !std::path::Path::new("/sys/class/net")
                .join(&self.interface)
                .join("wireless")
                .is_dir()
        {
            // A WireGuard/Tailscale VPN or cellular uplink can also have
            // private IPv4 routes. S1-G permits only actual 802.11 NICs.
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "source interface is not a verified Wi-Fi interface",
            ));
        }
        let mut addresses = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
            return Err(io::Error::last_os_error());
        }
        struct FreeIfAddrs(*mut libc::ifaddrs);
        impl Drop for FreeIfAddrs {
            fn drop(&mut self) {
                unsafe {
                    libc::freeifaddrs(self.0);
                }
            }
        }
        let _free = FreeIfAddrs(addresses);
        let mut found = false;
        let mut cursor = addresses;
        while !cursor.is_null() {
            let node = unsafe { &*cursor };
            let same = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }.to_bytes()
                == self.interface.as_bytes();
            if same
                && !node.ifa_addr.is_null()
                && !node.ifa_netmask.is_null()
                && unsafe { (*node.ifa_addr).sa_family } == libc::AF_INET as u16
            {
                let local = unsafe { &*(node.ifa_addr as *const sockaddr_in) };
                let mask = unsafe { &*(node.ifa_netmask as *const sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(local.sin_addr.s_addr));
                let mask = u32::from_be(mask.sin_addr.s_addr);
                let peer = u32::from(*self.peer.ip());
                let source = u32::from(self.source);
                let is_local_route = (peer & mask) == (source & mask) && mask != 0;
                if ip == self.source
                    && is_local_route
                    && (node.ifa_flags & libc::IFF_UP as u32) != 0
                    && (node.ifa_flags & libc::IFF_POINTOPOINT as u32) == 0
                    && (test_loopback || (node.ifa_flags & libc::IFF_LOOPBACK as u32) == 0)
                {
                    found = true;
                }
            }
            cursor = node.ifa_next;
        }
        if !found {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "exact up interface/source/direct peer subnet mismatch",
            ));
        }
        Ok(())
    }
}

fn is_private(addr: Ipv4Addr) -> bool {
    addr.is_private() && !addr.is_loopback() && !addr.is_link_local()
}

fn sockaddr(ip: Ipv4Addr, port: u16) -> sockaddr_in {
    sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    }
}

/// Fail-closed SO_BINDTODEVICE + source IP bind + peer sockname revalidation.
/// Only a specific owner-selected interface, not the default route, may carry
/// even a SYN. Requires kernel permission for SO_BINDTODEVICE: never degrade
/// to an unbound connect() if unavailable.
pub(super) fn connect_exact(
    route: &DirectWifiRoute,
    running: &AtomicBool,
    test_loopback: bool,
) -> io::Result<TcpStream> {
    route.validate(test_loopback)?;
    let device = CString::new(route.interface.as_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad interface"))?;
    let raw = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    struct OwnedFd(RawFd);
    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let mut fd = OwnedFd(raw);
    let bind_device = unsafe {
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast::<c_void>(),
            (device.as_bytes_with_nul().len()) as socklen_t,
        )
    };
    if bind_device != 0 {
        return Err(io::Error::last_os_error());
    }
    let source = sockaddr(route.source, 0);
    if unsafe {
        libc::bind(
            fd.0,
            &source as *const _ as *const sockaddr,
            size_of::<sockaddr_in>() as socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let peer = sockaddr(*route.peer.ip(), route.peer.port());
    let code = unsafe {
        libc::connect(
            fd.0,
            &peer as *const _ as *const sockaddr,
            size_of::<sockaddr_in>() as socklen_t,
        )
    };
    if code != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(io::Error::last_os_error());
    }
    let started = Instant::now();
    loop {
        if !running.load(Ordering::Acquire) || started.elapsed() >= Duration::from_secs(8) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer connect cancelled or expired",
            ));
        }
        let mut poll = libc::pollfd {
            fd: fd.0,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 100) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            continue;
        }
        let mut code = 0i32;
        let mut length = size_of::<i32>() as socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut code as *mut _ as *mut c_void,
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code));
        }
        break;
    }
    let flags = unsafe { libc::fcntl(fd.0, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd.0, libc::F_SETFL, flags & !libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { TcpStream::from_raw_fd(fd.0) };
    fd.0 = -1; // transport now owns the fd
    if stream.local_addr()?
        != SocketAddr::V4(SocketAddrV4::new(route.source, stream.local_addr()?.port()))
        || stream.peer_addr()? != SocketAddr::V4(route.peer)
        || route.validate(test_loopback).is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source or direct subnet changed during connector handshake",
        ));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    #[test]
    fn loopback_reverse_tcp_uses_exact_source_and_server_connector() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let route = DirectWifiRoute {
            interface: "lo".into(),
            source: Ipv4Addr::LOCALHOST,
            peer: SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port()),
        };
        // For hosted tests only allow loopback; production cannot enable it
        // via CLI and must use the exact private interface address.
        assert!(route.validate(false).is_err());
        assert!(route.validate(true).is_ok());
        let running = AtomicBool::new(true);
        let socket = connect_exact(&route, &running, true).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        assert_eq!(
            socket.local_addr().unwrap().ip(),
            std::net::IpAddr::V4(route.source)
        );
        assert_eq!(
            accepted.peer_addr().unwrap().ip(),
            std::net::IpAddr::V4(route.source)
        );
    }
    #[test]
    fn no_nonlocal_or_same_source_destination() {
        let route = DirectWifiRoute {
            interface: "lo".into(),
            source: "10.1.1.2".parse().unwrap(),
            peer: SocketAddrV4::new("8.8.8.8".parse().unwrap(), 43991),
        };
        assert!(route.validate(false).is_err());
    }
}
