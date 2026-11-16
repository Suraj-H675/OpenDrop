//! Source-bound near-peer discovery and transport, with no IP/interface
//! questions for the normal Linux receiver journey. This uses the same
//! bounded LAN broadcast announcement pattern as LocalSend, but never
//! adopts an advertised device as trusted. A discovered peer must complete
//! original RPK TLS, owner SAS and exact-file consent.
//!
//! The narrow D-147 implementation supports one unique private physical
//! Ethernet/Wi-Fi link per foreground session. VPN, cellular, USB, virtual
//! interfaces, multiple ambiguous links and unsupported containers fail
//! closed rather than silently selecting the default route.
use super::reverse_tcp::{connect_exact, DirectWifiRoute};
use libc::{self, c_void, sockaddr_in, socklen_t};
use opendrop_core::nearby::{
    AdvertisedRole, NearbyBeacon, NearbyCandidate, TcpDirection, NEARBY_TCP_PORT, NEARBY_UDP_PORT,
};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SESSION_DISCOVERY_DEADLINE: Duration = Duration::from_secs(120);
const BEACON_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LocalLink {
    pub interface: String,
    pub source: Ipv4Addr,
    pub prefix: u8,
}

fn private(addr: Ipv4Addr) -> bool {
    opendrop_core::nearby::is_private_link_peer(addr)
}

pub(super) fn detect_one_physical_link() -> io::Result<LocalLink> {
    let mut interfaces = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut interfaces) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Free(*mut libc::ifaddrs);
    impl Drop for Free {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _free = Free(interfaces);
    let mut candidates = BTreeSet::new();
    let mut pointer = interfaces;
    while !pointer.is_null() {
        let current = unsafe { &*pointer };
        pointer = current.ifa_next;
        if current.ifa_addr.is_null()
            || current.ifa_netmask.is_null()
            || unsafe { (*current.ifa_addr).sa_family } != libc::AF_INET as u16
            || current.ifa_flags & (libc::IFF_UP | libc::IFF_BROADCAST) as u32
                != (libc::IFF_UP | libc::IFF_BROADCAST) as u32
            || current.ifa_flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) as u32 != 0
        {
            continue;
        }
        let name = unsafe { CStr::from_ptr(current.ifa_name) };
        let Ok(name) = name.to_str() else { continue };
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            || name.len() >= libc::IFNAMSIZ
        {
            continue;
        }
        // Physical NIC, not a tun/tap/VPN/veth or USB tether fallback.
        // Sysfs source is kernel state, never an untrusted beacon field.
        let device = std::path::Path::new("/sys/class/net")
            .join(name)
            .join("device");
        if !device.exists() {
            continue;
        }
        let local = unsafe { &*(current.ifa_addr as *const sockaddr_in) };
        let netmask = unsafe { &*(current.ifa_netmask as *const sockaddr_in) };
        let source = Ipv4Addr::from(u32::from_be(local.sin_addr.s_addr));
        let mask = u32::from_be(netmask.sin_addr.s_addr);
        let prefix = mask.leading_ones() as u8;
        if !private(source) || !(16..=30).contains(&prefix) || mask != u32::MAX << (32 - prefix) {
            continue;
        }
        candidates.insert(LocalLink {
            interface: name.to_owned(),
            source,
            prefix,
        });
    }
    if candidates.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no unique private physical LAN interface; stop rather than use default route",
        ));
    }
    Ok(candidates.into_iter().next().expect("one checked"))
}

pub(super) fn bind_one_interface(socket: &UdpSocket, link: &LocalLink) -> io::Result<()> {
    let device = CString::new(link.interface.as_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid network interface"))?;
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast::<c_void>(),
            device.as_bytes_with_nul().len() as socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn directed_broadcast(link: &LocalLink) -> Ipv4Addr {
    let mask = u32::MAX << (32 - link.prefix);
    Ipv4Addr::from(u32::from(link.source) | !mask)
}

/// Foreground only: owner enables temporary Everyone before this runs. The
/// same *guest* protocol handler accepts either a normal incoming LAN TCP
/// connection or a connection Linux initiates to a phone hotspot listener.
/// A single physical session wins, and no automatic retry/replay occurs.
pub(super) fn wait_for_nearby_transfer(running: &AtomicBool) -> io::Result<TcpStream> {
    let link = detect_one_physical_link()?;
    wait_on_link(
        running,
        link,
        LinkKind::ProductionPhysical,
        SESSION_DISCOVERY_DEADLINE,
    )
}

#[derive(Clone, Copy)]
enum LinkKind {
    ProductionPhysical,
    // Compiled ONLY in debug builds with the explicitly enabled hosted
    // fixture feature. The production executable rejects that feature.
    #[cfg(all(feature = "hosted-guest-fixture", debug_assertions))]
    IsolatedCiVeth,
}

#[cfg(all(test, feature = "hosted-guest-fixture", debug_assertions))]
pub(super) fn wait_for_hosted_netns(
    running: &AtomicBool,
    link: LocalLink,
    deadline: Duration,
) -> io::Result<TcpStream> {
    validate_hosted_netns_link(&link)?;
    wait_on_link(running, link, LinkKind::IsolatedCiVeth, deadline)
}

#[cfg(all(test, feature = "hosted-guest-fixture", debug_assertions))]
pub(super) fn validate_hosted_netns_link(link: &LocalLink) -> io::Result<()> {
    // A test-only supplied local address does NOT supply a peer/candidate.
    // Verify that the declared veth actually exists, is up, and owns the
    // address and prefix in this network namespace. The production detector
    // never accepts this interface class.
    use std::process::Command;
    if !link.interface.starts_with("od148")
        || !private(link.source)
        || !(16..=30).contains(&link.prefix)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a D148 CI link",
        ));
    }
    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", &link.interface])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hosted link absent",
        ));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "interface encoding"))?;
    if !text.contains(&format!("inet {}/{} ", link.source, link.prefix)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong hosted interface address/prefix",
        ));
    }
    let link_info = Command::new("ip")
        .args(["-o", "link", "show", "dev", &link.interface])
        .output()?;
    let link_flags = String::from_utf8_lossy(&link_info.stdout);
    if !link_info.status.success()
        || !link_flags.contains(",UP,")
            && !link_flags.contains("<UP,")
            && !link_flags.contains(",UP>")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hosted link down",
        ));
    }
    Ok(())
}

fn wait_on_link(
    running: &AtomicBool,
    link: LocalLink,
    kind: LinkKind,
    deadline: Duration,
) -> io::Result<TcpStream> {
    let tcp = TcpListener::bind(SocketAddrV4::new(link.source, NEARBY_TCP_PORT))?;
    tcp.set_nonblocking(true)?;
    // UDP wildcard is *device-bound* using SO_BINDTODEVICE. In contrast,
    // TCP is never bound to a wildcard interface.
    let udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, NEARBY_UDP_PORT))?;
    bind_one_interface(&udp, &link)?;
    udp.set_broadcast(true)?;
    udp.set_read_timeout(Some(Duration::from_millis(80)))?;
    let beacon = NearbyBeacon::fresh(AdvertisedRole::ReceiverTcpListener)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "OS CSPRNG for local discovery"))?
        .encode();
    let broadcast = SocketAddrV4::new(directed_broadcast(&link), NEARBY_UDP_PORT);
    let started = Instant::now();
    let mut next_announcement = Instant::now();
    let mut attempts = 0u32;
    while running.load(Ordering::Acquire) && started.elapsed() < deadline {
        // Recheck link and allow owner cancellation BEFORE any SYN or beacon.
        match kind {
            LinkKind::ProductionPhysical => {
                if detect_one_physical_link()? != link {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "LAN link changed",
                    ));
                }
            }
            #[cfg(all(feature = "hosted-guest-fixture", debug_assertions))]
            LinkKind::IsolatedCiVeth => validate_hosted_netns_link(&link)?,
        }
        if Instant::now() >= next_announcement {
            // A broadcast failure must not trigger a WAN or DNS fallback.
            udp.send_to(&beacon, broadcast)?;
            next_announcement = Instant::now() + BEACON_INTERVAL;
        }
        if let Ok((socket, source)) = tcp.accept() {
            if let SocketAddr::V4(v4) = source {
                let candidate =
                    NearbyCandidate::from_packet(&beacon, *v4.ip(), link.source, link.prefix);
                // For accepted TCP, the peer isn't claiming a beacon role;
                // same-link classification is the only permissible exposure
                // reduction, never a trust/authentication decision.
                if candidate.is_ok()
                    && socket.local_addr()?.ip() == std::net::IpAddr::V4(link.source)
                {
                    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                    return Ok(socket);
                }
            }
            // Reject unpermitted source before pre-TLS identity exposure.
            drop(socket);
        }
        let mut received = [0u8; 128];
        match udp.recv_from(&mut received) {
            Ok((count, SocketAddr::V4(source))) => {
                attempts += 1;
                if attempts > 2048 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "excessive untrusted discovery packets",
                    ));
                }
                let Ok(candidate) = NearbyCandidate::from_packet(
                    &received[..count],
                    *source.ip(),
                    link.source,
                    link.prefix,
                ) else {
                    continue;
                };
                if candidate.receiver_tcp_direction() != Ok(TcpDirection::LocalConnects) {
                    continue;
                }
                // Actual TCP source bind / Wi-Fi interface and destination
                // validation are enforced again by connect_exact().
                let route = DirectWifiRoute {
                    interface: link.interface.clone(),
                    source: link.source,
                    peer: candidate.peer,
                };
                return connect_exact(&route, running, {
                    match kind {
                        LinkKind::ProductionPhysical => false,
                        #[cfg(all(feature = "hosted-guest-fixture", debug_assertions))]
                        LinkKind::IsolatedCiVeth => true,
                    }
                });
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "nearby discovery unavailable, expired or explicitly cancelled",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn broadcast_derived_from_actual_link_prefix() {
        let link = LocalLink {
            interface: "portable-wifi".into(),
            source: "10.34.80.134".parse().unwrap(),
            prefix: 24,
        };
        assert_eq!(directed_broadcast(&link).to_string(), "10.34.80.255");
    }
    #[test]
    fn invalid_discovery_never_becomes_transport_authority() {
        let beacon = NearbyBeacon::fresh(AdvertisedRole::SenderTcpListener).unwrap();
        assert!(NearbyCandidate::from_packet(
            &beacon.encode(),
            "10.34.81.141".parse().unwrap(),
            "10.34.80.134".parse().unwrap(),
            24
        )
        .is_err());
    }
    #[test]
    fn no_permission_or_route_never_implicitly_uses_default_network() {
        let disallowed = LocalLink {
            interface: "no-such-network".into(),
            source: "192.168.1.2".parse().unwrap(),
            prefix: 24,
        };
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(bind_one_interface(&listener, &disallowed).is_err());
    }
}
