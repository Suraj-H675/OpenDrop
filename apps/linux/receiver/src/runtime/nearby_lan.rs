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
    AdvertisedRole, DiscoveryRejection, NearbyBeacon, NearbyCandidate, TcpDirection,
    NEARBY_TCP_PORT, NEARBY_UDP_PORT,
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

// All counters saturate: untrusted UDP cannot create unbounded logs or UI.
const DIAGNOSTIC_COUNT_LIMIT: u16 = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct NearbyCounts {
    pub received: u16,
    pub rejected: u16,
    pub wrong_role: u16,
    pub permitted: u16,
    pub tcp_attempts: u16,
}
impl NearbyCounts {
    fn bump(value: &mut u16) {
        *value = value.saturating_add(1).min(DIAGNOSTIC_COUNT_LIMIT);
    }

    fn consider(
        &mut self,
        bytes: &[u8],
        source: Ipv4Addr,
        link: &LocalLink,
    ) -> Option<NearbyCandidate> {
        Self::bump(&mut self.received);
        let candidate = match NearbyCandidate::from_packet(bytes, source, link.source, link.prefix)
        {
            Ok(candidate) => candidate,
            Err(DiscoveryRejection::WrongLogicalRole) => {
                Self::bump(&mut self.wrong_role);
                return None;
            }
            Err(_) => {
                Self::bump(&mut self.rejected);
                return None;
            }
        };
        if candidate.receiver_tcp_direction() != Ok(TcpDirection::LocalConnects) {
            Self::bump(&mut self.wrong_role);
            return None;
        }
        Self::bump(&mut self.permitted);
        Some(candidate)
    }

    fn timeout_class(&self, owner_running: bool) -> NearbyFailure {
        if !owner_running {
            NearbyFailure::Cancelled
        } else if self.received == 0 {
            NearbyFailure::NoPackets
        } else if self.rejected > 0 {
            NearbyFailure::RejectedPackets
        } else if self.wrong_role > 0 {
            NearbyFailure::WrongRole
        } else {
            NearbyFailure::NoPermittedCandidate
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NearbyFailure {
    NoPrivateLink,
    TcpListenerBind,
    UdpSocketBind,
    UdpDeviceBind,
    UdpSend,
    UdpReceive,
    LinkChanged,
    TooManyPackets,
    NoPackets,
    RejectedPackets,
    WrongRole,
    NoPermittedCandidate,
    TcpConnect,
    Cancelled,
}
impl NearbyFailure {
    fn label(self) -> &'static str {
        match self {
            Self::NoPrivateLink => "No unique permitted physical private link",
            Self::TcpListenerBind => "TCP receiver socket bind failed",
            Self::UdpSocketBind => "UDP discovery socket bind failed",
            Self::UdpDeviceBind => "UDP Wi-Fi device binding failed",
            Self::UdpSend => "UDP discovery announcement send failed",
            Self::UdpReceive => "UDP discovery receive failed",
            Self::LinkChanged => "Physical private link changed during discovery",
            Self::TooManyPackets => "Untrusted UDP packet limit reached",
            Self::NoPackets => "No UDP advertisements observed",
            Self::RejectedPackets => "UDP advertisements received but rejected",
            Self::WrongRole => "UDP advertisements received with wrong sender role",
            Self::NoPermittedCandidate => "No permitted source-derived sender candidate",
            Self::TcpConnect => "Permitted discovery candidate but source-bound TCP connect failed",
            Self::Cancelled => "Discovery cancelled by foreground owner",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct NearbyDiagnosticError {
    code: NearbyFailure,
    counts: NearbyCounts,
}
impl std::fmt::Display for NearbyDiagnosticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code.label())
    }
}
impl std::error::Error for NearbyDiagnosticError {}

fn diagnostic_error(code: NearbyFailure, counts: NearbyCounts, kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, NearbyDiagnosticError { code, counts })
}

/// Safe, capped local owner Qt status. This contains no network endpoint,
/// identity, file metadata or untrusted packet bytes.
pub(super) fn safe_ui_diagnostic(error: &io::Error) -> Option<String> {
    let diagnostic = error.get_ref()?.downcast_ref::<NearbyDiagnosticError>()?;
    let c = diagnostic.counts;
    Some(format!(
        "Nearby: {} (UDP seen {}, rejected {}, wrong role {}, candidates {}, TCP attempts {}).",
        diagnostic.code.label(),
        c.received,
        c.rejected,
        c.wrong_role,
        c.permitted,
        c.tcp_attempts,
    ))
}

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
    let link = detect_one_physical_link().map_err(|error| {
        diagnostic_error(
            NearbyFailure::NoPrivateLink,
            NearbyCounts::default(),
            error.kind(),
        )
    })?;
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
    let mut stats = NearbyCounts::default();
    let tcp = TcpListener::bind(SocketAddrV4::new(link.source, NEARBY_TCP_PORT))
        .map_err(|e| diagnostic_error(NearbyFailure::TcpListenerBind, stats, e.kind()))?;
    tcp.set_nonblocking(true)
        .map_err(|e| diagnostic_error(NearbyFailure::TcpListenerBind, stats, e.kind()))?;
    // UDP wildcard is *device-bound* using SO_BINDTODEVICE. In contrast,
    // TCP is never bound to a wildcard interface.
    let udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, NEARBY_UDP_PORT))
        .map_err(|e| diagnostic_error(NearbyFailure::UdpSocketBind, stats, e.kind()))?;
    bind_one_interface(&udp, &link)
        .map_err(|e| diagnostic_error(NearbyFailure::UdpDeviceBind, stats, e.kind()))?;
    udp.set_broadcast(true)
        .map_err(|e| diagnostic_error(NearbyFailure::UdpSocketBind, stats, e.kind()))?;
    udp.set_read_timeout(Some(Duration::from_millis(80)))
        .map_err(|e| diagnostic_error(NearbyFailure::UdpSocketBind, stats, e.kind()))?;
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
                if detect_one_physical_link().map_or(true, |current| current != link) {
                    return Err(diagnostic_error(
                        NearbyFailure::LinkChanged,
                        stats,
                        io::ErrorKind::PermissionDenied,
                    ));
                }
            }
            #[cfg(all(feature = "hosted-guest-fixture", debug_assertions))]
            LinkKind::IsolatedCiVeth => validate_hosted_netns_link(&link)?,
        }
        if Instant::now() >= next_announcement {
            // A broadcast failure must not trigger a WAN or DNS fallback.
            udp.send_to(&beacon, broadcast)
                .map_err(|e| diagnostic_error(NearbyFailure::UdpSend, stats, e.kind()))?;
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
                    return Err(diagnostic_error(
                        NearbyFailure::TooManyPackets,
                        stats,
                        io::ErrorKind::PermissionDenied,
                    ));
                }
                let Some(candidate) = stats.consider(&received[..count], *source.ip(), &link)
                else {
                    continue;
                };
                // Actual TCP source bind / Wi-Fi interface and destination
                // validation are enforced again by connect_exact().
                let route = DirectWifiRoute {
                    interface: link.interface.clone(),
                    source: link.source,
                    peer: candidate.peer,
                };
                NearbyCounts::bump(&mut stats.tcp_attempts);
                return connect_exact(&route, running, {
                    match kind {
                        LinkKind::ProductionPhysical => false,
                        #[cfg(all(feature = "hosted-guest-fixture", debug_assertions))]
                        LinkKind::IsolatedCiVeth => true,
                    }
                })
                .map_err(|e| {
                    diagnostic_error(
                        if !running.load(Ordering::Acquire)
                            || e.kind() == io::ErrorKind::Interrupted
                        {
                            NearbyFailure::Cancelled
                        } else {
                            NearbyFailure::TcpConnect
                        },
                        stats,
                        e.kind(),
                    )
                });
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(diagnostic_error(NearbyFailure::UdpReceive, stats, e.kind())),
        }
    }
    let class = stats.timeout_class(running.load(Ordering::Acquire));
    Err(diagnostic_error(
        class,
        stats,
        if class == NearbyFailure::Cancelled {
            io::ErrorKind::Interrupted
        } else {
            io::ErrorKind::TimedOut
        },
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
    #[test]
    fn diagnostics_distinguish_no_packet_bad_packet_wrong_role_and_valid_sender() {
        let link = LocalLink {
            interface: "portable-wifi".into(),
            source: "10.34.80.134".parse().unwrap(),
            prefix: 24,
        };
        let peer = "10.34.80.141".parse().unwrap();
        let mut stats = NearbyCounts::default();
        assert_eq!(stats.timeout_class(true), NearbyFailure::NoPackets);
        assert_eq!(stats.timeout_class(false), NearbyFailure::Cancelled);
        assert!(stats.consider(b"broken", peer, &link).is_none());
        assert_eq!(stats.received, 1);
        assert_eq!(stats.rejected, 1);
        assert_eq!(stats.timeout_class(true), NearbyFailure::RejectedPackets);
        let receiver = NearbyBeacon::fresh(AdvertisedRole::ReceiverTcpListener)
            .unwrap()
            .encode();
        assert!(stats.consider(&receiver, peer, &link).is_none());
        assert_eq!(stats.wrong_role, 1);
        let sender = NearbyBeacon::fresh(AdvertisedRole::SenderTcpListener)
            .unwrap()
            .encode();
        assert!(stats
            .consider(&sender, "10.34.81.141".parse().unwrap(), &link)
            .is_none());
        assert_eq!(stats.rejected, 2);
        let candidate = stats.consider(&sender, peer, &link).unwrap();
        assert_eq!(
            candidate.receiver_tcp_direction(),
            Ok(TcpDirection::LocalConnects)
        );
        assert_eq!(stats.permitted, 1);
        assert_eq!(stats.received, 4);
    }

    #[test]
    fn diagnostic_counters_saturate_and_ui_never_shows_network_metadata() {
        let link = LocalLink {
            interface: "portable-wifi".into(),
            source: "192.168.44.6".parse().unwrap(),
            prefix: 24,
        };
        let mut stats = NearbyCounts::default();
        for _ in 0..1000 {
            assert!(stats
                .consider(b"noise", "192.168.44.1".parse().unwrap(), &link)
                .is_none());
        }
        assert_eq!(stats.received, DIAGNOSTIC_COUNT_LIMIT);
        assert_eq!(stats.rejected, DIAGNOSTIC_COUNT_LIMIT);
        let failure = diagnostic_error(
            NearbyFailure::RejectedPackets,
            stats,
            io::ErrorKind::InvalidData,
        );
        let safe = safe_ui_diagnostic(&failure).unwrap();
        assert!(safe.contains("UDP seen 64, rejected 64"));
        assert!(!safe.contains("192.168"));
        assert!(!safe.contains("portable-wifi"));
        assert!(safe_ui_diagnostic(&io::Error::other("peer 192.168.44.1")).is_none());
    }

    #[test]
    fn candidate_connect_error_preserves_failed_result_and_one_attempt() {
        let mut stats = NearbyCounts::default();
        stats.permitted = 1;
        NearbyCounts::bump(&mut stats.tcp_attempts);
        let failure = diagnostic_error(
            NearbyFailure::TcpConnect,
            stats,
            io::ErrorKind::ConnectionRefused,
        );
        assert_eq!(failure.kind(), io::ErrorKind::ConnectionRefused);
        let safe = safe_ui_diagnostic(&failure).unwrap();
        assert!(safe.contains("source-bound TCP connect failed"));
        assert!(safe.contains("candidates 1, TCP attempts 1"));
    }
}
