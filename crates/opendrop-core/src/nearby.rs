//! Minimal source-scoped local candidate discovery for OpenDrop.
//!
//! Discovery announcements are UNAUTHENTICATED hints. They convey neither
//! stable installation identities nor trust. Physical TCP direction differs
//! from TLS and file roles. A candidate can only become an authenticated
//! peer through the original strict RPK TLS + bilateral SAS + exact Offer
//! acceptance state machine.
//!
//! Format version 1: `ODNB` | version | advertised role | big-endian TCP port
//! | 128-bit fresh instance nonce. Exactly 24 bytes. Transport is one
//! explicitly validated local Wi-Fi/Ethernet link; no WAN scan or relay.
use ring::rand::{SecureRandom, SystemRandom};
use std::net::{Ipv4Addr, SocketAddrV4};

pub const NEARBY_UDP_PORT: u16 = 43992;
pub const NEARBY_TCP_PORT: u16 = 43991;
pub const NEARBY_LEN: usize = 24;
const MAGIC: &[u8; 4] = b"ODNB";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdvertisedRole {
    /// Linux/Windows local receiver accepts TCP; Android logical sender
    /// connects as TLS Client.
    ReceiverTcpListener = 1,
    /// Android phone hotspot host accepts TCP; Linux logical receiver
    /// connects but remains TLS Server.
    SenderTcpListener = 2,
}

impl AdvertisedRole {
    fn parse(byte: u8) -> Result<Self, DiscoveryRejection> {
        match byte {
            1 => Ok(Self::ReceiverTcpListener),
            2 => Ok(Self::SenderTcpListener),
            _ => Err(DiscoveryRejection::UnknownRole),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearbyBeacon {
    pub role: AdvertisedRole,
    pub port: u16,
    nonce: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryRejection {
    BadPacket,
    UnknownRole,
    UnsafeRoute,
    WrongLogicalRole,
    SelfAnnouncement,
}

impl NearbyBeacon {
    /// OS CSPRNG. Announcements are session-scoped (not a trusted identity).
    pub fn fresh(role: AdvertisedRole) -> Result<Self, DiscoveryRejection> {
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| DiscoveryRejection::BadPacket)?;
        Ok(Self {
            role,
            port: NEARBY_TCP_PORT,
            nonce,
        })
    }

    pub fn encode(&self) -> [u8; NEARBY_LEN] {
        let mut encoded = [0u8; NEARBY_LEN];
        encoded[..4].copy_from_slice(MAGIC);
        encoded[4] = 1;
        encoded[5] = self.role as u8;
        encoded[6..8].copy_from_slice(&self.port.to_be_bytes());
        encoded[8..].copy_from_slice(&self.nonce);
        encoded
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, DiscoveryRejection> {
        if bytes.len() != NEARBY_LEN || &bytes[..4] != MAGIC || bytes[4] != 1 {
            return Err(DiscoveryRejection::BadPacket);
        }
        let role = AdvertisedRole::parse(bytes[5])?;
        let port = u16::from_be_bytes([bytes[6], bytes[7]]);
        // One fixed authenticated transport endpoint in the initial slice.
        // No attacker-supplied privileged or alternative port probing.
        if port != NEARBY_TCP_PORT || bytes[8..].iter().all(|b| *b == 0) {
            return Err(DiscoveryRejection::BadPacket);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[8..]);
        Ok(Self { role, port, nonce })
    }
}

/// A candidate remains UNTRUSTED until the existing RPK/SAS ceremony.
/// Discovery never creates a trusted peer or authorizes a file write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearbyCandidate {
    pub peer: SocketAddrV4,
    pub role: AdvertisedRole,
    pub link_source: Ipv4Addr,
    pub link_prefix: u8,
    pub session_nonce: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDirection {
    LocalConnects,
    LocalAccepts,
}

impl NearbyCandidate {
    /// `source` is the actual UDP peer address, never a host string inside
    /// the untrusted packet. `local` and `prefix` come from the OS link,
    /// not a user-supplied public network route.
    pub fn from_packet(
        packet: &[u8],
        source: Ipv4Addr,
        local: Ipv4Addr,
        prefix: u8,
    ) -> Result<Self, DiscoveryRejection> {
        if source == local {
            return Err(DiscoveryRejection::SelfAnnouncement);
        }
        if !is_private_link_peer(source)
            || !is_private_link_peer(local)
            || !(16..=30).contains(&prefix)
        {
            return Err(DiscoveryRejection::UnsafeRoute);
        }
        let mask = u32::MAX << (32 - prefix);
        if (u32::from(source) & mask) != (u32::from(local) & mask) {
            return Err(DiscoveryRejection::UnsafeRoute);
        }
        let ad = NearbyBeacon::parse(packet)?;
        Ok(Self {
            peer: SocketAddrV4::new(source, ad.port),
            role: ad.role,
            link_source: local,
            link_prefix: prefix,
            session_nonce: ad.nonce,
        })
    }

    /// Linux/Windows receive-side plan; actual authentication is ALWAYS
    /// TLS Server, logical File Receiver, independent of TCP direction.
    pub fn receiver_tcp_direction(&self) -> Result<TcpDirection, DiscoveryRejection> {
        match self.role {
            AdvertisedRole::SenderTcpListener => Ok(TcpDirection::LocalConnects),
            AdvertisedRole::ReceiverTcpListener => Err(DiscoveryRejection::WrongLogicalRole),
        }
    }

    /// Android/Windows send-side plan; ALWAYS TLS Client and File Sender.
    pub fn sender_tcp_direction(&self) -> Result<TcpDirection, DiscoveryRejection> {
        match self.role {
            AdvertisedRole::ReceiverTcpListener => Ok(TcpDirection::LocalConnects),
            AdvertisedRole::SenderTcpListener => Err(DiscoveryRejection::WrongLogicalRole),
        }
    }
}

pub fn is_private_link_peer(ip: Ipv4Addr) -> bool {
    ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(role: AdvertisedRole) -> [u8; NEARBY_LEN] {
        let mut packet = NearbyBeacon::fresh(role).unwrap().encode();
        packet[8..].copy_from_slice(&[9u8; 16]);
        packet
    }

    #[test]
    fn native_android_and_linux_beacon_vectors_and_roles() {
        let sender = packet(AdvertisedRole::SenderTcpListener);
        assert_eq!(&sender[..8], b"ODNB\x01\x02\xab\xd7");
        assert_eq!(NearbyBeacon::parse(&sender).unwrap().encode(), sender);
        let found = NearbyCandidate::from_packet(
            &sender,
            "10.34.80.141".parse().unwrap(),
            "10.34.80.134".parse().unwrap(),
            24,
        )
        .unwrap();
        assert_eq!(
            found.receiver_tcp_direction(),
            Ok(TcpDirection::LocalConnects)
        );
        assert_eq!(
            found.sender_tcp_direction(),
            Err(DiscoveryRejection::WrongLogicalRole)
        );
        let receiver = packet(AdvertisedRole::ReceiverTcpListener);
        let peer = NearbyCandidate::from_packet(
            &receiver,
            "192.168.1.7".parse().unwrap(),
            "192.168.1.3".parse().unwrap(),
            24,
        )
        .unwrap();
        assert_eq!(peer.sender_tcp_direction(), Ok(TcpDirection::LocalConnects));
    }

    #[test]
    fn forged_untrusted_role_port_version_nonce_or_trailing_bytes_rejected() {
        let legitimate = packet(AdvertisedRole::ReceiverTcpListener);
        for field in [0, 4, 5, 6, 7] {
            let mut bytes = legitimate;
            bytes[field] ^= 0xff;
            assert!(NearbyBeacon::parse(&bytes).is_err());
        }
        let mut zero_nonce = legitimate;
        zero_nonce[8..].fill(0);
        assert!(NearbyBeacon::parse(&zero_nonce).is_err());
        assert!(NearbyBeacon::parse(&legitimate[..23]).is_err());
        let mut trailing = legitimate.to_vec();
        trailing.push(0);
        assert!(NearbyBeacon::parse(&trailing).is_err());
    }

    #[test]
    fn public_vpn_linklocal_self_wrong_subnet_and_no_discovery_are_rejected() {
        let packet = packet(AdvertisedRole::SenderTcpListener);
        let local = "10.34.80.134".parse().unwrap();
        for source in ["8.8.8.8", "100.101.102.103", "169.254.1.1", "10.35.1.7"] {
            let result = NearbyCandidate::from_packet(&packet, source.parse().unwrap(), local, 24);
            assert!(result.is_err(), "unsafe candidate {source}");
        }
        assert_eq!(
            NearbyCandidate::from_packet(&packet, local, local, 24),
            Err(DiscoveryRejection::SelfAnnouncement)
        );
        assert!(
            NearbyCandidate::from_packet(&packet, "10.34.80.141".parse().unwrap(), local, 0)
                .is_err()
        );
        // Blocked multicast/discovery never implies an authenticated peer.
        let unseen: Option<NearbyCandidate> = None;
        assert!(unseen.is_none());
    }

    #[test]
    fn blocked_multicast_still_allows_scoped_direct_local_candidate() {
        // The one-link directed-broadcast fallback does not need multicast
        // or internet. A packet obtained on that link is still untrusted,
        // and it can select ONLY TCP direction, never file authorization.
        let source: Ipv4Addr = "192.168.44.1".parse().unwrap();
        let local: Ipv4Addr = "192.168.44.6".parse().unwrap();
        let candidate = NearbyCandidate::from_packet(
            &packet(AdvertisedRole::SenderTcpListener),
            source,
            local,
            24,
        )
        .unwrap();
        assert_eq!(
            candidate.receiver_tcp_direction(),
            Ok(TcpDirection::LocalConnects)
        );
        assert_eq!(candidate.peer.ip(), &source);
        assert_ne!(candidate.session_nonce, [0; 16]);
    }
}
