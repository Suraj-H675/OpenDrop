//! OpenDrop S1 guest identity, canonical introduction and human-verification
//! types. Unlike the legacy DER-certificate fingerprint, a GuestSpkiFingerprint
//! hashes the canonical DER SubjectPublicKeyInfo of a P-256 installation key.
//!
//! A network hello is only a PROVISIONAL key claim. Neither accepting the
//! hello nor completing an exact-key TLS handshake grants file permissions.
//! Only the privileged platform UI will eventually issue human-verification
//! and exact-offer consent capabilities. There is intentionally no public
//! constructor from a bool, claimed DeviceId, or network confirmation.

use crate::identity::DeviceId;
use crate::Error;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime};

pub const GUEST_PROTOCOL: u8 = 1;
pub const GUEST_ALPN: &[u8] = b"opendrop-s1-guest-v1";
pub const HELLO_LEN: usize = 162;
pub const SAS_DIGITS: usize = 10;
pub const EVERYONE_WINDOW: Duration = Duration::from_secs(10 * 60);
pub const PAIRING_DEADLINE: Duration = Duration::from_secs(2 * 60);
pub const APPROVED_SESSION_LIMIT: Duration = Duration::from_secs(20 * 60);
const MAX_ATTEMPTS_PER_WINDOW: usize = 16;
const MAGIC: &[u8; 4] = b"ODGH";
// ISO/IEC 8825-1 DER of id-ecPublicKey / prime256v1 + BIT STRING with
// uncompressed P-256 point. Only this exact minimal encoding is supported.
// A key must ALSO successfully verify its TLS 1.3 CertificateVerify signature
// before being treated as provisionally possessed by the remote peer.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256Spki([u8; 91]);

impl P256Spki {
    pub fn from_canonical_der(der: &[u8]) -> Result<Self, Error> {
        let value: [u8; 91] = der
            .try_into()
            .map_err(|_| Error::Invalid("P-256 DER SPKI length"))?;
        if value[..P256_SPKI_PREFIX.len()] != P256_SPKI_PREFIX
            || value[P256_SPKI_PREFIX.len()] != 0x04
        {
            return Err(Error::Invalid("noncanonical P-256 DER SPKI"));
        }
        Ok(Self(value))
    }

    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    pub fn fingerprint(&self) -> GuestSpkiFingerprint {
        GuestSpkiFingerprint(Sha256::digest(self.0).into())
    }
}

/// NOT interchangeable with the legacy KeyFingerprint (certificate DER).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuestSpkiFingerprint([u8; 32]);

impl GuestSpkiFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut result, "{byte:02x}").expect("String formatting cannot fail");
        }
        result
    }

    pub fn from_hex(input: &str) -> Result<Self, Error> {
        if input.len() != 64 {
            return Err(Error::Invalid("guest SPKI fingerprint length"));
        }
        let mut bytes = [0u8; 32];
        for (n, pair) in input.as_bytes().chunks_exact(2).enumerate() {
            bytes[n] = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| Error::Invalid("guest SPKI hex"))?,
                16,
            )
            .map_err(|_| Error::Invalid("guest SPKI hex"))?;
        }
        if input != GuestSpkiFingerprint(bytes).to_hex() {
            return Err(Error::Invalid("noncanonical guest SPKI hex"));
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsSide {
    Client = 1,
    Server = 2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferSide {
    Sender = 1,
    Receiver = 2,
}

fn tls_role(value: u8) -> Result<TlsSide, Error> {
    match value {
        1 => Ok(TlsSide::Client),
        2 => Ok(TlsSide::Server),
        _ => Err(Error::Invalid("guest TLS role")),
    }
}
fn file_role(value: u8) -> Result<TransferSide, Error> {
    match value {
        1 => Ok(TransferSide::Sender),
        2 => Ok(TransferSide::Receiver),
        _ => Err(Error::Invalid("guest file role")),
    }
}

/// Fixed-length pre-TLS introduction; it conveys an UNTRUSTED exact-key pin,
/// not a trusted-device certificate. Intended for a targeted connection after
/// owner-enabled discovery, never for broadcasting stable identity material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestHello {
    pub(crate) device: DeviceId,
    pub(crate) spki: P256Spki,
    pub(crate) nonce: [u8; 32],
    pub(crate) tls_side: TlsSide,
    pub(crate) transfer_side: TransferSide,
}

impl GuestHello {
    pub fn new_local(
        device: DeviceId,
        spki: P256Spki,
        tls_side: TlsSide,
        transfer_side: TransferSide,
    ) -> Result<Self, Error> {
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Unauthorized)?;
        Ok(Self {
            device,
            spki,
            nonce,
            tls_side,
            transfer_side,
        })
    }

    pub fn encoded(&self) -> [u8; HELLO_LEN] {
        let mut data = [0u8; HELLO_LEN];
        data[..4].copy_from_slice(MAGIC);
        data[4] = GUEST_PROTOCOL;
        data[5] = self.tls_side as u8;
        data[6] = self.transfer_side as u8;
        data[7..39].copy_from_slice(self.device.as_str().as_bytes());
        data[39..130].copy_from_slice(self.spki.as_der());
        data[130..162].copy_from_slice(&self.nonce);
        data
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HELLO_LEN || &bytes[..4] != MAGIC || bytes[4] != GUEST_PROTOCOL {
            return Err(Error::Invalid("guest hello length/version/magic"));
        }
        let device = DeviceId::parse(
            std::str::from_utf8(&bytes[7..39])
                .map_err(|_| Error::Invalid("guest DeviceId UTF-8"))?,
        )?;
        if device.as_str().as_bytes() != &bytes[7..39] {
            return Err(Error::Invalid("noncanonical guest DeviceId"));
        }
        Ok(Self {
            device,
            tls_side: tls_role(bytes[5])?,
            transfer_side: file_role(bytes[6])?,
            spki: P256Spki::from_canonical_der(&bytes[39..130])?,
            nonce: bytes[130..162]
                .try_into()
                .map_err(|_| Error::Invalid("guest nonce"))?,
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device
    }

    pub fn public_key(&self) -> &P256Spki {
        &self.spki
    }
}

/// Canonical fixed-order context. Physical TLS roles and logical sender/
/// receiver roles are encoded separately. Both peers must compute identical
/// bytes, irrespective of who initiated the user-facing sharing workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestTranscript {
    client: GuestHello,
    server: GuestHello,
}

impl GuestTranscript {
    pub fn new(client: GuestHello, server: GuestHello) -> Result<Self, Error> {
        if client.tls_side != TlsSide::Client
            || server.tls_side != TlsSide::Server
            || client.transfer_side == server.transfer_side
            || client.device == server.device
            || client.spki == server.spki
            || client.nonce == server.nonce
        {
            return Err(Error::Invalid(
                "reflected/conflicting guest identities or roles",
            ));
        }
        Ok(Self { client, server })
    }

    pub fn client(&self) -> &GuestHello {
        &self.client
    }

    pub fn server(&self) -> &GuestHello {
        &self.server
    }

    pub fn canonical_digest(&self, tls13_cipher: u16, key_exchange_group: u16) -> [u8; 32] {
        // The actual post-handshake negotiated suite, group, and ALPN also
        // enter the transcript. The version and length of every element are
        // fixed, and no implementation-defined Debug/Display text is hashed.
        let mut hash = Sha256::new();
        hash.update(b"OpenDrop/S1/GuestTranscript/v1\0");
        hash.update([GUEST_PROTOCOL]);
        hash.update((GUEST_ALPN.len() as u16).to_be_bytes());
        hash.update(GUEST_ALPN);
        hash.update([0x03, 0x04]); // TLS 1.3
        hash.update(tls13_cipher.to_be_bytes());
        hash.update(key_exchange_group.to_be_bytes());
        hash.update(self.client.encoded());
        hash.update(self.server.encoded());
        hash.finalize().into()
    }
}

/// A local foreground owner action controls this capability. Discovery
/// advertisements disclose only temporary random identifiers, not SPKI.
/// This type is *closed* until a trusted platform UI explicitly opens it.
#[derive(Debug, Default)]
pub struct GuestAdmission {
    window: Option<Instant>,
    wall_window: Option<(SystemTime, SystemTime)>,
    active: Arc<AtomicUsize>,
    revoked: Arc<AtomicBool>,
    started: usize,
}

impl GuestAdmission {
    pub fn new_closed() -> Self {
        Self {
            window: None,
            wall_window: None,
            active: Arc::new(AtomicUsize::new(0)),
            revoked: Arc::new(AtomicBool::new(true)),
            started: 0,
        }
    }

    /// Only the audited platform owner-UI boundary may call this; a wire,
    /// terminal or public IPC boolean cannot open guest visibility.
    #[allow(dead_code)] // future trusted platform owner action
    pub(crate) fn open_from_local_owner_action(&mut self) {
        self.open_at(Instant::now());
    }

    fn open_at(&mut self, now: Instant) {
        // Prior permits must remain revocable even if the owner reopens.
        self.revoked.store(true, Ordering::Release);
        self.window = now.checked_add(EVERYONE_WINDOW);
        let wall_now = SystemTime::now();
        self.wall_window = wall_now
            .checked_add(EVERYONE_WINDOW)
            .map(|end| (wall_now, end));
        self.revoked = Arc::new(AtomicBool::new(false));
        self.started = 0;
    }

    pub fn admit(&mut self) -> Result<GuestAdmissionPermit, Error> {
        self.admit_at(Instant::now())
    }

    fn admit_at(&mut self, now: Instant) -> Result<GuestAdmissionPermit, Error> {
        if self.window.is_none_or(|deadline| now >= deadline)
            || !self.within_wall_window()
            || self.revoked.load(Ordering::Acquire)
            || self.started >= MAX_ATTEMPTS_PER_WINDOW
        {
            return Err(Error::Unauthorized);
        }
        // Even with two concurrent scheduling callbacks only one peer can
        // hold an admission permit; the 16-per-window budget is independent.
        if self
            .active
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Unauthorized);
        }
        self.started += 1;
        let lifetime = now
            .checked_add(APPROVED_SESSION_LIMIT)
            .ok_or(Error::Unauthorized)?;
        let started_wall = SystemTime::now();
        let expires_wall = started_wall
            .checked_add(APPROVED_SESSION_LIMIT)
            .ok_or(Error::Unauthorized)?;
        Ok(GuestAdmissionPermit {
            active: self.active.clone(),
            revoked: self.revoked.clone(),
            lifetime,
            started_wall,
            expires_wall,
        })
    }

    fn within_wall_window(&self) -> bool {
        let Some((started, expires)) = self.wall_window else {
            return false;
        };
        let now = SystemTime::now();
        now >= started && now < expires
    }

    pub fn remaining_visibility(&self) -> Duration {
        if self.revoked.load(Ordering::Acquire) || !self.within_wall_window() {
            return Duration::ZERO;
        }
        let monotonic = self
            .window
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .unwrap_or(Duration::ZERO);
        let wall = self
            .wall_window
            .and_then(|(_, end)| end.duration_since(SystemTime::now()).ok())
            .unwrap_or(Duration::ZERO);
        monotonic.min(wall)
    }

    /// Explicit owner revocation invalidates even previously admitted peers.
    /// Mere ten-minute discovery expiry does NOT revoke an accepted transfer.
    pub fn revoke_from_owner(&mut self) {
        self.revoked.store(true, Ordering::Release);
        self.window = None;
        self.wall_window = None;
    }
}

/// Only created for a single admitted peer; does not itself authenticate it.
#[derive(Debug)]
pub struct GuestAdmissionPermit {
    active: Arc<AtomicUsize>,
    revoked: Arc<AtomicBool>,
    lifetime: Instant,
    started_wall: SystemTime,
    expires_wall: SystemTime,
}

impl GuestAdmissionPermit {
    pub fn is_active(&self) -> bool {
        self.valid_at(Instant::now())
    }

    fn valid_at(&self, now: Instant) -> bool {
        let wall = SystemTime::now();
        now < self.lifetime
            && wall >= self.started_wall
            && wall < self.expires_wall
            && !self.revoked.load(Ordering::Acquire)
    }
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
extern "C" {
    fn opendrop_qt_take_guest_visibility_action() -> i32;
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxGuestVisibilityAction {
    None,
    Opened,
    Revoked,
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
impl GuestAdmission {
    /// Consumed only on the QApplication owner thread. The native callback
    /// verifies an active local seat and its genuine foreground button event.
    /// No caller-provided network boolean or terminal flag opens visibility.
    pub fn poll_linux_qt_owner_action(&mut self) -> Result<LinuxGuestVisibilityAction, Error> {
        match unsafe { opendrop_qt_take_guest_visibility_action() } {
            0 => Ok(LinuxGuestVisibilityAction::None),
            1 => {
                self.open_from_local_owner_action();
                Ok(LinuxGuestVisibilityAction::Opened)
            }
            2 => {
                self.revoke_from_owner();
                Ok(LinuxGuestVisibilityAction::Revoked)
            }
            _ => {
                self.revoke_from_owner();
                Err(Error::Unauthorized)
            }
        }
    }
}
impl Drop for GuestAdmissionPermit {
    fn drop(&mut self) {
        self.active.store(0, Ordering::Release);
    }
}

impl fmt::Display for GuestSpkiFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spki(marker: u8) -> P256Spki {
        let mut der = [0u8; 91];
        der[..26].copy_from_slice(&P256_SPKI_PREFIX);
        der[26] = 4;
        der[27..].fill(marker);
        P256Spki::from_canonical_der(&der).unwrap()
    }
    fn hello(id: char, key: u8, role: TlsSide, transfer: TransferSide) -> GuestHello {
        GuestHello {
            device: DeviceId::parse(&id.to_string().repeat(32)).unwrap(),
            spki: spki(key),
            nonce: [key; 32],
            tls_side: role,
            transfer_side: transfer,
        }
    }

    #[test]
    fn fixed_guest_hello_rejects_noncanonical_keys_versions_and_roles() {
        let sender = hello('a', 5, TlsSide::Client, TransferSide::Sender);
        let wire = sender.encoded();
        assert_eq!(GuestHello::parse(&wire).unwrap(), sender);
        let mut modified = wire;
        modified[4] = 0;
        assert!(GuestHello::parse(&modified).is_err());
        modified = wire;
        modified[5] = 3;
        assert!(GuestHello::parse(&modified).is_err());
        modified = wire;
        modified[7] = b'A';
        assert!(GuestHello::parse(&modified).is_err());
        modified = wire;
        modified[39] = 0x31;
        assert!(GuestHello::parse(&modified).is_err());
        assert!(GuestHello::parse(&wire[..161]).is_err());
    }

    #[test]
    fn transcript_rejects_reflection_and_wrong_roles_without_guessing() {
        let sender = hello('a', 1, TlsSide::Client, TransferSide::Sender);
        let receiver = hello('b', 2, TlsSide::Server, TransferSide::Receiver);
        let transcript = GuestTranscript::new(sender.clone(), receiver.clone()).unwrap();
        assert_eq!(transcript.client(), &sender);
        assert_ne!(
            transcript.canonical_digest(0x1301, 0x001d),
            transcript.canonical_digest(0x1302, 0x001d)
        );
        assert!(GuestTranscript::new(sender.clone(), sender.clone()).is_err());
        assert!(GuestTranscript::new(receiver.clone(), sender.clone()).is_err());
        let wrong_file_role = hello('b', 2, TlsSide::Server, TransferSide::Sender);
        assert!(GuestTranscript::new(sender.clone(), wrong_file_role).is_err());
        let mut reflection = receiver.clone();
        reflection.spki = sender.spki.clone();
        assert!(GuestTranscript::new(sender, reflection).is_err());
    }

    #[test]
    fn unknown_guests_are_closed_until_owner_enables_everyone() {
        let now = Instant::now();
        let mut window = GuestAdmission::new_closed();
        assert!(window.admit_at(now).is_err());
        window.open_at(now);
        let permit = window.admit_at(now).unwrap();
        assert!(window.admit_at(now).is_err());
        assert!(permit.valid_at(now + EVERYONE_WINDOW + Duration::from_secs(1)));
        drop(permit);
        assert!(window.admit_at(now + EVERYONE_WINDOW).is_err());
        window.revoke_from_owner();
        assert!(window.admit_at(now).is_err());
    }

    #[test]
    fn explicit_owner_revocation_invalidates_in_flight_permit() {
        let now = Instant::now();
        let mut window = GuestAdmission::new_closed();
        window.open_at(now);
        let permit = window.admit_at(now).unwrap();
        window.revoke_from_owner();
        assert!(!permit.valid_at(now));
        assert!(!permit.valid_at(now + APPROVED_SESSION_LIMIT));
    }

    #[test]
    fn spki_fingerprint_is_not_a_legacy_certificate_fingerprint() {
        let key = spki(3);
        assert_eq!(
            GuestSpkiFingerprint::from_hex(&key.fingerprint().to_hex()).unwrap(),
            key.fingerprint()
        );
        assert!(
            GuestSpkiFingerprint::from_hex(&key.fingerprint().to_hex().to_uppercase()).is_err()
        );
        assert_ne!(spki(3).fingerprint(), spki(4).fingerprint());
    }
}
