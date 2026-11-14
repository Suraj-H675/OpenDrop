//! Android's receipt-only sender recovery: a single encrypted-at-rest scoped
//! credential, not permission to repeat an uncertain file upload.
use crate::{Result, SendError};
use opendrop_core::guest::{
    GuestHello, GuestSpkiFingerprint, GuestTranscript, P256Spki, TlsSide, TransferSide, HELLO_LEN,
};
use opendrop_core::guest_recovery::{GuestOfferV1, MAX_RECOVERY_MILLIS};
use opendrop_core::guest_tls::{self, LocalGuestIdentity, VerifiedReceiptOnlyTls};
use opendrop_core::identity::{DeviceId, TransferId};
use opendrop_core::journal::{FileOffer, Receipt};
use opendrop_core::wire::{Control, Frame, WireRecoveryCredential};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::io::{self, Cursor, Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"ODAR";
const VERSION: u8 = 1;
const MAX_RECORD: usize = 1024;
const TICK_LIMIT: Duration = Duration::from_secs(8);
const ATTEMPTS: usize = 64;

/// Exposed only as a byte sequence that the Android adapter MUST seal with
/// its dedicated nonexportable AndroidKeyStore AES-GCM key before sending
/// any file byte. Never log it, persist plaintext or attach it to an Intent.
pub struct PendingRecovery {
    offer: FileOffer,
    receiver_spki: P256Spki,
    receiver_device: DeviceId,
    credential: WireRecoveryCredential,
    issued_ms: u64,
    expires_ms: u64,
}

impl std::fmt::Debug for PendingRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRecovery")
            .field("transfer_id", &self.offer.id)
            .field("receiver", &self.receiver_spki.fingerprint())
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

fn now_ms() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SendError::Protocol("invalid system clock"))?;
    u64::try_from(now.as_millis()).map_err(|_| SendError::Protocol("system clock overflow"))
}

impl PendingRecovery {
    pub fn new(
        offer: FileOffer,
        sender: GuestSpkiFingerprint,
        receiver_spki: P256Spki,
        receiver_device: DeviceId,
        credential: WireRecoveryCredential,
    ) -> Result<Self> {
        let offered = GuestOfferV1::from_verified_wire_offer(offer, sender)?;
        let issued_ms = now_ms()?;
        let expires_ms = issued_ms
            .checked_add(MAX_RECOVERY_MILLIS as u64)
            .ok_or(SendError::Protocol("recovery clock overflow"))?;
        Ok(Self {
            offer: offered.file_offer().clone(),
            receiver_spki,
            receiver_device,
            credential,
            issued_ms,
            expires_ms,
        })
    }

    pub fn transfer_id(&self) -> &TransferId {
        &self.offer.id
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    pub fn encode_for_android_keystore(&self) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        Frame::Control(Control::Offer(self.offer.clone())).write_to(&mut output)?;
        output.extend_from_slice(self.receiver_spki.as_der());
        output.extend_from_slice(self.receiver_device.as_str().as_bytes());
        output.extend_from_slice(self.credential.as_bytes());
        output.extend_from_slice(&self.issued_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_ms.to_be_bytes());
        if output.len() > MAX_RECORD {
            return Err(SendError::Protocol("recovery record bounds"));
        }
        Ok(output)
    }

    /// Only call on plaintext returned from an authenticated AndroidKeyStore
    /// AES-GCM unseal. The shared layer does NOT trust unencrypted preferences
    /// to hold this sensitive credential.
    pub fn decode_from_android_keystore(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_RECORD
            || input.len() < 5 + 6 + 91 + 32 + 32 + 16
            || &input[..4] != MAGIC
            || input[4] != VERSION
        {
            return Err(SendError::Protocol("recovery record format"));
        }
        let mut cursor = Cursor::new(&input[5..]);
        let offer = match Frame::read_from(&mut cursor)? {
            Frame::Control(Control::Offer(offer)) => offer,
            _ => return Err(SendError::Protocol("recovery is not an exact offer")),
        };
        let offset = 5 + cursor.position() as usize;
        let remaining = &input[offset..];
        if remaining.len() != 91 + 32 + 32 + 8 + 8 {
            return Err(SendError::Protocol("recovery record trailing bytes"));
        }
        let receiver_spki = P256Spki::from_canonical_der(&remaining[..91])?;
        let device = DeviceId::parse(
            std::str::from_utf8(&remaining[91..123])
                .map_err(|_| SendError::Protocol("recovery device ID"))?,
        )?;
        let credential = WireRecoveryCredential::from_authenticated_bytes(
            remaining[123..155]
                .try_into()
                .map_err(|_| SendError::Protocol("recovery credential length"))?,
        )?;
        let issued_ms = u64::from_be_bytes(
            remaining[155..163]
                .try_into()
                .map_err(|_| SendError::Protocol("recovery issued"))?,
        );
        let expires_ms = u64::from_be_bytes(
            remaining[163..171]
                .try_into()
                .map_err(|_| SendError::Protocol("recovery expires"))?,
        );
        if expires_ms <= issued_ms
            || expires_ms - issued_ms > MAX_RECOVERY_MILLIS as u64
            || now_ms()? < issued_ms
            || now_ms()? >= expires_ms
        {
            return Err(SendError::Protocol("recovery expired or clock rolled back"));
        }
        GuestOfferV1::from_verified_wire_offer(
            offer.clone(),
            GuestSpkiFingerprint::from_hex(offer.peer.as_str())?,
        )?;
        Ok(Self {
            offer,
            receiver_spki,
            receiver_device: device,
            credential,
            issued_ms,
            expires_ms,
        })
    }
}

/// Strict fresh receiver-original-key RPK TLS, scoped to an existing ID.
/// No SAS owner reapproval or new Offer is possible on the ODGR dispatcher.
/// The caller must select a verified LAN network and pass its TCP stream;
/// this routine NEVER chooses default cellular/Internet routes.
pub fn recover_committed<T: Read + Write>(
    mut transport: T,
    identity: &LocalGuestIdentity,
    recovery: &PendingRecovery,
    active: Arc<AtomicBool>,
) -> Result<Receipt> {
    if !active.load(Ordering::Acquire)
        || now_ms()? < recovery.issued_ms
        || now_ms()? >= recovery.expires_ms
        || identity.public_key().fingerprint().to_hex() != recovery.offer.peer.as_str()
    {
        return Err(SendError::Protocol("recovery identity, clock or lifecycle"));
    }
    let client = identity.new_hello(TlsSide::Client, TransferSide::Sender)?;
    transport.write_all(b"ODGR")?;
    transport.write_all(recovery.offer.id.as_str().as_bytes())?;
    transport.write_all(&client.encoded())?;
    transport.flush()?;
    let mut bytes = [0u8; HELLO_LEN];
    transport.read_exact(&mut bytes)?;
    let server = GuestHello::parse(&bytes)?;
    if server.public_key() != &recovery.receiver_spki
        || server.device_id() != &recovery.receiver_device
    {
        return Err(SendError::Protocol("recovery receiver identity changed"));
    }
    let transcript = GuestTranscript::new(client, server)?;
    let config = guest_tls::client_config(identity, &transcript)?;
    let mut connection = ClientConnection::new(
        config,
        ServerName::try_from("opendrop.invalid")
            .map_err(|_| SendError::Protocol("recovery TLS name"))?
            .to_owned(),
    )
    .map_err(|_| SendError::Protocol("recovery client TLS"))?;
    let started = std::time::Instant::now();
    for _ in 0..ATTEMPTS {
        if !active.load(Ordering::Acquire) || started.elapsed() >= TICK_LIMIT {
            return Err(SendError::Cancelled);
        }
        if !connection.is_handshaking() {
            break;
        }
        match connection.complete_io(&mut transport) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err(SendError::Protocol("recovery exact-key TLS failed")),
        }
    }
    if connection.is_handshaking() {
        return Err(SendError::Protocol("recovery handshake budget"));
    }
    let verified = VerifiedReceiptOnlyTls::from_completed_client(&connection, transcript, active)?;
    if !verified.is_active()
        || verified.peer_public_key() != &recovery.receiver_spki
        || verified.local_public_key() != identity.public_key()
    {
        return Err(SendError::Protocol("recovery keys not original"));
    }
    let mut tls = StreamOwned::new(connection, transport);
    Frame::Control(Control::GuestReceiptQuery(
        recovery.offer.clone(),
        recovery.credential.clone(),
    ))
    .write_to(&mut tls)?;
    tls.flush()?;
    let received = Frame::read_from(&mut tls)
        .map_err(|_| SendError::Protocol("no committed recovery receipt"))?;
    match received {
        Frame::Control(Control::Complete(receipt))
            if verified.is_active()
                && receipt.transfer_id == recovery.offer.id
                && receipt.peer == recovery.offer.peer
                && receipt.manifest == recovery.offer.manifest
                && receipt.bytes == recovery.offer.bytes
                && receipt.sha256 == recovery.offer.sha256 =>
        {
            Ok(receipt)
        }
        _ => Err(SendError::Protocol("recovery receipt not exact")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_recovery_is_rejected_without_exposing_token() {
        assert!(PendingRecovery::decode_from_android_keystore(&[]).is_err());
        assert!(PendingRecovery::decode_from_android_keystore(&[0; 1025]).is_err());
        assert!(PendingRecovery::decode_from_android_keystore(b"ODAR\x02").is_err());
        assert!(!format!(
            "{:?}",
            WireRecoveryCredential::from_authenticated_bytes([1; 32]).unwrap()
        )
        .contains("11111111"));
    }
}
