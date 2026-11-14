//! Bounded, real mutually authenticated TLS sender, no parallel data plane.
use crate::{Result, SendError};
use opendrop_core::guest::{
    GuestHello, GuestTranscript, P256Spki, TlsSide, TransferSide, HELLO_LEN, PAIRING_DEADLINE,
};
use opendrop_core::guest_recovery::GuestOfferV1;
use opendrop_core::guest_tls::{
    self, AwaitingPeerConfirmation, GuestConfirmation, LocalGuestIdentity, ProvisionalTlsPeer,
    VerifiedGuestSession, CONFIRM_LEN,
};
use opendrop_core::identity::{Sha256Digest, TransferId};
use opendrop_core::journal::Receipt;
use opendrop_core::wire::{self, Control, Frame};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const INTRO_LIMIT: Duration = Duration::from_secs(8);
const FRAME_LIMIT: Duration = Duration::from_secs(8);
const TRANSFER_LIMIT: Duration = Duration::from_secs(600);
// The Linux owner has up to 125 seconds to accept an exact Offer after
// bilateral SAS. Waiting only a normal 8-second wire-frame budget here
// would cause a legitimate human-reviewed transfer to time out.
const OFFER_CONSENT_LIMIT: Duration = Duration::from_secs(125);
const COMPLETE_LIMIT: Duration = Duration::from_secs(45);
const FILE_CHUNK: usize = 32 * 1024;
const MAX_HANDSHAKE_ROUNDS: usize = 64;

fn check_active(active: &AtomicBool, deadline: Instant) -> Result<()> {
    if !active.load(Ordering::Acquire) {
        return Err(SendError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(SendError::Protocol("sender deadline exceeded"));
    }
    Ok(())
}

/// A per-operation deadline that survives short socket timeouts and
/// fragmentation; the Android transport must configure 250ms SO_RCVTIMEO.
pub(crate) struct DeadlineIo<'a, T> {
    pub(crate) inner: &'a mut T,
    pub(crate) deadline: Instant,
    pub(crate) active: &'a AtomicBool,
}

impl<T: Read> Read for DeadlineIo<'_, T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.active.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline"));
            }
            match self.inner.read(output) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl<T: Write> Write for DeadlineIo<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            if !self.active.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "write deadline"));
            }
            match self.inner.write(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn deadline(now: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(now)
        .ok_or(SendError::Protocol("deadline overflow"))
}

fn write_control<T: Read + Write>(
    tls: &mut StreamOwned<ClientConnection, T>,
    value: Control,
    active: &AtomicBool,
) -> Result<()> {
    Frame::Control(value).write_to(&mut DeadlineIo {
        inner: tls,
        deadline: deadline(FRAME_LIMIT)?,
        active,
    })?;
    tls.flush()?;
    Ok(())
}

fn read_frame<T: Read + Write>(
    tls: &mut StreamOwned<ClientConnection, T>,
    active: &AtomicBool,
    limit: Duration,
) -> Result<Frame> {
    Ok(Frame::read_from(&mut DeadlineIo {
        inner: tls,
        deadline: deadline(limit)?,
        active,
    })?)
}

/// Stream a URI twice rather than loading it. A provider may change or
/// revoke its grant between passes: a second hashing pass at send time and
/// receiver-side independent digest both reject mutated content.
pub fn prehash_source(
    source: &mut impl Read,
    declared_size: Option<u64>,
) -> Result<(u64, Sha256Digest)> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut block = [0u8; FILE_CHUNK];
    loop {
        let count = source.read(&mut block)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(SendError::Protocol("file length overflow"))?;
        if total > wire::MAX_FILE {
            return Err(SendError::Protocol("file exceeds 64 MiB guest limit"));
        }
        hash.update(&block[..count]);
    }
    if declared_size.is_some_and(|claimed| claimed != total) {
        return Err(SendError::Protocol(
            "source provider declared inconsistent size",
        ));
    }
    Ok((total, Sha256Digest::parse(&hex_sha(&hash.finalize()))?))
}

fn hex_sha(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(digest.len() * 2);
    for part in digest {
        write!(&mut text, "{part:02x}").expect("write hex to String");
    }
    text
}

/// Construct the existing S1 FileOffer (one per TLS session), not a second
/// wire format. MIME is metadata for Android's local UI only; S1 wire does not
/// yet convey MIME and the sender must not claim otherwise.
pub fn prepare_offer(
    identity: &LocalGuestIdentity,
    name: &str,
    size: u64,
    digest: Sha256Digest,
) -> Result<GuestOfferV1> {
    opendrop_core::identity::validate_file_name(name)?;
    if size > wire::MAX_FILE {
        return Err(SendError::Protocol("file too large"));
    }
    let mut id = [0u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| SendError::Protocol("unavailable OS randomness"))?;
    let transfer_id = TransferId::parse(&hex_sha(&id))?;
    let mut manifest = Sha256::new();
    manifest.update(b"OpenDrop/S1/SingleFileManifest/v1\0");
    manifest.update((name.len() as u16).to_be_bytes());
    manifest.update(name.as_bytes());
    manifest.update(size.to_be_bytes());
    manifest.update(digest.as_str().as_bytes());
    let manifest = Sha256Digest::parse(&hex_sha(&manifest.finalize()))?;
    Ok(GuestOfferV1::new(
        transfer_id,
        identity.public_key().fingerprint(),
        manifest,
        name.to_owned(),
        size,
        digest,
    )?)
}

/// Android's network binding and LAN-route selection live OUTSIDE the wire
/// layer. Transport may be a hosted loopback TcpStream or a network-specific
/// Android socket, and the TLS role is independent from logical file roles.
pub struct PendingPairing<T: Read + Write> {
    tls: StreamOwned<ClientConnection, T>,
    provisional: ProvisionalTlsPeer,
    receiver_spki: P256Spki,
    receiver_device: opendrop_core::identity::DeviceId,
    active: Arc<AtomicBool>,
}

pub fn connect_guest<T: Read + Write>(
    mut stream: T,
    identity: &LocalGuestIdentity,
    active: Arc<AtomicBool>,
) -> Result<PendingPairing<T>> {
    let started = deadline(INTRO_LIMIT)?;
    let client = identity.new_hello(TlsSide::Client, TransferSide::Sender)?;
    DeadlineIo {
        inner: &mut stream,
        deadline: started,
        active: active.as_ref(),
    }
    .write_all(&client.encoded())?;
    stream.flush()?;
    let mut bytes = [0u8; HELLO_LEN];
    DeadlineIo {
        inner: &mut stream,
        deadline: started,
        active: active.as_ref(),
    }
    .read_exact(&mut bytes)?;
    let server = GuestHello::parse(&bytes)?;
    let receiver_spki = server.public_key().clone();
    let receiver_device = server.device_id().clone();
    let transcript = GuestTranscript::new(client, server)?;
    if transcript.server().transfer_side() != TransferSide::Receiver {
        return Err(SendError::Protocol("peer is not a file receiver"));
    }
    let config = guest_tls::client_config(identity, &transcript)?;
    let mut connection = ClientConnection::new(
        config,
        ServerName::try_from("opendrop.invalid")
            .map_err(|_| SendError::Protocol("internal server name"))?
            .to_owned(),
    )
    .map_err(|_| SendError::Protocol("TLS client configuration failed"))?;
    let handshake_deadline = deadline(INTRO_LIMIT)?;
    for _ in 0..MAX_HANDSHAKE_ROUNDS {
        check_active(active.as_ref(), handshake_deadline)?;
        if !connection.is_handshaking() {
            break;
        }
        let mut io = DeadlineIo {
            inner: &mut stream,
            deadline: handshake_deadline,
            active: active.as_ref(),
        };
        match connection.complete_io(&mut io) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err(SendError::Protocol("strict mutual raw-key TLS failed")),
        }
    }
    if connection.is_handshaking() {
        return Err(SendError::Protocol("TLS handshake budget exceeded"));
    }
    let provisional =
        ProvisionalTlsPeer::from_completed_client(&connection, transcript, active.clone())?;
    Ok(PendingPairing {
        tls: StreamOwned::new(connection, stream),
        provisional,
        receiver_spki,
        receiver_device,
        active,
    })
}

pub struct AuthenticatedSender<T: Read + Write> {
    tls: StreamOwned<ClientConnection, T>,
    verified: VerifiedGuestSession,
    receiver_spki: P256Spki,
    receiver_device: opendrop_core::identity::DeviceId,
    active: Arc<AtomicBool>,
}

impl<T: Read + Write> PendingPairing<T> {
    pub fn displayed_code(&self) -> &str {
        self.provisional.displayed_code()
    }

    #[cfg(target_os = "android")]
    pub fn confirm_in_android_owner_ui(self) -> Result<AuthenticatedSender<T>> {
        let approved = self.provisional.request_android_owner_sas()?;
        finish_sas(
            self.tls,
            approved,
            self.receiver_spki,
            self.receiver_device,
            self.active,
        )
    }

    #[cfg(all(feature = "hosted-guest-fixture", debug_assertions))]
    #[doc(hidden)]
    pub fn confirm_for_hosted_fixture(self) -> Result<AuthenticatedSender<T>> {
        let approved = self.provisional.approve_sas_for_hosted_guest_fixture()?;
        finish_sas(
            self.tls,
            approved,
            self.receiver_spki,
            self.receiver_device,
            self.active,
        )
    }
}

fn finish_sas<T: Read + Write>(
    mut tls: StreamOwned<ClientConnection, T>,
    approved: AwaitingPeerConfirmation,
    receiver_spki: P256Spki,
    receiver_device: opendrop_core::identity::DeviceId,
    active: Arc<AtomicBool>,
) -> Result<AuthenticatedSender<T>> {
    let outgoing = approved.outgoing_confirmation()?;
    DeadlineIo {
        inner: &mut tls,
        deadline: deadline(PAIRING_DEADLINE)?,
        active: active.as_ref(),
    }
    .write_all(outgoing.encoded())?;
    tls.flush()?;
    let mut input = [0u8; CONFIRM_LEN];
    DeadlineIo {
        inner: &mut tls,
        deadline: deadline(PAIRING_DEADLINE)?,
        active: active.as_ref(),
    }
    .read_exact(&mut input)?;
    let peer = GuestConfirmation::parse(&input)?;
    let verified = approved.verify_peer_then_finish(&peer)?;
    if !verified.is_active()
        || verified.local_transfer_side() != TransferSide::Sender
        || verified.logical_receiver_spki() != receiver_spki.fingerprint()
    {
        return Err(SendError::Protocol(
            "SAS role or receiver identity mismatch",
        ));
    }
    Ok(AuthenticatedSender {
        tls,
        verified,
        receiver_spki,
        receiver_device,
        active,
    })
}

impl<T: Read + Write> AuthenticatedSender<T> {
    /// Transfer one exact S1 Offer. A recovery verifier must be durably
    /// encrypted before ANY file byte is sent after GuestReady.
    pub fn send_one(
        mut self,
        offered: &GuestOfferV1,
        source: &mut impl Read,
        persist_recovery: impl FnOnce(&crate::recovery::PendingRecovery) -> Result<()>,
    ) -> Result<Receipt> {
        if !self.verified.is_active() || offered.sender() != self.verified.logical_sender_spki() {
            return Err(SendError::Protocol("wrong offer sender/session"));
        }
        let active = self.active.as_ref();
        write_control(
            &mut self.tls,
            Control::Offer(offered.file_offer().clone()),
            active,
        )?;
        let credential = match read_frame(&mut self.tls, active, OFFER_CONSENT_LIMIT)? {
            Frame::Control(Control::GuestReady(id, token)) if id == *offered.id() => token,
            Frame::Control(Control::Decline(_) | Control::Cancel(_) | Control::Failure(_)) => {
                return Err(SendError::Rejected)
            }
            _ => return Err(SendError::Protocol("unexpected ready response")),
        };
        let recovery = crate::recovery::PendingRecovery::new(
            offered.file_offer().clone(),
            self.verified.logical_sender_spki(),
            self.receiver_spki,
            self.receiver_device,
            credential,
        )?;
        persist_recovery(&recovery)?;

        let deadline = deadline(TRANSFER_LIMIT)?;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; FILE_CHUNK];
        loop {
            check_active(active, deadline)?;
            let len = source.read(&mut buffer)?;
            if len == 0 {
                break;
            }
            count = count
                .checked_add(len as u64)
                .ok_or(SendError::Protocol("source length overflow"))?;
            if count > offered.file_offer().bytes {
                return Err(SendError::Protocol("source mutated after prehash"));
            }
            hash.update(&buffer[..len]);
            Frame::Data(buffer[..len].to_vec()).write_to(&mut DeadlineIo {
                inner: &mut self.tls,
                deadline,
                active,
            })?;
        }
        if count != offered.file_offer().bytes
            || hex_sha(&hash.finalize()) != offered.file_offer().sha256.as_str()
        {
            return Err(SendError::Protocol(
                "source hash/length changed during streaming",
            ));
        }
        write_control(&mut self.tls, Control::End(offered.id().clone()), active)?;
        let reply = read_frame(&mut self.tls, active, COMPLETE_LIMIT)
            .map_err(|_| SendError::UncertainCompletion)?;
        match reply {
            Frame::Control(Control::Complete(receipt))
                if self.verified.is_active()
                    && receipt.transfer_id == *offered.id()
                    && receipt.peer == offered.file_offer().peer
                    && receipt.manifest == offered.file_offer().manifest
                    && receipt.bytes == offered.file_offer().bytes
                    && receipt.sha256 == offered.file_offer().sha256 =>
            {
                Ok(receipt)
            }
            _ => Err(SendError::UncertainCompletion),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_source_unknown_size_hashes_exact_bytes_without_buffering_whole_file() {
        let data: Vec<u8> = (0..109_007).map(|i| (i % 251) as u8).collect();
        let (size, hash) = prehash_source(&mut io::Cursor::new(&data), None).unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(hash.as_str(), hex_sha(&Sha256::digest(&data)));
        let error = prehash_source(&mut io::Cursor::new(&data), Some(size + 1)).unwrap_err();
        assert!(matches!(error, SendError::Protocol(_)));
    }

    struct RevokedUriReader;
    impl Read for RevokedUriReader {
        fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "content URI revoked",
            ))
        }
    }

    #[test]
    fn revoked_uri_permission_fails_closed_without_an_offer() {
        assert!(matches!(
            prehash_source(&mut RevokedUriReader, None),
            Err(SendError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    struct UnlimitedUri {
        remaining: u64,
    }
    impl Read for UnlimitedUri {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let take = bytes.len().min(self.remaining as usize);
            bytes[..take].fill(0x66);
            self.remaining -= take as u64;
            Ok(take)
        }
    }

    #[test]
    fn unknown_size_stream_cannot_bypass_wire_64mib_limit() {
        let mut source = UnlimitedUri {
            remaining: wire::MAX_FILE + 1,
        };
        assert!(matches!(
            prehash_source(&mut source, None),
            Err(SendError::Protocol(_))
        ));
    }

    #[test]
    fn cancelled_transport_does_not_read_any_more_bytes() {
        let live = AtomicBool::new(false);
        let mut underlying = io::Cursor::new(b"secret".to_vec());
        let mut guarded = DeadlineIo {
            inner: &mut underlying,
            deadline: deadline(Duration::from_secs(1)).unwrap(),
            active: &live,
        };
        assert_eq!(
            guarded.read(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(underlying.position(), 0);
    }
}
