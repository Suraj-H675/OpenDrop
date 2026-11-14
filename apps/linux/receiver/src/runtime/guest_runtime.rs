//! S1 guest admission for the existing foreground receiver. The provisional
//! and receipt-only channels are strictly separate from legacy paired mTLS
//! and from the shared durable file publication engine.

use super::{
    receive_verified_stream, serve_one, FrameDeadlineReader, UiEvent, CONSENT_LIMIT, FRAME_LIMIT,
    HANDSHAKE_LIMIT, IO_TICK, OFFER_LIMIT,
};
use opendrop_core::guest::{
    GuestAdmission, GuestHello, GuestTranscript, TlsSide, TransferSide, HELLO_LEN,
};
use opendrop_core::guest_recovery::{GuestOfferV1, GuestRecoveryCredential};
use opendrop_core::guest_tls::{
    self, AwaitingPeerConfirmation, GuestConfirmation, LocalGuestIdentity, ProvisionalTlsPeer,
    VerifiedGuestSession, VerifiedReceiptOnlyTls, CONFIRM_LEN,
};
use opendrop_core::identity::TransferId;
use opendrop_core::journal::Journal;
use opendrop_core::wire::{Control, Frame, WireRecoveryCredential};
use opendrop_linux_receiver::ForegroundLinuxReceiver;
use rustls::{ServerConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const RECOVERY_MAGIC: &[u8; 4] = b"ODGR";
const RECOVERY_PREFACE_LEN: usize = 4 + 32 + HELLO_LEN;
const HANDSHAKE_ATTEMPTS: usize = 64;

pub(super) struct GuestConfig {
    pub identity: Arc<LocalGuestIdentity>,
    pub admission: Arc<Mutex<GuestAdmission>>,
    pub live: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

pub(super) struct GuestSasRequest {
    pub provisional: ProvisionalTlsPeer,
    pub result: SyncSender<Option<AwaitingPeerConfirmation>>,
}

pub(super) struct GuestOfferRequest {
    pub verified: VerifiedGuestSession,
    pub offer: GuestOfferV1,
    pub active: Arc<AtomicBool>,
    pub result: SyncSender<Option<(ForegroundLinuxReceiver, GuestRecoveryCredential)>>,
}

struct GuestTransportGuard {
    live: Arc<AtomicBool>,
    global: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl Drop for GuestTransportGuard {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
        if let Ok(mut slot) = self.global.lock() {
            if slot
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &self.live))
            {
                *slot = None;
            }
        }
    }
}

fn connected_guest(guest: &GuestConfig) -> Result<GuestTransportGuard, &'static str> {
    let live = Arc::new(AtomicBool::new(true));
    let mut slot = guest.live.lock().map_err(|_| "guest session lock")?;
    if slot.as_ref().is_some_and(|old| old.load(Ordering::Acquire)) {
        return Err("guest already connected");
    }
    *slot = Some(live.clone());
    Ok(GuestTransportGuard {
        live,
        global: guest.live.clone(),
    })
}

fn read_tcp(
    socket: &mut TcpStream,
    data: &mut [u8],
    running: &AtomicBool,
    live: &AtomicBool,
) -> Result<(), &'static str> {
    let started = Instant::now();
    let mut offset = 0;
    while offset < data.len() {
        if !running.load(Ordering::Acquire)
            || !live.load(Ordering::Acquire)
            || started.elapsed() >= HANDSHAKE_LIMIT
        {
            return Err("guest introduction timeout");
        }
        match socket.read(&mut data[offset..]) {
            Ok(0) => return Err("closed guest introduction"),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("invalid guest introduction"),
        }
    }
    Ok(())
}

fn complete_rpk_tls(
    socket: &mut TcpStream,
    transcript: &GuestTranscript,
    identity: &LocalGuestIdentity,
    running: &AtomicBool,
    active: &AtomicBool,
) -> Result<ServerConnection, &'static str> {
    let config = guest_tls::server_config(identity, transcript).map_err(|_| "guest TLS keys")?;
    let mut connection = ServerConnection::new(config).map_err(|_| "guest TLS configuration")?;
    let start = Instant::now();
    for _ in 0..HANDSHAKE_ATTEMPTS {
        if !running.load(Ordering::Acquire)
            || !active.load(Ordering::Acquire)
            || start.elapsed() >= HANDSHAKE_LIMIT
        {
            return Err("guest TLS deadline or cancellation");
        }
        match connection.complete_io(socket) {
            Ok(_) if !connection.is_handshaking() => return Ok(connection),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("guest RPK authentication failed"),
        }
    }
    Err("guest TLS handshake budget")
}

/// Peek only four bounded bytes; a legacy TLS ClientHello begins with 0x16,
/// whereas guest prefaces are ODGH/ODGR. Neither mode may fall back to the
/// other after a rejected key or malformed introduction.
pub(super) fn route_connection(
    mut socket: TcpStream,
    paired: Option<Arc<rustls::ServerConfig>>,
    guest: Option<&Arc<GuestConfig>>,
    journal_path: &Path,
    ui: &SyncSender<UiEvent>,
    running: &AtomicBool,
) -> Result<(), &'static str> {
    socket
        .set_read_timeout(Some(IO_TICK))
        .map_err(|_| "socket read")?;
    socket
        .set_write_timeout(Some(IO_TICK))
        .map_err(|_| "socket write")?;
    let start = Instant::now();
    let mut prefix = [0u8; 4];
    loop {
        if !running.load(Ordering::Acquire) || start.elapsed() >= HANDSHAKE_LIMIT {
            return Err("connection preface timeout");
        }
        match socket.peek(&mut prefix) {
            Ok(0) => return Err("connection closed before preface"),
            Ok(count) if count == prefix.len() => break,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("unreadable connection preface"),
        }
    }
    match &prefix {
        b"ODGH" => serve_guest(
            socket,
            guest.ok_or("guest identity not provisioned")?,
            journal_path,
            ui,
            running,
        ),
        RECOVERY_MAGIC => serve_recovery(
            socket,
            guest.ok_or("guest receipt recovery unavailable")?,
            journal_path,
            running,
        ),
        _ => {
            let paired = paired.ok_or("no legacy paired TLS identity configured")?;
            serve_one(socket, paired, journal_path, ui, running)
        }
    }
}

fn await_local<T>(
    tls: &mut StreamOwned<ServerConnection, TcpStream>,
    result: &Receiver<Option<T>>,
    live: &AtomicBool,
    running: &AtomicBool,
    limit: Duration,
) -> Result<T, &'static str> {
    let start = Instant::now();
    let mut early = [0u8; 1];
    loop {
        if !running.load(Ordering::Acquire)
            || !live.load(Ordering::Acquire)
            || start.elapsed() >= limit
        {
            return Err("guest owner verification expired or revoked");
        }
        match result.try_recv() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => return Err("guest owner declined or dismissed"),
            Err(TryRecvError::Disconnected) => return Err("guest owner UI disconnected"),
            Err(TryRecvError::Empty) => {}
        }
        match tls.read(&mut early) {
            Ok(0) => return Err("guest TLS closed"),
            Ok(_) => return Err("guest sent bytes before owner verification"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("guest TLS interrupted"),
        }
    }
}

/// Only the fixed-size, role-tagged cryptographic confirmation is allowed to
/// arrive while the Linux owner is reviewing the SAS. This is NOT owner
/// consent: the pending bytes stay on the stack of this one live TLS session
/// and are authenticated against that session's exporter only AFTER the
/// genuine Qt "Codes match" action returns an opaque local capability.
///
/// The generic owner result makes the transport state machine unit-testable
/// without minting any test approval token in the production executable.
struct PendingPeerConfirmation {
    bytes: [u8; CONFIRM_LEN],
    received: usize,
}

impl PendingPeerConfirmation {
    fn new() -> Self {
        Self {
            bytes: [0; CONFIRM_LEN],
            received: 0,
        }
    }

    fn validate_prefix(&self) -> Result<(), &'static str> {
        if self.received >= 4 && &self.bytes[..4] != b"ODGC" {
            return Err("guest sent non-confirmation before owner verification");
        }
        if self.received >= 6 && (self.bytes[4] != 1 || self.bytes[5] != TlsSide::Client as u8) {
            return Err("guest sent malformed or wrong-role early confirmation");
        }
        Ok(())
    }

    fn complete(&self) -> Result<GuestConfirmation, &'static str> {
        if self.received != CONFIRM_LEN {
            return Err("guest confirmation incomplete");
        }
        GuestConfirmation::parse(&self.bytes).map_err(|_| "invalid guest confirmation")
    }
}

fn await_sas_owner_with_pending<R: Read, T>(
    tls: &mut R,
    result: &Receiver<Option<T>>,
    live: &AtomicBool,
    running: &AtomicBool,
    limit: Duration,
) -> Result<(T, PendingPeerConfirmation), &'static str> {
    let started = Instant::now();
    let mut pending = PendingPeerConfirmation::new();
    let mut extra = [0u8; 1];
    loop {
        if !running.load(Ordering::Acquire)
            || !live.load(Ordering::Acquire)
            || started.elapsed() >= limit
        {
            return Err("guest owner verification expired or revoked");
        }
        // Inspect one bounded TLS application read even when the Qt action
        // has just arrived: queued peer data must not hide an early Offer or
        // duplicate confirmation behind a legitimate 38-byte role proof.
        let target = if pending.received == CONFIRM_LEN {
            &mut extra[..]
        } else {
            &mut pending.bytes[pending.received..]
        };
        let just_completed = match tls.read(target) {
            Ok(0) => return Err("guest TLS closed during SAS verification"),
            Ok(count) if pending.received == CONFIRM_LEN && count != 0 => {
                return Err("guest sent extra bytes before bilateral SAS")
            }
            Ok(count) => {
                pending.received += count;
                pending.validate_prefix()?;
                if pending.received == CONFIRM_LEN {
                    pending.complete()?;
                }
                count != 0 && pending.received == CONFIRM_LEN
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                false
            }
            Err(_) => return Err("guest TLS interrupted during SAS verification"),
        };
        if just_completed {
            // A trailing Offer or duplicated proof can be buffered in the
            // same decrypted TLS record. Check it before consuming a Qt
            // approval that arrived during the final proof read.
            continue;
        }
        match result.try_recv() {
            Ok(Some(owner_action)) => return Ok((owner_action, pending)),
            Ok(None) => return Err("guest owner declined or dismissed"),
            Err(TryRecvError::Disconnected) => return Err("guest owner UI disconnected"),
            Err(TryRecvError::Empty) => {}
        }
    }
}

fn serve_guest(
    mut socket: TcpStream,
    guest: &GuestConfig,
    journal_path: &Path,
    ui: &SyncSender<UiEvent>,
    running: &AtomicBool,
) -> Result<(), &'static str> {
    // No reply or stable local SPKI before local Everyone is active.
    let permit = guest
        .admission
        .lock()
        .map_err(|_| "guest admission lock")?
        .admit()
        .map_err(|_| "guest visibility closed")?;
    let transport = connected_guest(guest)?;
    let mut hello = [0u8; HELLO_LEN];
    read_tcp(&mut socket, &mut hello, running, &transport.live)?;
    let client = GuestHello::parse(&hello).map_err(|_| "invalid guest hello")?;
    let server = guest
        .identity
        .new_hello(TlsSide::Server, TransferSide::Receiver)
        .map_err(|_| "local guest introduction")?;
    let transcript = GuestTranscript::new(client, server.clone())
        .map_err(|_| "guest roles or key reflection")?;
    // A withdrawn Everyone grant must not disclose the owner's stable SPKI
    // even if the untrusted peer raced to finish its targeted introduction.
    if !running.load(Ordering::Acquire)
        || !transport.live.load(Ordering::Acquire)
        || !permit.is_active()
    {
        return Err("guest visibility or transport revoked before identity reply");
    }
    socket
        .write_all(&server.encoded())
        .map_err(|_| "guest introduction reply")?;
    let connection = complete_rpk_tls(
        &mut socket,
        &transcript,
        &guest.identity,
        running,
        &transport.live,
    )?;
    let provisional = ProvisionalTlsPeer::from_completed_server(
        &connection,
        transcript,
        transport.live.clone(),
        permit,
    )
    .map_err(|_| "guest TLS provisional validation")?;
    let mut tls = StreamOwned::new(connection, socket);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    ui.send(UiEvent::GuestSas(GuestSasRequest {
        provisional,
        result: result_tx,
    }))
    .map_err(|_| "guest SAS UI unavailable")?;
    let (locally_verified, mut pending_peer) = await_sas_owner_with_pending(
        &mut tls,
        &result_rx,
        &transport.live,
        running,
        CONSENT_LIMIT,
    )?;
    let proof = locally_verified
        .outgoing_confirmation()
        .map_err(|_| "guest SAS expired before confirmation")?;
    tls.write_all(proof.encoded())
        .map_err(|_| "guest confirmation send")?;
    tls.flush().map_err(|_| "guest confirmation flush")?;
    if pending_peer.received < CONFIRM_LEN {
        FrameDeadlineReader {
            input: &mut tls,
            started: Instant::now(),
            limit: FRAME_LIMIT,
            running,
            session_active: Some(transport.live.as_ref()),
        }
        .read_exact(&mut pending_peer.bytes[pending_peer.received..])
        .map_err(|_| "guest confirmation not received")?;
        pending_peer.received = CONFIRM_LEN;
    }
    let peer_proof = pending_peer.complete()?;
    let verified = locally_verified
        .verify_peer_then_finish(&peer_proof)
        .map_err(|_| "guest bilateral SAS not verified")?;
    if !verified.is_active() {
        return Err("guest admission revoked");
    }
    let offer = match super::read_with_deadline(
        &mut tls,
        OFFER_LIMIT,
        running,
        Some(transport.live.as_ref()),
    )? {
        Frame::Control(Control::Offer(offer)) => {
            GuestOfferV1::from_verified_wire_offer(offer, verified.logical_sender_spki())
                .map_err(|_| "guest offer sender/key mismatch")?
        }
        _ => return Err("guest sent non-offer after SAS verification"),
    };
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    ui.send(UiEvent::GuestOffer(GuestOfferRequest {
        verified,
        offer,
        active: transport.live.clone(),
        result: result_tx,
    }))
    .map_err(|_| "guest exact-offer UI unavailable")?;
    let (receiver, token) = await_local(
        &mut tls,
        &result_rx,
        &transport.live,
        running,
        CONSENT_LIMIT,
    )?;
    let token = WireRecoveryCredential::from_authenticated_bytes(*token.as_bytes())
        .map_err(|_| "invalid guest receipt credential")?;
    let cancellation =
        opendrop_linux_receiver::SessionCancellation::from_transport_flag(transport.live.clone());
    let journal = Journal::open(journal_path).map_err(|_| "guest durable journal")?;
    receive_verified_stream(tls, receiver, cancellation, journal, running, Some(token))
}

fn serve_recovery(
    mut socket: TcpStream,
    guest: &GuestConfig,
    journal_path: &Path,
    running: &AtomicBool,
) -> Result<(), &'static str> {
    let transport = connected_guest(guest)?;
    let mut introduction = [0u8; RECOVERY_PREFACE_LEN];
    read_tcp(&mut socket, &mut introduction, running, &transport.live)?;
    if &introduction[..4] != RECOVERY_MAGIC {
        return Err("invalid guest recovery preface");
    }
    let id_text = std::str::from_utf8(&introduction[4..36])
        .map_err(|_| "invalid guest recovery transfer ID")?;
    let id = TransferId::parse(id_text).map_err(|_| "invalid guest recovery transfer ID")?;
    let client =
        GuestHello::parse(&introduction[36..]).map_err(|_| "invalid recovery guest hello")?;
    if client.public_key() == guest.identity.public_key() {
        return Err("reflected guest recovery identity");
    }
    let journal = Journal::open(journal_path).map_err(|_| "private journal")?;
    let scope = journal
        .guest_recovery_scope_for_targeted_tls(
            &id,
            client.public_key(),
            guest.identity.public_key(),
        )
        .map_err(|_| "unavailable guest recovery scope")?
        .ok_or("no authorized matching guest receipt recovery")?;
    let server = guest
        .identity
        .new_hello(TlsSide::Server, TransferSide::Receiver)
        .map_err(|_| "local receipt recovery introduction")?;
    let transcript = GuestTranscript::new(client, server.clone())
        .map_err(|_| "guest receipt recovery role mismatch")?;
    if !running.load(Ordering::Acquire) || !transport.live.load(Ordering::Acquire) {
        return Err("guest recovery transport revoked before identity reply");
    }
    socket
        .write_all(&server.encoded())
        .map_err(|_| "recovery server hello")?;
    let connection = complete_rpk_tls(
        &mut socket,
        &transcript,
        &guest.identity,
        running,
        &transport.live,
    )?;
    let receipt_tls = VerifiedReceiptOnlyTls::from_completed_server(
        &connection,
        transcript,
        transport.live.clone(),
    )
    .map_err(|_| "unverified guest recovery TLS")?;
    let mut tls = StreamOwned::new(connection, socket);
    match super::read_with_deadline(
        &mut tls,
        FRAME_LIMIT,
        running,
        Some(transport.live.as_ref()),
    )? {
        Frame::Control(Control::GuestReceiptQuery(offer, credential))
            if &offer == scope.file_offer() =>
        {
            let credential =
                GuestRecoveryCredential::from_transmitted_bytes(*credential.as_bytes())
                    .map_err(|_| "invalid guest recovery proof")?;
            if let Some(committed) = journal
                .query_guest_committed_receipt(&receipt_tls, &scope, &credential)
                .map_err(|_| "guest recovery rejected")?
            {
                let complete = opendrop_core::journal::Receipt {
                    transfer_id: committed.transfer_id,
                    peer: offer.peer,
                    manifest: committed.manifest,
                    bytes: committed.bytes,
                    sha256: committed.sha256,
                };
                Frame::Control(Control::Complete(complete))
                    .write_to(&mut tls)
                    .map_err(|_| "write recovered receipt")?;
                tls.flush().map_err(|_| "flush recovered receipt")?;
            }
            Ok(())
        }
        _ => Err("only exact existing committed receipt recovery is permitted"),
    }
}

#[cfg(test)]
mod confirmation_order_tests {
    use super::*;

    struct ScriptedTlsPlaintext {
        bytes: Vec<u8>,
        cursor: usize,
    }

    impl ScriptedTlsPlaintext {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, cursor: 0 }
        }
    }

    impl Read for ScriptedTlsPlaintext {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.cursor == self.bytes.len() {
                std::thread::yield_now();
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = output.len().min(self.bytes.len() - self.cursor);
            output[..count].copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
            self.cursor += count;
            Ok(count)
        }
    }

    fn plausible_client_confirmation() -> Vec<u8> {
        let mut bytes = vec![0; CONFIRM_LEN];
        bytes[..4].copy_from_slice(b"ODGC");
        bytes[4] = 1;
        bytes[5] = TlsSide::Client as u8;
        bytes
    }

    fn wait_for<T>(
        reader: &mut ScriptedTlsPlaintext,
        result: &Receiver<Option<T>>,
    ) -> Result<(T, PendingPeerConfirmation), &'static str> {
        let running = AtomicBool::new(true);
        let live = AtomicBool::new(true);
        await_sas_owner_with_pending(reader, result, &live, &running, Duration::from_millis(300))
    }

    #[test]
    fn linux_owner_can_confirm_before_peer_without_receiving_any_peer_bytes() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(Some("local-owner-approved")).unwrap();
        let (owner, pending) = wait_for(&mut ScriptedTlsPlaintext::new(Vec::new()), &rx).unwrap();
        assert_eq!(owner, "local-owner-approved");
        assert_eq!(pending.received, 0);
        assert!(pending.complete().is_err());
    }

    #[test]
    fn peer_can_confirm_first_but_has_no_authority_until_local_owner_approves() {
        let (tx, rx) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            tx.send(Some("local-owner-approved")).unwrap();
        });
        let mut input = ScriptedTlsPlaintext::new(plausible_client_confirmation());
        let (owner, pending) = wait_for(&mut input, &rx).unwrap();
        thread.join().unwrap();
        assert_eq!(owner, "local-owner-approved");
        assert_eq!(pending.received, CONFIRM_LEN);
        assert_eq!(
            pending.complete().unwrap().encoded().as_slice(),
            &plausible_client_confirmation()
        );
        // Parsing a role-tagged packet is not a valid cryptographic MAC,
        // a genuine owner approval or authorization to stage a file.
    }

    #[test]
    fn early_offer_behind_proof_and_duplicate_proof_are_rejected_even_if_owner_clicked() {
        for illegal in [vec![0, 0, 0, 12], plausible_client_confirmation()] {
            let (tx, rx) = mpsc::sync_channel(1);
            tx.send(Some(())).unwrap();
            let mut malicious = plausible_client_confirmation();
            malicious.extend_from_slice(&illegal);
            assert!(wait_for(&mut ScriptedTlsPlaintext::new(malicious), &rx).is_err());
        }
    }

    #[test]
    fn malformed_wrong_role_and_unexpected_early_data_are_rejected() {
        let mut malformed = plausible_client_confirmation();
        malformed[5] = TlsSide::Server as u8;
        for input in [malformed, b"BAD!!".to_vec(), b"UNEXPECTED OFFER".to_vec()] {
            let (tx, rx) = mpsc::sync_channel(1);
            tx.send(Some(())).unwrap();
            assert!(wait_for(&mut ScriptedTlsPlaintext::new(input), &rx).is_err());
        }
    }

    #[test]
    fn timeouts_cancel_and_owner_disconnection_cannot_finish_sas() {
        let (_tx, rx) = mpsc::sync_channel::<Option<()>>(1);
        let running = AtomicBool::new(true);
        let live = AtomicBool::new(true);
        let mut input = ScriptedTlsPlaintext::new(plausible_client_confirmation());
        assert!(
            await_sas_owner_with_pending(&mut input, &rx, &live, &running, Duration::ZERO,)
                .is_err()
        );
        live.store(false, Ordering::Release);
        assert!(await_sas_owner_with_pending(
            &mut input,
            &rx,
            &live,
            &running,
            Duration::from_secs(1),
        )
        .is_err());
        let (tx, rx) = mpsc::sync_channel::<Option<()>>(1);
        drop(tx);
        assert!(wait_for(&mut ScriptedTlsPlaintext::new(Vec::new()), &rx).is_err());
    }
}

/// This module is *only* built by the dedicated GitHub-hosted test feature.
/// Production never has a software signing key, a synthetic owner-action
/// issuer, or a CLI switch to use them. The native receiver socket dispatcher,
/// mutual rustls channel, wire, existing stage/publisher, durable journal and
/// restricted recovery dispatcher are all the production implementations.
#[cfg(all(test, feature = "hosted-guest-fixture"))]
mod hosted_socket_tests {
    use super::*;
    use opendrop_core::guest_tls::NativeP256Signer;
    use opendrop_core::identity::{DeviceId, Sha256Digest, TransferId};
    use opendrop_core::journal::{FileOffer, Receipt};
    use opendrop_linux_receiver::storage::LinuxReceiverStorage;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, StreamOwned};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::net::{SocketAddr, TcpListener};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::thread;

    struct VolatileCiSigner {
        key: EcdsaKeyPair,
        spki: Vec<u8>,
    }
    impl std::fmt::Debug for VolatileCiSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("VolatileCiSigner(TEST-ONLY; secret redacted)")
        }
    }
    impl NativeP256Signer for VolatileCiSigner {
        fn canonical_public_spki_der(&self) -> Result<Vec<u8>, opendrop_core::Error> {
            Ok(self.spki.clone())
        }
        fn sign_ecdsa_p256_sha256_der(
            &self,
            message: &[u8],
        ) -> Result<Vec<u8>, opendrop_core::Error> {
            self.key
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| opendrop_core::Error::Unauthorized)
        }
    }

    fn volatile_identity(tag: char) -> Arc<LocalGuestIdentity> {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                .unwrap();
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(key.public_key().as_ref());
        Arc::new(
            LocalGuestIdentity::from_platform_signer(
                DeviceId::parse(&tag.to_string().repeat(32)).unwrap(),
                Arc::new(VolatileCiSigner { key, spki }),
            )
            .unwrap(),
        )
    }

    fn guest_client(
        addr: SocketAddr,
        local: &LocalGuestIdentity,
        receipt_only: Option<&TransferId>,
    ) -> Result<(StreamOwned<ClientConnection, TcpStream>, ProvisionalTlsPeer), String> {
        let mut socket = TcpStream::connect(addr).map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let hello = local
            .new_hello(TlsSide::Client, TransferSide::Sender)
            .unwrap();
        if let Some(id) = receipt_only {
            socket.write_all(b"ODGR").map_err(|e| e.to_string())?;
            socket
                .write_all(id.as_str().as_bytes())
                .map_err(|e| e.to_string())?;
        }
        socket
            .write_all(&hello.encoded())
            .map_err(|e| e.to_string())?;
        let mut reply = [0u8; HELLO_LEN];
        socket.read_exact(&mut reply).map_err(|e| e.to_string())?;
        let server_hello = GuestHello::parse(&reply).map_err(|e| e.to_string())?;
        let transcript = GuestTranscript::new(hello, server_hello).map_err(|e| e.to_string())?;
        let config = guest_tls::client_config(local, &transcript).map_err(|e| e.to_string())?;
        let mut connection = ClientConnection::new(
            config,
            ServerName::try_from("opendrop.invalid").unwrap().to_owned(),
        )
        .map_err(|e| e.to_string())?;
        for _ in 0..64 {
            if !connection.is_handshaking() {
                break;
            }
            match connection.complete_io(&mut socket) {
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        if connection.is_handshaking() {
            return Err("client handshake did not finish".to_owned());
        }
        let provisional = ProvisionalTlsPeer::from_completed_client(
            &connection,
            transcript,
            Arc::new(AtomicBool::new(true)),
        )
        .map_err(|e| e.to_string())?;
        Ok((StreamOwned::new(connection, socket), provisional))
    }

    fn offer(local: &LocalGuestIdentity, bytes: &[u8]) -> GuestOfferV1 {
        GuestOfferV1::new(
            TransferId::parse(&"a".repeat(32)).unwrap(),
            local.public_key().fingerprint(),
            Sha256Digest::parse(&"b".repeat(64)).unwrap(),
            "hosted-loopback.bin".to_owned(),
            bytes.len() as u64,
            Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).unwrap(),
        )
        .unwrap()
    }

    fn ready(
        tls: &mut StreamOwned<ClientConnection, TcpStream>,
        offered: &FileOffer,
    ) -> WireRecoveryCredential {
        match Frame::read_from(tls).unwrap() {
            Frame::Control(Control::GuestReady(id, credential)) if id == offered.id => credential,
            unexpected => panic!("expected exact authenticated GuestReady, got {unexpected:?}"),
        }
    }

    fn authenticate_with_owner(
        tls: &mut StreamOwned<ClientConnection, TcpStream>,
        provisional: ProvisionalTlsPeer,
        first: bool,
    ) -> Result<VerifiedGuestSession, String> {
        let accepted = provisional
            .approve_sas_for_hosted_guest_fixture()
            .map_err(|e| e.to_string())?;
        let outgoing = accepted
            .outgoing_confirmation()
            .map_err(|e| e.to_string())?;
        if first {
            tls.write_all(outgoing.encoded())
                .map_err(|e| e.to_string())?;
            tls.flush().map_err(|e| e.to_string())?;
        }
        let mut server_bytes = [0u8; CONFIRM_LEN];
        tls.read_exact(&mut server_bytes)
            .map_err(|e| e.to_string())?;
        if !first {
            tls.write_all(outgoing.encoded())
                .map_err(|e| e.to_string())?;
            tls.flush().map_err(|e| e.to_string())?;
        }
        let received = GuestConfirmation::parse(&server_bytes).map_err(|e| e.to_string())?;
        accepted
            .verify_peer_then_finish(&received)
            .map_err(|e| e.to_string())
    }

    fn recover(
        addr: SocketAddr,
        identity: &LocalGuestIdentity,
        offered: &FileOffer,
        token: &WireRecoveryCredential,
    ) -> Result<Receipt, String> {
        let (mut tls, _provisional) = guest_client(addr, identity, Some(&offered.id))?;
        Frame::Control(Control::GuestReceiptQuery(offered.clone(), token.clone()))
            .write_to(&mut tls)
            .map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        match Frame::read_from(&mut tls).map_err(|e| e.to_string())? {
            Frame::Control(Control::Complete(receipt)) => Ok(receipt),
            unexpected => Err(format!("unexpected recovery response: {unexpected:?}")),
        }
    }

    fn temporary_owner_dirs() -> (tempfile::TempDir, PathBuf, PathBuf, LinuxReceiverStorage) {
        let temp = tempfile::Builder::new()
            .prefix("opendrop-s1c-loopback-")
            .tempdir()
            .unwrap();
        let private = temp.path().join("private");
        let destination = temp.path().join("destination");
        fs::create_dir(&private).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        let store = LinuxReceiverStorage::open_private(&private, &destination).unwrap();
        (temp, private.join("journal.sqlite"), destination, store)
    }

    /// A complete native TCP -> RPK TLS -> two separate synthetic owner UI
    /// actions -> exact offer -> GuestReady -> real filesystem publisher ->
    /// committed receipt -> fresh original-key receipt-only TLS progression.
    /// The simulated UI never appears in a production executable.
    fn run_transfer_and_recovery(peer_first: bool, lost_ack: bool) {
        let (_temp, journal_path, destination, store) = temporary_owner_dirs();
        let receiver = volatile_identity('b');
        let sender = volatile_identity('a');
        let mut admission = GuestAdmission::new_closed();
        admission.open_for_hosted_guest_fixture();
        let guest = Arc::new(GuestConfig {
            identity: receiver,
            admission: Arc::new(Mutex::new(admission)),
            live: Arc::new(Mutex::new(None)),
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let (ui_tx, ui_rx) = mpsc::sync_channel::<UiEvent>(4);
        let (code_tx, code_rx) = mpsc::sync_channel::<String>(1);
        let (result_tx, result_rx) = mpsc::sync_channel(6);
        let server_guest = guest.clone();
        let server_running = running.clone();
        let server_journal = journal_path.clone();
        let server_ui = ui_tx.clone();
        let server = thread::spawn(move || {
            // First ODGH + four strictly targeted ODGR connections; the
            // server never binds outside the disposable runner's loopback.
            for _ in 0..5 {
                let (socket, _) = listener.accept().unwrap();
                let result = route_connection(
                    socket,
                    None,
                    Some(&server_guest),
                    &server_journal,
                    &server_ui,
                    &server_running,
                );
                result_tx.send(result.is_ok()).unwrap();
            }
        });
        let ui_running = running.clone();
        let ui_journal = journal_path.clone();
        let ui = thread::spawn(move || {
            while ui_running.load(Ordering::Acquire) {
                match ui_rx.recv_timeout(Duration::from_millis(30)) {
                    Ok(UiEvent::GuestSas(request)) => {
                        let client_code = code_rx.recv_timeout(Duration::from_secs(4)).unwrap();
                        assert_eq!(request.provisional.displayed_code(), client_code);
                        if peer_first {
                            thread::sleep(Duration::from_millis(40));
                        }
                        let approval = request
                            .provisional
                            .approve_sas_for_hosted_guest_fixture()
                            .unwrap();
                        let _ = request.result.send(Some(approval));
                    }
                    Ok(UiEvent::GuestOffer(request)) => {
                        let mut journal = Journal::open(&ui_journal).unwrap();
                        let result = ForegroundLinuxReceiver::after_hosted_guest_fixture_approval(
                            request.verified,
                            request.offer,
                            &mut journal,
                            store.clone(),
                            request.active,
                        )
                        .unwrap();
                        let _ = request.result.send(Some(result));
                    }
                    Ok(UiEvent::Status(_)) | Ok(UiEvent::Offer(_)) => {
                        panic!("hosted guest must not enter the paired consent path");
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        let payload: Vec<u8> = (0..131_123).map(|n| (n % 251) as u8).collect();
        let offered = offer(&sender, &payload);
        let (mut tls, provisional) = guest_client(addr, &sender, None).unwrap();
        code_tx
            .send(provisional.displayed_code().to_owned())
            .unwrap();
        let verified = authenticate_with_owner(&mut tls, provisional, peer_first).unwrap();
        assert!(verified.is_active());
        assert_eq!(
            verified.logical_sender_spki(),
            sender.public_key().fingerprint()
        );
        Frame::Control(Control::Offer(offered.file_offer().clone()))
            .write_to(&mut tls)
            .unwrap();
        tls.flush().unwrap();
        let token = ready(&mut tls, offered.file_offer());
        for chunk in payload.chunks(32 * 1024) {
            Frame::Data(chunk.to_vec()).write_to(&mut tls).unwrap();
        }
        Frame::Control(Control::End(offered.id().clone()))
            .write_to(&mut tls)
            .unwrap();
        tls.flush().unwrap();
        if !lost_ack {
            match Frame::read_from(&mut tls).unwrap() {
                Frame::Control(Control::Complete(receipt)) => {
                    assert_eq!(receipt.transfer_id, *offered.id());
                    assert_eq!(receipt.sha256, offered.file_offer().sha256);
                    assert_eq!(receipt.bytes, payload.len() as u64);
                }
                other => panic!("expected actual authenticated Complete, got {other:?}"),
            }
        }
        drop(tls);
        let _original_result = result_rx.recv_timeout(Duration::from_secs(8)).unwrap();
        let published = destination.join(&offered.file_offer().name);
        assert_eq!(fs::read(&published).unwrap(), payload);
        let original_inode = fs::metadata(&published).unwrap().ino();
        let journal = rusqlite::Connection::open(&journal_path).unwrap();
        let phase: String = journal
            .query_row(
                "SELECT phase FROM transfers WHERE id=?1",
                [offered.id().as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(phase, "committed");
        drop(journal);

        let receipt = recover(addr, &sender, offered.file_offer(), &token).unwrap();
        assert_eq!(receipt.transfer_id, *offered.id());
        assert_eq!(receipt.sha256, offered.file_offer().sha256);
        assert!(result_rx.recv_timeout(Duration::from_secs(8)).unwrap());

        let wrong = WireRecoveryCredential::from_authenticated_bytes([7u8; 32]).unwrap();
        assert_ne!(wrong, token);
        assert!(recover(addr, &sender, offered.file_offer(), &wrong).is_err());
        assert!(!result_rx.recv_timeout(Duration::from_secs(8)).unwrap());

        let mut changed = offered.file_offer().clone();
        changed.name = "wrong-file.bin".to_owned();
        assert!(recover(addr, &sender, &changed, &token).is_err());
        assert!(!result_rx.recv_timeout(Duration::from_secs(8)).unwrap());

        // Corrupt ONLY the disposable runner's verifier expiry as an
        // adversarial test fixture. No production clock or secret is changed.
        let journal = rusqlite::Connection::open(&journal_path).unwrap();
        journal
            .execute(
                "UPDATE guest_receipt_verifiers SET issued_ms=1,expires_ms=2 WHERE id=?1",
                [offered.id().as_str()],
            )
            .unwrap();
        drop(journal);
        assert!(recover(addr, &sender, offered.file_offer(), &token).is_err());
        assert!(!result_rx.recv_timeout(Duration::from_secs(8)).unwrap());

        server.join().unwrap();
        running.store(false, Ordering::Release);
        drop(ui_tx);
        ui.join().unwrap();
        assert_eq!(fs::read(&published).unwrap(), payload);
        assert_eq!(fs::metadata(&published).unwrap().ino(), original_inode);
        let journal = rusqlite::Connection::open(&journal_path).unwrap();
        let (count, committed): (i64, i64) = journal
            .query_row(
                "SELECT count(*),sum(CASE WHEN phase='committed' THEN 1 ELSE 0 END) FROM transfers",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((count, committed), (1, 1));
    }

    #[test]
    fn hosted_native_socket_guest_owner_first_all_stages_and_exact_recovery() {
        run_transfer_and_recovery(false, false);
    }

    #[test]
    fn hosted_native_socket_guest_peer_first_lost_ack_recovers_without_republication() {
        run_transfer_and_recovery(true, true);
    }
}
