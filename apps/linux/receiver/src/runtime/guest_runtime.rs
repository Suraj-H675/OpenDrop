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
    let locally_verified = await_local(
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
    let mut peer_proof = [0u8; CONFIRM_LEN];
    FrameDeadlineReader {
        input: &mut tls,
        started: Instant::now(),
        limit: FRAME_LIMIT,
        running,
        session_active: Some(transport.live.as_ref()),
    }
    .read_exact(&mut peer_proof)
    .map_err(|_| "guest confirmation not received")?;
    let peer_proof =
        GuestConfirmation::parse(&peer_proof).map_err(|_| "invalid guest confirmation")?;
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
