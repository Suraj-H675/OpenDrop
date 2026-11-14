//! Bounded one-peer-at-a-time foreground integration. Legacy paired mTLS and
//! narrowly admitted guest-RPK TLS share ONE existing file-publication engine.
//! There is no background daemon, broadcast discovery implementation,
//! Android sender, automatic enrollment, or implicit trust upgrade.

use opendrop_core::authorization::{request_linux_qt_guest_offer_consent, AuthenticatedSession};
use opendrop_core::guest::{GuestAdmission, LinuxGuestVisibilityAction};
use opendrop_core::guest_tls::LocalGuestIdentity;
use opendrop_core::identity::DeviceId;
use opendrop_core::journal::{FileOffer, Journal};
use opendrop_core::receiver::ReceiveState;
use opendrop_core::wire::{Control, Frame, WireRecoveryCredential};
use opendrop_linux_receiver::storage::LinuxReceiverStorage;
use opendrop_linux_receiver::tls::load_provisioned_tls;
use opendrop_linux_receiver::{ForegroundLinuxReceiver, SessionCancellation};
use rustls::{ServerConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SyncSender, TryRecvError},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(8);
const OFFER_LIMIT: Duration = Duration::from_secs(5);
const CONSENT_LIMIT: Duration = Duration::from_secs(125);
const STREAM_LIMIT: Duration = Duration::from_secs(600);
const FRAME_LIMIT: Duration = Duration::from_secs(8);
const IO_TICK: Duration = Duration::from_millis(250);
const MAX_TRANSFER_FRAMES: usize = 131_072;

type TlsTransport = StreamOwned<ServerConnection, TcpStream>;
mod guest_runtime;
use guest_runtime::{GuestConfig, GuestOfferRequest, GuestSasRequest};

/// Per-frame budget independent of fragmented reads, temporary OS socket
/// timeouts or peer-controlled chunk boundaries. The underlying socket has
/// a short read timeout so a shutdown or failed TLS channel is noticed.
struct FrameDeadlineReader<'a, R: Read> {
    input: &'a mut R,
    started: Instant,
    limit: Duration,
    running: &'a AtomicBool,
    session_active: Option<&'a AtomicBool>,
}
impl<R: Read> Read for FrameDeadlineReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.running.load(Ordering::Acquire)
                || self
                    .session_active
                    .is_some_and(|session| !session.load(Ordering::Acquire))
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "receiver stopping or guest session revoked",
                ));
            }
            if self.started.elapsed() >= self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "frame read deadline",
                ));
            }
            match self.input.read(bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

extern "C" {
    fn opendrop_qt_foreground_start() -> i32;
    fn opendrop_qt_foreground_stop_requested() -> i32;
    fn opendrop_qt_foreground_poll();
    fn opendrop_qt_foreground_status(message: *const std::ffi::c_char);
    fn opendrop_qt_foreground_shutdown();
    fn opendrop_qt_guest_visibility_available(available: i32);
}

fn display(message: &'static [u8]) {
    // Every caller supplies a hardcoded, NUL-terminated display string.
    // Untrusted peer names and filesystem paths never cross this ABI.
    debug_assert_eq!(message.last(), Some(&0));
    unsafe { opendrop_qt_foreground_status(message.as_ptr().cast()) };
}

struct QtForeground;
impl QtForeground {
    fn start() -> Result<Self, &'static str> {
        if unsafe { opendrop_qt_foreground_start() } != 1 {
            return Err("Unable to open the local desktop receiver.");
        }
        Ok(Self)
    }
    fn poll(&self) -> bool {
        unsafe { opendrop_qt_foreground_poll() };
        let stop_requested = unsafe { opendrop_qt_foreground_stop_requested() };
        stop_requested == 0
    }
    fn guest_available(&self, available: bool) {
        unsafe { opendrop_qt_guest_visibility_available(i32::from(available)) };
    }
}
impl Drop for QtForeground {
    fn drop(&mut self) {
        unsafe { opendrop_qt_foreground_shutdown() };
    }
}

#[derive(Debug)]
struct Settings {
    listen: SocketAddr,
    private_root: PathBuf,
    default_destination: PathBuf,
    tls_identity_root: Option<PathBuf>,
    guest: Option<GuestKeySettings>,
}

#[derive(Debug)]
struct GuestKeySettings {
    module: PathBuf,
    token_label: String,
    key_label: String,
    device_id: DeviceId,
}

impl Settings {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, &'static str> {
        let mut arguments = args.into_iter();
        let mut listen = None;
        let mut private_root = None;
        let mut default_destination = None;
        let mut tls_identity_root = None;
        let mut guest_module = None;
        let mut guest_token_label = None;
        let mut guest_key_label = None;
        let mut guest_device_id = None;
        while let Some(key) = arguments.next() {
            if key == "--help" {
                return Ok(None);
            }
            let value = arguments.next().ok_or("Missing configuration value.")?;
            let field = match key.as_str() {
                "--listen" => &mut listen,
                "--private-root" => &mut private_root,
                "--destination" => &mut default_destination,
                "--tls-identity-root" => &mut tls_identity_root,
                "--guest-pkcs11-module" => &mut guest_module,
                "--guest-token-label" => &mut guest_token_label,
                "--guest-key-label" => &mut guest_key_label,
                "--guest-device-id" => &mut guest_device_id,
                _ => return Err("Unknown receiver option."),
            };
            if field.replace(value).is_some() {
                return Err("Repeated receiver option.");
            }
        }
        let address = listen
            .ok_or("Explicit numeric --listen IP:port is required.")?
            .parse::<SocketAddr>()
            .map_err(|_| "Invalid numeric listening IP:port.")?;
        if address.port() == 0 {
            return Err("A fixed nonzero listening port is required.");
        }
        let private_root = PathBuf::from(private_root.ok_or("Missing private root.")?);
        let default_destination =
            PathBuf::from(default_destination.ok_or("Missing owner destination.")?);
        let provided_guest = [
            guest_module.is_some(),
            guest_token_label.is_some(),
            guest_key_label.is_some(),
            guest_device_id.is_some(),
        ];
        if provided_guest.iter().any(|provided| *provided)
            && !provided_guest.iter().all(|provided| *provided)
        {
            return Err("Guest hardware key configuration must be complete.");
        }
        let guest = if provided_guest.iter().all(|provided| *provided) {
            Some(GuestKeySettings {
                module: PathBuf::from(guest_module.ok_or("Missing hardware module.")?),
                token_label: guest_token_label.ok_or("Missing token label.")?,
                key_label: guest_key_label.ok_or("Missing signing key label.")?,
                device_id: DeviceId::parse(
                    &guest_device_id.ok_or("Missing guest installation ID.")?,
                )
                .map_err(|_| "Invalid canonical guest installation ID.")?,
            })
        } else {
            None
        };
        if guest.is_none() && tls_identity_root.is_none() {
            return Err("No provisioned paired identity or guest hardware key.");
        }
        let tls_identity_root = tls_identity_root.map(PathBuf::from);
        if [&private_root, &default_destination]
            .iter()
            .any(|path| !path.is_absolute())
            || tls_identity_root
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || guest.as_ref().is_some_and(|key| !key.module.is_absolute())
        {
            return Err("Only absolute owner-controlled directories are allowed.");
        }
        Ok(Some(Self {
            listen: address,
            private_root,
            default_destination,
            tls_identity_root,
            guest,
        }))
    }
}

struct OwnerRequest {
    authenticated: AuthenticatedSession,
    offer: FileOffer,
    monitor: SyncSender<SessionCancellation>,
    result: SyncSender<Option<ForegroundLinuxReceiver>>,
}

enum UiEvent {
    Offer(OwnerRequest),
    GuestSas(GuestSasRequest),
    GuestOffer(GuestOfferRequest),
    Status(&'static [u8]),
}

pub fn run() -> Result<(), &'static str> {
    let args = std::env::args_os()
        .skip(1)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "Receiver arguments must be valid UTF-8.")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some(settings) = Settings::parse(args)? else {
        println!(
            "OpenDrop Linux receiver (explicitly provisioned paired or guest mode)\n\
             --listen IP:port --private-root ABS_PATH --destination ABS_PATH\n\
             [--tls-identity-root ABS_PATH]\n\
             [--guest-pkcs11-module ABS_PATH --guest-token-label LABEL\n\
              --guest-key-label LABEL --guest-device-id 32_HEX]\n\
             Legacy paired mode requires an independently provisioned 0700 identity folder with\n\
             server-cert.der, server-key.pkcs8.der, paired-client-root.der.\n\
             Guest mode requires an independently provisioned hardware-token P-256 signing key\n\
             with a protected authentication path. No software identity, automatic enrollment,\n\
             installation or implicit trust provisioning is performed."
        );
        return Ok(());
    };
    // Load all private credentials BEFORE opening any socket. No fabricated
    // identity or client trust root is installed on missing configuration.
    let config = settings
        .tls_identity_root
        .as_ref()
        .map(|root| load_provisioned_tls(root))
        .transpose()
        .map_err(|_| "No valid provisioned TLS identity and client trust root. Not listening.")?;
    let guest = settings
        .guest
        .map(|key| {
            let signer = crate::guest_signer::open_preprovisioned(
                &key.module,
                &key.token_label,
                &key.key_label,
            )
            .map_err(|_| "Guest hardware token is absent, locked or unsafe. Not listening.")?;
            let identity = LocalGuestIdentity::from_platform_signer(key.device_id, signer)
                .map_err(|_| "Guest hardware P-256 identity failed signing-key verification.")?;
            Ok::<_, &'static str>(Arc::new(GuestConfig {
                identity: Arc::new(identity),
                admission: Arc::new(Mutex::new(GuestAdmission::new_closed())),
                live: Arc::new(Mutex::new(None)),
            }))
        })
        .transpose()?;
    let storage =
        LinuxReceiverStorage::open_private(&settings.private_root, &settings.default_destination)
            .map_err(|_| "Private staging or owner destination directory is unsafe.")?;
    let journal_path = settings.private_root.join("journal.sqlite");
    let mut journal = Journal::open(&journal_path)
        .map_err(|_| "The private receive journal could not be opened safely.")?;
    let recovery = storage
        .recover_before_listen(&journal)
        .map_err(|_| "Startup recovery could not inspect private stage state safely.")?;
    // Uncertain CommitIntent and unidentified inventory remain untouched.
    // Never auto-republish, fabricate a receipt or silently delete them.
    let foreground = QtForeground::start()?;
    foreground.guest_available(guest.is_some());
    if recovery.preserved_unresolved_intent != 0
        || recovery.preserved_unverifiable_destination != 0
        || recovery.unidentified_private_entries != 0
    {
        display(b"Unresolved previous transfer: files were preserved for safe recovery.\0");
    }
    let listener = TcpListener::bind(settings.listen)
        .map_err(|_| "Could not bind the explicitly selected listening address.")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Could not configure the foreground receiver socket.")?;
    let running = Arc::new(AtomicBool::new(true));
    let (events_tx, events_rx) = mpsc::sync_channel::<UiEvent>(4);
    let worker_live = running.clone();
    let worker_guest = guest.clone();
    let worker = thread::spawn(move || {
        accept_single_peer(
            listener,
            config,
            worker_guest,
            journal_path,
            events_tx,
            worker_live,
        )
    });
    let mut was_guest_visible = false;
    while foreground.poll() {
        if let Some(guest) = guest.as_ref() {
            let mut admission = guest
                .admission
                .lock()
                .map_err(|_| "Guest admission policy unavailable.")?;
            match admission.poll_linux_qt_owner_action() {
                Ok(LinuxGuestVisibilityAction::Revoked) | Err(_) => {
                    admission.revoke_from_owner();
                    if let Ok(slot) = guest.live.lock() {
                        if let Some(active) = slot.as_ref() {
                            active.store(false, Ordering::Release);
                        }
                    }
                }
                Ok(LinuxGuestVisibilityAction::None | LinuxGuestVisibilityAction::Opened) => {}
            }
            let visible = !admission.remaining_visibility().is_zero();
            if visible && !was_guest_visible {
                display(b"Guest requests visible for ten minutes. Every file needs approval.\0");
            } else if !visible && was_guest_visible {
                display(b"Guest visibility ended. New guest requests are blocked.\0");
            }
            was_guest_visible = visible;
        }
        match events_rx.recv_timeout(Duration::from_millis(35)) {
            Ok(UiEvent::Status(text)) => display(text),
            Ok(UiEvent::Offer(request)) => {
                owner_approval(request, &mut journal, &storage, &running);
            }
            Ok(UiEvent::GuestSas(request)) => {
                let _ = request
                    .result
                    .send(request.provisional.request_linux_qt_sas().ok());
            }
            Ok(UiEvent::GuestOffer(request)) => {
                guest_owner_approval(request, &mut journal, &storage);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    running.store(false, Ordering::Release);
    if let Some(guest) = guest {
        if let Ok(mut admission) = guest.admission.lock() {
            admission.revoke_from_owner();
        }
    }
    worker
        .join()
        .map_err(|_| "Receiver worker stopped unexpectedly.")?;
    Ok(())
}

fn guest_owner_approval(
    request: GuestOfferRequest,
    journal: &mut Journal,
    storage: &LinuxReceiverStorage,
) {
    let result = request_linux_qt_guest_offer_consent(
        request.verified,
        request.offer,
        storage.owner_destination_display(),
        &request.active,
    )
    .and_then(|grant| {
        ForegroundLinuxReceiver::after_guest_owner_approval(
            grant,
            journal,
            storage.clone(),
            request.active.clone(),
        )
    });
    let _ = request.result.send(result.ok());
}

fn owner_approval(
    request: OwnerRequest,
    journal: &mut Journal,
    storage: &LinuxReceiverStorage,
    running: &AtomicBool,
) {
    if !running.load(Ordering::Acquire) {
        let _ = request.result.send(None);
        return;
    }
    let Ok((mut receiver, prompt, cancellation)) = ForegroundLinuxReceiver::incoming_offer(
        request.authenticated,
        journal,
        request.offer,
        storage.clone(),
    ) else {
        display(b"Transfer declined: this device is not currently authorized.\0");
        let _ = request.result.send(None);
        return;
    };
    // Transfer transport-lifetime ownership to the I/O worker BEFORE the
    // modal blocks this GUI thread. A disconnected client invalidates it.
    if request.monitor.send(cancellation).is_err() {
        let _ = request.result.send(None);
        return;
    }
    display(b"Review the incoming file and select a trusted save folder.\0");
    if receiver.request_owner_qt_approval(journal, prompt).is_err() {
        display(b"Incoming file declined, expired or no longer available.\0");
        let _ = request.result.send(None);
        return;
    }
    if request.result.send(Some(receiver)).is_err() {
        display(b"Peer disconnected. Transfer was not started.\0");
    }
}

fn accept_single_peer(
    listener: TcpListener,
    config: Option<Arc<rustls::ServerConfig>>,
    guest: Option<Arc<GuestConfig>>,
    journal_path: PathBuf,
    ui: SyncSender<UiEvent>,
    running: Arc<AtomicBool>,
) {
    let _ = ui.send(UiEvent::Status(
        b"Waiting for a previously paired device.\0",
    ));
    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((socket, _address)) => {
                // One worker and one session; there is no transfer parallelism
                // or per-client allocation outside the bounded TLS state.
                let outcome = guest_runtime::route_connection(
                    socket,
                    config.clone(),
                    guest.as_ref(),
                    &journal_path,
                    &ui,
                    &running,
                );
                if outcome.is_err() {
                    let _ = ui.try_send(UiEvent::Status(
                        b"Connection closed or transfer could not be completed safely.\0",
                    ));
                } else {
                    let _ = ui.try_send(UiEvent::Status(b"Ready for another paired device.\0"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(40));
            }
            Err(_) => {
                let _ = ui.try_send(UiEvent::Status(
                    b"Receiver socket failed; stop and restart.\0",
                ));
                break;
            }
        }
    }
}

fn serve_one(
    mut socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    journal_path: &Path,
    ui: &SyncSender<UiEvent>,
    running: &AtomicBool,
) -> Result<(), &'static str> {
    socket
        .set_read_timeout(Some(IO_TICK))
        .map_err(|_| "read timeout")?;
    socket
        .set_write_timeout(Some(IO_TICK))
        .map_err(|_| "write timeout")?;
    let mut connection = ServerConnection::new(config).map_err(|_| "TLS server")?;
    let handshake_started = Instant::now();
    while connection.is_handshaking() {
        if !running.load(Ordering::Acquire) || handshake_started.elapsed() >= HANDSHAKE_LIMIT {
            return Err("TLS handshake timeout");
        }
        match connection.complete_io(&mut socket) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("TLS client certificate rejected"),
        }
    }
    if connection.alpn_protocol() != Some(b"opendrop-s1".as_slice()) {
        return Err("unexpected TLS application protocol");
    }
    // Test-only peer enrollment is not a production pairing mechanism.
    // A CA-valid but unpaired client is rejected even after handshake.
    let journal = Journal::open(journal_path).map_err(|_| "private journal")?;
    let authenticated = AuthenticatedSession::from_paired_tls_server(&connection, &journal)
        .map_err(|_| "unpaired or revoked client certificate")?;
    let mut tls = StreamOwned::new(connection, socket);
    let first = read_with_deadline(&mut tls, OFFER_LIMIT, running, None)?;
    match first {
        Frame::Control(Control::ReceiptQuery(offer)) => {
            if let Some(receipt) = authenticated
                .committed_receipt_for_offer(&journal, &offer)
                .map_err(|_| "unauthorized receipt query")?
            {
                Frame::Control(Control::Complete(receipt))
                    .write_to(&mut tls)
                    .map_err(|_| "complete receipt")?;
                tls.flush().map_err(|_| "write receipt")?;
            }
            return Ok(());
        }
        Frame::Control(Control::Offer(offer)) => {
            if authenticated.peer_fingerprint() != &offer.peer {
                return Err("peer identity mismatch");
            }
            let (result_tx, result_rx) = mpsc::sync_channel(1);
            let (monitor_tx, monitor_rx) = mpsc::sync_channel(1);
            ui.send(UiEvent::Offer(OwnerRequest {
                authenticated,
                offer,
                monitor: monitor_tx,
                result: result_tx,
            }))
            .map_err(|_| "local UI unavailable")?;
            let cancellation = monitor_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| "local UI session unavailable")?;
            let waiting = Instant::now();
            let mut early_data = [0u8; 1];
            let receiver = loop {
                if !running.load(Ordering::Acquire) || waiting.elapsed() >= CONSENT_LIMIT {
                    return Err("approval expired");
                }
                match result_rx.try_recv() {
                    Ok(Some(receiver)) => break receiver,
                    Ok(None) => return Err("owner declined"),
                    Err(TryRecvError::Disconnected) => return Err("UI exited"),
                    Err(TryRecvError::Empty) => {}
                }
                // The peer must not send payload before Ready. Reading
                // catches TLS close_notify, EOF and unexpected early data;
                // dropping cancellation revokes any pending Qt grant.
                match tls.read(&mut early_data) {
                    Ok(0) => return Err("TLS session closed"),
                    Ok(_) => return Err("data before owner approval"),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => return Err("TLS session interrupted"),
                }
            };
            // This guard remains owned by the actual transport thread through
            // successful commit or any error. It revokes itself on Drop.
            return receive_verified_stream(tls, receiver, cancellation, journal, running, None);
        }
        _ => Err("only an Offer or exact ReceiptQuery is permitted"),
    }
}

fn read_with_deadline(
    tls: &mut TlsTransport,
    limit: Duration,
    running: &AtomicBool,
    session_active: Option<&AtomicBool>,
) -> Result<Frame, &'static str> {
    Frame::read_from(&mut FrameDeadlineReader {
        input: tls,
        started: Instant::now(),
        limit,
        running,
        session_active,
    })
    .map_err(|_| "invalid, truncated or timed-out wire frame")
}

fn receive_verified_stream(
    mut tls: TlsTransport,
    mut receiver: ForegroundLinuxReceiver,
    transport_owner: SessionCancellation,
    mut journal: Journal,
    running: &AtomicBool,
    guest_ready: Option<WireRecoveryCredential>,
) -> Result<(), &'static str> {
    receiver
        .start_staging()
        .map_err(|_| "cannot create private stage")?;
    let ready = match guest_ready {
        Some(token) => Control::GuestReady(receiver.pending_offer().id.clone(), token),
        None => Control::Ready(receiver.pending_offer().id.clone()),
    };
    Frame::Control(ready)
        .write_to(&mut tls)
        .map_err(|_| "send Ready")?;
    tls.flush().map_err(|_| "flush Ready")?;
    let started = Instant::now();
    for _ in 0..MAX_TRANSFER_FRAMES {
        if !running.load(Ordering::Acquire) || started.elapsed() >= STREAM_LIMIT {
            return Err("transfer timed out or owner closed receiver");
        }
        let frame = read_with_deadline(
            &mut tls,
            FRAME_LIMIT,
            running,
            Some(transport_owner.active_flag()),
        )?;
        receiver
            .receive_frame(frame)
            .map_err(|_| "transfer content rejected")?;
        match receiver.state() {
            ReceiveState::StreamVerified => {
                // Only after durable no-replace publication + independent
                // destination verification + committed receipt record.
                let complete = receiver
                    .commit_and_complete(&mut journal)
                    .map_err(|_| "publication outcome requires recovery")?;
                complete
                    .write_to(&mut tls)
                    .map_err(|_| "peer lost after local commit")?;
                tls.flush().map_err(|_| "peer lost after local commit")?;
                return Ok(());
            }
            ReceiveState::Cancelled | ReceiveState::Failed | ReceiveState::Declined => {
                return Err("transfer cancelled");
            }
            _ => {}
        }
    }
    Err("transfer frame count exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn args(rest: &[&str]) -> Result<Option<Settings>, &'static str> {
        Settings::parse(rest.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn no_listener_without_explicit_complete_owner_configuration() {
        assert!(args(&[]).is_err());
        assert!(args(&["--listen", "0.0.0.0:0"]).is_err());
        assert!(args(&["--listen", "127.0.0.1:80", "--destination", "relative"]).is_err());
        assert!(args(&[
            "--listen",
            "127.0.0.1:43991",
            "--private-root",
            "/tmp/only-this-fixture",
            "--destination",
            "/tmp/owner-files",
            "--tls-identity-root",
            "/tmp/missing-provisioned-identity",
        ])
        .is_ok());
    }

    #[test]
    fn duplicate_or_non_numeric_listener_inputs_are_rejected() {
        assert!(args(&[
            "--listen",
            "127.0.0.1:1",
            "--listen",
            "127.0.0.1:2",
            "--private-root",
            "/a",
            "--destination",
            "/b",
            "--tls-identity-root",
            "/c",
        ])
        .is_err());
        assert!(args(&[
            "--listen",
            "untrusted.example.com:43991",
            "--private-root",
            "/a",
            "--destination",
            "/b",
            "--tls-identity-root",
            "/c",
        ])
        .is_err());
    }

    #[test]
    fn guest_mode_requires_all_provisioning_fields_and_never_infers_identity() {
        let base = [
            "--listen",
            "127.0.0.1:43991",
            "--private-root",
            "/some-owner-private-directory",
            "--destination",
            "/some-owner-destination-directory",
        ];
        assert!(args(&base).is_err());
        let mut partial = base.to_vec();
        partial.extend(["--guest-pkcs11-module", "/usr/lib/pkcs11/module.so"]);
        assert!(args(&partial).is_err());
        let test_device = "f".repeat(32);
        partial.extend([
            "--guest-token-label",
            "OpenDrop Token",
            "--guest-key-label",
            "OpenDrop Installation",
            "--guest-device-id",
            test_device.as_str(),
        ]);
        let configured = args(&partial).unwrap().unwrap();
        assert!(configured.tls_identity_root.is_none());
        assert_eq!(configured.guest.unwrap().device_id.as_str(), "f".repeat(32));
        let last = partial.len() - 1;
        partial[last] = "peer-provided-ID";
        assert!(args(&partial).is_err());
    }

    #[test]
    fn revoked_guest_frame_reader_rejects_bytes_before_dispatch_or_stage() {
        let mut encoded = Cursor::new(vec![1u8, 32, 0, 0, 0, 1, 0x7f]);
        let running = AtomicBool::new(true);
        let guest_active = AtomicBool::new(false);
        let mut reader = FrameDeadlineReader {
            input: &mut encoded,
            started: Instant::now(),
            limit: FRAME_LIMIT,
            running: &running,
            session_active: Some(&guest_active),
        };
        let mut output = [0u8; 1];
        assert_eq!(
            reader.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(encoded.position(), 0);
        let mut normal = Cursor::new(vec![1u8]);
        let mut paired_reader = FrameDeadlineReader {
            input: &mut normal,
            started: Instant::now(),
            limit: FRAME_LIMIT,
            running: &running,
            session_active: None,
        };
        assert_eq!(paired_reader.read(&mut output).unwrap(), 1);
    }
}
