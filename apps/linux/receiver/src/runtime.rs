//! Bounded one-peer-at-a-time foreground integration; no discovery,
//! network pairing, daemon service, Android side, or automatic trust upgrade.

use opendrop_core::authorization::AuthenticatedSession;
use opendrop_core::journal::{FileOffer, Journal};
use opendrop_core::receiver::ReceiveState;
use opendrop_core::wire::{Control, Frame};
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
    Arc,
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

/// Per-frame budget independent of fragmented reads, temporary OS socket
/// timeouts or peer-controlled chunk boundaries. The underlying socket has
/// a short read timeout so a shutdown or failed TLS channel is noticed.
struct FrameDeadlineReader<'a, R: Read> {
    input: &'a mut R,
    started: Instant,
    limit: Duration,
    running: &'a AtomicBool,
}
impl<R: Read> Read for FrameDeadlineReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.running.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "receiver stopping",
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
    tls_identity_root: PathBuf,
}

impl Settings {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, &'static str> {
        let mut arguments = args.into_iter();
        let mut listen = None;
        let mut private_root = None;
        let mut default_destination = None;
        let mut tls_identity_root = None;
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
        let tls_identity_root =
            PathBuf::from(tls_identity_root.ok_or("Missing provisioned TLS identity root.")?);
        if [&private_root, &default_destination, &tls_identity_root]
            .iter()
            .any(|path| !path.is_absolute())
        {
            return Err("Only absolute owner-controlled directories are allowed.");
        }
        Ok(Some(Self {
            listen: address,
            private_root,
            default_destination,
            tls_identity_root,
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
            "OpenDrop Linux receiver (paired devices only)\n\
             --listen IP:port --private-root ABS_PATH --destination ABS_PATH \\\n+             --tls-identity-root ABS_PATH\n\
             Requires an independently provisioned 0700 identity folder with\n\
             server-cert.der, server-key.pkcs8.der, paired-client-root.der.\n\
             No automatic enrollment, installation or trust provisioning."
        );
        return Ok(());
    };
    // Load all private credentials BEFORE opening any socket. No fabricated
    // identity or client trust root is installed on missing configuration.
    let config = load_provisioned_tls(&settings.tls_identity_root)
        .map_err(|_| "No valid provisioned TLS identity and client trust root. Not listening.")?;
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
    let worker = thread::spawn(move || {
        accept_single_peer(listener, config, journal_path, events_tx, worker_live)
    });
    while foreground.poll() {
        match events_rx.recv_timeout(Duration::from_millis(35)) {
            Ok(UiEvent::Status(text)) => display(text),
            Ok(UiEvent::Offer(request)) => {
                owner_approval(request, &mut journal, &storage, &running);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    running.store(false, Ordering::Release);
    worker
        .join()
        .map_err(|_| "Receiver worker stopped unexpectedly.")?;
    Ok(())
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
    config: Arc<rustls::ServerConfig>,
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
                let outcome = serve_one(socket, config.clone(), &journal_path, &ui, &running);
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
    let first = read_with_deadline(&mut tls, OFFER_LIMIT, running)?;
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
            return receive_verified_stream(tls, receiver, cancellation, journal, running);
        }
        _ => Err("only an Offer or exact ReceiptQuery is permitted"),
    }
}

fn read_with_deadline(
    tls: &mut TlsTransport,
    limit: Duration,
    running: &AtomicBool,
) -> Result<Frame, &'static str> {
    Frame::read_from(&mut FrameDeadlineReader {
        input: tls,
        started: Instant::now(),
        limit,
        running,
    })
    .map_err(|_| "invalid, truncated or timed-out wire frame")
}

fn receive_verified_stream(
    mut tls: TlsTransport,
    mut receiver: ForegroundLinuxReceiver,
    _transport_owner: SessionCancellation,
    mut journal: Journal,
    running: &AtomicBool,
) -> Result<(), &'static str> {
    receiver
        .start_staging()
        .map_err(|_| "cannot create private stage")?;
    Frame::Control(Control::Ready(receiver.pending_offer().id.clone()))
        .write_to(&mut tls)
        .map_err(|_| "send Ready")?;
    tls.flush().map_err(|_| "flush Ready")?;
    let started = Instant::now();
    for _ in 0..MAX_TRANSFER_FRAMES {
        if !running.load(Ordering::Acquire) || started.elapsed() >= STREAM_LIMIT {
            return Err("transfer timed out or owner closed receiver");
        }
        let frame = read_with_deadline(&mut tls, FRAME_LIMIT, running)?;
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
}
