//! Narrow receiving-authorization boundary; NOT a new wire protocol.
//!
//! Trust comes from the authenticated rustls TLS 1.3 peer certificate, not
//! multicast claims, caller-supplied fingerprints, or UI-supplied booleans.
//! LocalConsentBroker remains test-only. The native Linux Qt issuer is
//! feature-gated, opens a real in-process desktop modal, and never accepts a
//! caller-supplied approval boolean or raw IPC/terminal response.

use crate::identity::{DeviceId, KeyFingerprint};
use crate::journal::{DurablePublisher, FileOffer, Journal, Receipt, Snapshot};
use crate::policy::ReceiveDecision;
use crate::Error;
use rustls::server::ServerConnection;
use rustls::ProtocolVersion;
use sha2::{Digest, Sha256};
#[cfg(any(test, all(target_os = "linux", feature = "linux-qt-consent")))]
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
use std::{
    ffi::{c_char, c_void, CString},
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    time::Duration,
};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-OpenDrop-P1A-OfferAuthorization";

/// Opaque proof produced ONLY from a completed TLS 1.3 server connection
/// authenticating a client certificate. The TLS configuration MUST require
/// actual client-certificate verification (rustls WebPkiClientVerifier or an
/// equivalently reviewed verifier), never `NoClientAuth` or accept-all.
/// DeviceId is an untrusted identity *claim* until checked against the journal.
pub struct AuthenticatedSession {
    device_id: DeviceId,
    fingerprint: KeyFingerprint,
    exporter: [u8; 32],
}

impl AuthenticatedSession {
    pub fn from_verified_tls_server(
        tls: &ServerConnection,
        claimed_device: DeviceId,
    ) -> Result<Self, Error> {
        if tls.is_handshaking() || tls.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            return Err(Error::Unauthorized);
        }
        let certificates = tls.peer_certificates().ok_or(Error::Unauthorized)?;
        let leaf = certificates.first().ok_or(Error::Unauthorized)?;
        let fingerprint = KeyFingerprint::parse(&format!("{:x}", Sha256::digest(leaf.as_ref())))?;
        let mut exporter = [0u8; 32];
        tls.export_keying_material(&mut exporter, EXPORTER_LABEL, None)
            .map_err(|_| Error::Unauthorized)?;
        Ok(Self {
            device_id: claimed_device,
            fingerprint,
            exporter,
        })
    }

    pub fn peer_fingerprint(&self) -> &KeyFingerprint {
        &self.fingerprint
    }

    /// Production Linux foreground listener: accepts ONLY a completed,
    /// strictly client-certificate-verified TLS 1.3 session whose actual
    /// certificate fingerprint already maps to one locally paired identity.
    /// A caller-supplied DeviceId or an unpaired/guest certificate cannot
    /// manufacture that identity. No pairing enrollment exists yet.
    pub fn from_paired_tls_server(
        tls: &ServerConnection,
        journal: &Journal,
    ) -> Result<Self, Error> {
        if tls.is_handshaking() || tls.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            return Err(Error::Unauthorized);
        }
        let leaf = tls
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(Error::Unauthorized)?;
        let actual = KeyFingerprint::parse(&format!("{:x}", Sha256::digest(leaf.as_ref())))?;
        let known_device = journal
            .paired_identity_for_cert(&actual)?
            .ok_or(Error::PeerUntrusted)?;
        let session = Self::from_verified_tls_server(tls, known_device)?;
        if session.fingerprint != actual {
            return Err(Error::Unauthorized);
        }
        Ok(session)
    }

    /// The only peer-facing lost-ACK receipt query. The caller must already
    /// own a completed, certificate-authenticated TLS session; knowing a
    /// transfer ID or guessed hash alone is insufficient. No destination
    /// reference or uncommitted state is disclosed. Guest receipts remain
    /// queryable after Everyone expires, but revoked peers are always denied.
    pub fn committed_receipt_for_offer(
        &self,
        journal: &Journal,
        offer: &FileOffer,
    ) -> Result<Option<Receipt>, Error> {
        offer.validate()?;
        if self.fingerprint != offer.peer
            || journal.peer_revoked_or_key_changed(&self.device_id, &self.fingerprint)?
        {
            return Err(Error::Unauthorized);
        }
        Ok(journal.lookup(offer)?.and_then(|snapshot| snapshot.receipt))
    }
}

/// No public fields and no deserialization, so a network message cannot be
/// turned directly into a local approval. It is explicitly offer-scoped.
pub struct ConsentPrompt {
    offer: FileOffer,
    // Preserved for the later audited native UI bridge. Until that bridge is
    // approved, only the cfg(test) consent broker may read this secret tag.
    #[allow(dead_code)]
    session: [u8; 32],
    device: DeviceId,
}

impl ConsentPrompt {
    /// The UI should display these *untrusted* metadata until the user chooses.
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }
    pub fn claimed_device(&self) -> &DeviceId {
        &self.device
    }
}

/// No public terminal issuer; ticket creation stays in this security module.
/// The Qt route makes the owner interact with the actual in-process dialog.
///
/// ```compile_fail
/// use opendrop_core::authorization::confirm_linux_foreground_owner;
/// ```
pub struct ConsentTicket {
    offer: FileOffer,
    session: [u8; 32],
    device: DeviceId,
}

/// Test-only model of the future privileged local-UI consent broker. Until a
/// real native approval event is wired, production code CANNOT mint a manual
/// consent ticket; this intentionally fails closed rather than accepting a
/// network-supplied boolean as user approval.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct LocalConsentBroker {
    consumed: HashSet<[u8; 32]>,
}

#[cfg(test)]
impl LocalConsentBroker {
    /// The native UI event handler calls this ONLY after a genuine user action.
    /// There is no bool-based network API or automatic guest grant here.
    pub(crate) fn approve_from_local_user_action(
        &mut self,
        prompt: ConsentPrompt,
    ) -> Result<ConsentTicket, Error> {
        let binding = consent_binding(&prompt.session, &prompt.device, &prompt.offer);
        if !self.consumed.insert(binding) {
            return Err(Error::Unauthorized);
        }
        Ok(ConsentTicket {
            offer: prompt.offer,
            session: prompt.session,
            device: prompt.device,
        })
    }
}

/// A receipt of local authorization for one session and one exact offer, not
/// a reusable peer credential. Do not serialize, clone or expose to IPC.
pub struct AuthorizedOffer {
    offer: FileOffer,
    session: [u8; 32],
    device: DeviceId,
    explicit_consent: bool,
}
impl AuthorizedOffer {
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }
    pub fn reserve(
        &self,
        journal: &mut Journal,
        session: &AuthenticatedSession,
    ) -> Result<Snapshot, Error> {
        self.require_current_authorization(journal, session)?;
        journal.reserve(&self.offer)
    }

    pub fn record_commit_intent(
        &self,
        journal: &mut Journal,
        session: &AuthenticatedSession,
        destination_ref: &str,
    ) -> Result<(), Error> {
        self.require_current_authorization(journal, session)?;
        journal.record_commit_intent(&self.offer, destination_ref)
    }

    pub fn publish_with(
        &self,
        journal: &mut Journal,
        session: &AuthenticatedSession,
        publisher: &mut impl DurablePublisher,
    ) -> Result<Receipt, Error> {
        self.require_current_authorization(journal, session)?;
        journal.publish_with(&self.offer, publisher)
    }

    fn require_current_authorization(
        &self,
        journal: &Journal,
        session: &AuthenticatedSession,
    ) -> Result<(), Error> {
        // Recheck before EVERY state-changing operation, not just reserve.
        // Native data-plane cancellation and in-flight revocation are not yet
        // implemented; this only gates the transaction API boundary.
        if self.session != session.exporter
            || self.device != session.device_id
            || self.offer.peer != session.fingerprint
        {
            return Err(Error::Unauthorized);
        }
        let now_ms = now_millis()?;
        let current = journal.authorize_receive(
            &session.device_id,
            &session.fingerprint,
            journal.visibility()?,
            now_ms,
            false,
        )?;
        let permitted = if self.explicit_consent {
            matches!(
                current,
                ReceiveDecision::RequireGuestConsent | ReceiveDecision::RequireTrustedConsent
            )
        } else {
            current == ReceiveDecision::AllowAutoAcceptedTrusted
        };
        if !permitted {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

pub enum OfferDecision {
    Denied,
    NeedsLocalConsent(ConsentPrompt),
    AutoAccepted(AuthorizedOffer),
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-qt-consent")))]
fn consent_binding(session: &[u8; 32], device: &DeviceId, offer: &FileOffer) -> [u8; 32] {
    let mut hash = Sha256::new();
    for component in [
        &session[..],
        device.as_str().as_bytes(),
        offer.id.as_str().as_bytes(),
        offer.peer.as_str().as_bytes(),
        offer.manifest.as_str().as_bytes(),
        offer.name.as_bytes(),
        &offer.bytes.to_be_bytes(),
        offer.sha256.as_str().as_bytes(),
    ] {
        hash.update((component.len() as u64).to_be_bytes());
        hash.update(component);
    }
    hash.finalize().into()
}

/// Only the receiver coordinator may compare a native lease against its
/// immutable authenticated session and exact offered bytes.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
pub(crate) fn matches_native_lease(
    session: &AuthenticatedSession,
    offer: &FileOffer,
    binding: &[u8; 32],
) -> bool {
    *binding == consent_binding(&session.exporter, &session.device_id, offer)
        && offer.peer == session.fingerprint
}

/// Non-serializable, non-clonable result of the in-process Qt owner modal.
/// A caller cannot approve anything by supplying a boolean or raw response.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
pub struct LinuxQtConsentGrant {
    ticket: ConsentTicket,
    destination: crate::receiver::LocalDestinationLease,
    selected_directory: PathBuf,
    pinned_directory: File,
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
impl LinuxQtConsentGrant {
    pub fn selected_directory(&self) -> &Path {
        &self.selected_directory
    }
    pub fn pinned_directory(&self) -> &File {
        &self.pinned_directory
    }
    pub fn into_parts(self) -> (ConsentTicket, crate::receiver::LocalDestinationLease) {
        (self.ticket, self.destination)
    }
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
const LINUX_QT_CONSENT_TTL: Duration = Duration::from_secs(120);

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
fn boot_time_nanos() -> i128 {
    // CLOCK_BOOTTIME also advances through suspend, unlike CLOCK_MONOTONIC.
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    (ts.tv_sec as i128) * 1_000_000_000 + (ts.tv_nsec as i128)
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
fn within_qt_owner_deadline(start: i128, end: i128, active: bool) -> bool {
    active && end >= start && end - start < (LINUX_QT_CONSENT_TTL.as_nanos() as i128)
}

// Bounded replay ledger for the lifetime of the TLS-owning process. A fresh
// process cannot recreate an old exporter without the original TLS session.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
static QT_CONSUMED: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
fn consume_qt_binding(binding: [u8; 32]) -> Result<(), Error> {
    let mut consumed = QT_CONSUMED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map_err(|_| Error::Unauthorized)?;
    if consumed.contains(&binding) || consumed.len() >= 4096 {
        return Err(Error::Unauthorized);
    }
    consumed.insert(binding);
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
fn qt_arg(text: &str) -> Result<CString, Error> {
    CString::new(text).map_err(|_| Error::Invalid("Qt display metadata"))
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
fn pin_approved_owner_directory(path: &Path) -> Result<File, Error> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Invalid("noncanonical owner destination"));
    }
    let relative = path
        .strip_prefix("/")
        .map_err(|_| Error::Invalid("owner destination path"))?;
    let root = File::open("/")?;
    let handle = openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| Error::Io(error.into()))?;
    let directory = File::from(handle);
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Error::Unauthorized);
    }
    Ok(directory)
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
#[derive(Default)]
struct QtPinnedDestination {
    selected: Option<(PathBuf, File)>,
}

// Called only while the bundled Qt dialog's own Accept-button handler runs.
// It pins the selected path before reporting UI acceptance. The context is a
// private stack object whose lifetime encloses the synchronous C++ modal.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
unsafe extern "C" fn qt_pin_owner_directory(
    context: *mut c_void,
    path: *const c_char,
    length: usize,
) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if context.is_null() || path.is_null() || length == 0 || length > 4096 {
            return false;
        }
        // SAFETY: the linked C++ bridge provides valid pointers only during
        // the synchronous modal. No other thread accesses this stack context.
        let data = unsafe { std::slice::from_raw_parts(path as *const u8, length) };
        let Ok(text) = std::str::from_utf8(data) else {
            return false;
        };
        if text
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return false;
        }
        let location = PathBuf::from(text);
        let Ok(owned_directory) = pin_approved_owner_directory(&location) else {
            return false;
        };
        let ctx = unsafe { &mut *(context as *mut QtPinnedDestination) };
        ctx.selected = Some((location, owned_directory));
        true
    }));
    if result.unwrap_or(false) {
        1
    } else {
        0
    }
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
unsafe extern "C" fn qt_transport_still_active(context: *const c_void) -> i32 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: points to the caller's live AtomicBool for the entire
    // synchronous Qt modal; only atomic loads occur on this pointer.
    let live = unsafe { &*(context as *const AtomicBool) };
    i32::from(live.load(Ordering::Acquire))
}

// Native code presents the modal but never sees TLS exporter secrets or
// constructs a ConsentTicket; no network/IPC entrypoint is registered.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
extern "C" {
    fn opendrop_qt_present_owner_consent(
        device: *const c_char,
        fingerprint: *const c_char,
        id: *const c_char,
        name: *const c_char,
        hash: *const c_char,
        bytes: u64,
        initial_dir: *const c_char,
        pin: unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> i32,
        pin_context: *mut c_void,
        is_active: unsafe extern "C" fn(*const c_void) -> i32,
        active_context: *const c_void,
        selected_out: *mut c_char,
        capacity: usize,
    ) -> i32;
}

/// Modal consent on QApplication's GUI thread only. Qt checks active logind
/// user/seat before and after the action; only its owned Accept-button handler
/// returns approval. This is not cryptographic physical-presence proof.
/// Rust enforces a monotonic 120s deadline, transport cancellation and
/// single-use session+offer binding. The TLS owner MUST mark its cancellation
/// flag when the socket closes; no native listener exists yet.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
pub fn request_linux_qt_owner_consent(
    prompt: ConsentPrompt,
    initial_destination: &Path,
    transport_active: &AtomicBool,
) -> Result<LinuxQtConsentGrant, Error> {
    if !transport_active.load(Ordering::Acquire) {
        return Err(Error::Unauthorized);
    }
    let started = boot_time_nanos();
    let initial = initial_destination
        .to_str()
        .ok_or(Error::Invalid("owner-selected directory encoding"))?;
    if !initial_destination.is_absolute()
        || initial.len() > 4096
        || initial.chars().any(char::is_control)
    {
        return Err(Error::Invalid("initial owner destination"));
    }
    let device = qt_arg(prompt.device.as_str())?;
    let peer = qt_arg(prompt.offer.peer.as_str())?;
    let transfer = qt_arg(prompt.offer.id.as_str())?;
    let file_name = qt_arg(&prompt.offer.name)?;
    let checksum = qt_arg(prompt.offer.sha256.as_str())?;
    let initial_dir = qt_arg(initial)?;
    let mut selected = [0i8; 4097];
    let mut pinned = QtPinnedDestination::default();
    // SAFETY: inputs live through this synchronous call; output is a writable
    // bounded buffer. The C++ ABI returns a status and a NUL-terminated path.
    let decision = unsafe {
        opendrop_qt_present_owner_consent(
            device.as_ptr(),
            peer.as_ptr(),
            transfer.as_ptr(),
            file_name.as_ptr(),
            checksum.as_ptr(),
            prompt.offer.bytes,
            initial_dir.as_ptr(),
            qt_pin_owner_directory,
            (&mut pinned as *mut QtPinnedDestination).cast::<c_void>(),
            qt_transport_still_active,
            (transport_active as *const AtomicBool).cast::<c_void>(),
            selected.as_mut_ptr(),
            selected.len(),
        )
    };
    if decision != 1
        || !within_qt_owner_deadline(
            started,
            boot_time_nanos(),
            transport_active.load(Ordering::Acquire),
        )
    {
        return Err(Error::Unauthorized);
    }
    let end = selected
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Unauthorized)?;
    let path_bytes: Vec<u8> = selected[..end].iter().map(|byte| *byte as u8).collect();
    let selected_path = PathBuf::from(
        std::str::from_utf8(&path_bytes).map_err(|_| Error::Invalid("Qt path encoding"))?,
    );
    if !selected_path.is_absolute()
        || end == 0
        || selected_path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || path_bytes.iter().any(u8::is_ascii_control)
    {
        return Err(Error::Invalid("Qt selected a noncanonical destination"));
    }
    let (pinned_path, pinned_directory) = pinned.selected.ok_or(Error::Unauthorized)?;
    if pinned_path != selected_path {
        return Err(Error::Unauthorized);
    }
    let pinned_stat = pinned_directory.metadata()?;
    let binding = consent_binding(&prompt.session, &prompt.device, &prompt.offer);
    consume_qt_binding(binding)?;
    let destination = crate::receiver::LocalDestinationLease::from_local_qt_owner_action(
        &prompt.offer,
        selected_path.clone(),
        binding,
        pinned_stat.dev(),
        pinned_stat.ino(),
    )?;
    let ticket = ConsentTicket {
        offer: prompt.offer,
        session: prompt.session,
        device: prompt.device,
    };
    Ok(LinuxQtConsentGrant {
        ticket,
        destination,
        selected_directory: selected_path,
        pinned_directory,
    })
}

#[cfg(all(test, target_os = "linux", feature = "linux-qt-consent"))]
mod linux_qt_authority_tests {
    use super::*;
    use crate::identity::{KeyFingerprint, Sha256Digest, TransferId};

    fn offer(id: &str) -> FileOffer {
        FileOffer {
            id: TransferId::parse(id).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: "file.txt".to_owned(),
            bytes: 4,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn privileged_deadline_includes_suspend_and_rejects_cancelled_or_expired() {
        let t = 100_000_000_000i128;
        let ttl = LINUX_QT_CONSENT_TTL.as_nanos() as i128;
        assert!(within_qt_owner_deadline(t, t + ttl - 1, true));
        assert!(!within_qt_owner_deadline(t, t + ttl, true));
        assert!(!within_qt_owner_deadline(t, t + 5, false));
        assert!(!within_qt_owner_deadline(t, t - 1, true));
    }

    #[test]
    fn one_use_consent_binding_differs_by_tls_session_and_exact_offer() {
        let claimed = DeviceId::parse(&"1".repeat(32)).unwrap();
        let mut first_exporter = [7u8; 32];
        let first = consent_binding(&first_exporter, &claimed, &offer(&"a".repeat(32)));
        assert!(consume_qt_binding(first).is_ok());
        assert!(consume_qt_binding(first).is_err());
        first_exporter[0] = 8;
        let other_session = consent_binding(&first_exporter, &claimed, &offer(&"a".repeat(32)));
        let other_offer = consent_binding(&[7u8; 32], &claimed, &offer(&"e".repeat(32)));
        assert_ne!(first, other_session);
        assert_ne!(first, other_offer);
        let session = AuthenticatedSession {
            device_id: claimed,
            fingerprint: offer(&"a".repeat(32)).peer,
            exporter: [7u8; 32],
        };
        let accepted = offer(&"a".repeat(32));
        assert!(matches_native_lease(&session, &accepted, &first));
        assert!(!matches_native_lease(&session, &accepted, &other_session));
        assert!(!matches_native_lease(
            &session,
            &offer(&"e".repeat(32)),
            &first
        ));
    }

    #[test]
    fn no_local_desktop_cannot_return_a_usable_approval() {
        // This is a fail-closed check only. We never create QApplication,
        // logind session, synthetic UI click, or a fake approved response.
        let claimed = DeviceId::parse(&"1".repeat(32)).unwrap();
        let prompt = ConsentPrompt {
            offer: offer(&"f".repeat(32)),
            session: [3u8; 32],
            device: claimed,
        };
        let disconnected = AtomicBool::new(false);
        assert!(matches!(
            request_linux_qt_owner_consent(prompt, Path::new("/tmp"), &disconnected),
            Err(Error::Unauthorized)
        ));
    }
}

fn check_at(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
    now_ms: i64,
) -> Result<OfferDecision, Error> {
    offer.validate()?;
    if offer.peer != session.fingerprint {
        return Ok(OfferDecision::Denied);
    }
    let mode = journal.visibility()?;
    Ok(
        match journal.authorize_receive(
            &session.device_id,
            &session.fingerprint,
            mode,
            now_ms,
            false,
        )? {
            ReceiveDecision::AllowAutoAcceptedTrusted => {
                OfferDecision::AutoAccepted(AuthorizedOffer {
                    offer: offer.clone(),
                    session: session.exporter,
                    device: session.device_id.clone(),
                    explicit_consent: false,
                })
            }
            ReceiveDecision::RequireGuestConsent | ReceiveDecision::RequireTrustedConsent => {
                OfferDecision::NeedsLocalConsent(ConsentPrompt {
                    offer: offer.clone(),
                    session: session.exporter,
                    device: session.device_id.clone(),
                })
            }
            _ => OfferDecision::Denied,
        },
    )
}

fn now_millis() -> Result<i64, Error> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unauthorized)?;
    i64::try_from(value.as_millis()).map_err(|_| Error::Unauthorized)
}

pub fn review_incoming(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
) -> Result<OfferDecision, Error> {
    check_at(journal, session, offer, now_millis()?)
}

pub fn authorize_local_consent(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
    ticket: ConsentTicket,
) -> Result<AuthorizedOffer, Error> {
    authorize_local_consent_at(journal, session, offer, ticket, now_millis()?)
}

fn authorize_local_consent_at(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
    ticket: ConsentTicket,
    now_ms: i64,
) -> Result<AuthorizedOffer, Error> {
    if ticket.session != session.exporter
        || ticket.device != session.device_id
        || ticket.offer != *offer
        || offer.peer != session.fingerprint
    {
        return Err(Error::Unauthorized);
    }
    let visibility = journal.visibility()?;
    match journal.authorize_receive(
        &session.device_id,
        &session.fingerprint,
        visibility,
        now_ms,
        false,
    )? {
        ReceiveDecision::RequireGuestConsent | ReceiveDecision::RequireTrustedConsent => {
            Ok(AuthorizedOffer {
                offer: offer.clone(),
                session: session.exporter,
                device: session.device_id.clone(),
                explicit_consent: true,
            })
        }
        _ => Err(Error::Unauthorized),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::identity::{Sha256Digest, TransferId};
    use crate::policy::Visibility;
    use rustls::client::ClientConnection;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use std::io::Cursor;
    use std::process::Command;
    use std::sync::Arc;

    struct Pair {
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
        client_cert: CertificateDer<'static>,
    }

    // Exercise real cryptographic TLS 1.3 mutual certificate authentication,
    // not fake peer IDs or test-only Session constructors. All keys are
    // generated ephemerally in the test directory using the existing OpenSSL.
    fn make_certificate(
        dir: &std::path::Path,
        name: &str,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let cert_pem = dir.join(format!("{name}.crt"));
        let key_pem = dir.join(format!("{name}.private"));
        let cert_der = dir.join(format!("{name}.cert.der"));
        let key_der = dir.join(format!("{name}.key.der"));
        let result = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-days",
                "1",
                "-subj",
                "/CN=OpenDrop-ephemeral-test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth,clientAuth",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                key_pem.to_str().unwrap(),
                "-out",
                cert_pem.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "ephemeral test certificate generation failed"
        );
        assert!(Command::new("openssl")
            .args([
                "x509",
                "-in",
                cert_pem.to_str().unwrap(),
                "-outform",
                "DER",
                "-out",
                cert_der.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success());
        assert!(Command::new("openssl")
            .args([
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                key_pem.to_str().unwrap(),
                "-outform",
                "DER",
                "-out",
                key_der.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success());
        (
            CertificateDer::from(std::fs::read(cert_der).unwrap()),
            PrivatePkcs8KeyDer::from(std::fs::read(key_der).unwrap()).into(),
        )
    }

    fn pair() -> Pair {
        let dir = tempfile::tempdir().unwrap();
        let (server_cert, server_key) = make_certificate(dir.path(), "server");
        let (client_cert, client_key) = make_certificate(dir.path(), "client");
        let mut server_roots = RootCertStore::empty();
        server_roots.add(server_cert.clone()).unwrap();
        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_cert.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let server = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(server_roots)
            .with_client_auth_cert(vec![client_cert.clone()], client_key)
            .unwrap();
        Pair {
            server: Arc::new(server),
            client: Arc::new(client),
            client_cert,
        }
    }

    fn handshake(pair: &Pair) -> ServerConnection {
        let mut server = ServerConnection::new(pair.server.clone()).unwrap();
        let mut client = ClientConnection::new(
            pair.client.clone(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        for _ in 0..16 {
            if client.wants_write() {
                let mut bytes = Vec::new();
                client.write_tls(&mut bytes).unwrap();
                server.read_tls(&mut Cursor::new(bytes)).unwrap();
                server.process_new_packets().unwrap();
            }
            if server.wants_write() {
                let mut bytes = Vec::new();
                server.write_tls(&mut bytes).unwrap();
                client.read_tls(&mut Cursor::new(bytes)).unwrap();
                client.process_new_packets().unwrap();
            }
            if !server.is_handshaking() && !client.is_handshaking() {
                return server;
            }
        }
        panic!("real mutual TLS handshake failed to complete");
    }

    fn device() -> DeviceId {
        DeviceId::parse(&"1".repeat(32)).unwrap()
    }
    fn offer(session: &AuthenticatedSession) -> FileOffer {
        FileOffer {
            id: TransferId::parse(&"2".repeat(32)).unwrap(),
            peer: session.peer_fingerprint().clone(),
            manifest: Sha256Digest::parse(&"3".repeat(64)).unwrap(),
            name: "photo.jpg".into(),
            bytes: 4,
            sha256: Sha256Digest::parse(&"4".repeat(64)).unwrap(),
        }
    }
    fn guest_visible(journal: &mut Journal) {
        journal
            .set_visibility(
                Visibility::default()
                    .everyone(now_millis().unwrap())
                    .unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn real_tls13_mutual_authentication_required_and_fingerprint_is_certificate_derived() {
        let pair = pair();
        let unhandshaken = ServerConnection::new(pair.server.clone()).unwrap();
        assert!(AuthenticatedSession::from_verified_tls_server(&unhandshaken, device()).is_err());
        let verified =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        assert_eq!(
            verified.peer_fingerprint().as_str(),
            format!("{:x}", Sha256::digest(pair.client_cert.as_ref()))
        );
    }

    #[test]
    fn server_rejects_an_untrusted_client_certificate_at_real_tls_handshake() {
        let trusted = pair();
        let unrelated = pair();
        // Same TLS version and valid signatures, but a different root/private
        // key. A claimed DeviceId or certificate string cannot override it.
        let wrong = Pair {
            server: trusted.server,
            client: unrelated.client,
            client_cert: unrelated.client_cert,
        };
        let attempted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handshake(&wrong)));
        assert!(
            attempted.is_err(),
            "unexpectedly accepted a different client certificate"
        );
    }

    #[test]
    fn wrong_peer_identity_or_unapproved_guest_is_denied() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let db = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&db.path().join("auth.sqlite")).unwrap();
        let correct = offer(&session);
        assert!(matches!(
            review_incoming(&journal, &session, &correct).unwrap(),
            OfferDecision::Denied
        ));
        guest_visible(&mut journal);
        let mut claimed = correct.clone();
        claimed.peer = KeyFingerprint::parse(&"e".repeat(64)).unwrap();
        assert!(matches!(
            review_incoming(&journal, &session, &claimed).unwrap(),
            OfferDecision::Denied
        ));
        assert!(matches!(
            review_incoming(&journal, &session, &correct).unwrap(),
            OfferDecision::NeedsLocalConsent(_)
        ));
        // No public constructor or deserializer creates ConsentTicket from
        // user-controlled ID, fingerprint, offer, or boolean.
    }

    #[test]
    fn consent_is_exact_offer_bound_one_use_and_session_replay_fails() {
        let pair = pair();
        let first =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let second =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        assert_ne!(first.exporter, second.exporter);
        let db = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&db.path().join("auth.sqlite")).unwrap();
        guest_visible(&mut journal);
        let offered = offer(&first);
        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &first, &offered).unwrap()
        else {
            panic!("expected owner prompt")
        };
        let mut broker = LocalConsentBroker::default();
        let ticket = broker.approve_from_local_user_action(prompt).unwrap();
        let mut altered = offered.clone();
        altered.name = "different.txt".into();
        assert!(matches!(
            authorize_local_consent(&journal, &first, &altered, ticket),
            Err(Error::Unauthorized)
        ));

        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &first, &offered).unwrap()
        else {
            panic!("expected prompt")
        };
        assert!(broker.approve_from_local_user_action(prompt).is_err()); // consumed approval
        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &second, &offered).unwrap()
        else {
            panic!("expected prompt")
        };
        let ticket = broker.approve_from_local_user_action(prompt).unwrap();
        assert!(authorize_local_consent(&journal, &first, &offered, ticket).is_err());
        // cross-session
    }

    #[test]
    fn verified_peer_autoaccept_defaults_off_revocation_blocks_and_guest_is_isolated() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let db = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&db.path().join("trust.sqlite")).unwrap();
        let offered = offer(&session);
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &session, &offered).unwrap()
        else {
            panic!("default autoaccept must be off")
        };
        let ticket = LocalConsentBroker::default()
            .approve_from_local_user_action(prompt)
            .unwrap();
        journal.revoke_device(&device()).unwrap();
        assert!(authorize_local_consent(&journal, &session, &offered, ticket).is_err());
        guest_visible(&mut journal);
        assert!(matches!(
            review_incoming(&journal, &session, &offered).unwrap(),
            OfferDecision::Denied
        ));
    }

    #[test]
    fn opt_in_autoaccept_is_session_scoped_and_revocation_invalidates_prior_grant() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("trust.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        journal.set_auto_accept(&device(), true).unwrap();
        let offered = offer(&session);
        let OfferDecision::AutoAccepted(granted) =
            review_incoming(&journal, &session, &offered).unwrap()
        else {
            panic!("verified per-device opt-in should permit autoaccept");
        };
        journal.revoke_device(&device()).unwrap();
        assert!(matches!(
            granted.reserve(&mut journal, &session),
            Err(Error::Unauthorized)
        ));
        assert!(journal.lookup(&offered).unwrap().is_none());
    }

    struct UncalledPublisher;
    impl DurablePublisher for UncalledPublisher {
        fn publish(&mut self, _: &FileOffer, _: &str) -> Result<crate::journal::Published, Error> {
            panic!("revoked or mismatched capability must not invoke publisher")
        }
        fn inspect_published(
            &mut self,
            _: &FileOffer,
            _: &str,
        ) -> Result<Option<crate::journal::Published>, Error> {
            panic!("unauthorized receipt path must not inspect destination")
        }
    }

    #[test]
    fn revoked_capability_cannot_commit_or_publish_even_after_reservation() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("trust.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        journal.set_auto_accept(&device(), true).unwrap();
        let offered = offer(&session);
        let OfferDecision::AutoAccepted(granted) =
            review_incoming(&journal, &session, &offered).unwrap()
        else {
            panic!("opt-in trusted peer must have capability")
        };
        granted.reserve(&mut journal, &session).unwrap();
        granted
            .record_commit_intent(&mut journal, &session, "private-local-destination")
            .unwrap();
        journal.revoke_device(&device()).unwrap();
        assert!(matches!(
            granted.record_commit_intent(&mut journal, &session, "private-local-destination"),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            granted.publish_with(&mut journal, &session, &mut UncalledPublisher),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            session.committed_receipt_for_offer(&journal, &offered),
            Err(Error::Unauthorized)
        ));
        assert_eq!(
            journal.lookup(&offered).unwrap().unwrap().phase,
            crate::journal::Phase::CommitIntent
        );
    }

    #[test]
    fn transfer_capability_does_not_work_in_a_different_tls_session() {
        let pair = pair();
        let first =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let second =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("trust.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), first.peer_fingerprint())
            .unwrap();
        journal.set_auto_accept(&device(), true).unwrap();
        let offered = offer(&first);
        let OfferDecision::AutoAccepted(granted) =
            review_incoming(&journal, &first, &offered).unwrap()
        else {
            panic!("expected autoaccept")
        };
        assert!(matches!(
            granted.reserve(&mut journal, &second),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            granted.record_commit_intent(&mut journal, &second, "destination"),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            granted.publish_with(&mut journal, &second, &mut UncalledPublisher),
            Err(Error::Unauthorized)
        ));
        assert!(journal.lookup(&offered).unwrap().is_none());
    }

    #[test]
    fn another_authenticated_peer_cannot_query_committed_receipt_by_transfer_id() {
        let first_pair = pair();
        let second_pair = pair();
        let first =
            AuthenticatedSession::from_verified_tls_server(&handshake(&first_pair), device())
                .unwrap();
        let other =
            AuthenticatedSession::from_verified_tls_server(&handshake(&second_pair), device())
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("receipt.sqlite")).unwrap();
        let offered = offer(&first);
        // Private deterministic recovery fixture seeds a receipt; this is NOT
        // a network-facing API and no actual OS publisher is claimed here.
        journal.reserve(&offered).unwrap();
        journal
            .record_commit_intent(&offered, "local-destination")
            .unwrap();
        struct VerifiedFixture;
        impl DurablePublisher for VerifiedFixture {
            fn publish(
                &mut self,
                o: &FileOffer,
                dest: &str,
            ) -> Result<crate::journal::Published, Error> {
                Ok(crate::journal::Published {
                    destination_ref: dest.into(),
                    bytes: o.bytes,
                    sha256: o.sha256.clone(),
                })
            }
            fn inspect_published(
                &mut self,
                o: &FileOffer,
                dest: &str,
            ) -> Result<Option<crate::journal::Published>, Error> {
                self.publish(o, dest).map(Some)
            }
        }
        journal
            .publish_with(&offered, &mut VerifiedFixture)
            .unwrap();
        assert!(first
            .committed_receipt_for_offer(&journal, &offered)
            .unwrap()
            .is_some());
        assert!(matches!(
            other.committed_receipt_for_offer(&journal, &offered),
            Err(Error::Unauthorized)
        ));
        let mut forged = offered.clone();
        forged.peer = other.peer_fingerprint().clone();
        assert!(matches!(
            other.committed_receipt_for_offer(&journal, &forged),
            Err(Error::DuplicateIdConflict)
        ));
    }

    #[test]
    fn revoked_cert_cannot_become_guest_by_changing_claimed_device_id() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let rotated_id = DeviceId::parse(&"f".repeat(32)).unwrap();
        let impersonator =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), rotated_id).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("revocation.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        journal.revoke_device(&device()).unwrap();
        guest_visible(&mut journal);
        assert!(matches!(
            review_incoming(&journal, &impersonator, &offer(&impersonator)).unwrap(),
            OfferDecision::Denied
        ));
    }

    #[test]
    fn same_device_id_with_different_certificate_is_not_silent_rotation() {
        let original = pair();
        let replacement = pair();
        let trusted =
            AuthenticatedSession::from_verified_tls_server(&handshake(&original), device())
                .unwrap();
        let changed =
            AuthenticatedSession::from_verified_tls_server(&handshake(&replacement), device())
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("rotation.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), trusted.peer_fingerprint())
            .unwrap();
        guest_visible(&mut journal);
        assert!(matches!(
            review_incoming(&journal, &changed, &offer(&changed)).unwrap(),
            OfferDecision::Denied
        ));
        // This tests changed certificate and key. Same-key renewal is a
        // separate case below; both require re-verification in current policy.
    }

    #[test]
    fn renewing_certificate_with_the_same_public_key_requires_reverification() {
        let dir = tempfile::tempdir().unwrap();
        let (original, _) = make_certificate(dir.path(), "original");
        let key = dir.path().join("original.private");
        let renewed = dir.path().join("renewed.crt");
        let creation = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-key",
                key.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=OpenDrop-renewed-certificate",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth,clientAuth",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-out",
                renewed.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(creation.status.success());
        let old_pub = Command::new("openssl")
            .args([
                "x509",
                "-in",
                dir.path().join("original.crt").to_str().unwrap(),
                "-pubkey",
                "-noout",
            ])
            .output()
            .unwrap();
        let new_pub = Command::new("openssl")
            .args([
                "x509",
                "-in",
                renewed.to_str().unwrap(),
                "-pubkey",
                "-noout",
            ])
            .output()
            .unwrap();
        assert!(old_pub.status.success() && new_pub.status.success());
        assert_eq!(
            old_pub.stdout, new_pub.stdout,
            "must hold public key constant"
        );
        let der = Command::new("openssl")
            .args(["x509", "-in", renewed.to_str().unwrap(), "-outform", "DER"])
            .output()
            .unwrap();
        assert!(der.status.success());
        let old_fingerprint =
            KeyFingerprint::parse(&format!("{:x}", Sha256::digest(original.as_ref()))).unwrap();
        let renewed_fingerprint =
            KeyFingerprint::parse(&format!("{:x}", Sha256::digest(&der.stdout))).unwrap();
        assert_ne!(old_fingerprint, renewed_fingerprint);
        let mut journal = Journal::open(&dir.path().join("rotation.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), &old_fingerprint)
            .unwrap();
        guest_visible(&mut journal);
        assert_eq!(
            journal
                .authorize_receive(
                    &device(),
                    &renewed_fingerprint,
                    journal.visibility().unwrap(),
                    now_millis().unwrap(),
                    true
                )
                .unwrap(),
            ReceiveDecision::Deny,
        );
    }
}
