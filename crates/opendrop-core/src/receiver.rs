//! S1 receiver coordinator. No network frame can move this state machine
//! through consent or committed publication.
//!
//! A feature-gated Linux in-process Qt owner action can issue a private
//! exact-session/offer ticket and a pinned destination lease. Other platforms
//! retain the shared protocol and do not inherit a network approval shortcut.

use crate::authorization::{
    authorize_local_consent, review_incoming, AuthenticatedSession, AuthorizedOffer, ConsentPrompt,
    ConsentTicket, OfferDecision,
};
use crate::guest_recovery::{GuestAuthorizedTransfer, GuestRecoveryCredential};
use crate::journal::{DurablePublisher, FileOffer, Journal, Phase, Receipt};
use crate::wire::{self, Control, Frame};
use crate::Error;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveState {
    AwaitingConsent,
    Accepted,
    Receiving,
    StreamVerified,
    CommitIntent,
    Committed,
    /// The journal has a durable exact receipt, but local private staging
    /// cleanup failed. Never re-publish; retry only owned staging cleanup.
    CommittedCleanupPending,
    Complete,
    Declined,
    Cancelled,
    Failed,
    /// Journal or publication outcome is uncertain; do not delete staged
    /// bytes or claim completion until authenticated receipt reconciliation.
    RecoveryRequired,
}

impl ReceiveState {
    fn can_cancel(self) -> bool {
        matches!(
            self,
            Self::AwaitingConsent | Self::Accepted | Self::Receiving | Self::StreamVerified
        )
    }

    fn can_decline(self) -> bool {
        self == Self::AwaitingConsent
    }
}

/// A local destination capability. Its private constructor MUST be supplied
/// later by a reviewed native adapter after genuine owner selection; not by a
/// network handler, deserializer, CLI-supplied peer path or remote caller.
/// Only the feature-gated in-process Qt owner ceremony can produce a lease;
/// the constructor is crate-private, never in a network-facing API.
///
/// ```compile_fail
/// use opendrop_core::receiver::LocalDestinationLease;
/// let _ = LocalDestinationLease::after_linux_owner_confirmation("file.txt");
/// ```
pub struct LocalDestinationLease {
    reference: String,
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    approved_directory: std::path::PathBuf,
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    session_offer_binding: [u8; 32],
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    directory_device: u64,
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    directory_inode: u64,
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
impl LocalDestinationLease {
    /// Internal constructor, only reachable through the security module's
    /// Qt modal owner gesture. No public arbitrary path/approval constructor.
    pub(crate) fn from_local_qt_owner_action(
        offer: &FileOffer,
        selected_directory: std::path::PathBuf,
        binding: [u8; 32],
        directory_device: u64,
        directory_inode: u64,
    ) -> Result<Self, Error> {
        offer.validate()?;
        if !selected_directory.is_absolute() {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            reference: offer.name.clone(),
            approved_directory: selected_directory,
            session_offer_binding: binding,
            directory_device,
            directory_inode,
        })
    }

    pub fn owner_approved_directory(&self) -> &std::path::Path {
        &self.approved_directory
    }

    /// This lease can only be used with the inode pinned at the Qt click.
    /// Subsequent path renames/replacements cannot redirect publication.
    pub fn matches_pinned_directory(&self, pinned: &std::fs::File) -> Result<bool, Error> {
        use std::os::unix::fs::MetadataExt;
        let info = pinned.metadata()?;
        Ok(info.is_dir()
            && info.dev() == self.directory_device
            && info.ino() == self.directory_inode
            && info.uid() == rustix::process::geteuid().as_raw()
            && info.mode() & 0o022 == 0)
    }
}

/// Owned local staging capability. A native adapter must implement these
/// operations on an owner-private temporary file, never on a path received
/// from the peer. The coordinator hashes only chunks successfully appended.
/// `discard` must remove only this transfer's private temporary data and be
/// safe if called again after a previously interrupted cleanup.
///
/// After durable commit intent, recovery belongs to the journal and native
/// publisher; deleting a possibly published file would be unsafe.
///
/// Native adapter requirements (NOT implemented or crash-tested here):
/// - Persist a locally generated staging identity bound to the exact offer,
///   inside a private, owner-controlled staging namespace before streaming.
///   Never accept stage paths from a peer. Reject symlinks and directory
///   escapes; unlink only the owned stage entry, never the final destination.
/// - At process restart, with no old session active, enumerate ONLY this
///   namespace through verified directory handles and compare exact IDs to
///   the durable journal. No journal record / Reserved: remove abandoned
///   private stage. CommitIntent: preserve stage until independent published
///   destination inspection and journal reconciliation. Committed: remove
///   leftover private stage only; never re-publish.
/// - Do not rely on Drop to clean up after power loss, and do not delete
///   uncertain CommitIntent staging on destruction.
pub trait StagingLease: Send {
    fn append_chunk(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn sync_staged(&mut self) -> Result<(), Error>;
    fn discard(&mut self) -> Result<(), Error>;
}

/// The receiver owns the verified TLS session and an exact immutable offer.
/// AuthorizedOffer can only originate from the established authorization
/// boundary, which verifies exporter, peer certificate and offer identity.
pub struct ReceiverCoordinator {
    authority: ReceiverAuthority,
    offer: FileOffer,
    state: ReceiveState,
    staging: Option<Box<dyn StagingLease>>,
    seen: u64,
    hash: Sha256,
    receipt: Option<Receipt>,
}

// The same durable receiver handles two *disjoint* authorization domains.
// A guest SPKI cannot be reinterpreted as a legacy paired certificate.
enum ReceiverAuthority {
    Paired {
        session: AuthenticatedSession,
        authorized: Option<AuthorizedOffer>,
    },
    Guest(GuestAuthorizedTransfer),
}

impl ReceiverAuthority {
    fn is_active_and_authorized(&self) -> bool {
        match self {
            Self::Paired { authorized, .. } => authorized.is_some(),
            Self::Guest(guest) => guest.is_active(),
        }
    }

    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    fn matches_lease(&self, offer: &FileOffer, binding: &[u8; 32]) -> bool {
        match self {
            Self::Paired { session, .. } => {
                crate::authorization::matches_native_lease(session, offer, binding)
            }
            Self::Guest(guest) => {
                guest.is_active()
                    && guest.journal_offer() == offer
                    && guest.session_binding() == binding
            }
        }
    }

    fn record_commit_intent(
        &self,
        journal: &mut Journal,
        destination_ref: &str,
    ) -> Result<(), Error> {
        match self {
            Self::Paired {
                session,
                authorized,
            } => authorized
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .record_commit_intent(journal, session, destination_ref),
            Self::Guest(guest) => guest.record_commit_intent(journal, destination_ref),
        }
    }

    fn publish_with(
        &self,
        journal: &mut Journal,
        publisher: &mut impl DurablePublisher,
    ) -> Result<Receipt, Error> {
        match self {
            Self::Paired {
                session,
                authorized,
            } => authorized
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .publish_with(journal, session, publisher),
            Self::Guest(guest) => guest.publish_with(journal, publisher),
        }
    }
}

impl ReceiverCoordinator {
    /// Guest and trusted auto-accept are intentionally NOT accepted in S1.
    /// Caller must show the returned prompt locally to the real owner.
    pub fn new(
        session: AuthenticatedSession,
        journal: &Journal,
        offer: FileOffer,
    ) -> Result<(Self, ConsentPrompt), Error> {
        wire::validate_offer(&offer)?;
        let prompt = match review_incoming(journal, &session, &offer)? {
            OfferDecision::NeedsLocalConsent(prompt) => prompt,
            OfferDecision::Denied | OfferDecision::AutoAccepted(_) => {
                return Err(Error::Unauthorized);
            }
        };
        let coordinator = Self {
            authority: ReceiverAuthority::Paired {
                session,
                authorized: None,
            },
            offer,
            state: ReceiveState::AwaitingConsent,
            staging: None,
            seen: 0,
            hash: Sha256::new(),
            receipt: None,
        };
        Ok((coordinator, prompt))
    }

    /// The only guest entry point. The opaque capability has already passed
    /// bilateral SAS and a separate exact-offer owner action. No network
    /// metadata, bool or public key alone can construct it.
    pub fn new_guest(
        authorized: GuestAuthorizedTransfer,
        journal: &mut Journal,
        recovery: &GuestRecoveryCredential,
    ) -> Result<Self, Error> {
        let offer = authorized.journal_offer().clone();
        wire::validate_offer(&offer)?;
        if !authorized.is_active() {
            return Err(Error::Unauthorized);
        }
        authorized.reserve_with_recovery(journal, recovery)?;
        let snapshot = journal.lookup(&offer)?.ok_or(Error::InvalidState)?;
        require_receiving_phase(snapshot.phase)?;
        Ok(Self {
            authority: ReceiverAuthority::Guest(authorized),
            offer,
            state: ReceiveState::Accepted,
            staging: None,
            seen: 0,
            hash: Sha256::new(),
            receipt: None,
        })
    }

    pub fn state(&self) -> ReceiveState {
        self.state
    }

    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    pub fn received_bytes(&self) -> u64 {
        self.seen
    }

    /// Only an opaque ticket minted after a real local user action can pass.
    /// The current test-only broker cannot mint tickets in production.
    pub fn accept_locally(
        &mut self,
        journal: &mut Journal,
        ticket: ConsentTicket,
    ) -> Result<(), Error> {
        if self.state != ReceiveState::AwaitingConsent {
            return Err(Error::InvalidState);
        }
        let ReceiverAuthority::Paired {
            session,
            authorized: slot,
        } = &mut self.authority
        else {
            return Err(Error::Unauthorized);
        };
        let authorized = authorize_local_consent(journal, session, &self.offer, ticket)?;
        let reservation = authorized.reserve(journal, session)?;
        // `reserve` is intentionally idempotent for recovery and exact
        // receipt lookup. A newly accepted stream must NOT reuse a journal
        // record that already entered publication or was committed.
        require_receiving_phase(reservation.phase)?;
        *slot = Some(authorized);
        self.state = ReceiveState::Accepted;
        Ok(())
    }

    pub fn start_receiving(&mut self, staging: Box<dyn StagingLease>) -> Result<(), Error> {
        if self.state != ReceiveState::Accepted
            || !self.authority.is_active_and_authorized()
            || self.staging.is_some()
        {
            return Err(Error::InvalidState);
        }
        self.staging = Some(staging);
        self.state = ReceiveState::Receiving;
        Ok(())
    }

    /// The locally owned staging adapter writes each chunk before it counts
    /// toward the authenticated stream digest. This is not final publication.
    pub fn note_staged_chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.state != ReceiveState::Receiving {
            return Err(Error::InvalidState);
        }
        if !self.authority.is_active_and_authorized() {
            self.fail()?;
            return Err(Error::Unauthorized);
        }
        if bytes.is_empty() || bytes.len() > wire::MAX_CHUNK {
            self.fail()?;
            return Err(Error::Invalid("S1 chunk size"));
        }
        let Some(next) = self.seen.checked_add(bytes.len() as u64) else {
            self.fail()?;
            return Err(Error::Invalid("S1 byte overflow"));
        };
        if next > self.offer.bytes || next > wire::MAX_FILE {
            self.fail()?;
            return Err(Error::Invalid("S1 advertised byte count"));
        }
        let result = self
            .staging
            .as_mut()
            .ok_or(Error::InvalidState)?
            .append_chunk(bytes);
        if let Err(error) = result {
            self.fail()?;
            return Err(error);
        }
        self.hash.update(bytes);
        self.seen = next;
        Ok(())
    }

    /// A truncated or corrupt stream can never enter commit-intent.
    pub fn finish_stream(&mut self, end: &Control) -> Result<(), Error> {
        if self.state != ReceiveState::Receiving {
            return Err(Error::InvalidState);
        }
        if !self.authority.is_active_and_authorized() {
            self.fail()?;
            return Err(Error::Unauthorized);
        }
        // The transport adapter must pass the authenticated End frame, not
        // infer completion merely from EOF or the advertised byte count.
        if validate_end_control(&self.offer, end).is_err() {
            self.fail()?;
            return Err(Error::Invalid("S1 exact End control required"));
        }
        let sha = format!("{:x}", self.hash.clone().finalize());
        if self.seen != self.offer.bytes || sha != self.offer.sha256.as_str() {
            self.fail()?;
            return Err(Error::Invalid("S1 source checksum or length"));
        }
        let result = self
            .staging
            .as_mut()
            .ok_or(Error::InvalidState)?
            .sync_staged();
        if let Err(error) = result {
            self.fail()?;
            return Err(error);
        }
        self.state = ReceiveState::StreamVerified;
        Ok(())
    }

    /// This cannot be reached by a remote path or arbitrary caller because
    /// there is no production constructor for the opaque local lease.
    pub fn record_commit_intent(
        &mut self,
        journal: &mut Journal,
        destination: &LocalDestinationLease,
    ) -> Result<(), Error> {
        if self.state != ReceiveState::StreamVerified {
            return Err(Error::InvalidState);
        }
        #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
        if destination.reference != self.offer.name
            || !self
                .authority
                .matches_lease(&self.offer, &destination.session_offer_binding)
        {
            return Err(Error::Unauthorized);
        }
        // The existing AuthorizedOffer verifies the session/visibility
        // BEFORE invoking Journal::record_commit_intent. Its Unauthorized
        // result therefore cannot represent a completed journal write, and
        // locally staged bytes should be removed. Other I/O/database errors
        // may leave an uncertain durable intent and MUST preserve staging.
        // Revisit this classification if the authorization or journal APIs
        // ever acquire post-mutation Unauthorized failures.
        match self
            .authority
            .record_commit_intent(journal, &destination.reference)
        {
            Ok(()) => {
                self.state = ReceiveState::CommitIntent;
                Ok(())
            }
            Err(error) if definitely_pre_journal_rejection(&error) => {
                self.fail()?;
                Err(error)
            }
            Err(error) => {
                self.state = ReceiveState::RecoveryRequired;
                Err(error)
            }
        }
    }

    /// DurablePublisher is a native trusted-computing-base adapter: it must
    /// enforce no-replace, fsync and independent destination byte inspection.
    /// The existing AuthorizedOffer and journal verify this session again
    /// before publishing and issue the receipt only after durable commit.
    pub fn publish(
        &mut self,
        journal: &mut Journal,
        publisher: &mut impl DurablePublisher,
    ) -> Result<&Receipt, Error> {
        if self.state != ReceiveState::CommitIntent {
            return Err(Error::InvalidState);
        }
        let result = self.authority.publish_with(journal, publisher);
        match result {
            Ok(receipt) if receipt_matches(&self.offer, &receipt) => {
                self.receipt = Some(receipt);
                // The journal is *already committed*. A failing stage unlink
                // cannot turn that into an uncommitted transfer. Keep both the
                // exact receipt and the owned stage for retry/restart cleanup.
                self.state = ReceiveState::CommittedCleanupPending;
                self.retry_committed_cleanup()?;
                self.receipt.as_ref().ok_or(Error::InvalidState)
            }
            Ok(_) => {
                self.state = ReceiveState::RecoveryRequired;
                Err(Error::Unauthorized)
            }
            Err(error) => {
                // The durable intent may require authenticated recovery.
                // Never blindly retry publication after an uncertain error.
                self.state = ReceiveState::RecoveryRequired;
                Err(error)
            }
        }
    }

    /// Idempotent cleanup of a *committed* transfer's private staging entry.
    /// This must not touch the already-published destination or re-publish.
    /// A cleanup failure leaves CommittedCleanupPending and the receipt
    /// available for local diagnosis and eventual restart reconciliation.
    pub fn retry_committed_cleanup(&mut self) -> Result<(), Error> {
        finalize_committed_stage(&mut self.state, &self.receipt, &mut self.staging)
    }

    /// Exact durable receipt remains recorded when staging cleanup fails.
    /// A caller must not conflate this with an outgoing Complete message:
    /// committed_completion requires cleanup success.
    pub fn durable_receipt(&self) -> Option<&Receipt> {
        self.receipt.as_ref()
    }

    /// The ONLY outgoing Complete constructor in the receiver coordinator.
    /// It cannot run after cancel, failure or an uncommitted journal intent.
    pub fn committed_completion(&mut self) -> Result<Frame, Error> {
        let receipt = self.receipt.clone().ok_or(Error::InvalidState)?;
        if !receipt_matches(&self.offer, &receipt) {
            return Err(Error::Unauthorized);
        }
        // No Complete frame while a private staging entry is awaiting
        // cleanup; the journal receipt remains separately recoverable.
        complete_once(&mut self.state, &self.receipt, &self.staging)?;
        Ok(Frame::Control(Control::Complete(receipt)))
    }

    /// Explicit local decline while the user-approval prompt is pending.
    /// No consent ticket, staging bytes or reservation is created.
    pub fn decline_locally(&mut self) -> Result<Frame, Error> {
        if !self.state.can_decline() {
            return Err(Error::InvalidState);
        }
        self.state = ReceiveState::Declined;
        Ok(Frame::Control(Control::Decline(self.offer.id.clone())))
    }

    pub fn cancel(&mut self) -> Result<(), Error> {
        cancel_precommit_stage(&mut self.state, &mut self.staging)
    }

    /// A remote Abort applies only to the exact accepted transfer. Wire
    /// `Ready` or `Decline` cannot create consent or alter a receiving state.
    pub fn abort_from_peer(&mut self, control: &Control) -> Result<(), Error> {
        match control {
            Control::Cancel(id) if id == &self.offer.id => self.cancel(),
            Control::Failure(id) if id == &self.offer.id => self.fail(),
            _ => Err(Error::Unauthorized),
        }
    }

    pub fn fail(&mut self) -> Result<(), Error> {
        if self.state == ReceiveState::Failed {
            return self.retry_precommit_cleanup();
        }
        if !self.state.can_cancel() {
            return Err(Error::InvalidState);
        }
        self.state = ReceiveState::Failed;
        discard_owned_staging(&mut self.staging)
    }

    /// A failed discard retains the staging capability so the local owner
    /// adapter can retry deletion. Never erase after a commit-intent attempt.
    pub fn retry_precommit_cleanup(&mut self) -> Result<(), Error> {
        if !matches!(
            self.state,
            ReceiveState::Cancelled | ReceiveState::Declined | ReceiveState::Failed
        ) {
            return Err(Error::InvalidState);
        }
        discard_owned_staging(&mut self.staging)
    }
}

fn discard_owned_staging(staging: &mut Option<Box<dyn StagingLease>>) -> Result<(), Error> {
    if let Some(lease) = staging.as_mut() {
        lease.discard()?;
    }
    *staging = None;
    Ok(())
}

fn cancel_precommit_stage(
    state: &mut ReceiveState,
    staging: &mut Option<Box<dyn StagingLease>>,
) -> Result<(), Error> {
    if *state != ReceiveState::Cancelled && !state.can_cancel() {
        return Err(Error::InvalidState);
    }
    *state = ReceiveState::Cancelled;
    discard_owned_staging(staging)
}

fn finalize_committed_stage(
    state: &mut ReceiveState,
    receipt: &Option<Receipt>,
    staging: &mut Option<Box<dyn StagingLease>>,
) -> Result<(), Error> {
    if *state == ReceiveState::Committed && receipt.is_some() && staging.is_none() {
        return Ok(());
    }
    if *state != ReceiveState::CommittedCleanupPending || receipt.is_none() {
        return Err(Error::InvalidState);
    }
    // An Err preserves both the owned stage and its durable receipt. The
    // caller may retry *only* cleanup, never the publication operation.
    discard_owned_staging(staging)?;
    *state = ReceiveState::Committed;
    Ok(())
}

fn complete_once(
    state: &mut ReceiveState,
    receipt: &Option<Receipt>,
    staging: &Option<Box<dyn StagingLease>>,
) -> Result<(), Error> {
    if *state != ReceiveState::Committed || receipt.is_none() || staging.is_some() {
        return Err(Error::InvalidState);
    }
    *state = ReceiveState::Complete;
    Ok(())
}

/// Restart decision, NOT a filesystem deletion function. This is applied
/// only after native validation of a staging entry from its private local
/// namespace and a trusted journal lookup; never accept a wire-supplied phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestartStaging {
    RemovePrivateStageOnly,
    PreserveForJournalReconciliation,
}

#[allow(dead_code)] // Native crash recovery remains a separate acceptance gate.
pub(crate) fn restart_staging(phase: Option<Phase>) -> RestartStaging {
    if phase == Some(Phase::CommitIntent) {
        RestartStaging::PreserveForJournalReconciliation
    } else {
        // No journal row, Reserved, or durably Committed: an inactive stage
        // entry can be removed, but never its final destination.
        RestartStaging::RemovePrivateStageOnly
    }
}

fn receipt_matches(offer: &FileOffer, receipt: &Receipt) -> bool {
    receipt.transfer_id == offer.id
        && receipt.peer == offer.peer
        && receipt.manifest == offer.manifest
        && receipt.bytes == offer.bytes
        && receipt.sha256 == offer.sha256
}

fn require_receiving_phase(phase: Phase) -> Result<(), Error> {
    if phase != Phase::Reserved {
        return Err(Error::InvalidState);
    }
    Ok(())
}

fn definitely_pre_journal_rejection(error: &Error) -> bool {
    matches!(error, Error::Unauthorized)
}

fn validate_end_control(offer: &FileOffer, end: &Control) -> Result<(), Error> {
    match end {
        Control::End(id) if id == &offer.id => Ok(()),
        _ => Err(Error::Invalid("S1 exact End control required")),
    }
}

#[cfg(all(test, target_os = "linux", feature = "linux-qt-consent"))]
mod native_destination_identity_tests {
    use super::*;
    use crate::identity::{KeyFingerprint, Sha256Digest, TransferId};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn lease_rejects_replaced_directory_inodes_and_weakened_permissions() {
        let owned = tempfile::tempdir().unwrap();
        let chosen = owned.path().join("chosen");
        let moved = owned.path().join("previous-inode");
        std::fs::create_dir(&chosen).unwrap();
        let original = std::fs::File::open(&chosen).unwrap();
        let info = original.metadata().unwrap();
        let offer = FileOffer {
            id: TransferId::parse(&"a".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: "file.txt".to_owned(),
            bytes: 4,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        };
        let lease = LocalDestinationLease::from_local_qt_owner_action(
            &offer,
            chosen.clone(),
            [8; 32],
            info.dev(),
            info.ino(),
        )
        .unwrap();
        assert!(lease.matches_pinned_directory(&original).unwrap());
        std::fs::rename(&chosen, &moved).unwrap();
        std::fs::create_dir(&chosen).unwrap();
        let replacement = std::fs::File::open(&chosen).unwrap();
        assert!(!lease.matches_pinned_directory(&replacement).unwrap());
        assert!(lease.matches_pinned_directory(&original).unwrap());
        std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!lease.matches_pinned_directory(&original).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{KeyFingerprint, Sha256Digest, TransferId};

    #[test]
    fn cancellation_is_only_precommit_and_terminal() {
        for state in [
            ReceiveState::AwaitingConsent,
            ReceiveState::Accepted,
            ReceiveState::Receiving,
            ReceiveState::StreamVerified,
        ] {
            assert!(state.can_cancel());
        }
        for state in [
            ReceiveState::CommitIntent,
            ReceiveState::Committed,
            ReceiveState::Complete,
            ReceiveState::Declined,
            ReceiveState::Cancelled,
            ReceiveState::Failed,
            ReceiveState::RecoveryRequired,
        ] {
            assert!(!state.can_cancel());
        }
    }

    #[test]
    fn decline_is_only_legal_before_local_acceptance() {
        assert!(ReceiveState::AwaitingConsent.can_decline());
        for state in [
            ReceiveState::Accepted,
            ReceiveState::Receiving,
            ReceiveState::StreamVerified,
            ReceiveState::CommitIntent,
            ReceiveState::Committed,
            ReceiveState::Complete,
            ReceiveState::Declined,
            ReceiveState::Cancelled,
            ReceiveState::Failed,
            ReceiveState::RecoveryRequired,
        ] {
            assert!(!state.can_decline());
        }
    }

    #[test]
    fn owned_precommit_staging_cleanup_is_exactly_once_or_retryable() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct FakeStage {
            discarded: Arc<AtomicUsize>,
            fail_discard: bool,
        }
        impl StagingLease for FakeStage {
            fn append_chunk(&mut self, _: &[u8]) -> Result<(), Error> {
                Ok(())
            }
            fn sync_staged(&mut self) -> Result<(), Error> {
                Ok(())
            }
            fn discard(&mut self) -> Result<(), Error> {
                self.discarded.fetch_add(1, Ordering::SeqCst);
                if self.fail_discard {
                    return Err(Error::Invalid("synthetic discard failure"));
                }
                Ok(())
            }
        }

        let successful = Arc::new(AtomicUsize::new(0));
        let mut stage: Option<Box<dyn StagingLease>> = Some(Box::new(FakeStage {
            discarded: successful.clone(),
            fail_discard: false,
        }));
        discard_owned_staging(&mut stage).unwrap();
        discard_owned_staging(&mut stage).unwrap();
        assert_eq!(successful.load(Ordering::SeqCst), 1);
        assert!(stage.is_none());

        let failed = Arc::new(AtomicUsize::new(0));
        let mut stage: Option<Box<dyn StagingLease>> = Some(Box::new(FakeStage {
            discarded: failed.clone(),
            fail_discard: true,
        }));
        assert!(discard_owned_staging(&mut stage).is_err());
        assert_eq!(failed.load(Ordering::SeqCst), 1);
        assert!(stage.is_some());
    }

    #[test]
    fn committed_or_inflight_publication_is_not_a_new_receive() {
        assert!(require_receiving_phase(Phase::Reserved).is_ok());
        assert!(require_receiving_phase(Phase::CommitIntent).is_err());
        assert!(require_receiving_phase(Phase::Committed).is_err());
    }

    #[test]
    fn revoked_or_expired_authorization_can_clean_before_journal_mutation() {
        assert!(definitely_pre_journal_rejection(&Error::Unauthorized));
        assert!(!definitely_pre_journal_rejection(&Error::InvalidState));
        assert!(!definitely_pre_journal_rejection(&Error::Invalid(
            "destination reference"
        )));
        assert!(!definitely_pre_journal_rejection(&Error::Io(
            std::io::Error::other("synthetic journal failure")
        )));
    }

    #[test]
    fn only_end_for_the_exact_transfer_can_finish_a_stream() {
        let offer = FileOffer {
            id: TransferId::parse(&"a".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: "data.bin".into(),
            bytes: 0,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        };
        assert!(validate_end_control(&offer, &Control::End(offer.id.clone())).is_ok());
        let wrong_id = TransferId::parse(&"e".repeat(32)).unwrap();
        assert!(validate_end_control(&offer, &Control::End(wrong_id)).is_err());
        assert!(validate_end_control(&offer, &Control::Ready(offer.id.clone())).is_err());
        assert!(validate_end_control(&offer, &Control::Cancel(offer.id.clone())).is_err());
    }

    #[test]
    fn exact_receipt_comparison_rejects_other_peer_or_transfer() {
        // Comparison logic exercises exact identity; genuine authenticated
        // session/consent/journal transitions require native integration.
        let offer = FileOffer {
            id: TransferId::parse(&"a".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: "test.bin".into(),
            bytes: 5,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        };
        let receipt = Receipt {
            transfer_id: offer.id.clone(),
            peer: offer.peer.clone(),
            manifest: offer.manifest.clone(),
            bytes: offer.bytes,
            sha256: offer.sha256.clone(),
        };
        // This test deliberately does not mint a real ReceiverCoordinator:
        // no public constructor can forge a completed TLS session.
        assert!(receipt_matches(&offer, &receipt));
        let mut changed = receipt.clone();
        changed.peer = KeyFingerprint::parse(&"e".repeat(64)).unwrap();
        assert!(!receipt_matches(&offer, &changed));
        changed = receipt.clone();
        changed.transfer_id = TransferId::parse(&"e".repeat(32)).unwrap();
        assert!(!receipt_matches(&offer, &changed));
        changed = receipt.clone();
        changed.bytes += 1;
        assert!(!receipt_matches(&offer, &changed));
    }

    /// Synthetic stage owned only by this test's tempdir. This exercises
    /// state/cleanup semantics, NOT symlink-safe Linux publication or an
    /// actual process/power-loss recovery implementation.
    struct OwnedStageFile {
        path: std::path::PathBuf,
        fail_next_discard: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl StagingLease for OwnedStageFile {
        fn append_chunk(&mut self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn sync_staged(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn discard(&mut self) -> Result<(), Error> {
            use std::sync::atomic::Ordering;
            if self.fail_next_discard.swap(false, Ordering::SeqCst) {
                return Err(Error::Io(std::io::Error::other(
                    "synthetic stage-only unlink failure",
                )));
            }
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(Error::Io(error)),
            }
        }
    }

    fn committed_fixture_receipt() -> Receipt {
        Receipt {
            transfer_id: TransferId::parse(&"a".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            bytes: 3,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn durable_commit_cleanup_removes_only_owned_stage_and_is_idempotent() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let owned = tempfile::tempdir().unwrap();
        let partial = owned.path().join("private-owned.partial");
        let destination = owned.path().join("published-destination.txt");
        std::fs::write(&partial, b"abc").unwrap();
        std::fs::write(&destination, b"do not delete").unwrap();
        let mut stage: Option<Box<dyn StagingLease>> = Some(Box::new(OwnedStageFile {
            path: partial.clone(),
            fail_next_discard: Arc::new(AtomicBool::new(false)),
        }));
        let receipt = Some(committed_fixture_receipt());
        let mut state = ReceiveState::CommittedCleanupPending;

        finalize_committed_stage(&mut state, &receipt, &mut stage).unwrap();
        assert_eq!(state, ReceiveState::Committed);
        assert!(!partial.exists());
        assert!(stage.is_none());
        assert_eq!(
            std::fs::read(&destination).unwrap().as_slice(),
            b"do not delete"
        );
        finalize_committed_stage(&mut state, &receipt, &mut stage).unwrap();
        complete_once(&mut state, &receipt, &stage).unwrap();
        assert_eq!(state, ReceiveState::Complete);
        assert!(complete_once(&mut state, &receipt, &stage).is_err());
        assert_eq!(
            std::fs::read(&destination).unwrap().as_slice(),
            b"do not delete"
        );
    }

    #[test]
    fn failed_postcommit_cleanup_retains_durable_receipt_and_stage_for_retry() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let owned = tempfile::tempdir().unwrap();
        let partial = owned.path().join("owned-stage.partial");
        let published = owned.path().join("real-destination");
        std::fs::write(&partial, b"abc").unwrap();
        std::fs::write(&published, b"durable destination").unwrap();
        let fail = Arc::new(AtomicBool::new(true));
        let mut stage: Option<Box<dyn StagingLease>> = Some(Box::new(OwnedStageFile {
            path: partial.clone(),
            fail_next_discard: fail,
        }));
        let receipt = Some(committed_fixture_receipt());
        let mut state = ReceiveState::CommittedCleanupPending;
        assert!(finalize_committed_stage(&mut state, &receipt, &mut stage).is_err());
        assert_eq!(state, ReceiveState::CommittedCleanupPending);
        assert!(stage.is_some());
        assert!(partial.exists());
        assert!(receipt.is_some());
        assert!(complete_once(&mut state, &receipt, &stage).is_err());
        assert_eq!(
            std::fs::read(&published).unwrap().as_slice(),
            b"durable destination"
        );

        finalize_committed_stage(&mut state, &receipt, &mut stage).unwrap();
        assert_eq!(state, ReceiveState::Committed);
        assert!(!partial.exists());
        assert_eq!(
            std::fs::read(&published).unwrap().as_slice(),
            b"durable destination"
        );
    }

    #[test]
    fn precommit_cancellation_can_retry_and_never_cleans_unknown_destinations() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let owned = tempfile::tempdir().unwrap();
        let partial = owned.path().join("only-my-stage.partial");
        let unrelated = owned.path().join("unrelated-file");
        std::fs::write(&partial, b"uncommitted").unwrap();
        std::fs::write(&unrelated, b"safe").unwrap();
        let mut stage: Option<Box<dyn StagingLease>> = Some(Box::new(OwnedStageFile {
            path: partial.clone(),
            fail_next_discard: Arc::new(AtomicBool::new(true)),
        }));
        let mut state = ReceiveState::Receiving;
        assert!(cancel_precommit_stage(&mut state, &mut stage).is_err());
        assert_eq!(state, ReceiveState::Cancelled);
        assert!(partial.exists());
        cancel_precommit_stage(&mut state, &mut stage).unwrap();
        cancel_precommit_stage(&mut state, &mut stage).unwrap();
        assert!(!partial.exists());
        assert_eq!(std::fs::read(&unrelated).unwrap().as_slice(), b"safe");

        let mut uncertain = ReceiveState::CommitIntent;
        let mut none = None;
        assert!(cancel_precommit_stage(&mut uncertain, &mut none).is_err());
        assert_eq!(uncertain, ReceiveState::CommitIntent);
    }

    #[test]
    fn restart_policy_preserves_intent_but_retires_precommit_and_committed_stages() {
        assert_eq!(
            restart_staging(None),
            RestartStaging::RemovePrivateStageOnly
        );
        assert_eq!(
            restart_staging(Some(Phase::Reserved)),
            RestartStaging::RemovePrivateStageOnly
        );
        assert_eq!(
            restart_staging(Some(Phase::CommitIntent)),
            RestartStaging::PreserveForJournalReconciliation
        );
        assert_eq!(
            restart_staging(Some(Phase::Committed)),
            RestartStaging::RemovePrivateStageOnly
        );
        // This tests the pure restart decision table; it neither deletes a
        // file nor simulates real process interruption or durable recovery.
    }
}
