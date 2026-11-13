//! S1-B Linux foreground receiving foundation.
//!
//! The real transport must construct AuthenticatedSession exclusively from a
//! completed strict client-certificate-verified TLS 1.3 server connection.
//! This crate does NOT open a listener, invent pairing, or accept network
//! approval booleans. The in-process Qt owner modal is the sole production
//! path to the core's opaque, one-use session- and offer-bound consent grant.
//!
//! This is not an installed Linux app or a claim of real Android→Linux
//! transfer success. Local filesystem and journal recovery require real OS
//! crash/restart verification before product acceptance.

#![cfg(target_os = "linux")]

mod inventory;
pub mod storage;
pub mod tls;

pub use inventory::RestartReport;

use opendrop_core::authorization::{
    request_linux_qt_owner_consent, AuthenticatedSession, ConsentPrompt,
};
use opendrop_core::journal::{FileOffer, Journal};
use opendrop_core::receiver::{LocalDestinationLease, ReceiveState, ReceiverCoordinator};
use opendrop_core::wire::{Control, Frame};
use opendrop_core::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use storage::{LinuxNativePublisher, LinuxReceiverStorage};

/// Owned by the local authenticated transport, NOT the peer's wire decoder.
/// Dropping or invalidating this handle makes pending and future owner
/// approval fail closed. No operation can turn a cancelled session back on.
pub struct SessionCancellation {
    active: Arc<AtomicBool>,
}

impl SessionCancellation {
    pub fn invalidate(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl Drop for SessionCancellation {
    fn drop(&mut self) {
        self.invalidate();
    }
}

/// One foreground authenticated peer and one exact offer. No code outside the
/// core may mint local consent; a Qt click callback is not an authorization
/// until an in-process privileged bridge has been audited and implemented.
///
/// Runtime listeners, mTLS server configuration, native Qt process startup
/// and background daemon lifecycle remain separate integration gates.
pub struct ForegroundLinuxReceiver {
    coordinator: ReceiverCoordinator,
    store: LinuxReceiverStorage,
    destination: Option<LocalDestinationLease>,
    publisher: Option<LinuxNativePublisher>,
    transport_active: Arc<AtomicBool>,
}

impl ForegroundLinuxReceiver {
    /// Caller MUST have authenticated the peer certificate and TLS exporter
    /// with the existing AuthenticatedSession::from_verified_tls_server.
    pub fn incoming_offer(
        verified_session: AuthenticatedSession,
        journal: &Journal,
        offer: FileOffer,
        store: LinuxReceiverStorage,
    ) -> Result<(Self, ConsentPrompt, SessionCancellation), Error> {
        let (coordinator, prompt) = ReceiverCoordinator::new(verified_session, journal, offer)?;
        let active = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                coordinator,
                store,
                destination: None,
                publisher: None,
                transport_active: active.clone(),
            },
            prompt,
            SessionCancellation { active },
        ))
    }

    pub fn state(&self) -> ReceiveState {
        self.coordinator.state()
    }

    /// Only locally displayable, UNTRUSTED peer metadata; no approval token.
    pub fn pending_offer(&self) -> &FileOffer {
        self.coordinator.offer()
    }

    /// Must run on the QApplication GUI thread in the trusted foreground
    /// application process, never in a network/DBus/message callback.
    /// The C++ modal returns no ticket: core Rust verifies the active local
    /// seat, monotonic deadline, session cancellation and single-use binding
    /// BEFORE constructing the opaque approval and destination capabilities.
    pub fn request_owner_qt_approval(
        &mut self,
        journal: &mut Journal,
        prompt: ConsentPrompt,
    ) -> Result<(), Error> {
        if self.coordinator.state() != ReceiveState::AwaitingConsent
            || prompt.offer() != self.coordinator.offer()
            || !self.transport_active.load(Ordering::Acquire)
        {
            return Err(Error::Unauthorized);
        }
        let granted = request_linux_qt_owner_consent(
            prompt,
            self.store.owner_destination_display(),
            &self.transport_active,
        );
        let grant = match granted {
            Ok(grant) => grant,
            Err(error) => {
                // A dismissed/expired/invalid Qt prompt must not stay pending
                // in the transfer coordinator. No ticket is ever created.
                self.coordinator.decline_locally()?;
                return Err(error);
            }
        };
        // Use the descriptor pinned inside the Qt Accept event. Never reopen
        // the display path, which could be replaced after the owner clicks.
        let updated_store = match self
            .store
            .with_pinned_owner_destination(grant.selected_directory(), grant.pinned_directory())
        {
            Ok(store) => store,
            Err(error) => {
                self.coordinator.decline_locally()?;
                return Err(error);
            }
        };
        let (ticket, destination) = grant.into_parts();
        if !self.transport_active.load(Ordering::Acquire)
            || destination.owner_approved_directory() != updated_store.owner_destination_display()
            || !destination.matches_pinned_directory(updated_store.pinned_destination())?
        {
            self.coordinator.decline_locally()?;
            return Err(Error::Unauthorized);
        }
        self.coordinator.accept_locally(journal, ticket)?;
        self.store = updated_store;
        self.destination = Some(destination);
        Ok(())
    }

    pub fn decline_from_owner(&mut self) -> Result<Frame, Error> {
        self.coordinator.decline_locally()
    }

    pub fn cancel_from_owner(&mut self) -> Result<(), Error> {
        self.coordinator.cancel()
    }

    fn require_live_transport(&mut self) -> Result<(), Error> {
        if self.transport_active.load(Ordering::Acquire) {
            return Ok(());
        }
        if matches!(
            self.coordinator.state(),
            ReceiveState::AwaitingConsent
                | ReceiveState::Accepted
                | ReceiveState::Receiving
                | ReceiveState::StreamVerified
        ) {
            self.coordinator.cancel()?;
        }
        Err(Error::Unauthorized)
    }

    pub fn start_staging(&mut self) -> Result<(), Error> {
        self.require_live_transport()?;
        if self.coordinator.state() != ReceiveState::Accepted || self.publisher.is_some() {
            return Err(Error::InvalidState);
        }
        // The stage name is generated locally by the OS CSPRNG; never from
        // the sender's advertised filename.
        let (stage, publisher) = self.store.allocate(self.coordinator.offer())?;
        self.coordinator.start_receiving(Box::new(stage))?;
        self.publisher = Some(publisher);
        Ok(())
    }

    /// Called ONLY by the authenticated TLS message dispatcher.
    /// The core validates byte count, SHA and exact End/Cancel transfer ID.
    /// No memory growth proportional to total file size.
    pub fn receive_frame(&mut self, frame: Frame) -> Result<(), Error> {
        self.require_live_transport()?;
        let outcome = match frame {
            Frame::Data(bytes) => self.coordinator.note_staged_chunk(&bytes),
            Frame::Control(Control::End(id)) => self.coordinator.finish_stream(&Control::End(id)),
            Frame::Control(message @ (Control::Cancel(_) | Control::Failure(_))) => {
                self.coordinator.abort_from_peer(&message)
            }
            _ => Err(Error::Invalid("unexpected authenticated transfer frame")),
        };
        // Extra data after End, duplicate End, a different transfer's Abort,
        // unsolicited Ready/Complete and other invalid controls must prevent
        // an otherwise verified stream from being committed.
        if outcome.is_err()
            && matches!(
                self.coordinator.state(),
                ReceiveState::AwaitingConsent
                    | ReceiveState::Accepted
                    | ReceiveState::Receiving
                    | ReceiveState::StreamVerified
            )
        {
            self.coordinator.fail()?;
        }
        outcome
    }

    /// This is a trusted local transaction step, NEVER a command accepted
    /// from the peer. The existing core records durable CommitIntent,
    /// performs no-replace publication and independently reads/hashes the
    /// destination before returning Complete.
    pub fn commit_and_complete(&mut self, journal: &mut Journal) -> Result<Frame, Error> {
        self.require_live_transport()?;
        if self.coordinator.state() != ReceiveState::StreamVerified {
            return Err(Error::InvalidState);
        }
        let destination = self.destination.as_ref().ok_or(Error::Unauthorized)?;
        if destination.owner_approved_directory() != self.store.owner_destination_display() {
            return Err(Error::Unauthorized);
        }
        if !destination.matches_pinned_directory(self.store.pinned_destination())? {
            return Err(Error::Unauthorized);
        }
        let publisher = self.publisher.as_mut().ok_or(Error::InvalidState)?;
        self.coordinator
            .record_commit_intent(journal, destination)?;
        self.coordinator.publish(journal, publisher)?;
        self.coordinator.committed_completion()
    }

    /// No unconditional retry of publication after an ambiguous error.
    /// If the journal is durably committed but stage cleanup alone failed,
    /// retry ONLY the owned private unlink, then emit exact Complete.
    pub fn retry_committed_stage_cleanup(&mut self) -> Result<Frame, Error> {
        self.coordinator.retry_committed_cleanup()?;
        self.coordinator.committed_completion()
    }
}

#[cfg(test)]
mod session_guard_tests {
    use super::*;

    #[test]
    fn transport_owner_drop_and_invalidation_are_irreversible() {
        let active = Arc::new(AtomicBool::new(true));
        let handle = SessionCancellation {
            active: active.clone(),
        };
        handle.invalidate();
        assert!(!active.load(Ordering::Acquire));
        drop(handle);
        assert!(!active.load(Ordering::Acquire));

        let second = Arc::new(AtomicBool::new(true));
        let second_handle = SessionCancellation {
            active: second.clone(),
        };
        drop(second_handle);
        assert!(!second.load(Ordering::Acquire));
    }
}
