//! S1-B Linux foreground receiving foundation.
//!
//! The real transport must construct AuthenticatedSession exclusively from a
//! completed strict client-certificate-verified TLS 1.3 server connection.
//! This crate does NOT open a listener, invent pairing, or accept network
//! approval booleans. A native Qt offer UI can present/decline offers, but
//! the privileged local approval bridge is NOT yet connected: fail closed.
//!
//! This is not an installed Linux app or a claim of real Android→Linux
//! transfer success. Local filesystem and journal recovery require real OS
//! crash/restart verification before product acceptance.

#![cfg(target_os = "linux")]

mod inventory;
pub mod storage;

pub use inventory::RestartReport;

use opendrop_core::authorization::{AuthenticatedSession, ConsentPrompt};
use opendrop_core::journal::{FileOffer, Journal};
use opendrop_core::receiver::{LocalDestinationLease, ReceiveState, ReceiverCoordinator};
use opendrop_core::wire::{Control, Frame};
use opendrop_core::Error;
use storage::{LinuxNativePublisher, LinuxReceiverStorage};

/// One foreground authenticated peer and one exact offer. No code outside the
/// core may mint local consent; a Qt click callback is not an authorization
/// until an in-process privileged bridge has been audited and implemented.
///
/// Runtime listeners, mTLS server configuration, desktop GUI consent and
/// background daemon lifecycle are deliberately outside this first batch.
pub struct ForegroundLinuxReceiver {
    coordinator: ReceiverCoordinator,
    store: LinuxReceiverStorage,
    destination: Option<LocalDestinationLease>,
    publisher: Option<LinuxNativePublisher>,
}

impl ForegroundLinuxReceiver {
    /// Caller MUST have authenticated the peer certificate and TLS exporter
    /// with the existing AuthenticatedSession::from_verified_tls_server.
    pub fn incoming_offer(
        verified_session: AuthenticatedSession,
        journal: &Journal,
        offer: FileOffer,
        store: LinuxReceiverStorage,
    ) -> Result<(Self, ConsentPrompt), Error> {
        let (coordinator, prompt) = ReceiverCoordinator::new(verified_session, journal, offer)?;
        Ok((
            Self {
                coordinator,
                store,
                destination: None,
                publisher: None,
            },
            prompt,
        ))
    }

    pub fn state(&self) -> ReceiveState {
        self.coordinator.state()
    }

    /// Only locally displayable, UNTRUSTED peer metadata; no approval token.
    pub fn pending_offer(&self) -> &FileOffer {
        self.coordinator.offer()
    }

    /// The secure native Qt owner-action issuer is unfinished. Until the
    /// genuine local application-controlled UI event is bound privately to
    /// ConsentPrompt, no production caller can accept or create a lease.
    /// Never replace this with a public bool, callback, terminal or IPC path.
    pub fn accept_unavailable(&self) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }

    pub fn decline_from_owner(&mut self) -> Result<Frame, Error> {
        self.coordinator.decline_locally()
    }

    pub fn cancel_from_owner(&mut self) -> Result<(), Error> {
        self.coordinator.cancel()
    }

    pub fn start_staging(&mut self) -> Result<(), Error> {
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
        if self.coordinator.state() != ReceiveState::StreamVerified {
            return Err(Error::InvalidState);
        }
        let destination = self.destination.as_ref().ok_or(Error::Unauthorized)?;
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
