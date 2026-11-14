//! OpenDrop shared identity, security policy, durable journal, and S1 transfer
//! contracts. No native consent issuer, app transport, or OS file adapter yet.

pub mod authorization;
pub mod guest;
pub mod guest_recovery;
pub mod guest_tls;
pub mod identity;
pub mod journal;
pub mod policy;
pub mod receiver;
pub mod wire;

#[cfg(test)]
mod durable_receipts_tests;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("peer identity changed or revoked")]
    PeerUntrusted,
    #[error("authenticated session or offer consent required")]
    Unauthorized,
    #[error("transfer ID reused for different peer or content")]
    DuplicateIdConflict,
    #[error("invalid transaction state")]
    InvalidState,
    #[error("destination publication failed: {0}")]
    Publication(String),
    #[error("local journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal database error: {0}")]
    Database(#[from] rusqlite::Error),
}
