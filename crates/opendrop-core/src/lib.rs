//! OpenDrop P1-A: platform-independent identity policy and durable transfer
//! journal. This is NOT an on-wire protocol, a keystore or a file-transfer app.

pub mod authorization;
pub mod identity;
pub mod journal;
pub mod policy;

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
