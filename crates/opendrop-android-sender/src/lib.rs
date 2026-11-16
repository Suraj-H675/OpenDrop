//! OpenDrop S1 Android file-sender engine.
//!
//! Shares the ONE versioned wire and exact-P256 RPK TLS implementation with
//! Linux. TCP connector, TLS client/server, logical sender/receiver and
//! authenticated public-key identity are deliberately separate concepts.
//! The production Android bridge is compiled ONLY on Android, and never
//! constructs software/private-file signing identities.

#[cfg(not(feature = "offline-smoke"))]
pub mod recovery;
#[cfg(not(feature = "offline-smoke"))]
pub mod sender;

#[cfg(target_os = "android")]
mod android_identity_probe;
#[cfg(all(target_os = "android", not(feature = "offline-smoke")))]
mod android_jni;

#[cfg(all(feature = "offline-smoke", feature = "hosted-guest-fixture"))]
compile_error!("offline Android diagnostic cannot link hosted sender fixture");

#[cfg(all(feature = "hosted-guest-fixture", not(debug_assertions)))]
compile_error!("test-only guest approval cannot be linked into release builds");

use opendrop_core::Error as CoreError;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("authentication, owner verification or protocol check failed: {0}")]
    Protocol(&'static str),
    #[error("sender source, socket or storage I/O failed")]
    Io(#[from] io::Error),
    #[error("guest protocol rejected input")]
    Core(#[from] CoreError),
    #[error("the user cancelled or left the foreground")]
    Cancelled,
    #[error("completion uncertain; receipt-only recovery required, never reupload automatically")]
    UncertainCompletion,
    #[error("recipient declined or cancelled")]
    Rejected,
}

pub type Result<T> = std::result::Result<T, SendError>;
