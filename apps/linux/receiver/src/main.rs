//! OpenDrop S1 foreground Linux receiver.
//!
//! This executable is intentionally NOT installed or started by CI. Existing
//! paired peers use strict, provisioned mutual TLS 1.3 and journal trust.
//! Unknown guests instead require an explicitly provisioned hardware P-256
//! signing identity, owner-enabled visibility, mutually authenticated raw-
//! public-key TLS 1.3, a genuine local Qt SAS gesture, peer confirmation, and
//! a *second* exact-offer local Qt Accept. Neither mode auto-enrolls peers.

// The source-only fake signer and owner-action constructors are available
// solely to hosted unit tests and never to a release executable.
#[cfg(all(feature = "hosted-guest-fixture", not(debug_assertions)))]
compile_error!("hosted-guest-fixture is forbidden for production release builds");

mod ephemeral_guest;
mod guest_signer;
#[cfg(feature = "kwallet-gpg")]
mod kwallet_gpg;
mod runtime;

fn main() {
    if let Err(message) = runtime::run() {
        eprintln!("OpenDrop receiver: {message}");
        std::process::exit(1);
    }
}
