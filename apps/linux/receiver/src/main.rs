//! OpenDrop S1 foreground Linux receiver.
//!
//! This executable is intentionally NOT installed or started by CI. Existing
//! paired peers use strict, provisioned mutual TLS 1.3 and journal trust.
//! Unknown guests instead require an explicitly provisioned hardware P-256
//! signing identity, owner-enabled visibility, mutually authenticated raw-
//! public-key TLS 1.3, a genuine local Qt SAS gesture, peer confirmation, and
//! a *second* exact-offer local Qt Accept. Neither mode auto-enrolls peers.

mod guest_signer;
mod runtime;

fn main() {
    if let Err(message) = runtime::run() {
        eprintln!("OpenDrop receiver: {message}");
        std::process::exit(1);
    }
}
