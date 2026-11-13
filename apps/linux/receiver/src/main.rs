//! OpenDrop S1 foreground Linux receiver.
//!
//! This executable is intentionally NOT installed or started by CI. No peer
//! can be received without separately provisioned strict TLS 1.3 material
//! AND an existing, nonrevoked journal pairing. The real owner Qt modal is
//! the only incoming-offer approval path.

mod runtime;

fn main() {
    if let Err(message) = runtime::run() {
        eprintln!("OpenDrop receiver: {message}");
        std::process::exit(1);
    }
}
