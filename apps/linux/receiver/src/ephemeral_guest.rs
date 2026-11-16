//! Explicit one-time guest signing identity. There are NO identity files.
//! Generate with the OS CSPRNG on every process start; never auto-replace
//! an expected missing or locked protected installation identity.
//!
//! The private EC scalar remains accessible within this process (not HSM
//! nonextractable). That is a disclosed limitation of RAM-only sharing.
use opendrop_core::guest::P256Spki;
use opendrop_core::guest_tls::{LocalGuestIdentity, NativeP256Signer};
use opendrop_core::identity::DeviceId;
use opendrop_core::Error;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

struct VolatileP256Signer {
    signing: EcdsaKeyPair,
    spki: P256Spki,
}

impl std::fmt::Debug for VolatileP256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenDrop one-time OS-CSPRNG P256 RAM-only signer [secret redacted]")
    }
}

impl NativeP256Signer for VolatileP256Signer {
    fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.spki.as_der().to_vec())
    }
    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.signing
            .sign(&SystemRandom::new(), message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| Error::Unauthorized)
    }
}

pub(crate) fn create_once() -> Result<LocalGuestIdentity, Error> {
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| Error::Unauthorized)?;
    // The generated PKCS8 document exists only in-process, never as a file,
    // environment variable, or command-line argument.
    let signing =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng)
            .map_err(|_| Error::Unauthorized)?;
    let point = signing.public_key().as_ref();
    if point.len() != 65 || point[0] != 4 {
        return Err(Error::Unauthorized);
    }
    let mut der = Vec::with_capacity(91);
    der.extend_from_slice(&SPKI_PREFIX);
    der.extend_from_slice(point);
    let spki = P256Spki::from_canonical_der(&der)?;
    let digest = Sha256::digest(spki.as_der());
    let id = digest[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let device_id = DeviceId::parse(&id)?;
    LocalGuestIdentity::from_platform_signer(
        device_id,
        Arc::new(VolatileP256Signer { signing, spki }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_time_identity_has_no_persisted_secret_and_no_spki_continuity() {
        let first = create_once().unwrap();
        let second = create_once().unwrap();
        assert_ne!(first.public_key(), second.public_key());
        assert_ne!(first.device_id(), second.device_id());
        assert_eq!(first.public_key().as_der().len(), 91);
        assert_eq!(second.public_key().as_der().len(), 91);
        // No path/file/wallet API exists in this module. Both signatures
        // were verified by the real shared LocalGuestIdentity constructor.
    }
}
