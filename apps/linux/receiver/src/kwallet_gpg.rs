//! Explicit KDE KWallet6 GPG-backed software P256 installation signer.
//! It is opt-in at COMPILE TIME and at RUNTIME; strict hardware PKCS11
//! never falls back here. The real KWallet6 native widget owns owner-unlock
//! interaction; no private key material is ever persisted by Rust to files.
//!
//! Risk disclosure: a software PKCS8 key is necessarily present in
//! OpenDrop process memory. This is not hardware non-extractability, and an
//! already compromised same-user session is beyond this storage boundary.
use opendrop_core::guest::P256Spki;
use opendrop_core::guest_tls::NativeP256Signer;
use opendrop_core::identity::DeviceId;
use opendrop_core::Error;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_KEY: usize = 512;
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

extern "C" {
    fn opendrop_kwallet_gpg_read(buffer: *mut u8, capacity: i32) -> i32;
    fn opendrop_kwallet_gpg_provision(pkcs8: *const u8, length: i32) -> i32;
}

struct SoftwareP256Signer {
    pair: EcdsaKeyPair,
    spki: P256Spki,
}
impl std::fmt::Debug for SoftwareP256Signer {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("KWallet6 GPG protected software P256 (in-process memory; key redacted)")
    }
}
impl NativeP256Signer for SoftwareP256Signer {
    fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.spki.as_der().to_vec())
    }
    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| Error::Unauthorized)
    }
}

fn import_key(pkcs8: &[u8]) -> Result<(Arc<dyn NativeP256Signer>, DeviceId), Error> {
    let random = SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &random)
        .map_err(|_| Error::Unauthorized)?;
    let point = pair.public_key().as_ref();
    if point.len() != 65 || point[0] != 4 {
        return Err(Error::Unauthorized);
    }
    let mut der = Vec::with_capacity(91);
    der.extend_from_slice(&SPKI_PREFIX);
    der.extend_from_slice(point);
    let spki = P256Spki::from_canonical_der(&der)?;
    let id = Sha256::digest(spki.as_der())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let id = DeviceId::parse(&id)?;
    Ok((Arc::new(SoftwareP256Signer { pair, spki }), id))
}

/// Existing owner-provisioned wallet and entry ONLY. No identity reset or
/// key generation on a missing/corrupted/locked/unsupported wallet.
pub fn open_existing() -> Result<(Arc<dyn NativeP256Signer>, DeviceId), Error> {
    let mut buffer = [0u8; MAX_KEY];
    let read = unsafe { opendrop_kwallet_gpg_read(buffer.as_mut_ptr(), MAX_KEY as i32) };
    let parsed = if (64..=MAX_KEY as i32).contains(&read) {
        import_key(&buffer[..read as usize])
    } else {
        Err(Error::Unauthorized)
    };
    buffer.fill(0);
    parsed
}

/// Explicit, separate offline CLI action, only after owner manually creates
/// an actual GPG-protected OpenDropGpg KWallet6 wallet. No TCP listener or
/// sender is even constructed. Requires the native wallet to have no entry.
pub fn provision_new_owner_identity() -> Result<DeviceId, Error> {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
        .map_err(|_| Error::Unauthorized)?;
    let mut secret = document.as_ref().to_vec();
    let accepted = unsafe { opendrop_kwallet_gpg_provision(secret.as_ptr(), secret.len() as i32) };
    secret.fill(0);
    if accepted != 1 {
        return Err(Error::Unauthorized);
    }
    // Read back only from the exact GPG-header-validated dedicated wallet.
    let (signer, device) = open_existing()?;
    opendrop_core::guest_tls::LocalGuestIdentity::from_platform_signer(device.clone(), signer)?;
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ephemeral_test_vector_matches_portable_native_p256_contract() {
        let rng = SystemRandom::new();
        let generated =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let (signer, device) = import_key(generated.as_ref()).unwrap();
        let expected = signer.canonical_public_spki_der().unwrap();
        let (reopened, device_again) = import_key(generated.as_ref()).unwrap();
        assert_eq!(device, device_again);
        assert_eq!(reopened.canonical_public_spki_der().unwrap(), expected);
        assert!(
            opendrop_core::guest_tls::LocalGuestIdentity::from_platform_signer(device, signer)
                .is_ok()
        );
        assert!(import_key(&[0u8; 150]).is_err());
    }
}
