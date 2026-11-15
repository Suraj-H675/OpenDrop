//! Windows-native per-installation ECDSA P-256 identity with persistent CNG
//! KSP handles. No private-key export, plaintext key file, sample credential,
//! implicit software fallback or Windows-specific TLS/wire fork.
//!
//! Windows Server CI tests CNG software KSP behavior, NOT Windows 11,
//! actual TPM provenance, user-approval UI or Explorer activation.
#![cfg(windows)]

use crate::guest_tls::NativeP256Signer;
use crate::identity::DeviceId;
use crate::Error;
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use std::fmt;
use std::sync::Mutex;

// ncrypt.h storage API. Using the operating system's native ABI avoids
// opaque-key extraction, extra private signing wrappers or new dependencies.
// Microsoft documents NCryptSignHash ECDSA as signing a SHA-256 prehash.
type Handle = usize;
type Status = i32;

#[link(name = "ncrypt")]
extern "system" {
    fn NCryptOpenStorageProvider(provider: *mut Handle, name: *const u16, flags: u32) -> Status;
    fn NCryptOpenKey(
        provider: Handle,
        key: *mut Handle,
        name: *const u16,
        legacy_spec: u32,
        flags: u32,
    ) -> Status;
    fn NCryptCreatePersistedKey(
        provider: Handle,
        key: *mut Handle,
        algorithm: *const u16,
        name: *const u16,
        legacy_spec: u32,
        flags: u32,
    ) -> Status;
    fn NCryptFinalizeKey(key: Handle, flags: u32) -> Status;
    fn NCryptSetProperty(
        object: Handle,
        property: *const u16,
        input: *const u8,
        length: u32,
        flags: u32,
    ) -> Status;
    fn NCryptGetProperty(
        object: Handle,
        property: *const u16,
        output: *mut u8,
        length: u32,
        result: *mut u32,
        flags: u32,
    ) -> Status;
    fn NCryptExportKey(
        key: Handle,
        wrapping_key: Handle,
        blob_type: *const u16,
        params: *const core::ffi::c_void,
        output: *mut u8,
        length: u32,
        result: *mut u32,
        flags: u32,
    ) -> Status;
    fn NCryptSignHash(
        key: Handle,
        padding: *const core::ffi::c_void,
        hash: *mut u8,
        hash_len: u32,
        signature: *mut u8,
        capacity: u32,
        result: *mut u32,
        flags: u32,
    ) -> Status;
    fn NCryptVerifySignature(
        key: Handle,
        padding: *const core::ffi::c_void,
        hash: *mut u8,
        hash_len: u32,
        signature: *mut u8,
        signature_len: u32,
        flags: u32,
    ) -> Status;
    fn NCryptFreeObject(object: Handle) -> Status;
    #[cfg(test)]
    fn NCryptDeleteKey(key: Handle, flags: u32) -> Status;
}

const SILENT: u32 = 0x40;
// NCryptSetProperty on a persistent key must explicitly request persisted
// storage. Without NCRYPT_PERSIST_FLAG, provider defaults might look safe in
// the current process while the explicit policy is not durable on reopen.
const PERSIST_PROPERTY: u32 = 0x8000_0000;
const HARDWARE: u32 = 0x1;
const SOFTWARE: u32 = 0x2;
const ALLOW_SIGN: u32 = 0x2;
const PRIVATE_EXPORT_FLAGS: u32 = 0xF;
const NTE_BAD_KEYSET: Status = 0x80090016_u32 as Status;
const NTE_NOT_FOUND: Status = 0x80090011_u32 as Status;
const PUBLIC_ECDSA_P256_MAGIC: u32 = 0x31534345;
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const PRODUCTION_KEY_NAME: &str = "OpenDrop.S1.Identity.P256.v1";

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
fn valid(status: Status) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

struct CngHandle(Handle);
// Handles are native process-scoped values, safely transferred between
// threads when all use is protected by the signer's Mutex.
unsafe impl Send for CngHandle {}
impl Drop for CngHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NCryptFreeObject(self.0) };
            self.0 = 0;
        }
    }
}

struct Handles {
    // Declare key before provider: drop will release key first.
    key: CngHandle,
    provider: CngHandle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderClass {
    /// Microsoft Platform Crypto Provider, requires provider-reported TPM
    /// hardware flag (not attestation or proof of device security policy).
    IntegratedTpm,
    /// Microsoft Software Key Storage Provider, a user-scoped protected
    /// software key. Process/OS compromise is outside its protection claims.
    WindowsUserProtected,
}
impl ProviderClass {
    fn provider_name(self) -> &'static str {
        match self {
            Self::IntegratedTpm => "Microsoft Platform Crypto Provider",
            Self::WindowsUserProtected => "Microsoft Software Key Storage Provider",
        }
    }
    fn expected_flag(self) -> u32 {
        match self {
            Self::IntegratedTpm => HARDWARE,
            Self::WindowsUserProtected => SOFTWARE,
        }
    }
}

/// Immutable public key and a locked, non-exportable persisted NCrypt key
/// handle. The provider is ALWAYS explicitly selected: no silent TPM failure
/// → software downgrade, rekey, or OS prompt that can block a TLS callback.
pub struct WindowsCngSigner {
    handles: Mutex<Handles>,
    spki: [u8; 91],
    class: ProviderClass,
}
impl fmt::Debug for WindowsCngSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsCngSigner")
            .field("provider_class", &self.class)
            .field("key", &"[PRIVATE KEY HANDLE]")
            .finish()
    }
}

fn property_u32(handle: Handle, property: &str) -> Result<u32, Error> {
    let mut value = 0u32;
    let mut size = 0u32;
    valid(unsafe {
        NCryptGetProperty(
            handle,
            wide(property).as_ptr(),
            (&mut value as *mut u32).cast::<u8>(),
            4,
            &mut size,
            0,
        )
    })?;
    if size != 4 {
        return Err(Error::Unauthorized);
    }
    Ok(value)
}

fn public_spki(key: Handle) -> Result<[u8; 91], Error> {
    let blob_type = wide("ECCPUBLICBLOB");
    let mut size = 0u32;
    valid(unsafe {
        NCryptExportKey(
            key,
            0,
            blob_type.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut size,
            0,
        )
    })?;
    // BCRYPT_ECCKEY_BLOB header: magic u32, key bytes u32, X[32], Y[32].
    if size != 72 {
        return Err(Error::Unauthorized);
    }
    let mut blob = [0u8; 72];
    let mut written = 0u32;
    valid(unsafe {
        NCryptExportKey(
            key,
            0,
            blob_type.as_ptr(),
            std::ptr::null(),
            blob.as_mut_ptr(),
            72,
            &mut written,
            0,
        )
    })?;
    if written != 72
        || u32::from_le_bytes(blob[..4].try_into().map_err(|_| Error::Unauthorized)?)
            != PUBLIC_ECDSA_P256_MAGIC
        || u32::from_le_bytes(blob[4..8].try_into().map_err(|_| Error::Unauthorized)?) != 32
    {
        return Err(Error::Unauthorized);
    }
    let mut spki = [0u8; 91];
    spki[..26].copy_from_slice(&SPKI_PREFIX);
    spki[26] = 4;
    spki[27..].copy_from_slice(&blob[8..72]);
    // The shared parser later validates SPKI format and a real signature.
    Ok(spki)
}

fn strict_positive_integer(raw: &[u8; 32], into: &mut Vec<u8>) -> Result<(), Error> {
    let first = raw
        .iter()
        .position(|&byte| byte != 0)
        .ok_or(Error::Unauthorized)?;
    let integer = &raw[first..];
    let padded = usize::from(integer[0] & 0x80 != 0);
    into.push(0x02);
    into.push((integer.len() + padded) as u8);
    if padded != 0 {
        into.push(0);
    }
    into.extend_from_slice(integer);
    Ok(())
}
/// CNG returns IEEE P1363 R||S. Rustls requires ASN.1 DER SEQUENCE of two
/// *canonical positive* integers. Never pass raw 64B or double-hash the TLS
/// message. Range/curve validity is independently verified by CNG+ring.
fn p1363_to_der(raw: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let mut members = Vec::with_capacity(70);
    strict_positive_integer(
        (&raw[..32]).try_into().map_err(|_| Error::Unauthorized)?,
        &mut members,
    )?;
    strict_positive_integer(
        (&raw[32..]).try_into().map_err(|_| Error::Unauthorized)?,
        &mut members,
    )?;
    if members.len() > 127 {
        return Err(Error::Unauthorized);
    }
    let mut der = Vec::with_capacity(2 + members.len());
    der.push(0x30);
    der.push(members.len() as u8);
    der.extend_from_slice(&members);
    Ok(der)
}

impl WindowsCngSigner {
    fn open_provider(class: ProviderClass) -> Result<CngHandle, Error> {
        let mut handle = 0;
        valid(unsafe {
            NCryptOpenStorageProvider(&mut handle, wide(class.provider_name()).as_ptr(), 0)
        })?;
        if handle == 0 {
            return Err(Error::Unauthorized);
        }
        let provider = CngHandle(handle);
        if property_u32(provider.0, "Impl Type")? & class.expected_flag() == 0 {
            return Err(Error::Unauthorized);
        }
        Ok(provider)
    }

    fn from_handles(
        class: ProviderClass,
        provider: CngHandle,
        key: CngHandle,
    ) -> Result<Self, Error> {
        let policy = property_u32(key.0, "Export Policy")?;
        if policy & PRIVATE_EXPORT_FLAGS != 0 || property_u32(key.0, "Key Usage")? & ALLOW_SIGN == 0
        {
            return Err(Error::Unauthorized);
        }
        let spki = public_spki(key.0)?;
        let result = Self {
            handles: Mutex::new(Handles { key, provider }),
            spki,
            class,
        };
        let challenge = b"OpenDrop/S1/CNG/IdentityProof/v1";
        let signature = result.sign_ecdsa_p256_sha256_der(challenge)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &result.spki[26..])
            .verify(challenge, &signature)
            .map_err(|_| Error::Unauthorized)?;
        Ok(result)
    }

    fn open_named(class: ProviderClass, name: &str) -> Result<Self, Error> {
        let provider = Self::open_provider(class)?;
        let mut handle = 0;
        valid(unsafe { NCryptOpenKey(provider.0, &mut handle, wide(name).as_ptr(), 0, SILENT) })?;
        if handle == 0 {
            return Err(Error::Unauthorized);
        }
        Self::from_handles(class, provider, CngHandle(handle))
    }

    /// Open an already-provisioned installation key. Missing/locked/changed
    /// provider is an ERROR, never an implicit new identity.
    pub fn open_existing(class: ProviderClass) -> Result<Self, Error> {
        Self::open_named(class, PRODUCTION_KEY_NAME)
    }

    fn provision_named(class: ProviderClass, name: &str) -> Result<Self, Error> {
        let provider = Self::open_provider(class)?;
        let mut existing = 0;
        let lookup =
            unsafe { NCryptOpenKey(provider.0, &mut existing, wide(name).as_ptr(), 0, SILENT) };
        if lookup == 0 {
            // An identity already exists: never rotate it.
            let _existing = CngHandle(existing);
            return Err(Error::Unauthorized);
        }
        if lookup != NTE_BAD_KEYSET && lookup != NTE_NOT_FOUND {
            return Err(Error::Unauthorized);
        }
        let mut new_key = 0;
        valid(unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut new_key,
                wide("ECDSA_P256").as_ptr(),
                wide(name).as_ptr(),
                0,
                0,
            )
        })?;
        if new_key == 0 {
            return Err(Error::Unauthorized);
        }
        let key = CngHandle(new_key);
        let no_export = 0u32;
        valid(unsafe {
            NCryptSetProperty(
                key.0,
                wide("Export Policy").as_ptr(),
                (&no_export as *const u32).cast::<u8>(),
                4,
                PERSIST_PROPERTY,
            )
        })?;
        let sign_only = ALLOW_SIGN;
        valid(unsafe {
            NCryptSetProperty(
                key.0,
                wide("Key Usage").as_ptr(),
                (&sign_only as *const u32).cast::<u8>(),
                4,
                PERSIST_PROPERTY,
            )
        })?;
        valid(unsafe { NCryptFinalizeKey(key.0, SILENT) })?;
        Self::from_handles(class, provider, key)
    }

    /// Provision exactly once, only after an audited local onboarding
    /// gesture expressly selecting this provider's security class.
    pub fn provision_with_explicit_owner_consent(class: ProviderClass) -> Result<Self, Error> {
        Self::provision_named(class, PRODUCTION_KEY_NAME)
    }

    pub fn provider_class(&self) -> ProviderClass {
        self.class
    }

    /// Stable public-key-derived identity removes any need for a second
    /// plaintext device-ID file; rotation requires a different key.
    pub fn installation_device_id(&self) -> Result<DeviceId, Error> {
        let hash = digest(
            &SHA256,
            &[
                b"OpenDrop/S1/WindowsDeviceId/v1\0".as_slice(),
                self.spki.as_slice(),
            ]
            .concat(),
        );
        let mut text = String::with_capacity(32);
        for byte in &hash.as_ref()[..16] {
            use std::fmt::Write;
            write!(&mut text, "{byte:02x}").map_err(|_| Error::Unauthorized)?;
        }
        DeviceId::parse(&text)
    }
}

impl NativeP256Signer for WindowsCngSigner {
    fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.spki.to_vec())
    }

    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let state = self.handles.lock().map_err(|_| Error::Unauthorized)?;
        let mut hash = digest(&SHA256, message).as_ref().to_vec();
        let mut signature = [0u8; 64];
        let mut written = 0u32;
        valid(unsafe {
            NCryptSignHash(
                state.key.0,
                std::ptr::null(),
                hash.as_mut_ptr(),
                32,
                signature.as_mut_ptr(),
                64,
                &mut written,
                SILENT,
            )
        })?;
        if written != 64 {
            return Err(Error::Unauthorized);
        }
        valid(unsafe {
            NCryptVerifySignature(
                state.key.0,
                std::ptr::null(),
                hash.as_mut_ptr(),
                32,
                signature.as_mut_ptr(),
                64,
                SILENT,
            )
        })?;
        let der = p1363_to_der(&signature)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.spki[26..])
            .verify(message, &der)
            .map_err(|_| Error::Unauthorized)?;
        signature.fill(0);
        hash.fill(0);
        Ok(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_tls::LocalGuestIdentity;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::sync::Arc;

    fn ephemeral_test_name() -> String {
        let mut entropy = [0u8; 16];
        SystemRandom::new()
            .fill(&mut entropy)
            .expect("OS randomness");
        let mut name = String::from("OpenDrop.S1.CI.Only.");
        for byte in &entropy {
            use std::fmt::Write;
            write!(&mut name, "{byte:02x}").unwrap();
        }
        name
    }

    fn remove_test_key(signer: WindowsCngSigner) {
        let mut state = signer.handles.lock().unwrap();
        let handle = state.key.0;
        assert_ne!(handle, 0);
        valid(unsafe { NCryptDeleteKey(handle, SILENT) }).expect("delete only CI-owned key");
        state.key.0 = 0;
    }

    #[test]
    fn p1363_integer_encoding_is_strict_der() {
        let mut raw = [0u8; 64];
        assert!(p1363_to_der(&raw).is_err());
        raw[0] = 0x80;
        raw[63] = 1;
        let der = p1363_to_der(&raw).unwrap();
        assert_eq!(der[..4], [0x30, 0x26, 0x02, 0x21]); // r: 0x00 0x80... => 33B
        assert_eq!(der[4], 0);
        assert_eq!(der[5], 0x80);
        assert_eq!(&der[37..], [0x02, 0x01, 0x01]);
    }

    #[test]
    fn explicit_software_ksp_p256_persists_without_private_export() {
        let name = ephemeral_test_name();
        let original =
            WindowsCngSigner::provision_named(ProviderClass::WindowsUserProtected, &name)
                .expect("hosted Windows 2022 user Software KSP provisioning");
        assert_eq!(
            original.provider_class(),
            ProviderClass::WindowsUserProtected
        );
        let stable_spki = original.canonical_public_spki_der().unwrap();
        let device_id = original.installation_device_id().unwrap();
        assert_eq!(stable_spki.len(), 91);
        assert_eq!(&stable_spki[..26], &SPKI_PREFIX);
        assert_eq!(stable_spki[26], 4);
        assert!(
            WindowsCngSigner::provision_named(ProviderClass::WindowsUserProtected, &name).is_err()
        );
        let signer: Arc<dyn NativeP256Signer> = Arc::new(original);
        let identity =
            LocalGuestIdentity::from_platform_signer(device_id.clone(), signer.clone()).unwrap();
        let signature = signer
            .sign_ecdsa_p256_sha256_der(b"S1 Windows CNG raw-public-key TLS signature")
            .unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &stable_spki[26..])
            .verify(b"S1 Windows CNG raw-public-key TLS signature", &signature)
            .unwrap();
        assert!(
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &stable_spki[26..])
                .verify(b"tampered message", &signature)
                .is_err()
        );
        assert_eq!(identity.public_key().as_der(), stable_spki);
        drop(identity);
        drop(signer);
        let reopened =
            WindowsCngSigner::open_named(ProviderClass::WindowsUserProtected, &name).unwrap();
        assert_eq!(reopened.canonical_public_spki_der().unwrap(), stable_spki);
        assert_eq!(reopened.installation_device_id().unwrap(), device_id);
        {
            let state = reopened.handles.lock().unwrap();
            // Explicit provisioning policy must survive closing/reopening
            // the persisted key, not just appear safe on its original handle.
            assert_eq!(property_u32(state.key.0, "Export Policy").unwrap(), 0);
            assert_eq!(property_u32(state.key.0, "Key Usage").unwrap(), ALLOW_SIGN);
        }
        remove_test_key(reopened);
        assert!(WindowsCngSigner::open_named(ProviderClass::WindowsUserProtected, &name).is_err());
    }
}
