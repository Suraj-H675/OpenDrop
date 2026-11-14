//! Linux S1 guest signing through a *pre-provisioned hardware PKCS#11 token*.
//! No private key is generated or exported here. No plaintext private-file,
//! software-token, default PIN or unprotected fallback is available.
//!
//! This intentionally narrow first provider requires a hardware-reported
//! slot, a token protected-authentication path, and a pre-existing P-256
//! signing key that reports its original non-extractable provenance.
//! Those flags are vendor assertions, not an independent hardware attestation.
//! TPM-backed and software-token compatibility is not claimed without real
//! tests and a separate provider-security decision.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use opendrop_core::guest_tls::NativeP256Signer;
use opendrop_core::Error;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const SIGN_TIMEOUT: Duration = Duration::from_secs(30);

struct SignRequest {
    digest: [u8; 32],
    reply: SyncSender<Result<Vec<u8>, Error>>,
}

pub struct HardwareP256Signer {
    public_spki: Vec<u8>,
    requests: SyncSender<SignRequest>,
}

impl fmt::Debug for HardwareP256Signer {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HardwareP256Signer")
            .field("public_spki_len", &self.public_spki.len())
            .finish_non_exhaustive()
    }
}

impl NativeP256Signer for HardwareP256Signer {
    fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.public_spki.clone())
    }

    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let (reply, receive) = mpsc::sync_channel(1);
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.requests
            .send(SignRequest { digest, reply })
            .map_err(|_| Error::Unauthorized)?;
        receive
            .recv_timeout(SIGN_TIMEOUT)
            .map_err(|_| Error::Unauthorized)?
    }
}

/// Only an explicitly selected *absolute* module and exact token/key labels
/// are accepted; there is no first-slot or first-key default. A vendor module
/// or token that cannot provide the required proof simply disables guest mode.
pub fn open_preprovisioned(
    module: &Path,
    token_label: &str,
    key_label: &str,
) -> Result<Arc<HardwareP256Signer>, Error> {
    if token_label.is_empty()
        || key_label.is_empty()
        || token_label.len() > 32
        || key_label.len() > 128
        || !module.is_absolute()
        || module
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Unauthorized);
    }
    // Loading a replaceable PKCS#11 plugin exposes every signing request to
    // arbitrary code. Require a root-owned immutable-by-nonroot path,
    // including ALL ancestors. Software-token flags are still not hardware
    // attestation, and a privileged root adversary is out of scope.
    for ancestor in module.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (ancestor == module && !metadata.is_file())
            || (ancestor != module && !metadata.is_dir())
        {
            return Err(Error::Unauthorized);
        }
    }
    let module = PathBuf::from(module);
    let token_label = token_label.to_owned();
    let key_label = key_label.to_owned();
    let (startup_tx, startup_rx) = mpsc::sync_channel(1);
    let (requests, queue) = mpsc::sync_channel::<SignRequest>(1);
    thread::Builder::new()
        .name("opendrop-hardware-p256".into())
        .spawn(move || {
            let ready = open_hardware_session(&module, &token_label, &key_label);
            match ready {
                Ok((session, key, spki)) => {
                    if startup_tx.send(Ok(spki)).is_err() {
                        return;
                    }
                    while let Ok(request) = queue.recv() {
                        let result = session
                            .sign(&Mechanism::Ecdsa, key, &request.digest)
                            .map_err(|_| Error::Unauthorized)
                            .and_then(|raw| raw_ecdsa_to_der(&raw));
                        if request.reply.send(result).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => {
                    let _ = startup_tx.send(Err(Error::Unauthorized));
                }
            }
        })
        .map_err(|_| Error::Unauthorized)?;
    let public_spki = startup_rx
        .recv_timeout(SIGN_TIMEOUT)
        .map_err(|_| Error::Unauthorized)??;
    Ok(Arc::new(HardwareP256Signer {
        public_spki,
        requests,
    }))
}

fn open_hardware_session(
    module: &Path,
    token_label: &str,
    key_label: &str,
) -> Result<(Session, cryptoki::object::ObjectHandle, Vec<u8>), Error> {
    let pkcs11 = Pkcs11::new(module).map_err(|_| Error::Unauthorized)?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|_| Error::Unauthorized)?;
    let mut selected = None;
    for slot in pkcs11
        .get_slots_with_token()
        .map_err(|_| Error::Unauthorized)?
    {
        let hardware = pkcs11
            .get_slot_info(slot)
            .map_err(|_| Error::Unauthorized)?
            .hardware_slot();
        let token = pkcs11
            .get_token_info(slot)
            .map_err(|_| Error::Unauthorized)?;
        if token.label() == token_label
            && hardware
            && token.protected_authentication_path()
            && token.token_initialized()
            && token.user_pin_initialized()
            && !token.user_pin_locked()
        {
            if selected.replace(slot).is_some() {
                return Err(Error::Unauthorized);
            }
        }
    }
    let slot = selected.ok_or(Error::Unauthorized)?;
    let session = pkcs11
        .open_ro_session(slot)
        .map_err(|_| Error::Unauthorized)?;
    // No PIN bytes flow through the process, environment, command line or
    // a software prompt. Only token-owned protected authentication is used.
    session
        .login(UserType::User, None)
        .map_err(|_| Error::Unauthorized)?;
    let label = key_label.as_bytes().to_vec();
    let private_keys = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.clone()),
        ])
        .map_err(|_| Error::Unauthorized)?;
    let public_keys = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label),
        ])
        .map_err(|_| Error::Unauthorized)?;
    if private_keys.len() != 1 || public_keys.len() != 1 {
        return Err(Error::Unauthorized);
    }
    let key = private_keys[0];
    let attributes = session
        .get_attributes(
            key,
            &[
                AttributeType::Token,
                AttributeType::Private,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
                AttributeType::Local,
                AttributeType::Sign,
            ],
        )
        .map_err(|_| Error::Unauthorized)?;
    if attributes.len() != 8
        || !attributes.contains(&Attribute::Token(true))
        || !attributes.contains(&Attribute::Private(true))
        || !attributes.contains(&Attribute::Sensitive(true))
        || !attributes.contains(&Attribute::Extractable(false))
        || !attributes.contains(&Attribute::AlwaysSensitive(true))
        || !attributes.contains(&Attribute::NeverExtractable(true))
        || !attributes.contains(&Attribute::Local(true))
        || !attributes.contains(&Attribute::Sign(true))
    {
        return Err(Error::Unauthorized);
    }
    let public_attributes = session
        .get_attributes(public_keys[0], &[AttributeType::PublicKeyInfo])
        .map_err(|_| Error::Unauthorized)?;
    let [Attribute::PublicKeyInfo(spki)] = public_attributes.as_slice() else {
        return Err(Error::Unauthorized);
    };
    opendrop_core::guest::P256Spki::from_canonical_der(spki)?;
    Ok((session, key, spki.clone()))
}

fn raw_ecdsa_to_der(raw: &[u8]) -> Result<Vec<u8>, Error> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[start..];
        let needs_padding = significant[0] & 0x80 != 0;
        let mut encoded = Vec::with_capacity(significant.len() + 3);
        encoded.extend_from_slice(&[0x02, (significant.len() + usize::from(needs_padding)) as u8]);
        if needs_padding {
            encoded.push(0);
        }
        encoded.extend_from_slice(significant);
        encoded
    }
    if raw.len() != 64 {
        return Err(Error::Unauthorized);
    }
    let r = integer(&raw[..32]);
    let s = integer(&raw[32..]);
    let mut der = Vec::with_capacity(2 + r.len() + s.len());
    der.extend_from_slice(&[0x30, (r.len() + s.len()) as u8]);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs11_raw_ecdsa_converts_to_strict_der_and_refuses_bad_lengths() {
        let mut input = [0u8; 64];
        input[31] = 1;
        input[63] = 0x80;
        assert_eq!(
            raw_ecdsa_to_der(&input).unwrap(),
            vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80]
        );
        assert!(raw_ecdsa_to_der(&input[..63]).is_err());
    }

    #[test]
    fn signer_refuses_relative_modules_and_implicit_token_defaults() {
        assert!(open_preprovisioned(Path::new("module.so"), "token", "key").is_err());
        assert!(open_preprovisioned(Path::new("/usr/lib/module.so"), "", "key").is_err());
        assert!(open_preprovisioned(Path::new("/usr/lib/module.so"), "token", "").is_err());
        assert!(
            open_preprovisioned(Path::new("/usr/lib/../lib/module.so"), "token", "key").is_err()
        );
    }
}
