//! Strict, provisioned-only TLS 1.3 server identity.
//!
//! The foreground receiver NEVER creates a device identity, auto-enrolls
//! unknown clients, or accepts a self-signed network-supplied root. Until a
//! separate, reviewed owner pairing/key-provisioning workflow exists, an
//! ordinary installation cannot load these private inputs and fails CLOSED.

use crate::storage::open_owner_directory;
use opendrop_core::Error;
use rustix::fs::{openat, Mode, OFlags};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

const LEAF: &str = "server-cert.der";
const KEY: &str = "server-key.pkcs8.der";
const ROOT: &str = "paired-client-root.der";
const MAX_CERT_DER: u64 = 16 * 1024;
const MAX_KEY_DER: u64 = 8 * 1024;

fn read_private_der(parent: &File, name: &str, max: u64) -> Result<Vec<u8>, Error> {
    let handle = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| Error::Io(error.into()))?;
    let mut file = File::from(handle);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err(Error::Unauthorized);
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(Error::Invalid("private TLS DER size"));
    }
    Ok(bytes)
}

/// Returns an authenticated-server-only configuration with a mandatory
/// validated client certificate and OpenDrop protocol ALPN. No PEM, fallback,
/// optional client authentication, or generated test identity is supported.
pub fn load_provisioned_tls(root_path: &Path) -> Result<Arc<ServerConfig>, Error> {
    let private = open_owner_directory(root_path, true)?;
    let certificate = CertificateDer::from(read_private_der(&private, LEAF, MAX_CERT_DER)?);
    let secret = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read_private_der(
        &private,
        KEY,
        MAX_KEY_DER,
    )?));
    let trust_anchor = CertificateDer::from(read_private_der(&private, ROOT, MAX_CERT_DER)?);
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(trust_anchor)
        .map_err(|_| Error::Invalid("invalid preprovisioned client trust root"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
            .build()
            .map_err(|_| {
                Error::Invalid("unable to construct strict client certificate verifier")
            })?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Invalid("TLS 1.3 only"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![certificate], secret)
        .map_err(|_| Error::Invalid("invalid preprovisioned TLS server certificate/key"))?;
    config.alpn_protocols = vec![b"opendrop-s1".to_vec()];
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn private_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn missing_identity_files_never_start_a_tls_server() {
        let dir = private_root();
        assert!(load_provisioned_tls(dir.path()).is_err());
    }

    #[test]
    fn symlinked_or_exposed_identity_roots_are_rejected() {
        let dir = private_root();
        let other = tempfile::tempdir().unwrap();
        let link = other.path().join("link");
        symlink(dir.path(), &link).unwrap();
        assert!(load_provisioned_tls(&link).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load_provisioned_tls(dir.path()).is_err());
    }

    #[test]
    fn identity_files_reject_symlink_and_unsafe_permissions() {
        let dir = private_root();
        let external = tempfile::tempdir().unwrap();
        let outside = external.path().join("key");
        std::fs::write(&outside, b"not a usable key").unwrap();
        symlink(&outside, dir.path().join(LEAF)).unwrap();
        let parent = open_owner_directory(dir.path(), true).unwrap();
        assert!(read_private_der(&parent, LEAF, MAX_CERT_DER).is_err());
        std::fs::remove_file(dir.path().join(LEAF)).unwrap();
        std::fs::write(dir.path().join(LEAF), b"bad").unwrap();
        std::fs::set_permissions(
            dir.path().join(LEAF),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(read_private_der(&parent, LEAF, MAX_CERT_DER).is_err());
    }
}
