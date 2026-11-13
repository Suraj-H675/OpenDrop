//! Crash-persistent, bounded *local* staging inventory; never a second
//! transaction journal. The shared SQLite Journal is the only phase authority.
//! Start-up must run before accepting peers while the owner-only stage lock is
//! held. An uncertain intent is never published or deleted by this module.
//! Actual sudden-power-loss/disk-model verification is a separate OS gate.

use crate::storage::{inspect_owned_published, StageIdentity};
use opendrop_core::identity::{KeyFingerprint, Sha256Digest, TransferId};
use opendrop_core::journal::{FileOffer, Journal, Phase};
use opendrop_core::wire::MAX_FILE;
use opendrop_core::Error;
use rustix::fs::{fsync, openat, unlinkat, AtFlags, Mode, OFlags, RawDir};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;

const VERSION: &str = "opendrop-s1-stage/1";
const MAX_RECORD_BYTES: usize = 1024;
const MAX_STAGE_ENTRIES: usize = 256;
const META_SUFFIX: &str = ".meta";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestartReport {
    pub removed_precommit: usize,
    pub removed_committed: usize,
    pub preserved_unresolved_intent: usize,
    pub intent_published_awaiting_authenticated_reconcile: usize,
    pub unidentified_private_entries: usize,
}

#[derive(Clone)]
struct PersistedStage {
    identity: StageIdentity,
    offer: FileOffer,
}

fn valid_stage_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 73
        && bytes.starts_with(b"s1-")
        && bytes[35] == b'-'
        && bytes.ends_with(b".part")
        && bytes[3..35].iter().all(u8::is_ascii_hexdigit)
        && bytes[36..68].iter().all(u8::is_ascii_hexdigit)
}

fn meta_name(identity: &StageIdentity) -> Result<String, Error> {
    if !valid_stage_name(&identity.name) {
        return Err(Error::Invalid("owned stage name"));
    }
    Ok(format!("{}{}", identity.name, META_SUFFIX))
}

fn encode(identity: &StageIdentity, offer: &FileOffer) -> Result<Vec<u8>, Error> {
    offer.validate()?;
    if offer.bytes > MAX_FILE
        || !valid_stage_name(&identity.name)
        || &identity.name[3..35] != offer.id.as_str()
    {
        return Err(Error::Invalid("stage/offer identity"));
    }
    let value = format!(
        "{VERSION}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        identity.name,
        identity.dev,
        identity.ino,
        offer.id.as_str(),
        offer.peer.as_str(),
        offer.manifest.as_str(),
        offer.bytes,
        offer.sha256.as_str(),
        offer.name
    );
    if value.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("stage record too large"));
    }
    Ok(value.into_bytes())
}

pub(crate) fn persist(
    dir: &File,
    identity: &StageIdentity,
    offer: &FileOffer,
) -> Result<(), Error> {
    let data = encode(identity, offer)?;
    let name = meta_name(identity)?;
    let fd = openat(
        dir,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREAT | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| Error::Io(error.into()))?;
    let mut record = File::from(fd);
    record.write_all(&data)?;
    record.sync_all()?;
    fsync(dir).map_err(|error| Error::Io(error.into()))?;
    Ok(())
}

fn decode(dir: &File, meta: &str) -> Result<PersistedStage, Error> {
    let name = meta
        .strip_suffix(META_SUFFIX)
        .ok_or(Error::Invalid("stage record suffix"))?;
    if !valid_stage_name(name) {
        return Err(Error::Invalid("stage record name"));
    }
    let fd = openat(
        dir,
        meta,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| Error::Io(error.into()))?;
    let mut file = File::from(fd);
    let stat = file.metadata()?;
    if !stat.is_file()
        || stat.uid() != rustix::process::geteuid().as_raw()
        || stat.mode() & 0o077 != 0
        || stat.len() > MAX_RECORD_BYTES as u64
    {
        return Err(Error::Unauthorized);
    }
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("stage record bounds"));
    }
    let content = std::str::from_utf8(&data).map_err(|_| Error::Invalid("stage record UTF-8"))?;
    let lines = content.lines().collect::<Vec<_>>();
    if lines.len() != 10 || lines[0] != VERSION || lines[1] != name {
        return Err(Error::Invalid("stage record format"));
    }
    let identity = StageIdentity {
        name: name.to_owned(),
        dev: lines[2]
            .parse()
            .map_err(|_| Error::Invalid("stage device"))?,
        ino: lines[3]
            .parse()
            .map_err(|_| Error::Invalid("stage inode"))?,
    };
    let offer = FileOffer {
        id: TransferId::parse(lines[4])?,
        peer: KeyFingerprint::parse(lines[5])?,
        manifest: Sha256Digest::parse(lines[6])?,
        bytes: lines[7]
            .parse()
            .map_err(|_| Error::Invalid("stage byte count"))?,
        sha256: Sha256Digest::parse(lines[8])?,
        name: lines[9].to_owned(),
    };
    // Re-encode to reject alternate spellings, extra whitespace and
    // inconsistent IDs. The durable record is not a remote authorization.
    if encode(&identity, &offer)? != data {
        return Err(Error::Invalid("noncanonical stage record"));
    }
    Ok(PersistedStage { identity, offer })
}

pub(crate) fn forget(dir: &File, identity: &StageIdentity) -> Result<(), Error> {
    let meta = meta_name(identity)?;
    let record = match decode(dir, &meta) {
        Ok(record) => record,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            fsync(dir).map_err(|error| Error::Io(error.into()))?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if record.identity.name != identity.name
        || record.identity.dev != identity.dev
        || record.identity.ino != identity.ino
    {
        return Err(Error::Unauthorized);
    }
    unlinkat(dir, meta.as_str(), AtFlags::empty()).map_err(|error| Error::Io(error.into()))?;
    fsync(dir).map_err(|error| Error::Io(error.into()))?;
    Ok(())
}

fn remove_owned_private_stage(dir: &File, record: &PersistedStage) -> Result<(), Error> {
    let identity = &record.identity;
    let fd = match openat(
        dir,
        identity.name.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(Error::Io(error.into())),
    };
    if let Some(fd) = fd {
        let info = File::from(fd).metadata()?;
        if !info.is_file() || info.dev() != identity.dev || info.ino() != identity.ino {
            return Err(Error::Unauthorized);
        }
        unlinkat(dir, identity.name.as_str(), AtFlags::empty())
            .map_err(|error| Error::Io(error.into()))?;
        fsync(dir).map_err(|error| Error::Io(error.into()))?;
    }
    forget(dir, identity)
}

/// Bounded local startup reconciliation. The journal is looked up by the
/// COMPLETE exact offer; guessed transfer IDs cannot be substituted.
/// Does not mutate the journal or trust store; only the owned private stage
/// namespace can be unlinked. Intent stays for later authenticated recovery.
pub(crate) fn reconcile(
    stage: &File,
    destination: &File,
    journal: &Journal,
) -> Result<RestartReport, Error> {
    let enumeration_fd = openat(
        stage,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| Error::Io(error.into()))?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
    let mut iter = RawDir::new(enumeration_fd, &mut buffer);
    let mut manifest_names = Vec::new();
    let mut parts = HashSet::new();
    while let Some(item) = iter.next() {
        let item = item.map_err(|error| Error::Io(error.into()))?;
        let name = std::str::from_utf8(item.file_name().to_bytes())
            .map_err(|_| Error::Invalid("private stage entry name"))?;
        if name == "." || name == ".." {
            continue;
        }
        if manifest_names.len() + parts.len() >= MAX_STAGE_ENTRIES {
            return Err(Error::Invalid("stage inventory entry bound"));
        }
        if name.ends_with(META_SUFFIX) {
            manifest_names.push(name.to_owned());
        } else if valid_stage_name(name) {
            parts.insert(name.to_owned());
        } else {
            // Unknown entry in an owner-private namespace: do NOT delete.
            return Err(Error::Invalid("unexpected private stage entry"));
        }
    }

    let mut report = RestartReport::default();
    for meta in manifest_names {
        let record = decode(stage, &meta)?;
        parts.remove(&record.identity.name);
        match journal.linux_local_recovery_phase(&record.offer)? {
            None => {
                // Missing journal evidence is NOT proof the stage was never
                // published. Preserve it for owner-supervised recovery.
                report.unidentified_private_entries += 1;
            }
            Some(Phase::Reserved) => {
                remove_owned_private_stage(stage, &record)?;
                report.removed_precommit += 1;
            }
            Some(Phase::Committed) => {
                // Even a durable Committed row does not make a missing or
                // subsequently replaced destination safe to ignore. Require
                // independent owned-inode and hash inspection before deleting
                // any leftover private copy; otherwise preserve for review.
                if inspect_owned_published(
                    destination,
                    &record.identity,
                    &record.offer,
                    &record.offer.name,
                )?
                .is_none()
                {
                    return Err(Error::Invalid(
                        "committed destination missing during recovery",
                    ));
                }
                remove_owned_private_stage(stage, &record)?;
                report.removed_committed += 1;
            }
            Some(Phase::CommitIntent) => {
                // Cannot call a network-facing receipt path without a newly
                // verified TLS session. Inspect the owned inode and exact
                // digest read-only; retain stage and manifest regardless.
                if inspect_owned_published(
                    destination,
                    &record.identity,
                    &record.offer,
                    &record.offer.name,
                )?
                .is_some()
                {
                    report.intent_published_awaiting_authenticated_reconcile += 1;
                }
                report.preserved_unresolved_intent += 1;
            }
        }
    }
    // A crash between creating the stage file and its fsynced inventory
    // record may leave private .part entries. Preserve and surface them for
    // explicit owner-reviewed cleanup, never infer permission to delete.
    report.unidentified_private_entries += parts.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendrop_core::identity::{KeyFingerprint, TransferId};

    fn fixture() -> (StageIdentity, FileOffer) {
        let id = TransferId::parse(&"a".repeat(32)).unwrap();
        let stage = StageIdentity {
            name: format!("s1-{}-{}.part", id.as_str(), "b".repeat(32)),
            dev: 42,
            ino: 76,
        };
        let offer = FileOffer {
            id,
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: "Example.txt".into(),
            bytes: 4,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        };
        (stage, offer)
    }

    #[test]
    fn durable_inventory_roundtrip_and_no_foreign_file_unlink() {
        let root = tempfile::tempdir().unwrap();
        let dir = File::open(root.path()).unwrap();
        let unrelated = root.path().join("not-a-stage.txt");
        std::fs::write(&unrelated, b"private unrelated").unwrap();
        let (stage, offer) = fixture();
        persist(&dir, &stage, &offer).unwrap();
        let parsed = decode(&dir, &meta_name(&stage).unwrap()).unwrap();
        assert_eq!(parsed.offer, offer);
        assert_eq!(parsed.identity.ino, stage.ino);
        forget(&dir, &stage).unwrap();
        forget(&dir, &stage).unwrap();
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"private unrelated");
    }

    #[test]
    fn forged_or_wrong_stage_name_is_rejected_before_write() {
        let (mut stage, offer) = fixture();
        stage.name = "../outside.part".into();
        assert!(encode(&stage, &offer).is_err());
        stage.name = format!("s1-{}-{}.part", "f".repeat(32), "b".repeat(32));
        assert!(encode(&stage, &offer).is_err());
    }

    #[test]
    fn symlinked_stage_manifest_never_authorizes_file_unlink() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let separate = tempfile::tempdir().unwrap();
        let dir = File::open(root.path()).unwrap();
        let (stage, offer) = fixture();
        let unrelated = separate.path().join("unrelated");
        std::fs::write(&unrelated, b"keep").unwrap();
        let meta = root.path().join(meta_name(&stage).unwrap());
        symlink(&unrelated, &meta).unwrap();
        assert!(persist(&dir, &stage, &offer).is_err());
        assert!(decode(&dir, &meta_name(&stage).unwrap()).is_err());
        assert!(forget(&dir, &stage).is_err());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"keep");
    }
}
