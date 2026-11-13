//! Linux-only owner-controlled filesystem adapter for the S1 receiver.
//!
//! The caller chooses the destination directory *locally*, before handling
//! untrusted offers. Directory handles stay pinned; no peer-supplied path is
//! passed to openat/renameat2. Every native failure fails closed.
//! Actual process-kill, power-loss and filesystem-specific behavior is NOT
//! verified by source code or synthetic unit tests.

use opendrop_core::identity::{validate_file_name, Sha256Digest};
use opendrop_core::journal::Journal;
use opendrop_core::journal::{DurablePublisher, FileOffer, Published};
use opendrop_core::receiver::StagingLease;
use opendrop_core::wire::{MAX_CHUNK, MAX_FILE};
use opendrop_core::Error;
use rustix::fs::{
    flock, fsync, mkdirat, openat, openat2, renameat_with, unlinkat, AtFlags, FlockOperation, Mode,
    OFlags, RenameFlags, ResolveFlags,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::inventory::{self, RestartReport};

const STAGE_DIRECTORY: &str = "staging";
const PRIVATE_MODE: u32 = 0o700;
const STAGE_FILE_MODE: u32 = 0o600;
const READ_BUFFER: usize = 64 * 1024;

fn io(error: rustix::io::Errno) -> Error {
    Error::Io(error.into())
}

fn verified_dir(file: &File, private: bool) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Unauthorized);
    }
    let forbidden = if private { 0o077 } else { 0o022 };
    if metadata.mode() & forbidden != 0 {
        return Err(Error::Invalid("Linux directory has unsafe permissions"));
    }
    Ok(())
}

/// Open an owner-specified *absolute* directory without following symlinks
/// in ANY component. The starting "/" handle is trusted and openat2 refuses
/// traversal outside it. Kernel without openat2 support fails closed.
fn open_owner_directory(path: &Path, private: bool) -> Result<File, Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Invalid(
            "Linux destination must be an absolute directory",
        ));
    }
    let relative = path
        .strip_prefix("/")
        .map_err(|_| Error::Invalid("Linux directory"))?;
    let root = File::open("/")?;
    let fd = openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io)?;
    let result = File::from(fd);
    verified_dir(&result, private)?;
    Ok(result)
}

fn verified_stage_entry(dir: &File, name: &str, dev: u64, ino: u64) -> Result<bool, Error> {
    let fd = match openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(io(error)),
    };
    let metadata = File::from(fd).metadata()?;
    if !metadata.is_file() || metadata.dev() != dev || metadata.ino() != ino {
        return Err(Error::Unauthorized);
    }
    Ok(true)
}

struct OwnedDirectories {
    stage: File,
    destination: File,
}

/// The native agent creates this from a locally selected owner directory,
/// NOT a network-supplied filename/path. The stage root's parent is private
/// mode 0700. The destination must be owner-owned and not group/world-writable.
#[derive(Clone)]
pub struct LinuxReceiverStorage {
    directories: Arc<OwnedDirectories>,
    destination_label: Arc<PathBuf>,
}

impl LinuxReceiverStorage {
    pub fn open_private(
        owner_private_root: &Path,
        owner_destination_directory: &Path,
    ) -> Result<Self, Error> {
        let root = open_owner_directory(owner_private_root, true)?;
        let destination = open_owner_directory(owner_destination_directory, false)?;
        match mkdirat(&root, STAGE_DIRECTORY, Mode::from_raw_mode(PRIVATE_MODE)) {
            Ok(()) => fsync(&root).map_err(io)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io(error)),
        }
        let stage = File::from(
            openat(
                &root,
                STAGE_DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        verified_dir(&stage, true)?;
        // Cooperating OpenDrop receiver instances must never perform startup
        // cleanup while another is actively staging. Held by Arc until the
        // last local storage handle is dropped; never wait for an old owner.
        flock(&stage, FlockOperation::NonBlockingLockExclusive).map_err(io)?;
        Ok(Self {
            directories: Arc::new(OwnedDirectories { stage, destination }),
            destination_label: Arc::new(owner_destination_directory.to_owned()),
        })
    }

    /// This path is DISPLAY-ONLY; all actual publication uses the pinned,
    /// symlink-checked directory file descriptor.
    pub fn owner_destination_display(&self) -> &Path {
        &self.destination_label
    }

    pub fn allocate(
        &self,
        offer: &FileOffer,
    ) -> Result<(LinuxOwnedStage, LinuxNativePublisher), Error> {
        offer.validate()?;
        if offer.bytes > MAX_FILE {
            return Err(Error::Invalid("S1 maximum file size"));
        }
        // Kernel CSPRNG; no network-supplied stage names or predictable IDs.
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let name = format!(
            "s1-{}-{}.part",
            offer.id.as_str(),
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let fd = openat(
            &self.directories.stage,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(STAGE_FILE_MODE),
        )
        .map_err(io)?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            // Fail closed; the private directory identity must be fixed by
            // the owning app, not repaired here with recursive operations.
            return Err(Error::Unauthorized);
        }
        fsync(&self.directories.stage).map_err(io)?;
        let identity = StageIdentity {
            name,
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        // Stage identity + exact offer must be persisted *before* the
        // coordinator can start appending data. A crash here leaves only a
        // private, non-publishable orphan; startup inventory treats unknown
        // entries conservatively (never unlinks unrelated entries).
        file.sync_all()?;
        inventory::persist(&self.directories.stage, &identity, offer)?;
        let stage = LinuxOwnedStage {
            dir: self.directories.clone(),
            file,
            identity: identity.clone(),
            written: 0,
            expected: offer.bytes,
        };
        let publisher = LinuxNativePublisher {
            dir: self.directories.clone(),
            source: identity,
            destination_name: offer.name.clone(),
        };
        Ok((stage, publisher))
    }

    /// Run before accepting any network connections or opening new sessions.
    /// Only the existing journal determines Reserved/Intent/Committed state.
    /// Unresolved intents are read-only inspected, NEVER re-published or
    /// silently marked committed. A future authenticated session must use
    /// the existing AuthorizedOffer::reconcile_intent transaction API.
    pub fn recover_before_listen(&self, journal: &Journal) -> Result<RestartReport, Error> {
        inventory::reconcile(
            &self.directories.stage,
            &self.directories.destination,
            journal,
        )
    }
}

#[derive(Clone)]
pub(crate) struct StageIdentity {
    pub(crate) name: String,
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

pub struct LinuxOwnedStage {
    dir: Arc<OwnedDirectories>,
    file: File,
    identity: StageIdentity,
    written: u64,
    expected: u64,
}

impl StagingLease for LinuxOwnedStage {
    fn append_chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Invalid("stage bytes overflow"))?;
        if bytes.is_empty() || bytes.len() > MAX_CHUNK || next > self.expected {
            return Err(Error::Invalid("stage length"));
        }
        self.file.write_all(bytes)?;
        self.written = next;
        Ok(())
    }

    fn sync_staged(&mut self) -> Result<(), Error> {
        if self.written != self.expected {
            return Err(Error::Invalid("staged byte count"));
        }
        self.file.sync_all()?;
        Ok(())
    }

    fn discard(&mut self) -> Result<(), Error> {
        if !verified_stage_entry(
            &self.dir.stage,
            &self.identity.name,
            self.identity.dev,
            self.identity.ino,
        )? {
            // In particular, a prior unlink or atomic rename may have
            // succeeded even if its directory fsync previously failed.
            // Re-sync the private directory before reporting cleanup done.
            fsync(&self.dir.stage).map_err(io)?;
            return inventory::forget(&self.dir.stage, &self.identity);
        }
        unlinkat(
            &self.dir.stage,
            self.identity.name.as_str(),
            AtFlags::empty(),
        )
        .map_err(io)?;
        fsync(&self.dir.stage).map_err(io)?;
        inventory::forget(&self.dir.stage, &self.identity)
    }
}

/// Trusted native publisher, separate from untrusted network framing.
/// Receives the stage identity only from LinuxReceiverStorage::allocate.
pub struct LinuxNativePublisher {
    dir: Arc<OwnedDirectories>,
    source: StageIdentity,
    destination_name: String,
}

impl LinuxNativePublisher {
    fn inspect_destination(
        &self,
        name: &str,
        offer: &FileOffer,
    ) -> Result<Option<Published>, Error> {
        if name != self.destination_name || name != offer.name {
            return Err(Error::Unauthorized);
        }
        inspect_owned_published(&self.dir.destination, &self.source, offer, name)
    }
}

/// Shared read-only destination verifier for ordinary journal publication and
/// restart inventory. It never creates/renames/deletes or mutates the journal.
pub(crate) fn inspect_owned_published(
    destination: &File,
    source: &StageIdentity,
    offer: &FileOffer,
    name: &str,
) -> Result<Option<Published>, Error> {
    validate_file_name(name)?;
    if name != offer.name {
        return Err(Error::Unauthorized);
    }
    let fd = match openat(
        destination,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let mut file = File::from(fd);
    let metadata = file.metadata()?;
    // renameat2 moves the inode, not a copy. Do not accept a preexisting
    // unrelated destination with an identical hash after crash/replay.
    if !metadata.is_file()
        || metadata.dev() != source.dev
        || metadata.ino() != source.ino
        || metadata.len() != offer.bytes
        || metadata.len() > MAX_FILE
    {
        return Err(Error::Invalid("published inode or byte count"));
    }
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or(Error::Invalid("published bytes overflow"))?;
        if bytes > offer.bytes {
            return Err(Error::Invalid("published file changed"));
        }
        hash.update(&buffer[..count]);
    }
    let sha256 = Sha256Digest::parse(&format!("{:x}", hash.finalize()))?;
    if bytes != offer.bytes || sha256 != offer.sha256 {
        return Err(Error::Invalid("published content does not match offer"));
    }
    Ok(Some(Published {
        destination_ref: name.to_owned(),
        bytes,
        sha256,
    }))
}

impl DurablePublisher for LinuxNativePublisher {
    fn publish(&mut self, offer: &FileOffer, destination_ref: &str) -> Result<Published, Error> {
        if destination_ref != self.destination_name || offer.name != destination_ref {
            return Err(Error::Unauthorized);
        }
        if !verified_stage_entry(
            &self.dir.stage,
            &self.source.name,
            self.source.dev,
            self.source.ino,
        )? {
            return Err(Error::Invalid("owned stage missing"));
        }
        // NOREPLACE: collision never overwrites the user's prior file.
        // EXDEV, unsupported renameat2 and permission denial fail closed.
        renameat_with(
            &self.dir.stage,
            self.source.name.as_str(),
            &self.dir.destination,
            destination_ref,
            RenameFlags::NOREPLACE,
        )
        .map_err(io)?;
        // If either fsync fails, commit outcome is UNCERTAIN: the core keeps
        // CommitIntent and never claims Complete. Recovery inspects first.
        fsync(&self.dir.stage).map_err(io)?;
        fsync(&self.dir.destination).map_err(io)?;
        self.inspect_destination(destination_ref, offer)?
            .ok_or(Error::Invalid("published destination disappeared"))
    }

    fn inspect_published(
        &mut self,
        offer: &FileOffer,
        destination_ref: &str,
    ) -> Result<Option<Published>, Error> {
        self.inspect_destination(destination_ref, offer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendrop_core::identity::{KeyFingerprint, TransferId};
    use std::io::Write;

    fn offer(bytes: &[u8], name: &str) -> FileOffer {
        FileOffer {
            id: TransferId::parse(&"a".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: name.into(),
            bytes: bytes.len() as u64,
            sha256: Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).unwrap(),
        }
    }

    #[test]
    fn stage_and_publish_no_replace_and_verify_destination_bytes() {
        let root = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let storage = LinuxReceiverStorage::open_private(root.path(), dest.path()).unwrap();
        let offered = offer(b"hello world", "report.txt");
        let (mut stage, mut publisher) = storage.allocate(&offered).unwrap();
        stage.append_chunk(b"hello ").unwrap();
        stage.append_chunk(b"world").unwrap();
        stage.sync_staged().unwrap();
        publisher.publish(&offered, "report.txt").unwrap();
        let proof = publisher
            .inspect_published(&offered, "report.txt")
            .unwrap()
            .unwrap();
        assert_eq!(proof.sha256, offered.sha256);
        stage.discard().unwrap(); // original stage was renamed
        assert_eq!(
            std::fs::read(dest.path().join("report.txt")).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn collision_does_not_replace_unrelated_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let store = LinuxReceiverStorage::open_private(root.path(), dest.path()).unwrap();
        let offered = offer(b"new", "same.txt");
        std::fs::write(dest.path().join("same.txt"), b"previous").unwrap();
        let (mut stage, mut publisher) = store.allocate(&offered).unwrap();
        stage.append_chunk(b"new").unwrap();
        stage.sync_staged().unwrap();
        assert!(publisher.publish(&offered, "same.txt").is_err());
        assert_eq!(
            std::fs::read(dest.path().join("same.txt")).unwrap(),
            b"previous"
        );
        stage.discard().unwrap();
    }

    #[test]
    fn cannot_open_symlinked_storage_directory_or_stage_name() {
        use std::os::unix::fs::symlink;
        let private = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let symlink_dir = private.path().join("link");
        symlink(dest.path(), &symlink_dir).unwrap();
        assert!(LinuxReceiverStorage::open_private(private.path(), &symlink_dir).is_err());
        let storage = LinuxReceiverStorage::open_private(private.path(), dest.path()).unwrap();
        let offered = offer(b"abc", "report.txt");
        let (mut stage, _) = storage.allocate(&offered).unwrap();
        stage.append_chunk(b"abc").unwrap();
        stage.sync_staged().unwrap();
        stage.discard().unwrap();
        // A replacement symlink at the old private stage name is NEVER
        // followed or unlinked as though it were the original stage inode.
        let staged_name = private.path().join("staging").join(&stage.identity.name);
        let untouched = dest.path().join("unrelated");
        std::fs::write(&untouched, b"do not touch").unwrap();
        symlink(&untouched, &staged_name).unwrap();
        assert!(stage.discard().is_err());
        assert_eq!(std::fs::read(&untouched).unwrap(), b"do not touch");
    }

    #[test]
    fn stage_enforces_total_bytes_and_rejects_path_from_offer() {
        let root = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let storage = LinuxReceiverStorage::open_private(root.path(), dest.path()).unwrap();
        assert!(storage.allocate(&offer(b"x", "../escape")).is_err());
        let offered = offer(b"a", "one.txt");
        let (mut stage, _) = storage.allocate(&offered).unwrap();
        assert!(stage.append_chunk(b"ab").is_err());
        stage.append_chunk(b"a").unwrap();
        assert!(stage.append_chunk(b"x").is_err());
        stage.sync_staged().unwrap();
        stage.discard().unwrap();
    }

    #[test]
    fn a_mismatching_staged_digest_never_returns_durable_publish_evidence() {
        let private = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let storage = LinuxReceiverStorage::open_private(private.path(), output.path()).unwrap();
        let offered = offer(b"good", "hash-check.bin");
        let (mut stage, mut publisher) = storage.allocate(&offered).unwrap();
        stage.append_chunk(b"evil").unwrap(); // correct byte count, wrong content
        stage.sync_staged().unwrap();
        assert!(publisher.publish(&offered, "hash-check.bin").is_err());
        assert!(publisher
            .inspect_published(&offered, "hash-check.bin")
            .is_err());
        // Physical publication MAY have happened by the time the independent
        // hash fails. The journal must stay CommitIntent/RecoveryRequired,
        // never manufacture an authenticated Complete.
        assert_eq!(
            std::fs::read(output.path().join("hash-check.bin")).unwrap(),
            b"evil"
        );
        stage.discard().unwrap(); // only owned private stage; never final file
    }

    #[test]
    fn restart_without_journal_evidence_preserves_private_stage() {
        use opendrop_core::journal::Journal;
        let private = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let foreign = destination.path().join("unrelated.bin");
        std::fs::write(&foreign, b"keep").unwrap();
        let journal_path = private.path().join("journal.sqlite");
        let journal = Journal::open(&journal_path).unwrap();
        let offered = offer(b"stage not yet reserved", "next.txt");
        let stage_name;
        {
            let storage =
                LinuxReceiverStorage::open_private(private.path(), destination.path()).unwrap();
            let (mut stage, publisher) = storage.allocate(&offered).unwrap();
            stage.append_chunk(b"stage not yet reserved").unwrap();
            stage.sync_staged().unwrap();
            stage_name = stage.identity.name.clone();
            // Simulated process interruption: drop the in-memory handles,
            // not a true kill -9 or sudden power loss.
            drop(stage);
            drop(publisher);
            drop(storage);
        }
        let storage =
            LinuxReceiverStorage::open_private(private.path(), destination.path()).unwrap();
        let result = storage.recover_before_listen(&journal).unwrap();
        assert_eq!(result.removed_precommit, 0);
        assert_eq!(result.preserved_unresolved_intent, 0);
        assert_eq!(result.unidentified_private_entries, 1);
        assert!(private.path().join("staging").join(&stage_name).exists());
        assert!(private
            .path()
            .join("staging")
            .join(format!("{stage_name}.meta"))
            .exists());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"keep");
        // An unknown journal state never manufactures cleanup authority.
        assert_eq!(storage.recover_before_listen(&journal).unwrap(), result);
    }
}
