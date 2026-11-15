use crate::identity::{KeyFingerprint, Sha256Digest, TransferId};
use crate::journal::{DurablePublisher, FileOffer, Journal, Phase, Published};
use crate::Error;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

fn offer(data: &[u8]) -> FileOffer {
    FileOffer {
        id: TransferId::parse(&"a".repeat(32)).unwrap(),
        peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
        manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
        name: "safe.bin".into(),
        bytes: data.len() as u64,
        sha256: Sha256Digest::parse(&format!("{:x}", Sha256::digest(data))).unwrap(),
    }
}

struct RealFilePublisher {
    data: Vec<u8>,
    fail_after_sync: bool,
    publishes: usize,
}
impl RealFilePublisher {
    fn inspect(path: &Path) -> Result<Option<Published>, Error> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Publication("cannot read committed target".into())),
        };
        Ok(Some(Published {
            destination_ref: path.to_string_lossy().into_owned(),
            bytes: data.len() as u64,
            sha256: Sha256Digest::parse(&format!("{:x}", Sha256::digest(&data)))?,
        }))
    }
}
impl DurablePublisher for RealFilePublisher {
    fn publish(&mut self, _offer: &FileOffer, target: &str) -> Result<Published, Error> {
        self.publishes += 1;
        let path = Path::new(target);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| Error::Publication("no-replace publication failed".into()))?;
        file.write_all(&self.data)
            .map_err(|_| Error::Publication("short write".into()))?;
        file.sync_all()
            .map_err(|_| Error::Publication("sync failed".into()))?;
        // This fixture exercises the PORTABLE journal commit/restart state
        // machine, not the native Windows publisher. Rust's File::open on a
        // directory cannot produce a flushable directory handle on Windows.
        // Keep the POSIX parent-directory durability assertion for Linux,
        // while Windows requires its own separately reviewed publisher.
        #[cfg(not(windows))]
        fs::File::open(path.parent().unwrap())
            .and_then(|d| d.sync_all())
            .map_err(|_| Error::Publication("parent sync failed".into()))?;
        if self.fail_after_sync {
            return Err(Error::Publication(
                "test-only crash after publication before DB receipt".into(),
            ));
        }
        Self::inspect(path)?.ok_or(Error::Publication("missing published item".into()))
    }
    fn inspect_published(
        &mut self,
        _offer: &FileOffer,
        target: &str,
    ) -> Result<Option<Published>, Error> {
        Self::inspect(Path::new(target))
    }
}

#[test]
fn restart_preserves_durable_verified_receipt_and_does_not_republish() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("receipt.sqlite");
    let target = dir.path().join("destination.bin");
    let payload = b"verified bytes only";
    let offer = offer(payload);
    {
        let mut journal = Journal::open(&db).unwrap();
        assert_eq!(journal.reserve(&offer).unwrap().phase, Phase::Reserved);
        journal
            .record_commit_intent(&offer, target.to_str().unwrap())
            .unwrap();
        let mut publisher = RealFilePublisher {
            data: payload.to_vec(),
            fail_after_sync: false,
            publishes: 0,
        };
        let receipt = journal.publish_with(&offer, &mut publisher).unwrap();
        assert_eq!(receipt.bytes, payload.len() as u64);
        assert_eq!(receipt.sha256, offer.sha256);
        assert_eq!(publisher.publishes, 1);
    }
    let mut recovered = Journal::open(&db).unwrap();
    assert_eq!(recovered.reserve(&offer).unwrap().phase, Phase::Committed);
    let mut never_publish = RealFilePublisher {
        data: b"would overwrite".to_vec(),
        fail_after_sync: false,
        publishes: 0,
    };
    let repeat = recovered.publish_with(&offer, &mut never_publish).unwrap();
    assert_eq!(repeat.sha256, offer.sha256);
    assert_eq!(never_publish.publishes, 0);
    assert_eq!(fs::read(target).unwrap(), payload);
    assert!(recovered.unresolved_intents().unwrap().is_empty());
}

#[test]
fn crash_after_file_publication_recovers_by_read_only_hash_inspection() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("intent.sqlite");
    let target = dir.path().join("already-published.bin");
    let payload = b"durable file after missing receipt";
    let offer = offer(payload);
    let mut publisher = RealFilePublisher {
        data: payload.to_vec(),
        fail_after_sync: true,
        publishes: 0,
    };
    {
        let mut journal = Journal::open(&db).unwrap();
        journal.reserve(&offer).unwrap();
        journal
            .record_commit_intent(&offer, target.to_str().unwrap())
            .unwrap();
        assert!(journal.publish_with(&offer, &mut publisher).is_err());
        assert_eq!(
            journal.lookup(&offer).unwrap().unwrap().phase,
            Phase::CommitIntent
        );
    }
    assert!(target.exists());
    let mut journal = Journal::open(&db).unwrap();
    assert_eq!(
        journal.unresolved_intents().unwrap(),
        vec![offer.id.clone()]
    );
    let receipt = journal
        .reconcile_intent(&offer, &mut publisher)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.sha256, offer.sha256);
    assert_eq!(publisher.publishes, 1); // inspect, never publish again
    assert_eq!(
        journal.lookup(&offer).unwrap().unwrap().phase,
        Phase::Committed
    );
    assert!(journal.unresolved_intents().unwrap().is_empty());
}

#[test]
fn absence_or_hash_mismatch_never_manufactures_completion() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("not-yet.bin");
    let offer = offer(b"right bytes");
    let mut journal = Journal::open(&dir.path().join("state.sqlite")).unwrap();
    journal.reserve(&offer).unwrap();
    journal
        .record_commit_intent(&offer, target.to_str().unwrap())
        .unwrap();
    let mut publisher = RealFilePublisher {
        data: vec![],
        fail_after_sync: false,
        publishes: 0,
    };
    assert!(journal
        .reconcile_intent(&offer, &mut publisher)
        .unwrap()
        .is_none());
    fs::write(&target, b"wrong bytes").unwrap();
    assert!(journal.reconcile_intent(&offer, &mut publisher).is_err());
    assert_eq!(
        journal.lookup(&offer).unwrap().unwrap().phase,
        Phase::CommitIntent
    );
    assert!(journal.lookup(&offer).unwrap().unwrap().receipt.is_none());
}

#[test]
fn duplicate_id_bound_to_peer_manifest_and_target() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&dir.path().join("db.sqlite")).unwrap();
    let offer = offer(b"a");
    journal.reserve(&offer).unwrap();
    journal.reserve(&offer).unwrap();
    let mut changed = offer.clone();
    changed.peer = KeyFingerprint::parse(&"d".repeat(64)).unwrap();
    assert!(matches!(
        journal.reserve(&changed),
        Err(Error::DuplicateIdConflict)
    ));
    changed = offer.clone();
    changed.manifest = Sha256Digest::parse(&"e".repeat(64)).unwrap();
    assert!(matches!(
        journal.lookup(&changed),
        Err(Error::DuplicateIdConflict)
    ));
    journal
        .record_commit_intent(&offer, "storage://first")
        .unwrap();
    assert!(matches!(
        journal.record_commit_intent(&offer, "storage://second"),
        Err(Error::InvalidState)
    ));
    assert_eq!(
        journal.lookup(&offer).unwrap().unwrap().phase,
        Phase::CommitIntent
    );
}

struct UnverifiedPublisher {
    claimed: Published,
    inspection: Option<Published>,
}

impl DurablePublisher for UnverifiedPublisher {
    fn publish(&mut self, _offer: &FileOffer, _target: &str) -> Result<Published, Error> {
        Ok(self.claimed.clone())
    }

    fn inspect_published(
        &mut self,
        _offer: &FileOffer,
        _target: &str,
    ) -> Result<Option<Published>, Error> {
        Ok(self.inspection.clone())
    }
}

#[test]
fn a_publishers_claim_alone_never_creates_a_complete_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let offer = offer(b"expected data");
    let mut journal = Journal::open(&dir.path().join("db.sqlite")).unwrap();
    journal.reserve(&offer).unwrap();
    journal
        .record_commit_intent(&offer, "storage://verified-location")
        .unwrap();
    let evidence = Published {
        destination_ref: "storage://verified-location".into(),
        bytes: offer.bytes,
        sha256: offer.sha256.clone(),
    };
    // The writer said it succeeded, but no committed destination exists.
    let mut missing = UnverifiedPublisher {
        claimed: evidence.clone(),
        inspection: None,
    };
    assert!(journal.publish_with(&offer, &mut missing).is_err());
    assert_eq!(
        journal.lookup(&offer).unwrap().unwrap().phase,
        Phase::CommitIntent
    );
    assert!(journal.lookup(&offer).unwrap().unwrap().receipt.is_none());

    // A native adapter also must not claim a receipt for different bytes.
    let mut wrong = UnverifiedPublisher {
        claimed: evidence.clone(),
        inspection: Some(Published {
            sha256: Sha256Digest::parse(&"f".repeat(64)).unwrap(),
            ..evidence
        }),
    };
    assert!(journal.publish_with(&offer, &mut wrong).is_err());
    assert_eq!(
        journal.lookup(&offer).unwrap().unwrap().phase,
        Phase::CommitIntent
    );
}

#[cfg(unix)]
#[test]
fn journal_creation_is_private_and_rejects_public_files_or_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("private.sqlite");
    let store = Journal::open(&db).unwrap();
    assert_eq!(
        fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(store);

    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(Journal::open(&db), Err(Error::Invalid(_))));
    // Rejected files must not be silently chmodded or otherwise modified.
    assert_eq!(
        fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o644
    );

    let alias = dir.path().join("alias.sqlite");
    symlink(&db, &alias).unwrap();
    assert!(matches!(Journal::open(&alias), Err(Error::Invalid(_))));
}
