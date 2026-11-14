//! SQLite-backed receipt and trust journal; no network protocol is frozen.
//! A native destination adapter must durably publish and re-open/hash the
//! actual file before returning its evidence to this journal.

use crate::guest::{GuestSpkiFingerprint, P256Spki};
use crate::guest_recovery::{GuestOfferV1, GuestRecoveryScope, MAX_RECOVERY_MILLIS};
use crate::identity::{validate_file_name, DeviceId, KeyFingerprint, Sha256Digest, TransferId};
use crate::policy::{self, PrivateVisibility, ReceiveDecision, Visibility};
use crate::Error;
use ring::constant_time::verify_slices_are_equal;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
use std::{fs::File, os::unix::fs::MetadataExt};

/// Keep private peer trust, destination references and transfer metadata out
/// of world-readable SQLite files. The owning platform must ALSO keep the
/// parent directory private and protect the database from replacement races.
#[cfg(unix)]
fn require_private_journal(path: &Path) -> Result<(), Error> {
    use std::fs::{self, OpenOptions};
    use std::io::ErrorKind;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Pre-create with restrictive permissions instead of allowing SQLite's
    // default file creation to expose trust/receipt data under umask 022.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Invalid("journal must be a private regular file"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOffer {
    pub id: TransferId,
    pub peer: KeyFingerprint,
    pub manifest: Sha256Digest,
    pub name: String,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}
impl FileOffer {
    pub fn validate(&self) -> Result<(), Error> {
        validate_file_name(&self.name)?;
        if self.bytes > i64::MAX as u64 {
            return Err(Error::Invalid("file too large for journal"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Reserved,
    CommitIntent,
    Committed,
}
impl Phase {
    fn from_db(s: &str) -> Result<Self, Error> {
        match s {
            "reserved" => Ok(Self::Reserved),
            "intent" => Ok(Self::CommitIntent),
            "committed" => Ok(Self::Committed),
            _ => Err(Error::Invalid("stored transaction phase")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub transfer_id: TransferId,
    pub peer: KeyFingerprint,
    pub manifest: Sha256Digest,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}

/// Evidence returned by a trusted native adapter only after: no-replace
/// publication, actual destination digest verification, and destination sync.
/// This value alone is not cryptographic proof; the adapter is a reviewed TCB.
#[derive(Debug, Clone)]
pub struct Published {
    pub destination_ref: String,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}

/// Platform implementation is responsible for filesystem or document-provider
/// semantics. `inspect_published` must be read-only and verify actual bytes.
pub trait DurablePublisher {
    fn publish(&mut self, offer: &FileOffer, destination_ref: &str) -> Result<Published, Error>;
    fn inspect_published(
        &mut self,
        offer: &FileOffer,
        destination_ref: &str,
    ) -> Result<Option<Published>, Error>;
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub phase: Phase,
    /// Local-only destination capability/reference. Never transmit a Snapshot
    /// to a remote peer; a network receipt contains no local file location.
    pub destination_ref: Option<String>,
    pub receipt: Option<Receipt>,
}

#[derive(Debug, Clone)]
pub struct TrustedDevice {
    pub device_id: DeviceId,
    pub fingerprint: KeyFingerprint,
    pub revoked: bool,
    pub auto_accept: bool,
}

/// Durable local journal. Raw mutation, recovery and receipt inspection are
/// private to this crate: external network handlers must use authenticated
/// `AuthorizedOffer` methods, never caller-supplied identifiers by themselves.
///
/// ```compile_fail
/// use opendrop_core::journal::{FileOffer, Journal};
/// fn bypass(db: &mut Journal, offer: &FileOffer) { let _ = db.reserve(offer); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::{FileOffer, Journal};
/// fn bypass(db: &mut Journal, offer: &FileOffer) { let _ = db.record_commit_intent(offer, "path"); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::{FileOffer, Journal, DurablePublisher};
/// fn bypass(db: &mut Journal, offer: &FileOffer, writer: &mut impl DurablePublisher) { let _ = db.publish_with(offer, writer); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::{FileOffer, Journal};
/// fn bypass(db: &Journal, offer: &FileOffer) { let _ = db.lookup(offer); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::{FileOffer, Journal, DurablePublisher};
/// fn bypass(db: &mut Journal, offer: &FileOffer, writer: &mut impl DurablePublisher) { let _ = db.reconcile_intent(offer, writer); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::Journal;
/// fn bypass(db: &Journal) { let _ = db.unresolved_intents(); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::Journal;
/// use opendrop_core::identity::DeviceId;
/// fn remote(db: &mut Journal, id: &DeviceId) { let _ = db.set_auto_accept(id, true); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::Journal;
/// use opendrop_core::identity::DeviceId;
/// fn remote(db: &mut Journal, id: &DeviceId) { let _ = db.revoke_device(id); }
/// ```
/// ```compile_fail
/// use opendrop_core::journal::Journal;
/// use opendrop_core::policy::Visibility;
/// fn remote(db: &mut Journal) { let _ = db.set_visibility(Visibility::default()); }
/// ```
pub struct Journal {
    db: Connection,
}

/// Owner-local, read-only recovery authority tied to a pinned 0700 stage
/// directory file descriptor. It cannot be constructed from network IDs,
/// filenames, public IPC fields, or a caller-supplied approval boolean.
/// This authority cannot mutate journal state or issue transfer receipts.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
pub struct LinuxLocalRecovery<'a> {
    journal: &'a Journal,
    protected_stage: &'a File,
}

/// Read-only local journal fact, never a network receipt or write authority.
#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRecoveryTransaction {
    pub phase: Phase,
    /// Only the accepted safe filename, not the native directory path.
    pub destination_ref: Option<String>,
}

#[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
impl LinuxLocalRecovery<'_> {
    pub fn transaction_for_exact_offer(
        &self,
        offer: &FileOffer,
    ) -> Result<Option<LinuxRecoveryTransaction>, Error> {
        let info = self.protected_stage.metadata()?;
        if !info.is_dir()
            || info.uid() != rustix::process::geteuid().as_raw()
            || info.mode() & 0o077 != 0
        {
            return Err(Error::Unauthorized);
        }
        Ok(self
            .journal
            .require_offer(offer)?
            .map(|(phase, destination_ref)| LinuxRecoveryTransaction {
                phase,
                destination_ref,
            }))
    }
}

// The persisted offer is deliberately compared field-by-field rather than
// accepting a transfer ID alone as authorization for an existing receipt.
type StoredOffer = (String, String, String, i64, String, String, Option<String>);
impl Journal {
    pub fn open(path: &Path) -> Result<Self, Error> {
        #[cfg(unix)]
        require_private_journal(path)?;
        // On Windows the packaged-app ACL/storage boundary must be validated
        // in a native test. The Linux permission check cannot prove that.
        let db = Connection::open(path)?;
        db.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;
            CREATE TABLE IF NOT EXISTS transfers(
                id TEXT PRIMARY KEY, peer TEXT NOT NULL, manifest TEXT NOT NULL,
                name TEXT NOT NULL, bytes INTEGER NOT NULL CHECK(bytes >= 0), sha TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('reserved','intent','committed')),
                destination_ref TEXT);
            CREATE TABLE IF NOT EXISTS trusted_devices(
                device_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
                auto_accept INTEGER NOT NULL DEFAULT 0 CHECK(auto_accept IN (0,1)));
            CREATE TABLE IF NOT EXISTS preferences(
                key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            /* Guest receipt verification is ONLY an adjunct to the same
            transfers(id) journal; it is not a publication/commit engine. */
        )?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS guest_receipt_verifiers(
                id TEXT PRIMARY KEY REFERENCES transfers(id) ON DELETE CASCADE,
                sender_spki BLOB NOT NULL CHECK(length(sender_spki)=91),
                receiver_spki BLOB NOT NULL CHECK(length(receiver_spki)=91),
                offer_digest BLOB NOT NULL CHECK(length(offer_digest)=32),
                verifier BLOB NOT NULL CHECK(length(verifier)=32),
                issued_ms INTEGER NOT NULL CHECK(issued_ms>=0),
                expires_ms INTEGER NOT NULL CHECK(expires_ms>issued_ms));",
        )?;
        Ok(Self { db })
    }

    /// May only be called from GuestAuthorizedTransfer after BOTH the real
    /// SAS owner action and exact-offer local destination consent. A crash
    /// after reservation but before this insert cannot produce Ready/bytes.
    pub(crate) fn register_guest_receipt_verifier(
        &mut self,
        scope: &GuestRecoveryScope,
        verifier: [u8; 32],
        issued_ms: i64,
        expires_ms: i64,
    ) -> Result<(), Error> {
        if issued_ms < 0
            || expires_ms <= issued_ms
            || expires_ms - issued_ms > MAX_RECOVERY_MILLIS
            || self.require_offer(scope.offer.journal_offer())? != Some((Phase::Reserved, None))
        {
            return Err(Error::Unauthorized);
        }
        if scope.offer_digest() != &scope.offer.canonical_digest()
            || scope.offer.sender() != scope.sender_spki.fingerprint()
        {
            return Err(Error::Unauthorized);
        }
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO guest_receipt_verifiers
            (id,sender_spki,receiver_spki,offer_digest,verifier,issued_ms,expires_ms)
            VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                scope.offer.id().as_str(),
                scope.sender_spki.as_der(),
                scope.receiver_spki.as_der(),
                scope.offer_digest.as_slice(),
                verifier.as_slice(),
                issued_ms,
                expires_ms,
            ],
        )?;
        let existing: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = tx.query_row(
            "SELECT sender_spki,receiver_spki,offer_digest,verifier,issued_ms,expires_ms
             FROM guest_receipt_verifiers WHERE id=?1",
            [scope.offer.id().as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        if existing.0 != scope.sender_spki.as_der()
            || existing.1 != scope.receiver_spki.as_der()
            || existing.2.as_slice() != scope.offer_digest()
            || verify_slices_are_equal(&existing.3, &verifier).is_err()
            || existing.4 != issued_ms
            || existing.5 != expires_ms
        {
            return Err(Error::DuplicateIdConflict);
        }
        tx.commit()?;
        Ok(())
    }

    /// Owner-local, READ-ONLY inventory of originally verified guest keys.
    /// A network ID must not grant this method to an ordinary public IPC
    /// caller: its purpose is to configure exact-key receipt-only TLS after
    /// restart, never to grant an Offer or change existing journal phases.
    #[allow(dead_code)]
    pub(crate) fn load_guest_recovery_scope(
        &self,
        id: &TransferId,
    ) -> Result<Option<GuestRecoveryScope>, Error> {
        let data: Option<(
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            String,
            String,
            String,
            i64,
            String,
        )> = self
            .db
            .query_row(
                "SELECT g.sender_spki,g.receiver_spki,g.offer_digest,
                        t.peer,t.manifest,t.name,t.bytes,t.sha
                 FROM guest_receipt_verifiers AS g
                 INNER JOIN transfers AS t ON t.id=g.id WHERE g.id=?1",
                [id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((sender, receiver, digest, peer, manifest, name, bytes, sha)) = data else {
            return Ok(None);
        };
        let sender = P256Spki::from_canonical_der(&sender)?;
        let receiver = P256Spki::from_canonical_der(&receiver)?;
        if peer != sender.fingerprint().to_hex() {
            return Err(Error::Unauthorized);
        }
        let offered = GuestOfferV1::new(
            id.clone(),
            sender.fingerprint(),
            Sha256Digest::parse(&manifest)?,
            name,
            u64::try_from(bytes).map_err(|_| Error::Invalid("guest recovery bytes"))?,
            Sha256Digest::parse(&sha)?,
        )?;
        let scope = GuestRecoveryScope {
            offer_digest: offered.canonical_digest(),
            offer: offered,
            sender_spki: sender,
            receiver_spki: receiver,
        };
        if digest.as_slice() != scope.offer_digest() {
            return Err(Error::Unauthorized);
        }
        Ok(Some(scope))
    }

    /// NEVER upgrades intent to committed or attempts publication. Returns
    /// only the existing S1-A committed receipt after exact guest verifier,
    /// original two keys, offer bytes, and expiry checks.
    pub(crate) fn read_guest_committed_receipt_exact(
        &self,
        scope: &GuestRecoveryScope,
        verifier: [u8; 32],
        now_ms: i64,
    ) -> Result<Option<Receipt>, Error> {
        if now_ms < 0 {
            return Err(Error::Unauthorized);
        }
        let data: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64)> = self
            .db
            .query_row(
                "SELECT sender_spki,receiver_spki,offer_digest,verifier,issued_ms,expires_ms
                 FROM guest_receipt_verifiers WHERE id=?1",
                [scope.offer.id().as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((sender, receiver, digest, saved_verifier, issued, expires)) = data else {
            return Err(Error::Unauthorized);
        };
        // Time rollback is evident when before issuance. Other host clock
        // manipulation cannot be securely detected without trusted time.
        if now_ms < issued
            || now_ms >= expires
            || expires - issued > MAX_RECOVERY_MILLIS
            || sender != scope.sender_spki.as_der()
            || receiver != scope.receiver_spki.as_der()
            || digest.as_slice() != scope.offer_digest()
            || verify_slices_are_equal(&saved_verifier, &verifier).is_err()
        {
            return Err(Error::Unauthorized);
        }
        Ok(self
            .lookup(scope.offer.journal_offer())?
            .and_then(|snapshot| snapshot.receipt))
    }

    /// INTERNAL recovery/transaction primitive; untrusted network handlers
    /// MUST use `authorization::AuthorizedOffer` instead. Deliberately
    /// crate-private so copying a peer fingerprint cannot authorize a write.
    /// A replay of identical parameters is idempotent; any mismatch fails.
    pub(crate) fn reserve(&mut self, offer: &FileOffer) -> Result<Snapshot, Error> {
        offer.validate()?;
        let tx = self.db.transaction()?;
        let existing: Option<(String, String, String, i64, String)> = tx
            .query_row(
                "SELECT peer,manifest,name,bytes,sha FROM transfers WHERE id=?1",
                [offer.id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        if let Some((peer, manifest, name, bytes, sha)) = existing {
            if peer != offer.peer.as_str()
                || manifest != offer.manifest.as_str()
                || name != offer.name
                || bytes != offer.bytes as i64
                || sha != offer.sha256.as_str()
            {
                return Err(Error::DuplicateIdConflict);
            }
        } else {
            tx.execute(
                "INSERT INTO transfers(id,peer,manifest,name,bytes,sha,phase)
                VALUES(?1,?2,?3,?4,?5,?6,'reserved')",
                params![
                    offer.id.as_str(),
                    offer.peer.as_str(),
                    offer.manifest.as_str(),
                    offer.name,
                    offer.bytes as i64,
                    offer.sha256.as_str()
                ],
            )?;
        }
        tx.commit()?;
        self.lookup(offer)?.ok_or(Error::InvalidState)
    }

    fn require_offer(&self, offer: &FileOffer) -> Result<Option<(Phase, Option<String>)>, Error> {
        offer.validate()?;
        let existing: Option<StoredOffer> = self.db.query_row(
            "SELECT peer,manifest,name,bytes,sha,phase,destination_ref FROM transfers WHERE id=?1",
            [offer.id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
        ).optional()?;
        let Some((peer, manifest, name, bytes, sha, phase, destination)) = existing else {
            return Ok(None);
        };
        if peer != offer.peer.as_str()
            || manifest != offer.manifest.as_str()
            || name != offer.name
            || bytes != offer.bytes as i64
            || sha != offer.sha256.as_str()
        {
            return Err(Error::DuplicateIdConflict);
        }
        Ok(Some((Phase::from_db(&phase)?, destination)))
    }

    /// INTERNAL recovery lookup. Network-facing committed receipts must go
    /// through `AuthenticatedSession::committed_receipt_for_offer`.
    pub(crate) fn lookup(&self, offer: &FileOffer) -> Result<Option<Snapshot>, Error> {
        let Some((phase, destination_ref)) = self.require_offer(offer)? else {
            return Ok(None);
        };
        let receipt = if phase == Phase::Committed {
            // The authenticated sender may learn only what it already offered
            // and what was verified; never disclose the receiver's local path.
            if destination_ref.is_none() {
                return Err(Error::InvalidState);
            }
            Some(Receipt {
                transfer_id: offer.id.clone(),
                peer: offer.peer.clone(),
                manifest: offer.manifest.clone(),
                bytes: offer.bytes,
                sha256: offer.sha256.clone(),
            })
        } else {
            None
        };
        Ok(Some(Snapshot {
            phase,
            destination_ref,
            receipt,
        }))
    }

    /// Bind startup phase inspection to an existing pinned owner-private
    /// staging directory (opened and locked by the native filesystem adapter).
    /// No unauthenticated API takes a transfer ID and returns a raw phase.
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    pub fn local_linux_recovery<'a>(
        &'a self,
        private_stage: &'a File,
    ) -> Result<LinuxLocalRecovery<'a>, Error> {
        let info = private_stage.metadata()?;
        if !info.is_dir()
            || info.uid() != rustix::process::geteuid().as_raw()
            || info.mode() & 0o077 != 0
        {
            return Err(Error::Unauthorized);
        }
        Ok(LinuxLocalRecovery {
            journal: self,
            protected_stage: private_stage,
        })
    }

    /// INTERNAL commit-intent; public writes require AuthorizedOffer.
    /// Commit-intent is fsynced via SQLite FULL before native publication.
    /// Same ID cannot switch targets after restart or a lost ACK.
    pub(crate) fn record_commit_intent(
        &mut self,
        offer: &FileOffer,
        destination_ref: &str,
    ) -> Result<(), Error> {
        if destination_ref.is_empty()
            || destination_ref.len() > 4096
            || destination_ref.contains('\0')
        {
            return Err(Error::Invalid("destination reference"));
        }
        match self.require_offer(offer)? {
            Some((Phase::Reserved, None)) => {
                self.db.execute("UPDATE transfers SET phase='intent',destination_ref=?2 WHERE id=?1 AND phase='reserved'",
                    params![offer.id.as_str(),destination_ref])?;
            }
            Some((Phase::CommitIntent, Some(ref existing))) if existing == destination_ref => {}
            _ => return Err(Error::InvalidState),
        }
        Ok(())
    }

    fn store_published(
        &mut self,
        offer: &FileOffer,
        expected_ref: &str,
        published: Published,
    ) -> Result<Receipt, Error> {
        if published.destination_ref != expected_ref
            || published.bytes != offer.bytes
            || published.sha256 != offer.sha256
        {
            return Err(Error::Invalid("published destination digest/bytes"));
        }
        let tx = self.db.transaction()?;
        let changed = tx.execute("UPDATE transfers SET phase='committed' WHERE id=?1 AND phase='intent' AND destination_ref=?2",
            params![offer.id.as_str(),expected_ref])?;
        if changed != 1 {
            return Err(Error::InvalidState);
        }
        tx.commit()?;
        self.lookup(offer)?
            .and_then(|s| s.receipt)
            .ok_or(Error::InvalidState)
    }

    /// INTERNAL publication; public writes require AuthorizedOffer.
    /// A retry cannot re-publish a committed item. On crash after publication
    /// but before this DB commit, use `reconcile_intent` instead.
    pub(crate) fn publish_with(
        &mut self,
        offer: &FileOffer,
        publisher: &mut impl DurablePublisher,
    ) -> Result<Receipt, Error> {
        let snap = self.lookup(offer)?.ok_or(Error::InvalidState)?;
        if let Some(receipt) = snap.receipt {
            return Ok(receipt);
        }
        if snap.phase != Phase::CommitIntent {
            return Err(Error::InvalidState);
        }
        let destination = snap.destination_ref.ok_or(Error::InvalidState)?;
        let published = publisher.publish(offer, &destination)?;
        // A reported successful write is not sufficient evidence to issue a
        // receipt. Require a distinct read-only inspection of the published
        // destination, validated against the originally accepted offer.
        if published.destination_ref != destination
            || published.bytes != offer.bytes
            || published.sha256 != offer.sha256
        {
            return Err(Error::Invalid("publisher reported mismatched output"));
        }
        let inspected = publisher
            .inspect_published(offer, &destination)?
            .ok_or_else(|| Error::Publication("published destination is absent".into()))?;
        self.store_published(offer, &destination, inspected)
    }

    /// INTERNAL restart-recovery operation, not a peer request endpoint.
    /// Read-only inspection before recovering a previously published file;
    /// absence or mismatch remains unresolved, NEVER silently re-published.
    #[allow(dead_code)] // production recovery wiring is an independent OS-storage gate
    pub(crate) fn reconcile_intent(
        &mut self,
        offer: &FileOffer,
        publisher: &mut impl DurablePublisher,
    ) -> Result<Option<Receipt>, Error> {
        let snap = self.lookup(offer)?.ok_or(Error::InvalidState)?;
        if let Some(receipt) = snap.receipt {
            return Ok(Some(receipt));
        }
        if snap.phase != Phase::CommitIntent {
            return Ok(None);
        }
        let destination = snap.destination_ref.ok_or(Error::InvalidState)?;
        match publisher.inspect_published(offer, &destination)? {
            Some(published) => self
                .store_published(offer, &destination, published)
                .map(Some),
            None => Ok(None),
        }
    }

    /// INTERNAL restart-recovery inventory. Not exposed as a network API.
    /// Display-safe list of intent IDs only; the native adapter decides what
    /// source/destination evidence is valid after a power loss.
    #[allow(dead_code)] // needed by private crash-recovery path and internal tests
    pub(crate) fn unresolved_intents(&self) -> Result<Vec<TransferId>, Error> {
        let mut stmt = self
            .db
            .prepare("SELECT id FROM transfers WHERE phase='intent' ORDER BY id")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .map(|r| r.map_err(Error::from).and_then(|s| TransferId::parse(&s)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Test-only enrollment fixture: do not expose a writable trusted-device
    /// API until a real cryptographic pairing ceremony can prove ownership.
    /// UI-supplied identifiers/fingerprints must never create durable trust.
    #[cfg(test)]
    pub(crate) fn record_cryptographically_verified_peer(
        &mut self,
        id: &DeviceId,
        key: &KeyFingerprint,
    ) -> Result<(), Error> {
        let existing = self.trusted_device(id)?;
        if existing.is_some() {
            return Err(Error::PeerUntrusted);
        } // reinstall/key change needs new explicit ceremony
        self.db.execute(
            "INSERT INTO trusted_devices(device_id,fingerprint) VALUES(?1,?2)",
            params![id.as_str(), key.as_str()],
        )?;
        Ok(())
    }
    pub(crate) fn trusted_device(&self, id: &DeviceId) -> Result<Option<TrustedDevice>, Error> {
        let row: Option<(String, i64, i64)> = self
            .db
            .query_row(
                "SELECT fingerprint,revoked,auto_accept FROM trusted_devices WHERE device_id=?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(key, revoked, auto)| {
            Ok(TrustedDevice {
                device_id: id.clone(),
                fingerprint: KeyFingerprint::parse(&key)?,
                revoked: revoked != 0,
                auto_accept: auto != 0,
            })
        })
        .transpose()
    }
    /// Only the authenticated TLS listener uses this to map a verified leaf
    /// certificate to an already paired, nonrevoked local identity. The wire
    /// peer cannot supply a claimed DeviceId and thereby select another row.
    /// No production trust-enrollment shortcut is introduced.
    pub(crate) fn paired_identity_for_cert(
        &self,
        fingerprint: &KeyFingerprint,
    ) -> Result<Option<DeviceId>, Error> {
        let mut statement = self.db.prepare(
            "SELECT device_id FROM trusted_devices
             WHERE fingerprint=?1 AND revoked=0 LIMIT 2",
        )?;
        let mut rows = statement.query([fingerprint.as_str()])?;
        let first = match rows.next()? {
            Some(row) => DeviceId::parse(&row.get::<_, String>(0)?)?,
            None => return Ok(None),
        };
        if rows.next()?.is_some() {
            return Err(Error::PeerUntrusted);
        }
        Ok(Some(first))
    }
    /// A previously revoked certificate is blocked even when an attacker
    /// supplies a different DeviceId under temporary Everyone visibility.
    pub(crate) fn peer_revoked_or_key_changed(
        &self,
        id: &DeviceId,
        actual: &KeyFingerprint,
    ) -> Result<bool, Error> {
        if let Some(known) = self.trusted_device(id)? {
            if known.revoked || known.fingerprint != *actual {
                return Ok(true);
            }
        }
        let revoked: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM trusted_devices WHERE fingerprint=?1 AND revoked=1)",
            [actual.as_str()],
            |r| r.get(0),
        )?;
        Ok(revoked)
    }
    /// Future privileged local UI only. No remotely callable trust mutation.
    #[allow(dead_code)] // native local-user action adapter is not yet wired
    pub(crate) fn revoke_device(&mut self, id: &DeviceId) -> Result<(), Error> {
        if self.db.execute(
            "UPDATE trusted_devices SET revoked=1, auto_accept=0 WHERE device_id=?1 AND revoked=0",
            [id.as_str()],
        )? != 1
        {
            return Err(Error::PeerUntrusted);
        }
        Ok(())
    }
    /// Future privileged local UI only; autoaccept is off until explicit opt-in.
    #[allow(dead_code)] // native local-user action adapter is not yet wired
    pub(crate) fn set_auto_accept(&mut self, id: &DeviceId, enabled: bool) -> Result<(), Error> {
        if self.db.execute(
            "UPDATE trusted_devices SET auto_accept=?2 WHERE device_id=?1 AND revoked=0",
            params![id.as_str(), i64::from(enabled)],
        )? != 1
        {
            return Err(Error::PeerUntrusted);
        }
        Ok(())
    }
    pub(crate) fn authorize_receive(
        &self,
        id: &DeviceId,
        actual_key: &KeyFingerprint,
        visibility: Visibility,
        now_ms: i64,
        explicitly_approved: bool,
    ) -> Result<ReceiveDecision, Error> {
        if self.peer_revoked_or_key_changed(id, actual_key)? {
            return Ok(ReceiveDecision::Deny);
        }
        let pinned = self.trusted_device(id)?;
        let peer = policy::Peer {
            device_id: id,
            actual_key,
            pinned_key: pinned.as_ref().map(|p| &p.fingerprint),
            revoked: pinned.as_ref().is_some_and(|p| p.revoked),
            auto_accept: pinned.as_ref().is_some_and(|p| p.auto_accept),
        };
        Ok(policy::decide_incoming(
            visibility.mode(now_ms),
            &peer,
            explicitly_approved,
        ))
    }
    /// Future privileged local UI only; Everyone expiry and default remain intact.
    #[allow(dead_code)] // native local-user action adapter is not yet wired
    pub(crate) fn set_visibility(&mut self, visibility: Visibility) -> Result<(), Error> {
        let (start, end) = visibility.persisted_interval();
        let mode = match visibility.previous() {
            PrivateVisibility::Off => "off",
            PrivateVisibility::TrustedOnly => "trusted",
        };
        let encoded = format!(
            "{mode}:{}:{}",
            start.map_or("-".to_string(), |x| x.to_string()),
            end.map_or("-".to_string(), |x| x.to_string())
        );
        self.db.execute(
            "INSERT INTO preferences(key,value) VALUES('visibility',?1)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [encoded],
        )?;
        Ok(())
    }
    pub fn visibility(&self) -> Result<Visibility, Error> {
        let entry: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM preferences WHERE key='visibility'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(entry) = entry else {
            return Ok(Visibility::default());
        };
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::Invalid("stored visibility"));
        }
        let previous = match parts[0] {
            "off" => PrivateVisibility::Off,
            "trusted" => PrivateVisibility::TrustedOnly,
            _ => return Err(Error::Invalid("stored visibility")),
        };
        let read = |s: &str| -> Result<Option<i64>, Error> {
            if s == "-" {
                Ok(None)
            } else {
                s.parse::<i64>()
                    .map(Some)
                    .map_err(|_| Error::Invalid("stored visibility clock"))
            }
        };
        Visibility::from_persisted(previous, read(parts[1])?, read(parts[2])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EffectiveVisibility, ReceiveDecision};

    fn id() -> DeviceId {
        DeviceId::parse(&"1".repeat(32)).unwrap()
    }
    fn key(a: char) -> KeyFingerprint {
        KeyFingerprint::parse(&a.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn verified_peer_is_persistent_but_never_implicitly_auto_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.sqlite");
        let peer = id();
        let public = key('a');
        let changed = key('b');
        {
            let mut store = Journal::open(&path).unwrap();
            assert_eq!(
                store.visibility().unwrap().mode(100),
                EffectiveVisibility::TrustedOnly
            );
            store
                .record_cryptographically_verified_peer(&peer, &public)
                .unwrap();
            assert_eq!(
                store
                    .authorize_receive(&peer, &public, Visibility::default(), 100, false)
                    .unwrap(),
                ReceiveDecision::RequireTrustedConsent
            );
            assert!(store
                .record_cryptographically_verified_peer(&peer, &changed)
                .is_err());
            store.set_auto_accept(&peer, true).unwrap();
            assert_eq!(
                store
                    .authorize_receive(&peer, &public, Visibility::default(), 100, false)
                    .unwrap(),
                ReceiveDecision::AllowAutoAcceptedTrusted
            );
            assert_eq!(
                store
                    .authorize_receive(&peer, &changed, Visibility::default(), 100, true)
                    .unwrap(),
                ReceiveDecision::Deny
            );
        }
        {
            let mut reopened = Journal::open(&path).unwrap();
            assert!(reopened.trusted_device(&peer).unwrap().unwrap().auto_accept);
            reopened.revoke_device(&peer).unwrap();
            assert_eq!(
                reopened
                    .authorize_receive(
                        &peer,
                        &public,
                        Visibility::private(PrivateVisibility::TrustedOnly),
                        100,
                        true
                    )
                    .unwrap(),
                ReceiveDecision::Deny
            );
            assert!(reopened.set_auto_accept(&peer, true).is_err());
            assert!(reopened
                .record_cryptographically_verified_peer(&peer, &public)
                .is_err());
        }
        assert!(
            Journal::open(&path)
                .unwrap()
                .trusted_device(&peer)
                .unwrap()
                .unwrap()
                .revoked
        );
    }

    #[test]
    fn existing_paired_certificate_lookup_is_local_exact_and_revocable() {
        let owned = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&owned.path().join("cert-mapping.sqlite")).unwrap();
        let device = id();
        let actual = key('a');
        let unrelated = key('b');
        assert!(journal.paired_identity_for_cert(&actual).unwrap().is_none());
        journal
            .record_cryptographically_verified_peer(&device, &actual)
            .unwrap();
        assert_eq!(
            journal.paired_identity_for_cert(&actual).unwrap(),
            Some(device.clone())
        );
        assert!(journal
            .paired_identity_for_cert(&unrelated)
            .unwrap()
            .is_none());
        journal.revoke_device(&device).unwrap();
        assert!(journal.paired_identity_for_cert(&actual).unwrap().is_none());
    }

    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    #[test]
    fn read_only_native_stage_recovery_has_exact_offer_and_phase_checks() {
        use std::fs::File;
        use std::os::unix::fs::PermissionsExt;

        let folder = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&folder.path().join("recovery.sqlite")).unwrap();
        let private_stage = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let stage_fd = File::open(private_stage.path()).unwrap();
        let offer = FileOffer {
            id: TransferId::parse(&"1".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"2".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"3".repeat(64)).unwrap(),
            name: "recovery.txt".into(),
            bytes: 1,
            sha256: Sha256Digest::parse(&"4".repeat(64)).unwrap(),
        };
        assert_eq!(
            journal
                .local_linux_recovery(&stage_fd)
                .unwrap()
                .transaction_for_exact_offer(&offer)
                .unwrap(),
            None
        );
        journal.reserve(&offer).unwrap();
        assert_eq!(
            journal
                .local_linux_recovery(&stage_fd)
                .unwrap()
                .transaction_for_exact_offer(&offer)
                .unwrap(),
            Some(LinuxRecoveryTransaction {
                phase: Phase::Reserved,
                destination_ref: None,
            })
        );
        let mut wrong = offer.clone();
        wrong.sha256 = Sha256Digest::parse(&"5".repeat(64)).unwrap();
        assert!(journal
            .local_linux_recovery(&stage_fd)
            .unwrap()
            .transaction_for_exact_offer(&wrong)
            .is_err());
        journal
            .record_commit_intent(&offer, "recovery.txt")
            .unwrap();
        assert_eq!(
            journal
                .local_linux_recovery(&stage_fd)
                .unwrap()
                .transaction_for_exact_offer(&offer)
                .unwrap(),
            Some(LinuxRecoveryTransaction {
                phase: Phase::CommitIntent,
                destination_ref: Some("recovery.txt".into()),
            })
        );
        std::fs::set_permissions(private_stage.path(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(matches!(
            journal.local_linux_recovery(&stage_fd),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn guest_visibility_expires_on_disk_reopen_and_keeps_prior_off_setting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("visibility.sqlite");
        {
            let mut journal = Journal::open(&path).unwrap();
            journal
                .set_visibility(
                    Visibility::private(PrivateVisibility::Off)
                        .everyone(20_000)
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(
                journal.visibility().unwrap().mode(20_001),
                EffectiveVisibility::Everyone
            );
        }
        let journal = Journal::open(&path).unwrap();
        assert_eq!(
            journal.visibility().unwrap().mode(620_000),
            EffectiveVisibility::Off
        );
        assert_eq!(
            journal.visibility().unwrap().mode(19_000),
            EffectiveVisibility::Off
        );
        let untrusted = id();
        let fingerprint = key('a');
        assert_eq!(
            journal
                .authorize_receive(
                    &untrusted,
                    &fingerprint,
                    journal.visibility().unwrap(),
                    620_000,
                    true
                )
                .unwrap(),
            ReceiveDecision::Deny
        );
    }
}
