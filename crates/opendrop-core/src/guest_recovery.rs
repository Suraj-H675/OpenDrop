//! Transfer-specific, non-enrolling S1 guest receipt recovery.
//!
//! This is a credential/authorization adjunct to the EXISTING durable
//! Journal transaction engine, never another publication state machine.
//! The SQLite journal retains only a SHA-256 verifier of the 256-bit random
//! credential. A fresh exact-key TLS connection plus the credential may
//! query ONLY an already committed, exact-offer receipt for at most 24 hours.
//! It must not authorize another offer, stream, destination or peer trust.

use crate::guest::{GuestSpkiFingerprint, P256Spki, TransferSide};
use crate::guest_tls::{VerifiedGuestSession, VerifiedReceiptOnlyTls};
use crate::identity::{validate_file_name, KeyFingerprint, Sha256Digest, TransferId};
use crate::journal::{FileOffer, Journal, Receipt};
use crate::Error;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_RECOVERY_MILLIS: i64 = 24 * 60 * 60 * 1000;

fn authoritative_local_now_millis() -> Result<i64, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unauthorized)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| Error::Unauthorized)
}

/// Versioned GuestV1 offer. The accepted S1-A FileOffer remains unchanged,
/// but a guest SPKI is NEVER inferred from a legacy certificate fingerprint:
/// it must be explicitly validated in this versioned constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestOfferV1 {
    transfer: FileOffer,
    sender: GuestSpkiFingerprint,
}

impl GuestOfferV1 {
    /// Construct only from a bounded, decoded wire Offer after the same TLS
    /// channel has reached VerifiedGuestSession. A guest SPKI value never
    /// upgrades the legacy paired-certificate trust domain.
    pub fn from_verified_wire_offer(
        offered: FileOffer,
        actual_sender: GuestSpkiFingerprint,
    ) -> Result<Self, Error> {
        crate::wire::validate_offer(&offered)?;
        if offered.peer.as_str() != actual_sender.to_hex() {
            return Err(Error::Unauthorized);
        }
        let original = Self::new(
            offered.id.clone(),
            actual_sender,
            offered.manifest.clone(),
            offered.name.clone(),
            offered.bytes,
            offered.sha256.clone(),
        )?;
        if original.transfer != offered {
            return Err(Error::Unauthorized);
        }
        Ok(original)
    }

    pub fn new(
        id: TransferId,
        sender: GuestSpkiFingerprint,
        manifest: Sha256Digest,
        name: String,
        bytes: u64,
        sha256: Sha256Digest,
    ) -> Result<Self, Error> {
        validate_file_name(&name)?;
        let transfer = FileOffer {
            id,
            // The legacy wire container can hold this value, but only a
            // separate guest-v1 journal binding asserts its SPKI domain.
            peer: KeyFingerprint::parse(&sender.to_hex())?,
            manifest,
            name,
            bytes,
            sha256,
        };
        transfer.validate()?;
        Ok(Self { transfer, sender })
    }

    pub fn id(&self) -> &TransferId {
        &self.transfer.id
    }

    pub fn sender(&self) -> GuestSpkiFingerprint {
        self.sender
    }

    pub fn file_offer(&self) -> &FileOffer {
        &self.transfer
    }

    pub(crate) fn journal_offer(&self) -> &FileOffer {
        &self.transfer
    }

    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"OpenDrop/S1/GuestOffer/v1\0");
        hash.update(self.transfer.id.as_str().as_bytes());
        hash.update(self.sender.as_bytes());
        hash.update(self.transfer.manifest.as_str().as_bytes());
        hash.update(self.transfer.bytes.to_be_bytes());
        hash.update((self.transfer.name.len() as u16).to_be_bytes());
        hash.update(self.transfer.name.as_bytes());
        hash.update(self.transfer.sha256.as_str().as_bytes());
        hash.finalize().into()
    }
}

pub struct GuestRecoveryCredential([u8; 32]);

impl std::fmt::Debug for GuestRecoveryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuestRecoveryCredential([REDACTED])")
    }
}
impl GuestRecoveryCredential {
    pub fn generate() -> Result<Self, Error> {
        let mut secret = [0u8; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| Error::Unauthorized)?;
        Ok(Self(secret))
    }
    /// Only the protected native key-store/session transport may retain or
    /// transmit these bytes. This method never writes to logs or disk.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn from_transmitted_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes == [0u8; 32] {
            return Err(Error::Unauthorized);
        }
        Ok(Self(bytes))
    }
}

impl Drop for GuestRecoveryCredential {
    fn drop(&mut self) {
        // Best-effort memory hygiene; stack copies, OS crash dumps and
        // allocator behavior are outside Rust's guaranteed zeroization.
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

/// Opaque exact transfer+key binding, never constructible from network names.
pub struct GuestRecoveryScope {
    pub(crate) offer: GuestOfferV1,
    pub(crate) sender_spki: P256Spki,
    pub(crate) receiver_spki: P256Spki,
    pub(crate) offer_digest: [u8; 32],
}

impl GuestRecoveryScope {
    pub fn exact_transfer_id(&self) -> &TransferId {
        self.offer.id()
    }
    pub fn file_offer(&self) -> &FileOffer {
        self.offer.file_offer()
    }
    pub fn sender_key(&self) -> &P256Spki {
        &self.sender_spki
    }
    pub fn receiver_key(&self) -> &P256Spki {
        &self.receiver_spki
    }
    pub fn offer_digest(&self) -> &[u8; 32] {
        &self.offer_digest
    }
    pub(crate) fn verifier(&self, token: &GuestRecoveryCredential) -> [u8; 32] {
        let input = self.verifier_input();
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()), &input);
        tag.as_ref()
            .try_into()
            .expect("HMAC-SHA256 verifier is 32 bytes")
    }

    fn verifier_input(&self) -> Vec<u8> {
        let mut input = Vec::with_capacity(32 + 32 + 91 + 91 + 32);
        input.extend_from_slice(b"OpenDrop/S1/GuestReceiptVerifier/v1\0");
        input.extend_from_slice(self.offer.id().as_str().as_bytes());
        input.extend_from_slice(self.sender_spki.as_der());
        input.extend_from_slice(self.receiver_spki.as_der());
        input.extend_from_slice(&self.offer_digest);
        input
    }

    pub(crate) fn verify_saved_verifier(
        &self,
        token: &GuestRecoveryCredential,
        stored: &[u8],
    ) -> bool {
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()),
            &self.verifier_input(),
            stored,
        )
        .is_ok()
    }
}

/// Local UI exact-offer approval. Private constructor; it must only be
/// produced by an audited native application-owned UI action after SAS
/// confirmation. No public boolean, remote message, or terminal constructor.
#[allow(dead_code)]
pub(crate) struct LocalGuestOfferConsent {
    session_hash: [u8; 32],
    offer_digest: [u8; 32],
}

impl LocalGuestOfferConsent {
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    pub(crate) fn from_audited_linux_qt_action(session: [u8; 32], offer: [u8; 32]) -> Self {
        Self {
            session_hash: session,
            offer_digest: offer,
        }
    }
}

/// Bilateral SAS verification is NOT sufficient to receive a file. This
/// capability exists only after an additional exact-offer local UI consent.
pub struct GuestAuthorizedTransfer {
    session: VerifiedGuestSession,
    scope: GuestRecoveryScope,
}

impl VerifiedGuestSession {
    #[allow(dead_code)]
    pub(crate) fn authorize_guest_offer_from_owner_ui(
        self,
        offered: GuestOfferV1,
        local_action: LocalGuestOfferConsent,
    ) -> Result<GuestAuthorizedTransfer, Error> {
        if !self.is_active()
            || self.local_transfer_side() != TransferSide::Receiver
            || self.logical_sender_spki() != offered.sender()
            || self.session_binding() != &local_action.session_hash
            || offered.canonical_digest() != local_action.offer_digest
        {
            return Err(Error::Unauthorized);
        }
        let scope = GuestRecoveryScope {
            sender_spki: self.logical_sender_public_key().clone(),
            receiver_spki: self.logical_receiver_public_key().clone(),
            offer_digest: offered.canonical_digest(),
            offer: offered,
        };
        Ok(GuestAuthorizedTransfer {
            session: self,
            scope,
        })
    }
}

impl GuestAuthorizedTransfer {
    pub fn exact_scope(&self) -> &GuestRecoveryScope {
        &self.scope
    }

    pub(crate) fn journal_offer(&self) -> &FileOffer {
        self.scope.offer.journal_offer()
    }

    pub(crate) fn session_binding(&self) -> &[u8; 32] {
        self.session.session_binding()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.session.is_active()
    }

    pub(crate) fn record_commit_intent(
        &self,
        journal: &mut Journal,
        destination_ref: &str,
    ) -> Result<(), Error> {
        if !self.session.is_active() {
            return Err(Error::Unauthorized);
        }
        journal.record_commit_intent(self.scope.offer.journal_offer(), destination_ref)
    }

    pub(crate) fn publish_with(
        &self,
        journal: &mut Journal,
        publisher: &mut impl crate::journal::DurablePublisher,
    ) -> Result<Receipt, Error> {
        if !self.session.is_active() {
            return Err(Error::Unauthorized);
        }
        journal.publish_with(self.scope.offer.journal_offer(), publisher)
    }

    /// Reuses S1-A's single reserve transaction. A successful return is
    /// required before native staging can begin. The second journal write
    /// stores ONLY a credential verifier and exact identity binding.
    pub fn reserve_with_recovery(
        &self,
        journal: &mut Journal,
        token: &GuestRecoveryCredential,
    ) -> Result<(), Error> {
        if !self.session.is_active() {
            return Err(Error::Unauthorized);
        }
        // Never accept a network/UI caller-supplied clock or expiry.
        let issued_ms = authoritative_local_now_millis()?;
        let recovery_millis = MAX_RECOVERY_MILLIS;
        if issued_ms < 0 || issued_ms.checked_add(recovery_millis).is_none() {
            return Err(Error::Invalid("guest recovery clock"));
        }
        journal.reserve(self.scope.offer.journal_offer())?;
        journal.register_guest_receipt_verifier(
            &self.scope,
            self.scope.verifier(token),
            issued_ms,
            issued_ms + recovery_millis,
        )
    }
}

/// Identity-scoped, read-only response. Not a new publication transaction
/// and not an authorization to reopen staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCommittedReceipt {
    pub transfer_id: TransferId,
    pub sender: GuestSpkiFingerprint,
    pub manifest: Sha256Digest,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}

impl GuestCommittedReceipt {
    pub(crate) fn from_checked_receipt(receipt: Receipt, sender: GuestSpkiFingerprint) -> Self {
        Self {
            transfer_id: receipt.transfer_id,
            sender,
            manifest: receipt.manifest,
            bytes: receipt.bytes,
            sha256: receipt.sha256,
        }
    }
}

impl Journal {
    /// No network caller can invoke this without a NEW exact-key TLS 1.3
    /// receipt-only peer with BOTH original identity keys, plus the 256-bit
    /// bearer secret. It returns only an existing committed receipt; no write
    /// to transfers, no promotion of CommitIntent, no automatic republish.
    pub fn query_guest_committed_receipt(
        &self,
        pinned_tls: &VerifiedReceiptOnlyTls,
        scope: &GuestRecoveryScope,
        token: &GuestRecoveryCredential,
    ) -> Result<Option<GuestCommittedReceipt>, Error> {
        if !pinned_tls.is_active()
            || pinned_tls.peer_public_key() != scope.sender_key()
            || pinned_tls.local_public_key() != scope.receiver_key()
        {
            return Err(Error::Unauthorized);
        }
        // Expiry is enforced by the receiver's own clock, never the sender's.
        let now_ms = authoritative_local_now_millis()?;
        self.read_guest_committed_receipt_exact(scope, token, now_ms)
            .map(|receipt| {
                receipt
                    .map(|r| GuestCommittedReceipt::from_checked_receipt(r, scope.offer.sender()))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{DurablePublisher, Phase, Published};

    // Synthetic exact-offer journal proof. It is NOT a physical native
    // publisher or a real TLS session; those are distinct acceptance gates.
    struct TestOnlyPublished;
    impl DurablePublisher for TestOnlyPublished {
        fn publish(&mut self, offer: &FileOffer, target: &str) -> Result<Published, Error> {
            Ok(Published {
                destination_ref: target.to_owned(),
                bytes: offer.bytes,
                sha256: offer.sha256.clone(),
            })
        }
        fn inspect_published(
            &mut self,
            offer: &FileOffer,
            target: &str,
        ) -> Result<Option<Published>, Error> {
            self.publish(offer, target).map(Some)
        }
    }

    fn test_spki(marker: u8) -> P256Spki {
        let mut der = [0u8; 91];
        der[..26].copy_from_slice(&[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]);
        der[26] = 4;
        der[27..].fill(marker);
        P256Spki::from_canonical_der(&der).unwrap()
    }

    fn test_scope() -> GuestRecoveryScope {
        let sender = test_spki(5);
        let receiver = test_spki(6);
        let offered = GuestOfferV1::new(
            TransferId::parse(&"a".repeat(32)).unwrap(),
            sender.fingerprint(),
            Sha256Digest::parse(&"b".repeat(64)).unwrap(),
            "guest.txt".to_owned(),
            17,
            Sha256Digest::parse(&"c".repeat(64)).unwrap(),
        )
        .unwrap();
        GuestRecoveryScope {
            offer_digest: offered.canonical_digest(),
            offer: offered,
            sender_spki: sender,
            receiver_spki: receiver,
        }
    }

    #[test]
    fn guest_offer_requires_the_exact_authenticated_sender_spki() {
        let scope = test_scope();
        let original = scope.offer.file_offer().clone();
        let exact = GuestOfferV1::from_verified_wire_offer(
            original.clone(),
            scope.sender_spki.fingerprint(),
        )
        .unwrap();
        assert_eq!(exact.file_offer(), &original);
        assert_eq!(exact.canonical_digest(), scope.offer_digest);
        assert!(GuestOfferV1::from_verified_wire_offer(
            original.clone(),
            test_spki(7).fingerprint(),
        )
        .is_err());
        let mut substituted = original.clone();
        substituted.sha256 = Sha256Digest::parse(&"d".repeat(64)).unwrap();
        let altered =
            GuestOfferV1::from_verified_wire_offer(substituted, scope.sender_spki.fingerprint())
                .unwrap();
        assert_ne!(altered.canonical_digest(), scope.offer_digest);

        let mut malformed = original;
        malformed.name = "../overwrite".to_string();
        assert!(
            GuestOfferV1::from_verified_wire_offer(malformed, scope.sender_spki.fingerprint(),)
                .is_err()
        );
    }

    #[test]
    fn targeted_receipt_recovery_is_read_only_exact_key_and_expires() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("targeted-recovery.sqlite")).unwrap();
        let scope = test_scope();
        let credential = GuestRecoveryCredential::generate().unwrap();
        let now = authoritative_local_now_millis().unwrap();
        journal.reserve(scope.offer.journal_offer()).unwrap();
        journal
            .register_guest_receipt_verifier(
                &scope,
                scope.verifier(&credential),
                now,
                now + MAX_RECOVERY_MILLIS,
            )
            .unwrap();
        let looked_up = journal
            .guest_recovery_scope_for_targeted_tls(
                scope.exact_transfer_id(),
                scope.sender_key(),
                scope.receiver_key(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(looked_up.offer_digest(), scope.offer_digest());
        assert!(journal
            .guest_recovery_scope_for_targeted_tls(
                scope.exact_transfer_id(),
                &test_spki(7),
                scope.receiver_key(),
            )
            .unwrap()
            .is_none());
        assert!(journal
            .guest_recovery_scope_for_targeted_tls(
                scope.exact_transfer_id(),
                scope.sender_key(),
                &test_spki(8),
            )
            .unwrap()
            .is_none());
        assert!(journal
            .read_guest_committed_receipt_exact(&looked_up, &credential, now)
            .unwrap()
            .is_none());
        journal
            .record_commit_intent(scope.offer.journal_offer(), "guest.txt")
            .unwrap();
        assert!(journal
            .read_guest_committed_receipt_exact(&looked_up, &credential, now)
            .unwrap()
            .is_none());
        journal
            .publish_with(scope.offer.journal_offer(), &mut TestOnlyPublished)
            .unwrap();
        let committed = journal
            .read_guest_committed_receipt_exact(&looked_up, &credential, now)
            .unwrap()
            .unwrap();
        assert_eq!(committed.transfer_id, scope.exact_transfer_id().clone());
        assert_eq!(
            journal
                .lookup(scope.offer.journal_offer())
                .unwrap()
                .unwrap()
                .phase,
            Phase::Committed
        );

        let expired = tempfile::tempdir().unwrap();
        let mut old = Journal::open(&expired.path().join("expired.sqlite")).unwrap();
        old.reserve(scope.offer.journal_offer()).unwrap();
        old.register_guest_receipt_verifier(
            &scope,
            scope.verifier(&credential),
            now - MAX_RECOVERY_MILLIS - 10,
            now - 10,
        )
        .unwrap();
        assert!(old
            .guest_recovery_scope_for_targeted_tls(
                scope.exact_transfer_id(),
                scope.sender_key(),
                scope.receiver_key(),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn bearer_credential_is_random_nonzero_and_never_prints_secret_bytes() {
        let first = GuestRecoveryCredential::generate().unwrap();
        let second = GuestRecoveryCredential::generate().unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        assert!(first.as_bytes().iter().any(|byte| *byte != 0));
        assert_eq!(format!("{first:?}"), "GuestRecoveryCredential([REDACTED])");
        assert!(GuestRecoveryCredential::from_transmitted_bytes([0; 32]).is_err());
    }

    #[test]
    fn guest_verifier_survives_restart_but_only_committed_exact_offer_is_visible() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("guest-receipt.sqlite");
        let scope = test_scope();
        let secret = GuestRecoveryCredential::generate().unwrap();
        let issued = 100_000i64;
        {
            let mut journal = Journal::open(&db).unwrap();
            journal.reserve(scope.offer.journal_offer()).unwrap();
            journal
                .register_guest_receipt_verifier(
                    &scope,
                    scope.verifier(&secret),
                    issued,
                    issued + MAX_RECOVERY_MILLIS,
                )
                .unwrap();
            assert!(journal
                .read_guest_committed_receipt_exact(&scope, &secret, issued + 1,)
                .unwrap()
                .is_none());
            journal
                .record_commit_intent(scope.offer.journal_offer(), "guest.txt")
                .unwrap();
            assert!(journal
                .read_guest_committed_receipt_exact(&scope, &secret, issued + 1,)
                .unwrap()
                .is_none());
            journal
                .publish_with(scope.offer.journal_offer(), &mut TestOnlyPublished)
                .unwrap();
        }
        let restarted = Journal::open(&db).unwrap();
        let reloaded = restarted
            .load_guest_recovery_scope(scope.exact_transfer_id())
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.offer_digest(), scope.offer_digest());
        let result = restarted
            .read_guest_committed_receipt_exact(&reloaded, &secret, issued + 1)
            .unwrap()
            .unwrap();
        assert_eq!(result.transfer_id, scope.offer.transfer.id);
        assert_eq!(result.bytes, 17);
        assert_eq!(
            result.peer.as_str(),
            scope.sender_spki.fingerprint().to_hex()
        );
        assert_eq!(
            restarted
                .lookup(scope.offer.journal_offer())
                .unwrap()
                .unwrap()
                .phase,
            Phase::Committed
        );
    }

    #[test]
    fn token_expiry_key_substitution_offer_substitution_and_reissue_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&root.path().join("negative.sqlite")).unwrap();
        let scope = test_scope();
        let good = GuestRecoveryCredential::generate().unwrap();
        let wrong = GuestRecoveryCredential::generate().unwrap();
        journal.reserve(scope.offer.journal_offer()).unwrap();
        journal
            .register_guest_receipt_verifier(
                &scope,
                scope.verifier(&good),
                500,
                501 + MAX_RECOVERY_MILLIS - 1,
            )
            .unwrap();
        assert!(journal
            .register_guest_receipt_verifier(
                &scope,
                scope.verifier(&wrong),
                500,
                500 + MAX_RECOVERY_MILLIS,
            )
            .is_err());
        assert!(journal
            .read_guest_committed_receipt_exact(&scope, &wrong, 501)
            .is_err());
        assert!(journal
            .read_guest_committed_receipt_exact(&scope, &good, 499)
            .is_err());
        assert!(journal
            .read_guest_committed_receipt_exact(&scope, &good, 500 + MAX_RECOVERY_MILLIS,)
            .is_err());
        let mut swapped = test_scope();
        swapped.receiver_spki = test_spki(9);
        assert!(journal
            .read_guest_committed_receipt_exact(&swapped, &good, 501)
            .is_err());
        let mut altered = test_scope();
        altered.offer.transfer.bytes += 1;
        altered.offer_digest = altered.offer.canonical_digest();
        assert!(journal
            .read_guest_committed_receipt_exact(&altered, &good, 501)
            .is_err());
    }
}
