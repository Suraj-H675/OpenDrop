//! Narrow receiving-authorization boundary; NOT a new wire protocol.
//!
//! Trust comes from the authenticated rustls TLS 1.3 peer certificate, not
//! multicast claims, caller-supplied fingerprints, or UI-supplied booleans.
//! LocalConsentBroker is strictly test-only. The real native GUI approval
//! issuer does not yet exist and must remain private to this security module;
//! neither a terminal nor network/public IPC is an acceptable fallback.

use crate::identity::{DeviceId, KeyFingerprint};
use crate::journal::{DurablePublisher, FileOffer, Journal, Receipt, Snapshot};
use crate::policy::ReceiveDecision;
use crate::Error;
use rustls::server::ServerConnection;
use rustls::ProtocolVersion;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-OpenDrop-P1A-OfferAuthorization";

/// Opaque proof produced ONLY from a completed TLS 1.3 server connection
/// authenticating a client certificate. The TLS configuration MUST require
/// actual client-certificate verification (rustls WebPkiClientVerifier or an
/// equivalently reviewed verifier), never `NoClientAuth` or accept-all.
/// DeviceId is an untrusted identity *claim* until checked against the journal.
pub struct AuthenticatedSession {
    device_id: DeviceId,
    fingerprint: KeyFingerprint,
    exporter: [u8; 32],
}

impl AuthenticatedSession {
    pub fn from_verified_tls_server(
        tls: &ServerConnection,
        claimed_device: DeviceId,
    ) -> Result<Self, Error> {
        if tls.is_handshaking() || tls.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            return Err(Error::Unauthorized);
        }
        let certificates = tls.peer_certificates().ok_or(Error::Unauthorized)?;
        let leaf = certificates.first().ok_or(Error::Unauthorized)?;
        let fingerprint = KeyFingerprint::parse(&format!("{:x}", Sha256::digest(leaf.as_ref())))?;
        let mut exporter = [0u8; 32];
        tls.export_keying_material(&mut exporter, EXPORTER_LABEL, None)
            .map_err(|_| Error::Unauthorized)?;
        Ok(Self {
            device_id: claimed_device,
            fingerprint,
            exporter,
        })
    }

    pub fn peer_fingerprint(&self) -> &KeyFingerprint {
        &self.fingerprint
    }

    /// The only peer-facing lost-ACK receipt query. The caller must already
    /// own a completed, certificate-authenticated TLS session; knowing a
    /// transfer ID or guessed hash alone is insufficient. No destination
    /// reference or uncommitted state is disclosed. Guest receipts remain
    /// queryable after Everyone expires, but revoked peers are always denied.
    pub fn committed_receipt_for_offer(
        &self,
        journal: &Journal,
        offer: &FileOffer,
    ) -> Result<Option<Receipt>, Error> {
        offer.validate()?;
        if self.fingerprint != offer.peer
            || journal.peer_revoked_or_key_changed(&self.device_id, &self.fingerprint)?
        {
            return Err(Error::Unauthorized);
        }
        Ok(journal.lookup(offer)?.and_then(|snapshot| snapshot.receipt))
    }
}

/// No public fields and no deserialization, so a network message cannot be
/// turned directly into a local approval. It is explicitly offer-scoped.
pub struct ConsentPrompt {
    offer: FileOffer,
    // Preserved for the later audited native UI bridge. Until that bridge is
    // approved, only the cfg(test) consent broker may read this secret tag.
    #[allow(dead_code)]
    session: [u8; 32],
    device: DeviceId,
}

impl ConsentPrompt {
    /// The UI should display these *untrusted* metadata until the user chooses.
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }
    pub fn claimed_device(&self) -> &DeviceId {
        &self.device
    }
}

/// Production Linux consent has no public issuer. The reviewed in-process Qt
/// bridge must privately bind the exact session/offer/destination. A terminal,
/// ordinary IPC, bool or raw token is not an acceptable approval source.
///
/// A public terminal issuer must remain unresolvable:
/// ```compile_fail
/// use opendrop_core::authorization::confirm_linux_foreground_owner;
/// ```
pub struct ConsentTicket {
    offer: FileOffer,
    session: [u8; 32],
    device: DeviceId,
}

/// Test-only model of the future privileged local-UI consent broker. Until a
/// real native approval event is wired, production code CANNOT mint a manual
/// consent ticket; this intentionally fails closed rather than accepting a
/// network-supplied boolean as user approval.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct LocalConsentBroker {
    consumed: HashSet<[u8; 32]>,
}

#[cfg(test)]
impl LocalConsentBroker {
    /// The native UI event handler calls this ONLY after a genuine user action.
    /// There is no bool-based network API or automatic guest grant here.
    pub(crate) fn approve_from_local_user_action(
        &mut self,
        prompt: ConsentPrompt,
    ) -> Result<ConsentTicket, Error> {
        let binding = consent_binding(&prompt.session, &prompt.device, &prompt.offer);
        if !self.consumed.insert(binding) {
            return Err(Error::Unauthorized);
        }
        Ok(ConsentTicket {
            offer: prompt.offer,
            session: prompt.session,
            device: prompt.device,
        })
    }
}

/// A receipt of local authorization for one session and one exact offer, not
/// a reusable peer credential. Do not serialize, clone or expose to IPC.
pub struct AuthorizedOffer {
    offer: FileOffer,
    session: [u8; 32],
    device: DeviceId,
    explicit_consent: bool,
}
impl AuthorizedOffer {
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }
    pub fn reserve(
        &self,
        journal: &mut Journal,
        session: &AuthenticatedSession,
    ) -> Result<Snapshot, Error> {
        self.require_current_authorization(journal, session)?;
        journal.reserve(&self.offer)
    }

    pub fn record_commit_intent(
        &self,
        journal: &mut Journal,
        session: &AuthenticatedSession,
        destination_ref: &str,
    ) -> Result<(), Error> {
        self.require_current_authorization(journal, session)?;
        journal.record_commit_intent(&self.offer, destination_ref)
    }

    pub fn publish_with(
        &self,
        journal: &mut Journal,
        session: &AuthenticatedSession,
        publisher: &mut impl DurablePublisher,
    ) -> Result<Receipt, Error> {
        self.require_current_authorization(journal, session)?;
        journal.publish_with(&self.offer, publisher)
    }

    fn require_current_authorization(
        &self,
        journal: &Journal,
        session: &AuthenticatedSession,
    ) -> Result<(), Error> {
        // Recheck before EVERY state-changing operation, not just reserve.
        // Native data-plane cancellation and in-flight revocation are not yet
        // implemented; this only gates the transaction API boundary.
        if self.session != session.exporter
            || self.device != session.device_id
            || self.offer.peer != session.fingerprint
        {
            return Err(Error::Unauthorized);
        }
        let now_ms = now_millis()?;
        let current = journal.authorize_receive(
            &session.device_id,
            &session.fingerprint,
            journal.visibility()?,
            now_ms,
            false,
        )?;
        let permitted = if self.explicit_consent {
            matches!(
                current,
                ReceiveDecision::RequireGuestConsent | ReceiveDecision::RequireTrustedConsent
            )
        } else {
            current == ReceiveDecision::AllowAutoAcceptedTrusted
        };
        if !permitted {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

pub enum OfferDecision {
    Denied,
    NeedsLocalConsent(ConsentPrompt),
    AutoAccepted(AuthorizedOffer),
}

#[cfg(test)]
fn consent_binding(session: &[u8; 32], device: &DeviceId, offer: &FileOffer) -> [u8; 32] {
    let mut hash = Sha256::new();
    for component in [
        &session[..],
        device.as_str().as_bytes(),
        offer.id.as_str().as_bytes(),
        offer.peer.as_str().as_bytes(),
        offer.manifest.as_str().as_bytes(),
        offer.name.as_bytes(),
        &offer.bytes.to_be_bytes(),
        offer.sha256.as_str().as_bytes(),
    ] {
        hash.update((component.len() as u64).to_be_bytes());
        hash.update(component);
    }
    hash.finalize().into()
}

fn check_at(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
    now_ms: i64,
) -> Result<OfferDecision, Error> {
    offer.validate()?;
    if offer.peer != session.fingerprint {
        return Ok(OfferDecision::Denied);
    }
    let mode = journal.visibility()?;
    Ok(
        match journal.authorize_receive(
            &session.device_id,
            &session.fingerprint,
            mode,
            now_ms,
            false,
        )? {
            ReceiveDecision::AllowAutoAcceptedTrusted => {
                OfferDecision::AutoAccepted(AuthorizedOffer {
                    offer: offer.clone(),
                    session: session.exporter,
                    device: session.device_id.clone(),
                    explicit_consent: false,
                })
            }
            ReceiveDecision::RequireGuestConsent | ReceiveDecision::RequireTrustedConsent => {
                OfferDecision::NeedsLocalConsent(ConsentPrompt {
                    offer: offer.clone(),
                    session: session.exporter,
                    device: session.device_id.clone(),
                })
            }
            _ => OfferDecision::Denied,
        },
    )
}

fn now_millis() -> Result<i64, Error> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unauthorized)?;
    i64::try_from(value.as_millis()).map_err(|_| Error::Unauthorized)
}

pub fn review_incoming(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
) -> Result<OfferDecision, Error> {
    check_at(journal, session, offer, now_millis()?)
}

pub fn authorize_local_consent(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
    ticket: ConsentTicket,
) -> Result<AuthorizedOffer, Error> {
    authorize_local_consent_at(journal, session, offer, ticket, now_millis()?)
}

fn authorize_local_consent_at(
    journal: &Journal,
    session: &AuthenticatedSession,
    offer: &FileOffer,
    ticket: ConsentTicket,
    now_ms: i64,
) -> Result<AuthorizedOffer, Error> {
    if ticket.session != session.exporter
        || ticket.device != session.device_id
        || ticket.offer != *offer
        || offer.peer != session.fingerprint
    {
        return Err(Error::Unauthorized);
    }
    let visibility = journal.visibility()?;
    match journal.authorize_receive(
        &session.device_id,
        &session.fingerprint,
        visibility,
        now_ms,
        false,
    )? {
        ReceiveDecision::RequireGuestConsent | ReceiveDecision::RequireTrustedConsent => {
            Ok(AuthorizedOffer {
                offer: offer.clone(),
                session: session.exporter,
                device: session.device_id.clone(),
                explicit_consent: true,
            })
        }
        _ => Err(Error::Unauthorized),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::identity::{Sha256Digest, TransferId};
    use crate::policy::Visibility;
    use rustls::client::ClientConnection;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use std::io::Cursor;
    use std::process::Command;
    use std::sync::Arc;

    struct Pair {
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
        client_cert: CertificateDer<'static>,
    }

    // Exercise real cryptographic TLS 1.3 mutual certificate authentication,
    // not fake peer IDs or test-only Session constructors. All keys are
    // generated ephemerally in the test directory using the existing OpenSSL.
    fn make_certificate(
        dir: &std::path::Path,
        name: &str,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let cert_pem = dir.join(format!("{name}.crt"));
        let key_pem = dir.join(format!("{name}.private"));
        let cert_der = dir.join(format!("{name}.cert.der"));
        let key_der = dir.join(format!("{name}.key.der"));
        let result = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-days",
                "1",
                "-subj",
                "/CN=OpenDrop-ephemeral-test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth,clientAuth",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                key_pem.to_str().unwrap(),
                "-out",
                cert_pem.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "ephemeral test certificate generation failed"
        );
        assert!(Command::new("openssl")
            .args([
                "x509",
                "-in",
                cert_pem.to_str().unwrap(),
                "-outform",
                "DER",
                "-out",
                cert_der.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success());
        assert!(Command::new("openssl")
            .args([
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                key_pem.to_str().unwrap(),
                "-outform",
                "DER",
                "-out",
                key_der.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success());
        (
            CertificateDer::from(std::fs::read(cert_der).unwrap()),
            PrivatePkcs8KeyDer::from(std::fs::read(key_der).unwrap()).into(),
        )
    }

    fn pair() -> Pair {
        let dir = tempfile::tempdir().unwrap();
        let (server_cert, server_key) = make_certificate(dir.path(), "server");
        let (client_cert, client_key) = make_certificate(dir.path(), "client");
        let mut server_roots = RootCertStore::empty();
        server_roots.add(server_cert.clone()).unwrap();
        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_cert.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let server = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(server_roots)
            .with_client_auth_cert(vec![client_cert.clone()], client_key)
            .unwrap();
        Pair {
            server: Arc::new(server),
            client: Arc::new(client),
            client_cert,
        }
    }

    fn handshake(pair: &Pair) -> ServerConnection {
        let mut server = ServerConnection::new(pair.server.clone()).unwrap();
        let mut client = ClientConnection::new(
            pair.client.clone(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        for _ in 0..16 {
            if client.wants_write() {
                let mut bytes = Vec::new();
                client.write_tls(&mut bytes).unwrap();
                server.read_tls(&mut Cursor::new(bytes)).unwrap();
                server.process_new_packets().unwrap();
            }
            if server.wants_write() {
                let mut bytes = Vec::new();
                server.write_tls(&mut bytes).unwrap();
                client.read_tls(&mut Cursor::new(bytes)).unwrap();
                client.process_new_packets().unwrap();
            }
            if !server.is_handshaking() && !client.is_handshaking() {
                return server;
            }
        }
        panic!("real mutual TLS handshake failed to complete");
    }

    fn device() -> DeviceId {
        DeviceId::parse(&"1".repeat(32)).unwrap()
    }
    fn offer(session: &AuthenticatedSession) -> FileOffer {
        FileOffer {
            id: TransferId::parse(&"2".repeat(32)).unwrap(),
            peer: session.peer_fingerprint().clone(),
            manifest: Sha256Digest::parse(&"3".repeat(64)).unwrap(),
            name: "photo.jpg".into(),
            bytes: 4,
            sha256: Sha256Digest::parse(&"4".repeat(64)).unwrap(),
        }
    }
    fn guest_visible(journal: &mut Journal) {
        journal
            .set_visibility(
                Visibility::default()
                    .everyone(now_millis().unwrap())
                    .unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn real_tls13_mutual_authentication_required_and_fingerprint_is_certificate_derived() {
        let pair = pair();
        let unhandshaken = ServerConnection::new(pair.server.clone()).unwrap();
        assert!(AuthenticatedSession::from_verified_tls_server(&unhandshaken, device()).is_err());
        let verified =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        assert_eq!(
            verified.peer_fingerprint().as_str(),
            format!("{:x}", Sha256::digest(pair.client_cert.as_ref()))
        );
    }

    #[test]
    fn server_rejects_an_untrusted_client_certificate_at_real_tls_handshake() {
        let trusted = pair();
        let unrelated = pair();
        // Same TLS version and valid signatures, but a different root/private
        // key. A claimed DeviceId or certificate string cannot override it.
        let wrong = Pair {
            server: trusted.server,
            client: unrelated.client,
            client_cert: unrelated.client_cert,
        };
        let attempted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handshake(&wrong)));
        assert!(
            attempted.is_err(),
            "unexpectedly accepted a different client certificate"
        );
    }

    #[test]
    fn wrong_peer_identity_or_unapproved_guest_is_denied() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let db = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&db.path().join("auth.sqlite")).unwrap();
        let correct = offer(&session);
        assert!(matches!(
            review_incoming(&journal, &session, &correct).unwrap(),
            OfferDecision::Denied
        ));
        guest_visible(&mut journal);
        let mut claimed = correct.clone();
        claimed.peer = KeyFingerprint::parse(&"e".repeat(64)).unwrap();
        assert!(matches!(
            review_incoming(&journal, &session, &claimed).unwrap(),
            OfferDecision::Denied
        ));
        assert!(matches!(
            review_incoming(&journal, &session, &correct).unwrap(),
            OfferDecision::NeedsLocalConsent(_)
        ));
        // No public constructor or deserializer creates ConsentTicket from
        // user-controlled ID, fingerprint, offer, or boolean.
    }

    #[test]
    fn consent_is_exact_offer_bound_one_use_and_session_replay_fails() {
        let pair = pair();
        let first =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let second =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        assert_ne!(first.exporter, second.exporter);
        let db = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&db.path().join("auth.sqlite")).unwrap();
        guest_visible(&mut journal);
        let offered = offer(&first);
        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &first, &offered).unwrap()
        else {
            panic!("expected owner prompt")
        };
        let mut broker = LocalConsentBroker::default();
        let ticket = broker.approve_from_local_user_action(prompt).unwrap();
        let mut altered = offered.clone();
        altered.name = "different.txt".into();
        assert!(matches!(
            authorize_local_consent(&journal, &first, &altered, ticket),
            Err(Error::Unauthorized)
        ));

        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &first, &offered).unwrap()
        else {
            panic!("expected prompt")
        };
        assert!(broker.approve_from_local_user_action(prompt).is_err()); // consumed approval
        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &second, &offered).unwrap()
        else {
            panic!("expected prompt")
        };
        let ticket = broker.approve_from_local_user_action(prompt).unwrap();
        assert!(authorize_local_consent(&journal, &first, &offered, ticket).is_err());
        // cross-session
    }

    #[test]
    fn verified_peer_autoaccept_defaults_off_revocation_blocks_and_guest_is_isolated() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let db = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&db.path().join("trust.sqlite")).unwrap();
        let offered = offer(&session);
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        let OfferDecision::NeedsLocalConsent(prompt) =
            review_incoming(&journal, &session, &offered).unwrap()
        else {
            panic!("default autoaccept must be off")
        };
        let ticket = LocalConsentBroker::default()
            .approve_from_local_user_action(prompt)
            .unwrap();
        journal.revoke_device(&device()).unwrap();
        assert!(authorize_local_consent(&journal, &session, &offered, ticket).is_err());
        guest_visible(&mut journal);
        assert!(matches!(
            review_incoming(&journal, &session, &offered).unwrap(),
            OfferDecision::Denied
        ));
    }

    #[test]
    fn opt_in_autoaccept_is_session_scoped_and_revocation_invalidates_prior_grant() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("trust.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        journal.set_auto_accept(&device(), true).unwrap();
        let offered = offer(&session);
        let OfferDecision::AutoAccepted(granted) =
            review_incoming(&journal, &session, &offered).unwrap()
        else {
            panic!("verified per-device opt-in should permit autoaccept");
        };
        journal.revoke_device(&device()).unwrap();
        assert!(matches!(
            granted.reserve(&mut journal, &session),
            Err(Error::Unauthorized)
        ));
        assert!(journal.lookup(&offered).unwrap().is_none());
    }

    struct UncalledPublisher;
    impl DurablePublisher for UncalledPublisher {
        fn publish(&mut self, _: &FileOffer, _: &str) -> Result<crate::journal::Published, Error> {
            panic!("revoked or mismatched capability must not invoke publisher")
        }
        fn inspect_published(
            &mut self,
            _: &FileOffer,
            _: &str,
        ) -> Result<Option<crate::journal::Published>, Error> {
            panic!("unauthorized receipt path must not inspect destination")
        }
    }

    #[test]
    fn revoked_capability_cannot_commit_or_publish_even_after_reservation() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("trust.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        journal.set_auto_accept(&device(), true).unwrap();
        let offered = offer(&session);
        let OfferDecision::AutoAccepted(granted) =
            review_incoming(&journal, &session, &offered).unwrap()
        else {
            panic!("opt-in trusted peer must have capability")
        };
        granted.reserve(&mut journal, &session).unwrap();
        granted
            .record_commit_intent(&mut journal, &session, "private-local-destination")
            .unwrap();
        journal.revoke_device(&device()).unwrap();
        assert!(matches!(
            granted.record_commit_intent(&mut journal, &session, "private-local-destination"),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            granted.publish_with(&mut journal, &session, &mut UncalledPublisher),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            session.committed_receipt_for_offer(&journal, &offered),
            Err(Error::Unauthorized)
        ));
        assert_eq!(
            journal.lookup(&offered).unwrap().unwrap().phase,
            crate::journal::Phase::CommitIntent
        );
    }

    #[test]
    fn transfer_capability_does_not_work_in_a_different_tls_session() {
        let pair = pair();
        let first =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let second =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("trust.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), first.peer_fingerprint())
            .unwrap();
        journal.set_auto_accept(&device(), true).unwrap();
        let offered = offer(&first);
        let OfferDecision::AutoAccepted(granted) =
            review_incoming(&journal, &first, &offered).unwrap()
        else {
            panic!("expected autoaccept")
        };
        assert!(matches!(
            granted.reserve(&mut journal, &second),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            granted.record_commit_intent(&mut journal, &second, "destination"),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            granted.publish_with(&mut journal, &second, &mut UncalledPublisher),
            Err(Error::Unauthorized)
        ));
        assert!(journal.lookup(&offered).unwrap().is_none());
    }

    #[test]
    fn another_authenticated_peer_cannot_query_committed_receipt_by_transfer_id() {
        let first_pair = pair();
        let second_pair = pair();
        let first =
            AuthenticatedSession::from_verified_tls_server(&handshake(&first_pair), device())
                .unwrap();
        let other =
            AuthenticatedSession::from_verified_tls_server(&handshake(&second_pair), device())
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("receipt.sqlite")).unwrap();
        let offered = offer(&first);
        // Private deterministic recovery fixture seeds a receipt; this is NOT
        // a network-facing API and no actual OS publisher is claimed here.
        journal.reserve(&offered).unwrap();
        journal
            .record_commit_intent(&offered, "local-destination")
            .unwrap();
        struct VerifiedFixture;
        impl DurablePublisher for VerifiedFixture {
            fn publish(
                &mut self,
                o: &FileOffer,
                dest: &str,
            ) -> Result<crate::journal::Published, Error> {
                Ok(crate::journal::Published {
                    destination_ref: dest.into(),
                    bytes: o.bytes,
                    sha256: o.sha256.clone(),
                })
            }
            fn inspect_published(
                &mut self,
                o: &FileOffer,
                dest: &str,
            ) -> Result<Option<crate::journal::Published>, Error> {
                self.publish(o, dest).map(Some)
            }
        }
        journal
            .publish_with(&offered, &mut VerifiedFixture)
            .unwrap();
        assert!(first
            .committed_receipt_for_offer(&journal, &offered)
            .unwrap()
            .is_some());
        assert!(matches!(
            other.committed_receipt_for_offer(&journal, &offered),
            Err(Error::Unauthorized)
        ));
        let mut forged = offered.clone();
        forged.peer = other.peer_fingerprint().clone();
        assert!(matches!(
            other.committed_receipt_for_offer(&journal, &forged),
            Err(Error::DuplicateIdConflict)
        ));
    }

    #[test]
    fn revoked_cert_cannot_become_guest_by_changing_claimed_device_id() {
        let pair = pair();
        let session =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), device()).unwrap();
        let rotated_id = DeviceId::parse(&"f".repeat(32)).unwrap();
        let impersonator =
            AuthenticatedSession::from_verified_tls_server(&handshake(&pair), rotated_id).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("revocation.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), session.peer_fingerprint())
            .unwrap();
        journal.revoke_device(&device()).unwrap();
        guest_visible(&mut journal);
        assert!(matches!(
            review_incoming(&journal, &impersonator, &offer(&impersonator)).unwrap(),
            OfferDecision::Denied
        ));
    }

    #[test]
    fn same_device_id_with_different_certificate_is_not_silent_rotation() {
        let original = pair();
        let replacement = pair();
        let trusted =
            AuthenticatedSession::from_verified_tls_server(&handshake(&original), device())
                .unwrap();
        let changed =
            AuthenticatedSession::from_verified_tls_server(&handshake(&replacement), device())
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&dir.path().join("rotation.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), trusted.peer_fingerprint())
            .unwrap();
        guest_visible(&mut journal);
        assert!(matches!(
            review_incoming(&journal, &changed, &offer(&changed)).unwrap(),
            OfferDecision::Denied
        ));
        // This tests changed certificate and key. Same-key renewal is a
        // separate case below; both require re-verification in current policy.
    }

    #[test]
    fn renewing_certificate_with_the_same_public_key_requires_reverification() {
        let dir = tempfile::tempdir().unwrap();
        let (original, _) = make_certificate(dir.path(), "original");
        let key = dir.path().join("original.private");
        let renewed = dir.path().join("renewed.crt");
        let creation = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-key",
                key.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=OpenDrop-renewed-certificate",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth,clientAuth",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-out",
                renewed.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(creation.status.success());
        let old_pub = Command::new("openssl")
            .args([
                "x509",
                "-in",
                dir.path().join("original.crt").to_str().unwrap(),
                "-pubkey",
                "-noout",
            ])
            .output()
            .unwrap();
        let new_pub = Command::new("openssl")
            .args([
                "x509",
                "-in",
                renewed.to_str().unwrap(),
                "-pubkey",
                "-noout",
            ])
            .output()
            .unwrap();
        assert!(old_pub.status.success() && new_pub.status.success());
        assert_eq!(
            old_pub.stdout, new_pub.stdout,
            "must hold public key constant"
        );
        let der = Command::new("openssl")
            .args(["x509", "-in", renewed.to_str().unwrap(), "-outform", "DER"])
            .output()
            .unwrap();
        assert!(der.status.success());
        let old_fingerprint =
            KeyFingerprint::parse(&format!("{:x}", Sha256::digest(original.as_ref()))).unwrap();
        let renewed_fingerprint =
            KeyFingerprint::parse(&format!("{:x}", Sha256::digest(&der.stdout))).unwrap();
        assert_ne!(old_fingerprint, renewed_fingerprint);
        let mut journal = Journal::open(&dir.path().join("rotation.sqlite")).unwrap();
        journal
            .record_cryptographically_verified_peer(&device(), &old_fingerprint)
            .unwrap();
        guest_visible(&mut journal);
        assert_eq!(
            journal
                .authorize_receive(
                    &device(),
                    &renewed_fingerprint,
                    journal.visibility().unwrap(),
                    now_millis().unwrap(),
                    true
                )
                .unwrap(),
            ReceiveDecision::Deny,
        );
    }
}
