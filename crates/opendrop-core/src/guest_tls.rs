//! Strict, provisional raw-public-key TLS 1.3 pairing for *both* connection
//! roles. No CA shortcut, accept-all verifier, TLS 1.2, resumption, 0-RTT or
//! persistent peer enrollment. Exact key pins come from a bounded UNTRUSTED
//! introduction and only become human-verified after the SAS ceremony.
//!
//! Platform P-256 signers never export private key material. TLS signatures
//! are DER ECDSA-SHA256 signatures over the rustls-provided TLS message.
//! Android Keystore, Windows CNG and Linux OS providers are NOT implemented
//! here; the shared signer contract compiles portably and fails closed without
//! one of those reviewed native adapters.

use crate::guest::{
    GuestAdmissionPermit, GuestHello, GuestSpkiFingerprint, GuestTranscript, P256Spki, TlsSide,
    TransferSide, GUEST_ALPN, PAIRING_DEADLINE,
};
use crate::identity::DeviceId;
use crate::Error;
use ring::hmac;
use ring::signature::{self, UnparsedPublicKey};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    client, server, CertificateError, CipherSuite, ClientConfig, ClientConnection,
    DigitallySignedStruct, HandshakeKind, NamedGroup, ProtocolVersion, ServerConfig,
    ServerConnection, SignatureAlgorithm, SignatureScheme,
};
use rustls::{crypto::verify_tls13_signature_with_raw_key, crypto::CryptoProvider};
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const SAS_EXPORTER: &[u8] = b"EXPORTER-OpenDrop-S1-SAS-v1";
const CONFIRM_EXPORTER: &[u8] = b"EXPORTER-OpenDrop-S1-Confirm-v1";
const SESSION_EXPORTER: &[u8] = b"EXPORTER-OpenDrop-S1-SessionBinding-v1";
const CONFIRM_MAGIC: &[u8; 4] = b"ODGC";
pub const CONFIRM_LEN: usize = 38;
const SAS_MODULUS: u64 = 10_000_000_000;

/// Platform-specific trusted signing port; the key stays in the OS provider.
/// The platform must return *canonical* P-256 SPKI and DER ECDSA-SHA256.
/// No software/private-file fallback is constructed by this trait.
pub trait NativeP256Signer: fmt::Debug + Send + Sync {
    fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error>;
    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Installation-specific local identity. Never stores or exports a secret key.
pub struct LocalGuestIdentity {
    device: DeviceId,
    public: P256Spki,
    signer: Arc<dyn NativeP256Signer>,
}

impl LocalGuestIdentity {
    pub fn from_platform_signer(
        device: DeviceId,
        signer: Arc<dyn NativeP256Signer>,
    ) -> Result<Self, Error> {
        let public = P256Spki::from_canonical_der(&signer.canonical_public_spki_der()?)?;
        let challenge = b"OpenDrop/S1/P256/LocalSigningKeyProof/v1";
        let proof = signer.sign_ecdsa_p256_sha256_der(challenge)?;
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &public.as_der()[26..])
            .verify(challenge, &proof)
            .map_err(|_| Error::Unauthorized)?;
        Ok(Self {
            device,
            public,
            signer,
        })
    }

    pub fn public_key(&self) -> &P256Spki {
        &self.public
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device
    }

    pub fn new_hello(
        &self,
        tls_side: TlsSide,
        transfer_side: TransferSide,
    ) -> Result<GuestHello, Error> {
        GuestHello::new_local(
            self.device.clone(),
            self.public.clone(),
            tls_side,
            transfer_side,
        )
    }

    fn certified_raw_public_key(&self) -> Arc<CertifiedKey> {
        let signer = P256RustlsKey {
            signer: self.signer.clone(),
            spki: self.public.clone(),
        };
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(self.public.as_der().to_vec())],
            Arc::new(signer),
        ))
    }
}

#[derive(Debug)]
struct P256RustlsKey {
    signer: Arc<dyn NativeP256Signer>,
    spki: P256Spki,
}

impl SigningKey for P256RustlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(P256RustlsSigner {
                    signer: self.signer.clone(),
                    spki: self.spki.clone(),
                }) as Box<dyn Signer>
            })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_der()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct P256RustlsSigner {
    signer: Arc<dyn NativeP256Signer>,
    spki: P256Spki,
}

impl Signer for P256RustlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = self
            .signer
            .sign_ecdsa_p256_sha256_der(message)
            .map_err(|_| rustls::Error::General("native P-256 signer unavailable".into()))?;
        // An accidentally mismatched platform signer cannot make an
        // arbitrary TLS signature or identity claim succeed.
        UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &self.spki.as_der()[26..],
        )
        .verify(message, &signature)
        .map_err(|_| rustls::Error::General("native P-256 signature/key mismatch".into()))?;
        Ok(signature)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

struct ExactGuestServerVerifier {
    peer: P256Spki,
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}
struct ExactGuestClientVerifier {
    peer: P256Spki,
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl fmt::Debug for ExactGuestServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactGuestServerVerifier")
            .field("peer", &self.peer.fingerprint())
            .finish()
    }
}
impl fmt::Debug for ExactGuestClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactGuestClientVerifier")
            .field("peer", &self.peer.fingerprint())
            .finish()
    }
}

fn assert_exact_raw_key(
    expected: &P256Spki,
    actual: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), rustls::Error> {
    if !intermediates.is_empty()
        || actual.as_ref() != expected.as_der()
        || P256Spki::from_canonical_der(actual.as_ref()).is_err()
    {
        return Err(rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ));
    }
    Ok(())
}

fn verify_tls13_p256(
    message: &[u8],
    cert: &CertificateDer<'_>,
    signature: &DigitallySignedStruct,
    algorithms: &rustls::crypto::WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    if signature.scheme != SignatureScheme::ECDSA_NISTP256_SHA256 {
        return Err(rustls::Error::General(
            "wrong guest TLS signature algorithm".into(),
        ));
    }
    let raw = SubjectPublicKeyInfoDer::from(cert.as_ref());
    verify_tls13_signature_with_raw_key(message, &raw, signature, algorithms)
}

impl ServerCertVerifier for ExactGuestServerVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !ocsp.is_empty() {
            return Err(rustls::Error::General(
                "guest raw key cannot carry OCSP".into(),
            ));
        }
        assert_exact_raw_key(&self.peer, cert, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 prohibited".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        assert_exact_raw_key(&self.peer, cert, &[])?;
        verify_tls13_p256(message, cert, signature, &self.schemes)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for ExactGuestClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        assert_exact_raw_key(&self.peer, cert, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 prohibited".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        assert_exact_raw_key(&self.peer, cert, &[])?;
        verify_tls13_p256(message, cert, signature, &self.schemes)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Mutually proof-of-possession-verified raw-key TLS configuration for a
/// SPECIFIC introductory client/server key pair. No key here is *socially*
/// trusted until both real users explicitly compare the SAS and confirm.
pub fn client_config(
    local: &LocalGuestIdentity,
    transcript: &GuestTranscript,
) -> Result<Arc<ClientConfig>, Error> {
    if transcript.client().device_id() != local.device_id()
        || transcript.client().public_key() != local.public_key()
    {
        return Err(Error::Unauthorized);
    }
    let provider = provider();
    let verifier = Arc::new(ExactGuestServerVerifier {
        peer: transcript.server().public_key().clone(),
        schemes: provider.signature_verification_algorithms,
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Unauthorized)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(client::AlwaysResolvesClientRawPublicKeys::new(
            local.certified_raw_public_key(),
        )));
    config.alpn_protocols = vec![GUEST_ALPN.to_vec()];
    config.resumption = client::Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    Ok(Arc::new(config))
}

pub fn server_config(
    local: &LocalGuestIdentity,
    transcript: &GuestTranscript,
) -> Result<Arc<ServerConfig>, Error> {
    if transcript.server().device_id() != local.device_id()
        || transcript.server().public_key() != local.public_key()
    {
        return Err(Error::Unauthorized);
    }
    let provider = provider();
    let verifier = Arc::new(ExactGuestClientVerifier {
        peer: transcript.client().public_key().clone(),
        schemes: provider.signature_verification_algorithms,
    });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Unauthorized)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(server::AlwaysResolvesServerRawPublicKeys::new(
            local.certified_raw_public_key(),
        )));
    config.alpn_protocols = vec![GUEST_ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

fn cipher_id(suite: CipherSuite) -> Result<u16, Error> {
    match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(0x1301),
        CipherSuite::TLS13_AES_256_GCM_SHA384 => Ok(0x1302),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Ok(0x1303),
        _ => Err(Error::Unauthorized),
    }
}
fn group_id(group: NamedGroup) -> Result<u16, Error> {
    match group {
        NamedGroup::X25519 => Ok(0x001d),
        NamedGroup::secp256r1 => Ok(0x0017),
        NamedGroup::secp384r1 => Ok(0x0018),
        _ => Err(Error::Unauthorized),
    }
}

pub struct ProvisionalTlsPeer {
    transcript: GuestTranscript,
    local_tls_side: TlsSide,
    transcript_hash: [u8; 32],
    session_binding: [u8; 32],
    sas: String,
    proof_key: [u8; 32],
    live: Arc<AtomicBool>,
    deadline: Instant,
    admission: Option<GuestAdmissionPermit>,
}

/// Fresh mutual TLS 1.3 proof of the ORIGINAL pinned keys for a receipt-only
/// reconnect. This is NOT a VerifiedGuestSession, cannot enter SAS approval,
/// cannot authorize a new offer/stream, and does not require renewed Everyone
/// visibility. The existing 256-bit recovery credential and exact journal
/// binding are required to disclose a committed receipt.
pub struct VerifiedReceiptOnlyTls {
    channel: ProvisionalTlsPeer,
}

impl VerifiedReceiptOnlyTls {
    pub fn from_completed_server(
        tls: &ServerConnection,
        transcript: GuestTranscript,
        live: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        if transcript.server().transfer_side != TransferSide::Receiver
            || transcript.client().transfer_side != TransferSide::Sender
        {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            channel: ProvisionalTlsPeer::from_verified_channel(
                tls.is_handshaking(),
                tls.handshake_kind(),
                tls.protocol_version(),
                tls.alpn_protocol(),
                tls.peer_certificates(),
                tls.negotiated_cipher_suite().map(|suite| suite.suite()),
                tls.negotiated_key_exchange_group()
                    .map(|group| group.name()),
                transcript,
                TlsSide::Server,
                live,
                None,
                |label, context| {
                    let mut output = [0u8; 32];
                    tls.export_keying_material(&mut output[..], label, Some(context))?;
                    Ok(output)
                },
            )?,
        })
    }

    pub fn from_completed_client(
        tls: &ClientConnection,
        transcript: GuestTranscript,
        live: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        if transcript.client().transfer_side != TransferSide::Receiver
            || transcript.server().transfer_side != TransferSide::Sender
        {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            channel: ProvisionalTlsPeer::from_verified_channel(
                tls.is_handshaking(),
                tls.handshake_kind(),
                tls.protocol_version(),
                tls.alpn_protocol(),
                tls.peer_certificates(),
                tls.negotiated_cipher_suite().map(|suite| suite.suite()),
                tls.negotiated_key_exchange_group()
                    .map(|group| group.name()),
                transcript,
                TlsSide::Client,
                live,
                None,
                |label, context| {
                    let mut output = [0u8; 32];
                    tls.export_keying_material(&mut output[..], label, Some(context))?;
                    Ok(output)
                },
            )?,
        })
    }

    pub fn is_active(&self) -> bool {
        self.channel.live.load(Ordering::Acquire) && Instant::now() < self.channel.deadline
    }
    pub fn peer_public_key(&self) -> &P256Spki {
        self.channel.peer_public_key()
    }
    pub fn local_public_key(&self) -> &P256Spki {
        match self.channel.local_tls_side {
            TlsSide::Client => self.channel.transcript.client().public_key(),
            TlsSide::Server => self.channel.transcript.server().public_key(),
        }
    }
}

impl ProvisionalTlsPeer {
    pub fn from_completed_client(
        tls: &ClientConnection,
        transcript: GuestTranscript,
        live: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        Self::from_verified_channel(
            tls.is_handshaking(),
            tls.handshake_kind(),
            tls.protocol_version(),
            tls.alpn_protocol(),
            tls.peer_certificates(),
            tls.negotiated_cipher_suite().map(|suite| suite.suite()),
            tls.negotiated_key_exchange_group()
                .map(|group| group.name()),
            transcript,
            TlsSide::Client,
            live,
            None,
            |label, context| {
                let mut output = [0u8; 32];
                tls.export_keying_material(&mut output[..], label, Some(context))?;
                Ok(output)
            },
        )
    }

    pub fn from_completed_server(
        tls: &ServerConnection,
        transcript: GuestTranscript,
        live: Arc<AtomicBool>,
        admission: GuestAdmissionPermit,
    ) -> Result<Self, Error> {
        if !admission.is_active() {
            return Err(Error::Unauthorized);
        }
        Self::from_verified_channel(
            tls.is_handshaking(),
            tls.handshake_kind(),
            tls.protocol_version(),
            tls.alpn_protocol(),
            tls.peer_certificates(),
            tls.negotiated_cipher_suite().map(|suite| suite.suite()),
            tls.negotiated_key_exchange_group()
                .map(|group| group.name()),
            transcript,
            TlsSide::Server,
            live,
            Some(admission),
            |label, context| {
                let mut output = [0u8; 32];
                tls.export_keying_material(&mut output[..], label, Some(context))?;
                Ok(output)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_verified_channel(
        handshaking: bool,
        kind: Option<HandshakeKind>,
        version: Option<ProtocolVersion>,
        alpn: Option<&[u8]>,
        certificates: Option<&[CertificateDer<'static>]>,
        suite: Option<CipherSuite>,
        group: Option<NamedGroup>,
        transcript: GuestTranscript,
        local_role: TlsSide,
        live: Arc<AtomicBool>,
        admission: Option<GuestAdmissionPermit>,
        mut exporter: impl FnMut(&[u8], &[u8]) -> Result<[u8; 32], rustls::Error>,
    ) -> Result<Self, Error> {
        if handshaking
            || !matches!(
                kind,
                Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
            )
            || version != Some(ProtocolVersion::TLSv1_3)
            || alpn != Some(GUEST_ALPN)
            || !live.load(Ordering::Acquire)
        {
            return Err(Error::Unauthorized);
        }
        let expected = match local_role {
            TlsSide::Client => transcript.server(),
            TlsSide::Server => transcript.client(),
        };
        let peer = certificates
            .filter(|chain| chain.len() == 1)
            .and_then(|chain| chain.first())
            .ok_or(Error::Unauthorized)?;
        if peer.as_ref() != expected.public_key().as_der() {
            return Err(Error::Unauthorized);
        }
        let hash = transcript.canonical_digest(
            cipher_id(suite.ok_or(Error::Unauthorized)?)?,
            group_id(group.ok_or(Error::Unauthorized)?)?,
        );
        let sas_key = exporter(SAS_EXPORTER, &hash).map_err(|_| Error::Unauthorized)?;
        let proof_key = exporter(CONFIRM_EXPORTER, &hash).map_err(|_| Error::Unauthorized)?;
        // The public transcript digest alone is not a session secret. Bind
        // subsequent owner actions to this *fresh TLS connection* instead.
        let session_binding = exporter(SESSION_EXPORTER, &hash).map_err(|_| Error::Unauthorized)?;
        let sas = sas_from_uniform_exporter(&sas_key)?;
        let deadline = Instant::now()
            .checked_add(PAIRING_DEADLINE)
            .ok_or(Error::Unauthorized)?;
        Ok(Self {
            transcript,
            local_tls_side: local_role,
            transcript_hash: hash,
            session_binding,
            sas,
            proof_key,
            live,
            deadline,
            admission,
        })
    }

    /// This displayed SAS remains unauthoritative until the actual local
    /// owner independently compares it and approves in privileged UI.
    pub fn displayed_code(&self) -> &str {
        &self.sas
    }

    pub fn peer_public_key(&self) -> &P256Spki {
        match self.local_tls_side {
            TlsSide::Client => self.transcript.server().public_key(),
            TlsSide::Server => self.transcript.client().public_key(),
        }
    }

    /// A mismatched code revokes the transport-owned session flag immediately
    /// and consumes the provisional capability. The native transport owner
    /// must also close the TLS socket when it observes this revoked flag.
    pub fn abort_for_mismatch(self) {
        self.live.store(false, Ordering::Release);
    }

    #[cfg(feature = "hosted-guest-fixture")]
    #[doc(hidden)]
    pub fn approve_sas_for_hosted_guest_fixture(self) -> Result<AwaitingPeerConfirmation, Error> {
        self.accept_local_human_code(MatchedCodeOwnerAction { _private: () })
    }

    /// A genuine local desktop button action is required before emitting
    /// either side's proof. The wire cannot invoke this transition directly.
    #[cfg(all(target_os = "linux", feature = "linux-qt-consent"))]
    pub fn request_linux_qt_sas(self) -> Result<AwaitingPeerConfirmation, Error> {
        use std::ffi::{c_char, c_void, CString};

        unsafe extern "C" fn still_active(context: *const c_void) -> i32 {
            if context.is_null() {
                return 0;
            }
            let active = unsafe { &*(context as *const AtomicBool) };
            i32::from(active.load(Ordering::Acquire))
        }

        extern "C" {
            fn opendrop_qt_present_guest_sas(
                code: *const c_char,
                fingerprint: *const c_char,
                live: unsafe extern "C" fn(*const c_void) -> i32,
                live_context: *const c_void,
            ) -> i32;
        }

        if !self.live.load(Ordering::Acquire)
            || self.deadline <= Instant::now()
            || self
                .admission
                .as_ref()
                .is_some_and(|permit| !permit.is_active())
        {
            self.abort_for_mismatch();
            return Err(Error::Unauthorized);
        }
        let code =
            CString::new(self.displayed_code()).map_err(|_| Error::Invalid("guest SAS display"))?;
        let fingerprint = CString::new(self.peer_public_key().fingerprint().to_hex())
            .map_err(|_| Error::Invalid("guest key display"))?;
        let decision = unsafe {
            opendrop_qt_present_guest_sas(
                code.as_ptr(),
                fingerprint.as_ptr(),
                still_active,
                (self.live.as_ref() as *const AtomicBool).cast::<c_void>(),
            )
        };
        if decision != 1 {
            self.abort_for_mismatch();
            return Err(Error::Unauthorized);
        }
        self.accept_local_human_code(MatchedCodeOwnerAction { _private: () })
    }

    // No public caller-supplied bool can advance this state. Future Linux
    // Qt/Android/Windows *trusted in-process UI issuers* are implemented in
    // their platform adapters; until then real guest approval fails closed.
    #[allow(dead_code)]
    pub(crate) fn accept_local_human_code(
        self,
        owner_action: MatchedCodeOwnerAction,
    ) -> Result<AwaitingPeerConfirmation, Error> {
        let _ = owner_action;
        if Instant::now() >= self.deadline
            || !self.live.load(Ordering::Acquire)
            || self
                .admission
                .as_ref()
                .is_some_and(|permit| !permit.is_active())
        {
            self.live.store(false, Ordering::Release);
            return Err(Error::Unauthorized);
        }
        Ok(AwaitingPeerConfirmation { provisional: self })
    }
}

/// Opaque local-human action. Only the trusted native UI adapter within the
/// core security module may eventually issue this capability.
pub(crate) struct MatchedCodeOwnerAction {
    _private: (),
}

/// Both confirmations use independent TLS-exporter-derived role-separated
/// HMAC tags; only a trusted UI can make the local sender emit its tag.
pub struct AwaitingPeerConfirmation {
    provisional: ProvisionalTlsPeer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestConfirmation([u8; CONFIRM_LEN]);

impl GuestConfirmation {
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; CONFIRM_LEN] = input
            .try_into()
            .map_err(|_| Error::Invalid("guest confirmation length"))?;
        if bytes[..4] != *CONFIRM_MAGIC || bytes[4] != 1 || !matches!(bytes[5], 1 | 2) {
            return Err(Error::Invalid("guest confirmation version/role"));
        }
        Ok(Self(bytes))
    }
    pub fn encoded(&self) -> &[u8; CONFIRM_LEN] {
        &self.0
    }
}

fn confirmation_input(binding: &[u8; 32], role: TlsSide) -> Vec<u8> {
    let mut input = Vec::with_capacity(65);
    input.extend_from_slice(b"OpenDrop/S1/VerifiedUserConfirmation/v1\0");
    input.extend_from_slice(binding);
    input.push(role as u8);
    input
}

fn confirmation_mac(key: &[u8; 32], binding: &[u8; 32], role: TlsSide) -> [u8; 32] {
    let input = confirmation_input(binding, role);
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &input);
    tag.as_ref()
        .try_into()
        .expect("HMAC-SHA256 outputs 32 bytes")
}

impl AwaitingPeerConfirmation {
    pub fn outgoing_confirmation(&self) -> Result<GuestConfirmation, Error> {
        if self.provisional.deadline <= Instant::now()
            || !self.provisional.live.load(Ordering::Acquire)
        {
            return Err(Error::Unauthorized);
        }
        let mut packet = [0u8; CONFIRM_LEN];
        packet[..4].copy_from_slice(CONFIRM_MAGIC);
        packet[4] = 1;
        packet[5] = self.provisional.local_tls_side as u8;
        packet[6..].copy_from_slice(&confirmation_mac(
            &self.provisional.proof_key,
            &self.provisional.transcript_hash,
            self.provisional.local_tls_side,
        ));
        Ok(GuestConfirmation(packet))
    }

    pub fn verify_peer_then_finish(
        self,
        peer: &GuestConfirmation,
    ) -> Result<VerifiedGuestSession, Error> {
        if Instant::now() >= self.provisional.deadline
            || !self.provisional.live.load(Ordering::Acquire)
            || self
                .provisional
                .admission
                .as_ref()
                .is_some_and(|permit| !permit.is_active())
        {
            self.provisional.live.store(false, Ordering::Release);
            return Err(Error::Unauthorized);
        }
        let opposite = match self.provisional.local_tls_side {
            TlsSide::Client => TlsSide::Server,
            TlsSide::Server => TlsSide::Client,
        };
        let expected_input = confirmation_input(&self.provisional.transcript_hash, opposite);
        if peer.0[5] != opposite as u8
            || hmac::verify(
                &hmac::Key::new(hmac::HMAC_SHA256, &self.provisional.proof_key),
                &expected_input,
                &peer.0[6..],
            )
            .is_err()
        {
            self.provisional.live.store(false, Ordering::Release);
            return Err(Error::Unauthorized);
        }
        Ok(VerifiedGuestSession {
            transcript: self.provisional.transcript,
            binding: self.provisional.session_binding,
            local_tls_side: self.provisional.local_tls_side,
            live: self.provisional.live,
            admission: self.provisional.admission,
        })
    }
}

/// The peer has proven the exact TLS RPK key AND the local owner has
/// independently approved the displayed code AND a peer confirmation arrived
/// on that same session. Still NOT authorization to receive a file.
pub struct VerifiedGuestSession {
    transcript: GuestTranscript,
    binding: [u8; 32],
    local_tls_side: TlsSide,
    live: Arc<AtomicBool>,
    admission: Option<GuestAdmissionPermit>,
}

impl VerifiedGuestSession {
    pub fn is_active(&self) -> bool {
        self.live.load(Ordering::Acquire)
            && self
                .admission
                .as_ref()
                .is_none_or(|permit| permit.is_active())
    }
    pub fn peer_spki_fingerprint(&self) -> GuestSpkiFingerprint {
        let peer = match self.local_tls_side {
            TlsSide::Client => self.transcript.server(),
            TlsSide::Server => self.transcript.client(),
        };
        peer.public_key().fingerprint()
    }
    pub fn local_spki_fingerprint(&self) -> GuestSpkiFingerprint {
        let local = match self.local_tls_side {
            TlsSide::Client => self.transcript.client(),
            TlsSide::Server => self.transcript.server(),
        };
        local.public_key().fingerprint()
    }
    pub fn session_binding(&self) -> &[u8; 32] {
        &self.binding
    }
    pub fn logical_sender_spki(&self) -> GuestSpkiFingerprint {
        let sender = if self.transcript.client().transfer_side == TransferSide::Sender {
            self.transcript.client()
        } else {
            self.transcript.server()
        };
        sender.public_key().fingerprint()
    }
    pub fn logical_receiver_spki(&self) -> GuestSpkiFingerprint {
        let receiver = if self.transcript.client().transfer_side == TransferSide::Receiver {
            self.transcript.client()
        } else {
            self.transcript.server()
        };
        receiver.public_key().fingerprint()
    }
    pub fn logical_sender_public_key(&self) -> &P256Spki {
        if self.transcript.client().transfer_side == TransferSide::Sender {
            self.transcript.client().public_key()
        } else {
            self.transcript.server().public_key()
        }
    }
    pub fn logical_receiver_public_key(&self) -> &P256Spki {
        if self.transcript.client().transfer_side == TransferSide::Receiver {
            self.transcript.client().public_key()
        } else {
            self.transcript.server().public_key()
        }
    }
    pub fn local_transfer_side(&self) -> TransferSide {
        match self.local_tls_side {
            TlsSide::Client => self.transcript.client().transfer_side,
            TlsSide::Server => self.transcript.server().transfer_side,
        }
    }
}

fn sas_from_uniform_exporter(material: &[u8; 32]) -> Result<String, Error> {
    let limit = u64::MAX - (u64::MAX % SAS_MODULUS);
    for block in material.chunks_exact(8) {
        let candidate = u64::from_be_bytes(block.try_into().expect("8-byte chunk"));
        if candidate < limit {
            let n = candidate % SAS_MODULUS;
            return Ok(format!("{:05}-{:05}", n / 100_000, n % 100_000));
        }
    }
    // Rejection sampling is unbiased and bounded. The probability of four
    // rejects is negligible; fail closed rather than introduce modulo bias.
    Err(Error::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::{GuestAdmission, TlsSide, TransferSide};
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    struct TestOnlyMemoryP256 {
        key: EcdsaKeyPair,
        spki: Vec<u8>,
    }

    impl fmt::Debug for TestOnlyMemoryP256 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("TestOnlyMemoryP256(private-key-redacted)")
        }
    }

    impl NativeP256Signer for TestOnlyMemoryP256 {
        fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error> {
            Ok(self.spki.clone())
        }
        fn sign_ecdsa_p256_sha256_der(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            let rng = SystemRandom::new();
            Ok(self
                .key
                .sign(&rng, data)
                .map_err(|_| Error::Unauthorized)?
                .as_ref()
                .to_vec())
        }
    }

    /// Cryptographic key material is created in memory only under cfg(test).
    /// This is NOT a runtime fallback or production key-store adapter.
    fn identity(tag: char) -> LocalGuestIdentity {
        let rng = SystemRandom::new();
        let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &rng)
            .unwrap();
        let point = key.public_key().as_ref();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 4);
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(point);
        LocalGuestIdentity::from_platform_signer(
            DeviceId::parse(&tag.to_string().repeat(32)).unwrap(),
            Arc::new(TestOnlyMemoryP256 { key, spki }),
        )
        .unwrap()
    }

    fn tls_pair() -> (
        LocalGuestIdentity,
        LocalGuestIdentity,
        GuestTranscript,
        ClientConnection,
        ServerConnection,
    ) {
        let sender = identity('a');
        let receiver = identity('b');
        let client_hello = sender
            .new_hello(TlsSide::Client, TransferSide::Sender)
            .unwrap();
        let server_hello = receiver
            .new_hello(TlsSide::Server, TransferSide::Receiver)
            .unwrap();
        let transcript = GuestTranscript::new(client_hello, server_hello).unwrap();
        let client = ClientConnection::new(
            client_config(&sender, &transcript).unwrap(),
            ServerName::try_from("opendrop.invalid").unwrap().to_owned(),
        )
        .unwrap();
        let server = ServerConnection::new(server_config(&receiver, &transcript).unwrap()).unwrap();
        (sender, receiver, transcript, client, server)
    }

    fn exchange(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), rustls::Error> {
        for _ in 0..32 {
            if client.wants_write() {
                let mut bytes = Vec::new();
                client.write_tls(&mut bytes).unwrap();
                server.read_tls(&mut bytes.as_slice()).unwrap();
                server.process_new_packets()?;
            }
            if server.wants_write() {
                let mut bytes = Vec::new();
                server.write_tls(&mut bytes).unwrap();
                client.read_tls(&mut bytes.as_slice()).unwrap();
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General(
            "synthetic TLS handshake budget".into(),
        ))
    }

    #[test]
    fn exact_key_mutual_tls_and_bilateral_sas_complete_without_peer_enrollment() {
        let (_sender, _receiver, transcript, mut client, mut server) = tls_pair();
        exchange(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(client.alpn_protocol(), Some(GUEST_ALPN));
        assert_eq!(server.alpn_protocol(), Some(GUEST_ALPN));
        let mut admission = GuestAdmission::new_closed();
        admission.open_from_local_owner_action();
        let live_client = Arc::new(AtomicBool::new(true));
        let live_server = Arc::new(AtomicBool::new(true));
        let client_provisional =
            ProvisionalTlsPeer::from_completed_client(&client, transcript.clone(), live_client)
                .unwrap();
        let server_provisional = ProvisionalTlsPeer::from_completed_server(
            &server,
            transcript.clone(),
            live_server.clone(),
            admission.admit().unwrap(),
        )
        .unwrap();
        assert_eq!(
            client_provisional.displayed_code(),
            server_provisional.displayed_code()
        );
        assert_eq!(client_provisional.displayed_code().len(), 11);
        let client_confirmed = client_provisional
            .accept_local_human_code(MatchedCodeOwnerAction { _private: () })
            .unwrap();
        let server_confirmed = server_provisional
            .accept_local_human_code(MatchedCodeOwnerAction { _private: () })
            .unwrap();
        let client_proof = client_confirmed.outgoing_confirmation().unwrap();
        let server_proof = server_confirmed.outgoing_confirmation().unwrap();
        let verified_client = client_confirmed
            .verify_peer_then_finish(&server_proof)
            .unwrap();
        let verified_server = server_confirmed
            .verify_peer_then_finish(&client_proof)
            .unwrap();
        assert!(verified_client.is_active());
        assert!(verified_server.is_active());
        assert_eq!(
            verified_client.session_binding(),
            verified_server.session_binding()
        );
        assert_eq!(
            verified_client.logical_sender_spki(),
            verified_server.logical_sender_spki()
        );
        assert_eq!(
            verified_client.logical_receiver_spki(),
            verified_server.logical_receiver_spki()
        );
        live_server.store(false, Ordering::Release);
        assert!(!verified_server.is_active());
    }

    #[test]
    fn wrong_introduced_key_is_rejected_by_tls_before_any_sas_or_offer() {
        let (sender, receiver, _correct, _unused_client, mut server) = tls_pair();
        let attacker = identity('c');
        let forged = GuestTranscript::new(
            sender
                .new_hello(TlsSide::Client, TransferSide::Sender)
                .unwrap(),
            attacker
                .new_hello(TlsSide::Server, TransferSide::Receiver)
                .unwrap(),
        )
        .unwrap();
        // Sender pins one server RPK, but the actual TLS server signs with
        // another RPK. The rustls verifier must NOT return an assertion.
        let mut client = ClientConnection::new(
            client_config(&sender, &forged).unwrap(),
            ServerName::try_from("opendrop.invalid").unwrap().to_owned(),
        )
        .unwrap();
        assert!(exchange(&mut client, &mut server).is_err());
        // Conversely a server must reject a client key substitution.
        let correct = GuestTranscript::new(
            sender
                .new_hello(TlsSide::Client, TransferSide::Sender)
                .unwrap(),
            receiver
                .new_hello(TlsSide::Server, TransferSide::Receiver)
                .unwrap(),
        )
        .unwrap();
        let mut client = ClientConnection::new(
            client_config(
                &attacker,
                &GuestTranscript::new(
                    attacker
                        .new_hello(TlsSide::Client, TransferSide::Sender)
                        .unwrap(),
                    receiver
                        .new_hello(TlsSide::Server, TransferSide::Receiver)
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            ServerName::try_from("opendrop.invalid").unwrap().to_owned(),
        )
        .unwrap();
        let mut actual_server =
            ServerConnection::new(server_config(&receiver, &correct).unwrap()).unwrap();
        assert!(exchange(&mut client, &mut actual_server).is_err());
    }

    #[test]
    fn cancelled_and_wrong_role_proofs_cannot_be_replayed_as_user_approval() {
        let (_, _, transcript, mut client, mut server) = tls_pair();
        exchange(&mut client, &mut server).unwrap();
        let live = Arc::new(AtomicBool::new(true));
        let provisional =
            ProvisionalTlsPeer::from_completed_client(&client, transcript, live.clone()).unwrap();
        let confirming = provisional
            .accept_local_human_code(MatchedCodeOwnerAction { _private: () })
            .unwrap();
        let own_proof = confirming.outgoing_confirmation().unwrap();
        assert!(confirming.verify_peer_then_finish(&own_proof).is_err());
        assert!(!live.load(Ordering::Acquire));
    }

    #[test]
    fn mismatched_code_aborts_transport_and_cannot_authorize_offer() {
        let (_, _, transcript, mut client, mut server) = tls_pair();
        exchange(&mut client, &mut server).unwrap();
        let live = Arc::new(AtomicBool::new(true));
        let provisional =
            ProvisionalTlsPeer::from_completed_client(&client, transcript, live.clone()).unwrap();
        provisional.abort_for_mismatch();
        assert!(!live.load(Ordering::Acquire));
    }

    #[test]
    fn sas_has_exact_ten_decimal_digits_and_no_shortening() {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(1_234_567_890u64).to_be_bytes());
        assert_eq!(sas_from_uniform_exporter(&key).unwrap(), "12345-67890");
        key[..8].copy_from_slice(&(12u64).to_be_bytes());
        assert_eq!(sas_from_uniform_exporter(&key).unwrap(), "00000-00012");
    }

    #[test]
    fn confirmations_are_bounded_and_explicitly_role_tagged() {
        let mut garbage = [0u8; CONFIRM_LEN];
        assert!(GuestConfirmation::parse(&garbage).is_err());
        garbage[..4].copy_from_slice(CONFIRM_MAGIC);
        garbage[4] = 1;
        garbage[5] = 1;
        assert!(GuestConfirmation::parse(&garbage).is_ok());
        assert!(GuestConfirmation::parse(&garbage[..37]).is_err());
        garbage[5] = 3;
        assert!(GuestConfirmation::parse(&garbage).is_err());
        let a = confirmation_mac(&[3; 32], &[4; 32], TlsSide::Client);
        let b = confirmation_mac(&[3; 32], &[4; 32], TlsSide::Server);
        assert_ne!(a, b);
        assert_ne!(a, confirmation_mac(&[3; 32], &[5; 32], TlsSide::Client));
    }

    #[test]
    fn portable_role_hmac_vectors_reject_reflection_and_role_substitution() {
        // Exact synthetic inputs shared with Android Keystore and Windows CNG
        // conformance tests. This does not replace a real TLS exporter test.
        let digest_hex = "3f8db22cd9ceeb9c016cbaa1b8db2d2a8c332ef0f75dacfd306aa8b6cbcccd1d";
        let mut digest = [0u8; 32];
        for (idx, bytes) in digest_hex.as_bytes().chunks_exact(2).enumerate() {
            digest[idx] = u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap();
        }
        let proof_key = std::array::from_fn(|idx| idx as u8);
        let as_hex = |tag: [u8; 32]| {
            tag.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            as_hex(confirmation_mac(&proof_key, &digest, TlsSide::Client)),
            "d8aa4d659cd59194bbbf8d1df632757dd849d4daad791329c15433ab9e729378"
        );
        assert_eq!(
            as_hex(confirmation_mac(&proof_key, &digest, TlsSide::Server)),
            "42bf49d8e2362912e3945fa4d0320e5596bb1cd00cdf89ec84153f6a89cc0f75"
        );
    }
}
