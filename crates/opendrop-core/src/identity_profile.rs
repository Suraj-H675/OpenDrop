//! D-146 limited amendment to D-135: identity *continuity* capabilities,
//! not a second TLS or file protocol. The private signing-key provider
//! remains behind NativeP256Signer.
//!
//! A temporary guest must never acquire paired trust, auto-accept or a
//! promised 24-hour receipt-recovery period. An existing expected persistent
//! identity that disappears or becomes locked must fail CLOSED, not convert
//! into a temporary one.
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProfile {
    /// Installation P256 key in an independently validated native protected
    /// provider. Backend availability is NOT evidence of its protection.
    ProtectedPersistent,
    /// Fresh P256 key held only by this process. Owner explicitly requested
    /// a one-time verified guest exchange. Never used for existing trust.
    OneTimeVerifiedGuest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityCapabilities {
    pub may_remember_trusted_peer: bool,
    pub may_enable_per_device_auto_accept: bool,
    pub may_recover_receipt_after_restart: bool,
}

impl IdentityProfile {
    pub const fn capabilities(self) -> IdentityCapabilities {
        match self {
            Self::ProtectedPersistent => IdentityCapabilities {
                may_remember_trusted_peer: true,
                may_enable_per_device_auto_accept: true,
                may_recover_receipt_after_restart: true,
            },
            Self::OneTimeVerifiedGuest => IdentityCapabilities {
                may_remember_trusted_peer: false,
                may_enable_per_device_auto_accept: false,
                may_recover_receipt_after_restart: false,
            },
        }
    }

    pub fn require_persistent_trust(self) -> Result<(), Error> {
        if self.capabilities().may_remember_trusted_peer {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    pub fn require_recovery_after_restart(self) -> Result<(), Error> {
        if self.capabilities().may_recover_receipt_after_restart {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}

/// The provider's state is explicit. Never infer a temporary identity merely
/// because the native persistent store cannot be opened. An owner may choose
/// one-time mode ONLY on a new installation with no established trusted ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedProtectedIdentity {
    NewInstallationNoProtectedIdentity,
    ExistingProtectedIdentity,
}

pub fn authorize_identity_profile(
    requested: IdentityProfile,
    expected: ExpectedProtectedIdentity,
    has_explicit_one_time_owner_action: bool,
) -> Result<IdentityCapabilities, Error> {
    match (requested, expected) {
        (IdentityProfile::ProtectedPersistent, _) => {
            Ok(IdentityProfile::ProtectedPersistent.capabilities())
        }
        (
            IdentityProfile::OneTimeVerifiedGuest,
            ExpectedProtectedIdentity::NewInstallationNoProtectedIdentity,
        ) if has_explicit_one_time_owner_action => {
            Ok(IdentityProfile::OneTimeVerifiedGuest.capabilities())
        }
        _ => Err(Error::Unauthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_identity_preserves_d135_continuity_contract() {
        let capabilities = IdentityProfile::ProtectedPersistent.capabilities();
        assert!(capabilities.may_remember_trusted_peer);
        assert!(capabilities.may_enable_per_device_auto_accept);
        assert!(capabilities.may_recover_receipt_after_restart);
        assert!(IdentityProfile::ProtectedPersistent
            .require_persistent_trust()
            .is_ok());
        assert!(IdentityProfile::ProtectedPersistent
            .require_recovery_after_restart()
            .is_ok());
    }
    #[test]
    fn one_time_guest_never_promotes_trust_or_restart_receipt() {
        let capabilities = IdentityProfile::OneTimeVerifiedGuest.capabilities();
        assert!(!capabilities.may_remember_trusted_peer);
        assert!(!capabilities.may_enable_per_device_auto_accept);
        assert!(!capabilities.may_recover_receipt_after_restart);
        assert!(IdentityProfile::OneTimeVerifiedGuest
            .require_persistent_trust()
            .is_err());
        assert!(IdentityProfile::OneTimeVerifiedGuest
            .require_recovery_after_restart()
            .is_err());
    }
    #[test]
    fn missing_or_locked_existing_identity_cannot_downgrade_implicitly() {
        for explicit in [false, true] {
            assert!(authorize_identity_profile(
                IdentityProfile::OneTimeVerifiedGuest,
                ExpectedProtectedIdentity::ExistingProtectedIdentity,
                explicit
            )
            .is_err());
        }
        assert!(authorize_identity_profile(
            IdentityProfile::OneTimeVerifiedGuest,
            ExpectedProtectedIdentity::NewInstallationNoProtectedIdentity,
            false
        )
        .is_err());
        assert!(authorize_identity_profile(
            IdentityProfile::OneTimeVerifiedGuest,
            ExpectedProtectedIdentity::NewInstallationNoProtectedIdentity,
            true
        )
        .is_ok());
    }
}
