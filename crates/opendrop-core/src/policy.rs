//! Approved receiver visibility and per-peer consent. Discovery is a hint,
//! never an authentication or authorization decision.
use crate::identity::{DeviceId, KeyFingerprint};
use crate::Error;

pub const EVERYONE_MILLIS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateVisibility {
    Off,
    TrustedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveVisibility {
    Off,
    TrustedOnly,
    Everyone,
}

/// Persisted fields are wall-clock timestamps. In-process UI must ALSO use a
/// monotonic timer; after restart, unknown/rolled-back clock expires guest
/// exposure conservatively. No background service is claimed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Visibility {
    previous: PrivateVisibility,
    everyone_started_ms: Option<i64>,
    everyone_until_ms: Option<i64>,
}
impl Default for Visibility {
    fn default() -> Self {
        Self {
            previous: PrivateVisibility::TrustedOnly,
            everyone_started_ms: None,
            everyone_until_ms: None,
        }
    }
}
impl Visibility {
    pub fn private(mode: PrivateVisibility) -> Self {
        Self {
            previous: mode,
            everyone_started_ms: None,
            everyone_until_ms: None,
        }
    }
    pub fn everyone(mut self, now_ms: i64) -> Result<Self, Error> {
        if now_ms < 0 {
            return Err(Error::Invalid("clock"));
        }
        self.everyone_started_ms = Some(now_ms);
        self.everyone_until_ms = Some(
            now_ms
                .checked_add(EVERYONE_MILLIS)
                .ok_or(Error::Invalid("clock overflow"))?,
        );
        Ok(self)
    }
    pub fn mode(&self, now_ms: i64) -> EffectiveVisibility {
        match (self.everyone_started_ms, self.everyone_until_ms) {
            (Some(start), Some(end)) if now_ms >= start && now_ms < end => {
                EffectiveVisibility::Everyone
            }
            _ => match self.previous {
                PrivateVisibility::Off => EffectiveVisibility::Off,
                PrivateVisibility::TrustedOnly => EffectiveVisibility::TrustedOnly,
            },
        }
    }
    pub fn previous(&self) -> PrivateVisibility {
        self.previous
    }
    pub fn persisted_interval(&self) -> (Option<i64>, Option<i64>) {
        (self.everyone_started_ms, self.everyone_until_ms)
    }
    pub fn from_persisted(
        previous: PrivateVisibility,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<Self, Error> {
        if start.is_some() != end.is_some()
            || start.is_some_and(|v| v < 0)
            || end.is_some_and(|v| v < 0)
            || start
                .zip(end)
                .is_some_and(|(a, b)| a.checked_add(EVERYONE_MILLIS) != Some(b))
        {
            return Err(Error::Invalid("persisted visibility interval"));
        }
        Ok(Self {
            previous,
            everyone_started_ms: start,
            everyone_until_ms: end,
        })
    }
}

pub(crate) struct Peer<'a> {
    pub device_id: &'a DeviceId,
    pub actual_key: &'a KeyFingerprint,
    pub pinned_key: Option<&'a KeyFingerprint>,
    pub revoked: bool,
    pub auto_accept: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveDecision {
    Deny,
    RequireGuestConsent,
    RequireTrustedConsent,
    AllowExplicit,
    AllowAutoAcceptedTrusted,
}

pub(crate) fn decide_incoming(
    visibility: EffectiveVisibility,
    peer: &Peer<'_>,
    explicitly_approved: bool,
) -> ReceiveDecision {
    // DeviceId by itself and unverified advertisements are not trust.
    let _ = peer.device_id;
    if visibility == EffectiveVisibility::Off || peer.revoked {
        return ReceiveDecision::Deny;
    }
    if let Some(pinned) = peer.pinned_key {
        if pinned != peer.actual_key {
            return ReceiveDecision::Deny;
        }
        if explicitly_approved {
            return ReceiveDecision::AllowExplicit;
        }
        if peer.auto_accept {
            return ReceiveDecision::AllowAutoAcceptedTrusted;
        }
        return ReceiveDecision::RequireTrustedConsent;
    }
    if visibility != EffectiveVisibility::Everyone {
        return ReceiveDecision::Deny;
    }
    if explicitly_approved {
        ReceiveDecision::AllowExplicit
    } else {
        ReceiveDecision::RequireGuestConsent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> DeviceId {
        DeviceId::parse(&"3".repeat(32)).unwrap()
    }
    fn fp(s: char) -> KeyFingerprint {
        KeyFingerprint::parse(&s.to_string().repeat(64)).unwrap()
    }
    #[test]
    fn everyone_expires_to_prior_private_mode() {
        let private = Visibility::default();
        assert_eq!(private.mode(1), EffectiveVisibility::TrustedOnly);
        let guest = private.everyone(1000).unwrap();
        assert_eq!(guest.mode(1000), EffectiveVisibility::Everyone);
        assert_eq!(guest.mode(600999), EffectiveVisibility::Everyone);
        assert_eq!(guest.mode(601000), EffectiveVisibility::TrustedOnly);
        let off = Visibility::private(PrivateVisibility::Off)
            .everyone(1000)
            .unwrap();
        assert_eq!(off.mode(601000), EffectiveVisibility::Off);
        assert_eq!(guest.mode(900), EffectiveVisibility::TrustedOnly); // rolled-back clock
        let (a, b) = guest.persisted_interval();
        assert_eq!(
            Visibility::from_persisted(guest.previous(), a, b)
                .unwrap()
                .mode(601000),
            EffectiveVisibility::TrustedOnly
        );
    }
    #[test]
    fn guest_consent_never_upgrades_to_paired_auto_accept() {
        let device = id();
        let key = fp('a');
        let guest = Peer {
            device_id: &device,
            actual_key: &key,
            pinned_key: None,
            revoked: false,
            auto_accept: true,
        };
        assert_eq!(
            decide_incoming(EffectiveVisibility::TrustedOnly, &guest, true),
            ReceiveDecision::Deny
        );
        assert_eq!(
            decide_incoming(EffectiveVisibility::Everyone, &guest, false),
            ReceiveDecision::RequireGuestConsent
        );
        assert_eq!(
            decide_incoming(EffectiveVisibility::Everyone, &guest, true),
            ReceiveDecision::AllowExplicit
        );
    }
    #[test]
    fn unverified_changed_or_revoked_key_never_auto_receives() {
        let device = id();
        let pinned = fp('a');
        let changed = fp('b');
        let mut peer = Peer {
            device_id: &device,
            actual_key: &pinned,
            pinned_key: Some(&pinned),
            revoked: false,
            auto_accept: false,
        };
        assert_eq!(
            decide_incoming(EffectiveVisibility::TrustedOnly, &peer, false),
            ReceiveDecision::RequireTrustedConsent
        );
        peer.auto_accept = true;
        assert_eq!(
            decide_incoming(EffectiveVisibility::TrustedOnly, &peer, false),
            ReceiveDecision::AllowAutoAcceptedTrusted
        );
        peer.actual_key = &changed;
        assert_eq!(
            decide_incoming(EffectiveVisibility::Everyone, &peer, true),
            ReceiveDecision::Deny
        );
        peer.actual_key = &pinned;
        peer.revoked = true;
        assert_eq!(
            decide_incoming(EffectiveVisibility::Everyone, &peer, true),
            ReceiveDecision::Deny
        );
    }
}
