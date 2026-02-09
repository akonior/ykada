
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinPolicy {
    Never,
    Once,
    Always,
}

impl PinPolicy {
    pub fn default() -> Self {
        Self::Always
    }

    pub fn recommended_cardano() -> Self {
        Self::Always
    }

    pub fn to_yubikey_pin_policy(self) -> yubikey::PinPolicy {
        match self {
            PinPolicy::Never => yubikey::PinPolicy::Never,
            PinPolicy::Once => yubikey::PinPolicy::Once,
            PinPolicy::Always => yubikey::PinPolicy::Always,
        }
    }

    pub fn from_yubikey_pin_policy(policy: yubikey::PinPolicy) -> Result<Self, PolicyError> {
        match policy {
            yubikey::PinPolicy::Never => Ok(PinPolicy::Never),
            yubikey::PinPolicy::Once => Ok(PinPolicy::Once),
            yubikey::PinPolicy::Always => Ok(PinPolicy::Always),
            _ => Err(PolicyError::UnsupportedPinPolicy {
                policy: format!("{:?}", policy),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

impl TouchPolicy {
    pub fn default() -> Self {
        Self::Never
    }

    pub fn recommended_cardano() -> Self {
        Self::Always
    }

    pub fn to_yubikey_touch_policy(self) -> yubikey::TouchPolicy {
        match self {
            TouchPolicy::Never => yubikey::TouchPolicy::Never,
            TouchPolicy::Always => yubikey::TouchPolicy::Always,
            TouchPolicy::Cached => yubikey::TouchPolicy::Cached,
        }
    }

    pub fn from_yubikey_touch_policy(policy: yubikey::TouchPolicy) -> Result<Self, PolicyError> {
        match policy {
            yubikey::TouchPolicy::Never => Ok(TouchPolicy::Never),
            yubikey::TouchPolicy::Always => Ok(TouchPolicy::Always),
            yubikey::TouchPolicy::Cached => Ok(TouchPolicy::Cached),
            _ => Err(PolicyError::UnsupportedTouchPolicy {
                policy: format!("{:?}", policy),
            }),
        }
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("PIN policy not supported: {policy}")]
    UnsupportedPinPolicy { policy: String },

    #[error("Touch policy not supported: {policy}")]
    UnsupportedTouchPolicy { policy: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_policy_conversion() {
        let policy = PinPolicy::Always;
        let yubikey_policy = policy.to_yubikey_pin_policy();
        assert_eq!(yubikey_policy, yubikey::PinPolicy::Always);
    }

    #[test]
    fn test_pin_policy_from_yubikey() {
        let yubikey_policy = yubikey::PinPolicy::Always;
        let policy = PinPolicy::from_yubikey_pin_policy(yubikey_policy).unwrap();
        assert_eq!(policy, PinPolicy::Always);
    }

    #[test]
    fn test_touch_policy_conversion() {
        let policy = TouchPolicy::Always;
        let yubikey_policy = policy.to_yubikey_touch_policy();
        assert_eq!(yubikey_policy, yubikey::TouchPolicy::Always);
    }

    #[test]
    fn test_touch_policy_from_yubikey() {
        let yubikey_policy = yubikey::TouchPolicy::Always;
        let policy = TouchPolicy::from_yubikey_touch_policy(yubikey_policy).unwrap();
        assert_eq!(policy, TouchPolicy::Always);
    }

    #[test]
    fn test_recommended_policies() {
        assert_eq!(PinPolicy::recommended_cardano(), PinPolicy::Always);
        assert_eq!(TouchPolicy::recommended_cardano(), TouchPolicy::Always);
    }

    #[test]
    fn test_policy_error_display() {
        let err = PolicyError::UnsupportedPinPolicy {
            policy: "Unknown".to_string(),
        };
        assert!(err.to_string().contains("not supported"));

        let err = PolicyError::UnsupportedTouchPolicy {
            policy: "Unknown".to_string(),
        };
        assert!(err.to_string().contains("not supported"));
    }
}
