use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PinPolicy {
    Never,
    Once,
    Always,
}

impl PinPolicy {
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
            other => Err(PolicyError::UnsupportedPinPolicy {
                policy: format!("{other:?}"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

impl TouchPolicy {
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
            other => Err(PolicyError::UnsupportedTouchPolicy {
                policy: format!("{other:?}"),
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
    fn test_pin_policy_round_trip() {
        [PinPolicy::Never, PinPolicy::Once, PinPolicy::Always]
            .into_iter()
            .for_each(|policy| {
                let converted = policy.to_yubikey_pin_policy();
                assert_eq!(PinPolicy::from_yubikey_pin_policy(converted), Ok(policy));
            });
    }

    #[test]
    fn test_touch_policy_round_trip() {
        [TouchPolicy::Never, TouchPolicy::Always, TouchPolicy::Cached]
            .into_iter()
            .for_each(|policy| {
                let converted = policy.to_yubikey_touch_policy();
                assert_eq!(
                    TouchPolicy::from_yubikey_touch_policy(converted),
                    Ok(policy)
                );
            });
    }
}
