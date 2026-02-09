use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    Authentication,
    Signature,
    KeyManagement,
    CardAuthentication,
}

impl Slot {
    pub fn default_signing() -> Self {
        Self::Signature
    }

    pub fn to_yubikey_slot_id(self) -> yubikey::piv::SlotId {
        match self {
            Slot::Authentication => yubikey::piv::SlotId::Authentication,
            Slot::Signature => yubikey::piv::SlotId::Signature,
            Slot::KeyManagement => yubikey::piv::SlotId::KeyManagement,
            Slot::CardAuthentication => yubikey::piv::SlotId::CardAuthentication,
        }
    }

    pub fn from_yubikey_slot_id(slot: yubikey::piv::SlotId) -> Result<Self, SlotError> {
        match slot {
            yubikey::piv::SlotId::Authentication => Ok(Slot::Authentication),
            yubikey::piv::SlotId::Signature => Ok(Slot::Signature),
            yubikey::piv::SlotId::KeyManagement => Ok(Slot::KeyManagement),
            yubikey::piv::SlotId::CardAuthentication => Ok(Slot::CardAuthentication),
            _ => Err(SlotError::Unsupported {
                slot: format!("{:?}", slot),
            }),
        }
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    #[error("Slot not supported: {slot}")]
    Unsupported { slot: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_conversion() {
        let slot = Slot::Signature;
        let yubikey_slot = slot.to_yubikey_slot_id();
        assert_eq!(yubikey_slot, yubikey::piv::SlotId::Signature);
    }

    #[test]
    fn test_slot_from_yubikey() {
        let yubikey_slot = yubikey::piv::SlotId::Signature;
        let slot = Slot::from_yubikey_slot_id(yubikey_slot).unwrap();
        assert_eq!(slot, Slot::Signature);
    }

    #[test]
    fn test_default_signing_slot() {
        assert_eq!(Slot::default_signing(), Slot::Signature);
    }

    #[test]
    fn test_slot_error_display() {
        let err = SlotError::Unsupported {
            slot: "Unknown".to_string(),
        };
        assert!(err.to_string().contains("not supported"));
    }
}
