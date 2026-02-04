//! Slot type for YubiKey PIV slots

use thiserror::Error;

/// PIV slot identifier
///
/// YubiKey PIV has multiple slots for storing different keys.
/// This type provides a type-safe way to reference slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    /// PIV Authentication slot (9a)
    Authentication,
    /// Digital Signature slot (9c)
    Signature,
    /// Key Management slot (9d)
    KeyManagement,
    /// Card Authentication slot (9e)
    CardAuthentication,
}

impl Slot {
    /// Get the default slot for signing operations
    pub fn default_signing() -> Self {
        Self::Signature
    }

    /// Convert to yubikey crate's SlotId
    pub fn to_yubikey_slot_id(self) -> yubikey::piv::SlotId {
        match self {
            Slot::Authentication => yubikey::piv::SlotId::Authentication,
            Slot::Signature => yubikey::piv::SlotId::Signature,
            Slot::KeyManagement => yubikey::piv::SlotId::KeyManagement,
            Slot::CardAuthentication => yubikey::piv::SlotId::CardAuthentication,
        }
    }

    /// Convert from yubikey crate's SlotId
    ///
    /// # Errors
    ///
    /// Returns `SlotError::Unsupported` if the slot is not supported by ykada
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

/// Errors that can occur when working with slots
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    /// Slot is not supported by ykada
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
