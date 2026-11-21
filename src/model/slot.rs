#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    Signature,
    KeyManagement,
}

use ed25519_dalek::VerifyingKey;

// What a slot holds, as the YubiKey's own key metadata reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKey {
    Empty,
    Ed25519(VerifyingKey),
    // RSA, ECC or X25519: put there by another tool.
    Other,
}

// Fixed wallet layout: payment key in 9c, stake key in 9d.
pub const PAYMENT_SLOT: Slot = Slot::Signature;
pub const STAKE_SLOT: Slot = Slot::KeyManagement;

impl Slot {
    pub fn id(self) -> &'static str {
        match self {
            Slot::Signature => "9c",
            Slot::KeyManagement => "9d",
        }
    }

    pub fn to_yubikey_slot_id(self) -> yubikey::piv::SlotId {
        match self {
            Slot::Signature => yubikey::piv::SlotId::Signature,
            Slot::KeyManagement => yubikey::piv::SlotId::KeyManagement,
        }
    }
}
