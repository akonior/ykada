#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    Signature,
    KeyManagement,
}

// Fixed wallet layout: payment key in 9c, stake key in 9d.
pub const PAYMENT_SLOT: Slot = Slot::Signature;
pub const STAKE_SLOT: Slot = Slot::KeyManagement;

impl Slot {
    pub fn to_yubikey_slot_id(self) -> yubikey::piv::SlotId {
        match self {
            Slot::Signature => yubikey::piv::SlotId::Signature,
            Slot::KeyManagement => yubikey::piv::SlotId::KeyManagement,
        }
    }
}
