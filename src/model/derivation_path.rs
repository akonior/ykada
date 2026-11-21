// A fixed CIP-1852 path m/1852'/1815'/0'/role/index as BIP32-Ed25519 child indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivationPath([u32; 5]);

const HARDENED: u32 = 0x8000_0000;
const PURPOSE: u32 = HARDENED | 1852;
const COIN_TYPE: u32 = HARDENED | 1815;
const ACCOUNT_0: u32 = HARDENED;

impl DerivationPath {
    // m/1852'/1815'/0'/0/0 — external payment key.
    pub const PAYMENT: Self = Self([PURPOSE, COIN_TYPE, ACCOUNT_0, 0, 0]);
    // m/1852'/1815'/0'/2/0 — stake key.
    pub const STAKE: Self = Self([PURPOSE, COIN_TYPE, ACCOUNT_0, 2, 0]);

    pub fn indices(&self) -> [u32; 5] {
        self.0
    }
}
