use crate::model::{CardanoAddress, SeedPhrase};
use ed25519_dalek::VerifyingKey;

#[derive(Debug)]
pub struct GeneratedWallet {
    pub mnemonic: SeedPhrase,
    pub payment_vk: VerifyingKey,
    pub stake_vk: VerifyingKey,
    pub address: CardanoAddress,
}
