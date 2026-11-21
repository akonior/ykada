use crate::model::CardanoAddress;
use ed25519_dalek::VerifyingKey;

#[derive(Debug)]
pub struct WalletInfo {
    pub serial: u32,
    pub firmware: (u8, u8, u8),
    pub payment_vk: Option<VerifyingKey>,
    pub stake_vk: Option<VerifyingKey>,
    pub address: Option<CardanoAddress>,
}
