use ed25519_dalek::VerifyingKey;
use pallas_addresses::ShelleyAddress;

#[derive(Debug)]
pub struct WalletInfo {
    pub payment_vk: Option<VerifyingKey>,
    pub address: Option<ShelleyAddress>,
}
