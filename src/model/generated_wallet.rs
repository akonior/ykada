use crate::model::SeedPhrase;
use pallas_addresses::ShelleyAddress;

#[derive(Debug)]
pub struct GeneratedWallet {
    pub mnemonic: SeedPhrase,
    pub address: ShelleyAddress,
}
