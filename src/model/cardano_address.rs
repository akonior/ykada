use crate::logic::{Bech32Encodable, Bech32Error};
use crate::model::Network;
use bech32::ToBase32;

#[derive(Debug)]
pub struct CardanoAddress {
    payment_key_hash: [u8; 28],
    stake_key_hash: [u8; 28],
    network: Network,
}

impl CardanoAddress {
    pub fn from_key_hashes(
        payment_key_hash: [u8; 28],
        stake_key_hash: [u8; 28],
        network: Network,
    ) -> Self {
        Self {
            payment_key_hash,
            stake_key_hash,
            network,
        }
    }

    pub fn to_bytes(&self) -> [u8; 57] {
        let header = match self.network {
            Network::Testnet => 0x00u8,
            Network::Mainnet => 0x01u8,
        };
        let mut bytes = [0u8; 57];
        bytes[0] = header;
        bytes[1..29].copy_from_slice(&self.payment_key_hash);
        bytes[29..57].copy_from_slice(&self.stake_key_hash);
        bytes
    }
}

impl Bech32Encodable for CardanoAddress {
    fn to_bech32(&self) -> Result<String, Bech32Error> {
        let hrp = match self.network {
            Network::Mainnet => "addr",
            Network::Testnet => "addr_test",
        };
        bech32::encode(hrp, self.to_bytes().to_base32(), bech32::Variant::Bech32)
            .map_err(Bech32Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes_testnet_header() {
        let payment_hash = [1u8; 28];
        let stake_hash = [2u8; 28];
        let addr = CardanoAddress::from_key_hashes(payment_hash, stake_hash, Network::Testnet);
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), 57);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(&bytes[1..29], &payment_hash);
        assert_eq!(&bytes[29..57], &stake_hash);
    }

    #[test]
    fn test_to_bytes_mainnet_header() {
        let payment_hash = [1u8; 28];
        let stake_hash = [2u8; 28];
        let addr = CardanoAddress::from_key_hashes(payment_hash, stake_hash, Network::Mainnet);
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), 57);
        assert_eq!(bytes[0], 0x01);
    }

    #[test]
    fn test_bech32_testnet_prefix() {
        let payment_hash = [1u8; 28];
        let stake_hash = [2u8; 28];
        let addr = CardanoAddress::from_key_hashes(payment_hash, stake_hash, Network::Testnet);
        let encoded = addr.to_bech32().unwrap();
        assert!(encoded.starts_with("addr_test1"), "got: {}", encoded);
    }

    #[test]
    fn test_bech32_mainnet_prefix() {
        let payment_hash = [1u8; 28];
        let stake_hash = [2u8; 28];
        let addr = CardanoAddress::from_key_hashes(payment_hash, stake_hash, Network::Mainnet);
        let encoded = addr.to_bech32().unwrap();
        assert!(encoded.starts_with("addr1"), "got: {}", encoded);
    }
}
