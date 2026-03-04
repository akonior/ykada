use ed25519_bip32::{DerivationScheme, XPrv};
use ed25519_dalek::VerifyingKey;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use thiserror::Error;

use crate::model::{DerivationPath, Ed25519PrivateKey, SeedPhrase};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoKey(XPrv);

#[derive(Error, Debug)]
#[error("Cardano key error")]
pub struct CardanoKeyError {
    #[from]
    source: ed25519_bip32::PrivateKeyError,
}

impl CardanoKey {
    pub fn from_seed_phrase(seed: &SeedPhrase, passphrase: &str) -> Result<Self, CardanoKeyError> {
        let entropy = seed.entropy();
        let mut output = [0u8; 96];

        pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), &entropy, 4096, &mut output);

        let root_key = XPrv::normalize_bytes_force3rd(output);
        Ok(CardanoKey(root_key))
    }

    pub fn derive(&self, path: &DerivationPath) -> Self {
        let derived_key = path.indices().iter().fold(self.0.clone(), |key, &index| {
            key.derive(DerivationScheme::V2, index)
        });
        CardanoKey(derived_key)
    }

    pub fn public_key(&self) -> VerifyingKey {
        let arr: [u8; 32] = *self.0.public().public_key_bytes();
        VerifyingKey::from_bytes(&arr).expect("XPub public_key_bytes() is a valid Ed25519 point")
    }

    pub fn private_key(&self) -> Ed25519PrivateKey {
        let extended_secret = self.0.extended_secret_key_bytes();
        let mut k_l = [0u8; 32];
        k_l.copy_from_slice(&extended_secret[..32]);
        Ed25519PrivateKey::from(k_l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DerivationPath;

    const CIP3_MNEMONIC: &str = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    const CIP3_ROOT_KEY_NO_PASSPHRASE: &str = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620";
    const CIP3_ROOT_KEY_WITH_PASSPHRASE: &str = "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e";

    #[test]
    fn test_icarus_root_key_no_passphrase() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        let expected_root_bytes = hex::decode(CIP3_ROOT_KEY_NO_PASSPHRASE).unwrap();
        let root_bytes = root.0.extended_secret_key_bytes();
        let chain_code = root.0.chain_code();

        let mut reconstructed = Vec::with_capacity(96);
        reconstructed.extend_from_slice(root_bytes);
        reconstructed.extend_from_slice(chain_code);

        assert_eq!(reconstructed, expected_root_bytes);
    }

    #[test]
    fn test_icarus_root_key_with_passphrase() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "foo").unwrap();

        let expected_root_bytes = hex::decode(CIP3_ROOT_KEY_WITH_PASSPHRASE).unwrap();
        let root_bytes = root.0.extended_secret_key_bytes();
        let chain_code = root.0.chain_code();

        let mut reconstructed = Vec::with_capacity(96);
        reconstructed.extend_from_slice(root_bytes);
        reconstructed.extend_from_slice(chain_code);

        assert_eq!(reconstructed, expected_root_bytes);
    }

    #[test]
    fn test_derive_payment_key() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();
        let payment_key = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap());
        assert_eq!(payment_key.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_staking_key() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();
        let staking_key = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap());
        assert_eq!(staking_key.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_change_key() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();
        let change_key = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/1/0").unwrap());
        assert_eq!(change_key.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_multiple_addresses() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        let key0 = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap());
        let key1 = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/0/1").unwrap());
        let key2 = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/0/2").unwrap());

        assert_ne!(key0.public_key().as_bytes(), key1.public_key().as_bytes());
        assert_ne!(key1.public_key().as_bytes(), key2.public_key().as_bytes());
        assert_ne!(key0.public_key().as_bytes(), key2.public_key().as_bytes());
    }

    #[test]
    fn test_public_key_extraction() {
        let seed = SeedPhrase::try_from(
            "test walk nut penalty hip pave soap entry language right filter choice",
        )
        .unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        let pub_key = root.public_key();
        assert_eq!(pub_key.as_bytes().len(), 32);
        assert_eq!(pub_key.as_bytes(), root.public_key().as_bytes());
    }

    #[test]
    fn test_xprv_to_xpub_vs_piv_key_round_trip() {
        let seed = SeedPhrase::try_from(
            "test walk nut penalty hip pave soap entry language right filter choice",
        )
        .unwrap();

        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();
        test_public_key_consistency(&root, "root key");

        let derived = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap());
        test_public_key_consistency(&derived, "derived key");

        let staking_key = root.derive(&DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap());
        test_public_key_consistency(&staking_key, "staking key");

        let root_with_passphrase = CardanoKey::from_seed_phrase(&seed, "foo").unwrap();
        test_public_key_consistency(&root_with_passphrase, "root key with passphrase");
    }

    fn test_public_key_consistency(cardano_key: &CardanoKey, context: &str) {
        let xpub_bytes = cardano_key.public_key();
        let extended_secret = cardano_key.0.extended_secret_key_bytes();
        let chain_code = cardano_key.0.chain_code();

        let mut reconstructed_extended = [0u8; 64];
        reconstructed_extended[..32].copy_from_slice(&extended_secret[..32]);
        reconstructed_extended[32..].copy_from_slice(&extended_secret[32..64]);

        let reconstructed_xprv =
            XPrv::from_extended_and_chaincode(&reconstructed_extended, chain_code);
        let reconstructed_xpub = reconstructed_xprv.public();

        assert_eq!(
            xpub_bytes.as_bytes(),
            reconstructed_xpub.public_key_bytes().as_slice(),
            "Public key mismatch for {}: XPub = {}, Reconstructed = {}",
            context,
            hex::encode(xpub_bytes.as_bytes()),
            hex::encode(reconstructed_xpub.public_key_bytes())
        );
    }
}
