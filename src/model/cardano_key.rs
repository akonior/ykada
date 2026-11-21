use ed25519_bip32::{DerivationScheme, XPrv};
use ed25519_dalek::SigningKey;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

use crate::model::{DerivationPath, SeedPhrase};

// No Debug: XPrv's Debug prints the extended private key.
pub struct CardanoKey(XPrv);

impl CardanoKey {
    pub fn from_seed_phrase(seed: &SeedPhrase) -> Self {
        let entropy = seed.entropy();
        let mut output = [0u8; 96];

        pbkdf2_hmac::<Sha512>(b"", &entropy, 4096, &mut output);

        CardanoKey(XPrv::normalize_bytes_force3rd(output))
    }

    pub fn derive(&self, path: &DerivationPath) -> Self {
        let derived_key = path.indices().iter().fold(self.0.clone(), |key, &index| {
            key.derive(DerivationScheme::V2, index)
        });
        CardanoKey(derived_key)
    }

    // kL as an RFC-8032 seed, because that is all PIV can import. The device hashes it again,
    // so the public key is clamp(SHA-512(kL))*G, not BIP32-Ed25519's kL*G (see docs/keys-and-addresses.md).
    pub fn private_key(&self) -> SigningKey {
        let extended_secret = self.0.extended_secret_key_bytes();
        let mut k_l = [0u8; 32];
        k_l.copy_from_slice(&extended_secret[..32]);
        SigningKey::from_bytes(&k_l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DerivationPath;

    const CIP3_MNEMONIC: &str = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    const CIP3_ROOT_KEY: &str = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620";

    #[test]
    fn test_icarus_root_key() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed);

        let expected_root_bytes = hex::decode(CIP3_ROOT_KEY).unwrap();
        let root_bytes = root.0.extended_secret_key_bytes();
        let chain_code = root.0.chain_code();

        let mut reconstructed = Vec::with_capacity(96);
        reconstructed.extend_from_slice(root_bytes);
        reconstructed.extend_from_slice(chain_code);

        assert_eq!(reconstructed, expected_root_bytes);
    }

    #[test]
    fn test_derive_distinct_keys_per_path() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed);
        let vk = |path: &DerivationPath| root.derive(path).private_key().verifying_key();
        assert_ne!(vk(&DerivationPath::PAYMENT), vk(&DerivationPath::STAKE));
    }
}
