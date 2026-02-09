//! Cardano key derivation using BIP32-Ed25519 (CIP-1852) and Icarus master key generation (CIP-3)

use ed25519_bip32::{DerivationScheme, XPrv};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use thiserror::Error;

use crate::model::{DerivationPath, PublicKey, SeedPhrase};

/// Cardano extended private key (96 bytes: 64-byte extended secret + 32-byte chain code)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoKey(XPrv);

/// Errors that can occur during Cardano key operations
#[derive(Error, Debug)]
#[error("Cardano key error")]
pub struct CardanoKeyError {
    #[from]
    source: ed25519_bip32::PrivateKeyError,
}

impl CardanoKey {
    /// Generate a root Cardano key from a seed phrase using the Icarus method (CIP-3)
    ///
    /// This implements the Icarus master key generation algorithm:
    /// - PBKDF2-HMAC-SHA512 with 4096 iterations
    /// - Salt = raw entropy bytes from mnemonic
    /// - Password = passphrase (UTF-8 bytes)
    /// - Output = 96 bytes, then normalized with Ed25519 bit tweaks
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed phrase (BIP39 mnemonic)
    /// * `passphrase` - Optional passphrase (empty string if none)
    ///
    /// # Errors
    ///
    /// Returns an error if the key normalization fails
    pub fn from_seed_phrase(seed: &SeedPhrase, passphrase: &str) -> Result<Self, CardanoKeyError> {
        let entropy = seed.entropy();
        let mut output = [0u8; 96];

        // Icarus method: PBKDF2 with entropy as salt, passphrase as password
        pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), &entropy, 4096, &mut output);

        // Normalize with Ed25519 bit tweaks (clears bits 0-2, sets bit 254, clears bit 255, clears 3rd highest bit)
        let root_key = XPrv::normalize_bytes_force3rd(output);
        Ok(CardanoKey(root_key))
    }

    /// Derive a child key along the given derivation path using BIP32-Ed25519 (CIP-1852)
    ///
    /// # Arguments
    ///
    /// * `path` - The derivation path (e.g., "m/1852'/1815'/0'/0/0")
    ///
    /// # Example
    ///
    /// ```
    /// use ykada::model::{CardanoKey, SeedPhrase, DerivationPath};
    ///
    /// let seed = SeedPhrase::try_from("test walk nut penalty hip pave soap entry language right filter choice").unwrap();
    /// let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();
    /// let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
    /// let child = root.derive(&path);
    /// ```
    pub fn derive(&self, path: &DerivationPath) -> Self {
        let indices = path.indices();
        let derived_key = indices.iter().fold(self.0.clone(), |key, &index| {
            key.derive(DerivationScheme::V2, index)
        });
        CardanoKey(derived_key)
    }

    /// Extract the 32-byte Ed25519 public key
    ///
    /// # Example
    ///
    /// ```
    /// use ykada::model::{CardanoKey, SeedPhrase};
    ///
    /// let seed = SeedPhrase::try_from("test walk nut penalty hip pave soap entry language right filter choice").unwrap();
    /// let key = CardanoKey::from_seed_phrase(&seed, "").unwrap();
    /// let public_key = key.public_key();
    /// ```
    pub fn public_key(&self) -> PublicKey {
        let xpub = self.0.public();
        let pub_bytes = xpub.public_key_bytes();
        PublicKey::from_slice(pub_bytes).expect("XPub public_key_bytes() always returns 32 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DerivationPath;
    use hex;

    // CIP-3 Icarus test vectors
    const CIP3_MNEMONIC: &str = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    const CIP3_ROOT_KEY_NO_PASSPHRASE: &str = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620";
    const CIP3_ROOT_KEY_WITH_PASSPHRASE: &str = "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e";

    #[test]
    fn test_icarus_root_key_no_passphrase() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        // Verify the root key matches the CIP-3 test vector
        // XPrv layout: [0..64] = extended secret key, [64..96] = chain code
        let expected_root_bytes = hex::decode(CIP3_ROOT_KEY_NO_PASSPHRASE).unwrap();
        let root_bytes = root.0.extended_secret_key_bytes();
        let chain_code = root.0.chain_code();

        // Reconstruct the 96-byte key: extended secret (64 bytes) + chain code (32 bytes)
        let mut reconstructed = Vec::with_capacity(96);
        reconstructed.extend_from_slice(root_bytes);
        reconstructed.extend_from_slice(chain_code);

        assert_eq!(reconstructed, expected_root_bytes);
    }

    #[test]
    fn test_icarus_root_key_with_passphrase() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "foo").unwrap();

        // Verify the root key matches the CIP-3 test vector with passphrase "foo"
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

        // Derive payment key: m/1852'/1815'/0'/0/0
        let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let payment_key = root.derive(&path);

        // Verify we can extract a public key
        let pub_key = payment_key.public_key();
        assert_eq!(pub_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_staking_key() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        // Derive staking key: m/1852'/1815'/0'/2/0
        let path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();
        let staking_key = root.derive(&path);

        let pub_key = staking_key.public_key();
        assert_eq!(pub_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_change_key() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        // Derive change key: m/1852'/1815'/0'/1/0
        let path = DerivationPath::try_from("m/1852'/1815'/0'/1/0").unwrap();
        let change_key = root.derive(&path);

        let pub_key = change_key.public_key();
        assert_eq!(pub_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_multiple_addresses() {
        let seed = SeedPhrase::try_from(CIP3_MNEMONIC).unwrap();
        let root = CardanoKey::from_seed_phrase(&seed, "").unwrap();

        // Derive multiple payment addresses
        let path0 = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let path1 = DerivationPath::try_from("m/1852'/1815'/0'/0/1").unwrap();
        let path2 = DerivationPath::try_from("m/1852'/1815'/0'/0/2").unwrap();

        let key0 = root.derive(&path0);
        let key1 = root.derive(&path1);
        let key2 = root.derive(&path2);

        // All should produce different public keys
        let pub0 = key0.public_key();
        let pub1 = key1.public_key();
        let pub2 = key2.public_key();

        assert_ne!(pub0.as_bytes(), pub1.as_bytes());
        assert_ne!(pub1.as_bytes(), pub2.as_bytes());
        assert_ne!(pub0.as_bytes(), pub2.as_bytes());
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

        // Verify public key is deterministic
        let pub_key2 = root.public_key();
        assert_eq!(pub_key.as_bytes(), pub_key2.as_bytes());
    }
}
