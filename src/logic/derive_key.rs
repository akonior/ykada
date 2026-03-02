use crate::model::{CardanoKey, DerivationPath, SeedPhrase};
use crate::{Ed25519PrivateKey, YkadaResult};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub fn derive_key_pair(
    seed: &SeedPhrase,
    passphrase: &str,
    path: &DerivationPath,
) -> YkadaResult<(Ed25519PrivateKey, VerifyingKey)> {
    let root = CardanoKey::from_seed_phrase(seed, passphrase)?;
    let derived = root.derive(path);
    let private_key = derived.private_key();
    // Both the real YubiKey (import_cv_key) and FakeYubiKey.sign() treat the imported
    // kL bytes as an Ed25519 seed (RFC 8032): they internally expand via SHA-512 and
    // sign with SHA512_clamped(kL).  The corresponding public key is therefore also
    // derived via RFC 8032, NOT via direct scalar multiplication (kL * G) as the
    // Cardano BIP32-Ed25519 spec would give.  Using the RFC 8032 verifying key here
    // ensures the witness VKey matches the actual signing key on the device.
    let verifying_key = SigningKey::from_bytes(private_key.as_array()).verifying_key();
    Ok((private_key, verifying_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;

    fn derive_private_key(
        seed_phrase: &str,
        passphrase: &str,
        path: Option<&str>,
    ) -> YkadaResult<Ed25519PrivateKey> {
        let seed = SeedPhrase::try_from(seed_phrase)?;
        let derivation_path = match path {
            Some(path_str) => DerivationPath::try_from(path_str)?,
            None => DerivationPath::default(),
        };
        debug!("Deriving key from seed phrase");
        debug!("Derivation path: {:?}", derivation_path);
        let root_key = CardanoKey::from_seed_phrase(&seed, passphrase)?;
        Ok(root_key.derive(&derivation_path).private_key())
    }

    #[test]
    fn test_derive_private_key() {
        let seed_phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let passphrase = "";
        let path = Some("m/1852'/1815'/0'/0/0");

        let result = derive_private_key(seed_phrase, passphrase, path);

        assert!(result.is_ok(), "error: {:?}", result.err());
        assert_eq!(result.unwrap().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_private_key_default_path() {
        let seed_phrase = "test walk nut penalty hip pave soap entry language right filter choice";

        let result = derive_private_key(seed_phrase, "", None);

        assert!(result.is_ok(), "error: {:?}", result.err());
        assert_eq!(result.unwrap().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_private_key_with_passphrase() {
        let seed_phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
        let passphrase = "foo";
        let path = Some("m/1852'/1815'/0'/0/0");

        let result = derive_private_key(seed_phrase, passphrase, path);

        assert!(result.is_ok(), "error: {:?}", result.err());
        assert_eq!(result.unwrap().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_key_pair_payment_path() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();

        let result = derive_key_pair(&seed, "", &path);

        assert!(result.is_ok(), "error: {:?}", result.err());
        let (sk, vk) = result.unwrap();
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(vk.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_key_pair_stake_path() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();

        let result = derive_key_pair(&seed, "", &path);

        assert!(result.is_ok(), "error: {:?}", result.err());
        let (sk, vk) = result.unwrap();
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(vk.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_key_pair_deterministic() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();

        let (_, vk1) = derive_key_pair(&seed, "", &path).unwrap();
        let (_, vk2) = derive_key_pair(&seed, "", &path).unwrap();
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    }
}
