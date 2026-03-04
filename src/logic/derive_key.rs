use crate::model::{CardanoKey, DerivationPath, SeedPhrase};
use crate::YkadaResult;
use ed25519_dalek::SigningKey;

pub fn derive_key_pair(
    seed: &SeedPhrase,
    passphrase: &str,
    path: &DerivationPath,
) -> YkadaResult<SigningKey> {
    let root = CardanoKey::from_seed_phrase(seed, passphrase)?;
    // Both the real YubiKey (import_cv_key) and FakeYubiKey.sign() treat the imported
    // kL bytes as an Ed25519 seed (RFC 8032): they internally expand via SHA-512 and
    // sign with SHA512_clamped(kL).  The corresponding public key is therefore also
    // derived via RFC 8032, NOT via direct scalar multiplication (kL * G) as the
    // Cardano BIP32-Ed25519 spec would give.  Using the RFC 8032 verifying key here
    // ensures the witness VKey matches the actual signing key on the device.
    Ok(root.derive(path).private_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;

    fn derive_private_key(
        seed_phrase: &str,
        passphrase: &str,
        path: Option<&str>,
    ) -> YkadaResult<SigningKey> {
        let seed = SeedPhrase::try_from(seed_phrase)?;
        let derivation_path = match path {
            Some(path_str) => DerivationPath::try_from(path_str)?,
            None => DerivationPath::default(),
        };
        debug!("Deriving key from seed phrase");
        debug!("Derivation path: {:?}", derivation_path);
        derive_key_pair(&seed, passphrase, &derivation_path)
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
        let sk = result.unwrap();
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(sk.verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_key_pair_stake_path() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();

        let result = derive_key_pair(&seed, "", &path);

        assert!(result.is_ok(), "error: {:?}", result.err());
        let sk = result.unwrap();
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(sk.verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_key_pair_deterministic() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();

        let vk1 = derive_key_pair(&seed, "", &path).unwrap().verifying_key();
        let vk2 = derive_key_pair(&seed, "", &path).unwrap().verifying_key();
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    }
}
