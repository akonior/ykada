use crate::model::{CardanoKey, DerivationPath, SeedPhrase};
use crate::YkadaResult;
use ed25519_dalek::SigningKey;

pub(crate) fn derive_signing_key(
    seed: &SeedPhrase,
    path: &DerivationPath,
) -> YkadaResult<SigningKey> {
    let root = CardanoKey::from_seed_phrase(seed, "")?;
    Ok(root.derive(path).private_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_signing_key_payment_path() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();

        let sk = derive_signing_key(&seed, &path).unwrap();
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(sk.verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_signing_key_stake_path() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();

        let sk = derive_signing_key(&seed, &path).unwrap();
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(sk.verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_signing_key_deterministic() {
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let seed = SeedPhrase::try_from(phrase).unwrap();
        let path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();

        let vk1 = derive_signing_key(&seed, &path).unwrap().verifying_key();
        let vk2 = derive_signing_key(&seed, &path).unwrap().verifying_key();
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    }
}
