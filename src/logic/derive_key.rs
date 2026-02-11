use crate::model::{CardanoKey, DerivationPath, SeedPhrase};
use crate::{Ed25519PrivateKey, YkadaResult};
use tracing::debug;

pub fn derive_private_key(
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
) -> YkadaResult<Ed25519PrivateKey> {
    let seed = SeedPhrase::try_from(seed_phrase)?;

    let derivation_path = if let Some(path_str) = path {
        DerivationPath::try_from(path_str)?
    } else {
        DerivationPath::default()
    };

    debug!("Deriving key from seed phrase");
    debug!("Derivation path: {:?}", derivation_path);

    let root_key = CardanoKey::from_seed_phrase(&seed, passphrase)?;
    let derived_key = root_key.derive(&derivation_path);

    Ok(derived_key.private_key())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
