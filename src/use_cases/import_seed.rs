
use crate::model::{CardanoKey, DerivationPath, SeedPhrase};
use crate::ports::{DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier};
use crate::{ManagementKey, YkadaResult};
use tracing::debug;

pub fn import_private_key_from_seed_phrase<F>(
    finder: &F,
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<ed25519_dalek::VerifyingKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + ManagementKeyVerifier,
{
    let seed = SeedPhrase::try_from(seed_phrase)?;

    let derivation_path = if let Some(path_str) = path {
        DerivationPath::try_from(path_str)?
    } else {
        DerivationPath::default()
    };

    debug!("Deriving key from seed phrase");
    debug!("Derivation path: {:?}", derivation_path);

    let root_key = CardanoKey::from_seed_phrase(&seed, passphrase)?;

    let child_key = root_key.derive(&derivation_path);

    let piv_key = child_key.to_piv_key();

    let mut device = finder.find_first()?;
    device.authenticate(mgmt_key)?;

    device.import_key(piv_key, config)?;

    debug!("Key imported successfully");
    Ok(child_key.verifying_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::model::Pin;

    #[test]
    fn test_import_from_seed_phrase() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let seed_phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let passphrase = "";
        let path = Some("m/1852'/1815'/0'/0/0");
        let config = crate::ports::KeyConfig::default();
        let mgmt_key = crate::model::ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        let result = import_private_key_from_seed_phrase(
            &finder,
            seed_phrase,
            passphrase,
            path,
            config,
            Some(&mgmt_key),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
        let verifying_key = result.unwrap();
        assert_eq!(verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_import_from_seed_phrase_with_passphrase() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let seed_phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
        let passphrase = "foo";
        let path = Some("m/1852'/1815'/0'/0/0");
        let config = crate::ports::KeyConfig::default();
        let mgmt_key = crate::model::ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        let result = import_private_key_from_seed_phrase(
            &finder,
            seed_phrase,
            passphrase,
            path,
            config,
            Some(&mgmt_key),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    #[test]
    fn test_import_from_seed_phrase_default_path() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let seed_phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let passphrase = "";
        let config = crate::ports::KeyConfig::default();
        let mgmt_key = crate::model::ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        let result = import_private_key_from_seed_phrase(
            &finder,
            seed_phrase,
            passphrase,
            None,
            config,
            Some(&mgmt_key),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
    }
}
