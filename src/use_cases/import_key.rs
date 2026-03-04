use crate::logic::check_firmware_version;
use crate::ports::{DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier};
use crate::{DerPrivateKey, ManagementKey, YkadaResult};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::debug;

pub fn import_private_key_in_der_format_use_case<F>(
    finder: &F,
    der: DerPrivateKey,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + ManagementKeyVerifier + DeviceReader,
{
    let signing_key = SigningKey::from_pkcs8_der(der.0.as_slice())?;
    let secret_key = signing_key.as_bytes();

    debug!("Imported private key from DER: {:?}", signing_key);

    let mut device = finder.find_first()?;
    check_firmware_version(device.firmware_version())?;

    device.authenticate(mgmt_key)?;

    device.import_key(secret_key.into(), signing_key.verifying_key(), config)?;

    debug!("Loaded private key to YubiKey");

    Ok(signing_key.verifying_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::model::Pin;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SecretKey;

    #[test]
    fn test_import_private_key_success() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let secret_bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let expected_verifying_key = signing_key.verifying_key();
        let der_bytes = signing_key.to_pkcs8_der().unwrap();
        let der_key = DerPrivateKey(der_bytes.as_bytes().to_vec());

        let config = KeyConfig::default();
        let mgmt_key = ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        let result =
            import_private_key_in_der_format_use_case(&finder, der_key, config, Some(&mgmt_key));

        assert!(result.is_ok(), "error: {:?}", result.err());
        let verifying_key = result.unwrap();
        assert_eq!(verifying_key, expected_verifying_key);
    }
}
