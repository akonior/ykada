use crate::error::YkadaResult;
use crate::model::ManagementKey;
use crate::ports::{DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier};
use crate::Ed25519PublicKey;

pub fn generate_key_use_case<F>(
    finder: &F,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<Ed25519PublicKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + crate::ports::ManagementKeyVerifier,
{
    let mut device = finder.find_first()?;

    device.authenticate(mgmt_key)?;

    device.generate_key(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::error::DeviceError;
    use crate::model::{ManagementKey, Pin};
    use crate::YkadaError;

    #[test]
    fn test_generate_key_success() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let config = KeyConfig::default();
        let mgmt_key = ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);
        let result = generate_key_use_case(&finder, config, Some(&mgmt_key));

        assert!(result.is_ok(), "error: {:?}", result.err());
        let verifying_key = result.unwrap();
        assert_eq!(verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_generate_key_device_not_found() {
        let finder = FakeDeviceFinder { device: None };
        let config = KeyConfig::default();
        let result = generate_key_use_case(&finder, config, None);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::NotFound)
        ));
    }

    #[test]
    fn test_generate_key_authentication_failed() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let config = KeyConfig::default();
        let wrong_mgmt_key = ManagementKey::new([1u8; 24]);
        let result = generate_key_use_case(&finder, config, Some(&wrong_mgmt_key));

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }
}
