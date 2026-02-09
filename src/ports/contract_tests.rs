#[macro_export]
macro_rules! contract_tests_for {
      (
          $mod_name:ident,
          make = $make:expr,
          tests = {
            $( $test_name:ident => $tmpl:path ),+ $(,)?
        }
      ) => {
          mod $mod_name {
              use super::*;

              $(
                  #[test]
                  fn $test_name() {
                      let op = ($make)();
                      $tmpl(op);
                  }
              )+
          }
      };
  }

#[cfg(test)]
pub mod yubikey_contract {
    use ed25519_dalek::{SecretKey, SigningKey};

    use crate::{
        error::{CryptoError, DeviceError},
        model::{Algorithm, ManagementKey, Pin, Slot, TouchPolicy},
        ports::{KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer},
        CardanoKey, DerivationPath, SeedPhrase, YkadaError,
    };

    const TESTING_MANAGEMENT_KEY: ManagementKey = ManagementKey::new([
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
    ]);

    pub(crate) fn test_pin_verification_success(mut device: impl PinVerifier) {
        assert!(device.verify_pin(&Pin::default()).is_ok());
    }

    pub(crate) fn test_pin_verification_failure(mut device: impl PinVerifier) {
        let wrong_pin = Pin::from_str("999999").unwrap();

        let result = device.verify_pin(&wrong_pin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::PinVerificationFailed { .. })
        ));
    }

    pub(crate) fn test_mgmt_key_authentication_success_default(
        mut device: impl ManagementKeyVerifier,
    ) {
        let result = device.authenticate(Some(&TESTING_MANAGEMENT_KEY));

        assert!(result.is_ok());
    }

    pub(crate) fn test_mgmt_key_authentication_failure(mut device: impl ManagementKeyVerifier) {
        let wrong_mgmt_key = ManagementKey::new([1u8; 24]);

        let result = device.authenticate(Some(&wrong_mgmt_key));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    pub(crate) fn test_import_key_fail_not_authenticated(mut device: impl KeyManager) {
        let secret_key = SecretKey::from([0u8; 32]);
        let config = KeyConfig::default();

        let result = device.import_key(secret_key, config.clone());

        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    pub(crate) fn test_import_key_success(mut device: impl KeyManager + ManagementKeyVerifier) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let secret_key = SecretKey::from([0u8; 32]);
        let config = KeyConfig::default();

        let result = device.import_key(secret_key, config.clone());

        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    pub(crate) fn test_sign_key_not_found(mut device: impl Signer) {
        let empty_slot = Slot::Authentication;
        let result = device.sign(
            b"test data",
            empty_slot,
            Algorithm::default_cardano(),
            Some(&Pin::default()),
        );

        match result.unwrap_err() {
            YkadaError::Crypto(CryptoError::SignatureFailed { .. }) => { /* ok */ }
            other => panic!("expected error: {other:?}"),
        }
    }

    pub(crate) fn test_sign_invalid_pin(mut device: impl Signer) {
        let result = device.sign(
            b"test data",
            Slot::Signature,
            Algorithm::default_cardano(),
            Some(&Pin::from_str("999999").unwrap()),
        );

        match result.unwrap_err() {
            YkadaError::Device(DeviceError::PinVerificationFailed { .. }) => { /* ok */ }
            other => panic!("expected error: {other:?}"),
        }
    }

    pub(crate) fn test_sign_success(mut device: impl Signer + ManagementKeyVerifier + KeyManager) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let secret_bytes = [0u8; 32];
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let secret_key = SecretKey::from(*signing_key.as_bytes());

        let mut config = KeyConfig::default();
        config.touch_policy = TouchPolicy::Never;

        let result = device.import_key(secret_key, config.clone());

        assert!(result.is_ok(), "error: {:?}", result.err());

        let data = b"test data";
        let result = device.sign(
            data,
            config.slot,
            Algorithm::default_cardano(),
            Some(&Pin::default()),
        );

        assert!(result.is_ok());

        let signature_bytes = result.unwrap();
        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| "Invalid signature length")
            .expect("Invalid signature length");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        verifying_key
            .verify_strict(data, &signature)
            .expect("Signature verification failed");
    }

    pub(crate) fn test_generate_key_not_authenticated(mut device: impl KeyManager) {
        let config = KeyConfig::default();
        let result = device.generate_key(config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    pub(crate) fn test_generate_key_success(
        mut device: impl KeyManager + ManagementKeyVerifier + Signer,
    ) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let mut config = KeyConfig::default();
        config.touch_policy = TouchPolicy::Never;
        let result = device.generate_key(config.clone());

        assert!(result.is_ok(), "error: {:?}", result.err());
        let verifying_key = result.unwrap();
        assert_eq!(verifying_key.as_bytes().len(), 32);

        let pin = Pin::default();
        let data = b"test data";
        let sign_result = device.sign(data, config.slot, Algorithm::default_cardano(), Some(&pin));

        assert!(sign_result.is_ok(), "error: {:?}", sign_result.err());
        let signature_bytes = sign_result.unwrap();
        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| "Invalid signature length")
            .expect("Invalid signature length");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        verifying_key
            .verify_strict(data, &signature)
            .expect("Signature verification failed");
    }

    pub(crate) fn test_import_seed_phrase_derived_key(
        mut device: impl KeyManager + ManagementKeyVerifier + Signer,
    ) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let seed_phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
        let seed = SeedPhrase::try_from(seed_phrase).expect("Invalid seed phrase");

        let root_key =
            CardanoKey::from_seed_phrase(&seed, "").expect("Failed to generate root key");
        let path =
            DerivationPath::try_from("m/1852'/1815'/0'/0/0").expect("Invalid derivation path");
        let child_key = root_key.derive(&path);

        child_key.public_key();
        let piv_key = child_key.to_piv_key();

        let config = KeyConfig {
            slot: crate::model::Slot::KeyManagement,
            ..KeyConfig::default()
        };

        device
            .import_key(piv_key, config)
            .expect("Failed to import key");
    }
}
