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

/// Generates a test module that runs all standard YubiKey contract tests against a device
/// created by `$make`. Adding a new test to `yubikey_contract` automatically includes it
/// in every caller without any changes at the call site.
///
/// Usage: `run_yubikey_contract_tests!(my_mod, make = || MyDevice::new());`
#[macro_export]
macro_rules! run_yubikey_contract_tests {
    ($mod_name:ident, make = $make:expr) => {
        mod $mod_name {
            use super::*;
            use $crate::ports::contract_tests::yubikey_contract;

            #[test]
            fn test_pin_verification_success() {
                yubikey_contract::test_pin_verification_success(($make)());
            }
            #[test]
            fn test_pin_verification_failure() {
                yubikey_contract::test_pin_verification_failure(($make)());
            }
            #[test]
            fn test_mgmt_key_authentication_success_default() {
                yubikey_contract::test_mgmt_key_authentication_success_default(($make)());
            }
            #[test]
            fn test_mgmt_key_authentication_failure() {
                yubikey_contract::test_mgmt_key_authentication_failure(($make)());
            }
            #[test]
            fn test_import_key_fail_not_authenticated() {
                yubikey_contract::test_import_key_fail_not_authenticated(($make)());
            }
            #[test]
            fn test_import_key_success() {
                yubikey_contract::test_import_key_success(($make)());
            }
            #[test]
            fn test_sign_key_not_found() {
                yubikey_contract::test_sign_key_not_found(($make)());
            }
            #[test]
            fn test_sign_invalid_pin() {
                yubikey_contract::test_sign_invalid_pin(($make)());
            }
            #[test]
            fn test_sign_success() {
                yubikey_contract::test_sign_success(($make)());
            }
            #[test]
            fn test_generate_key_not_authenticated() {
                yubikey_contract::test_generate_key_not_authenticated(($make)());
            }
            #[test]
            fn test_generate_key_success() {
                yubikey_contract::test_generate_key_success(($make)());
            }
            #[test]
            fn test_import_seed_phrase_derived_key() {
                yubikey_contract::test_import_seed_phrase_derived_key(($make)());
            }
        }
    };
}

#[cfg(test)]
pub mod yubikey_contract {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use std::str::FromStr;

    use crate::{
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
            YkadaError::YubikeyLib(yubikey::Error::WrongPin { tries: 2 })
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
        let error = result.unwrap_err();
        assert!(
            matches!(error, YkadaError::AuthenticationFailed { .. }),
            "error: {:?}",
            error
        );
    }

    pub(crate) fn test_import_key_fail_not_authenticated(mut device: impl KeyManager) {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let vk: VerifyingKey = signing_key.verifying_key();
        let config = KeyConfig::default();

        let result = device.import_key(signing_key, vk, config.clone());
        let error = result.unwrap_err();

        assert!(
            matches!(
                error,
                YkadaError::YubikeyLib(yubikey::Error::AuthenticationError)
            ),
            "error: {:?}",
            error
        );
    }

    pub(crate) fn test_import_key_success(mut device: impl KeyManager + ManagementKeyVerifier) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let vk: VerifyingKey = signing_key.verifying_key();
        let config = KeyConfig::default();

        let result = device.import_key(signing_key, vk, config.clone());

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
            YkadaError::YubikeyLib(yubikey::Error::GenericError) => { /* ok */ }
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
            YkadaError::YubikeyLib(yubikey::Error::WrongPin { tries: 2 }) => { /* ok */ }
            other => panic!("expected error: {other:?}"),
        }
    }

    pub(crate) fn test_sign_success(mut device: impl Signer + ManagementKeyVerifier + KeyManager) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let config = KeyConfig {
            touch_policy: TouchPolicy::Never,
            ..Default::default()
        };

        let result = device.import_key(signing_key, verifying_key, config.clone());

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
            YkadaError::AuthenticationFailed { .. }
        ));
    }

    pub(crate) fn test_generate_key_success(
        mut device: impl KeyManager + ManagementKeyVerifier + Signer,
    ) {
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let config = KeyConfig {
            touch_policy: TouchPolicy::Never,
            ..Default::default()
        };
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

        let private_key = child_key.private_key();
        let cardano_vk = child_key.public_key();

        let config = KeyConfig {
            slot: crate::model::Slot::KeyManagement,
            ..KeyConfig::default()
        };

        device
            .import_key(private_key, cardano_vk, config)
            .expect("Failed to import key");
    }
}
