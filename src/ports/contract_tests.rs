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
    use crate::{
        error::DeviceError,
        model::{ManagementKey, Pin},
        ports::{ManagementKeyVerifier, PinVerifier},
        YkadaError,
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
}
