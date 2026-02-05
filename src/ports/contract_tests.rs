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
    use crate::{error::DeviceError, model::Pin, ports::PinVerifier, YkadaError};

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
}
