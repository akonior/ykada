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
        model::Pin,
        ports::{PinVerifier, YubiKeyOps},
    };

    pub(crate) fn test_pin_verification_success(mut device: impl YubiKeyOps) {
        assert!(device.verify_pin(&Pin::default()).is_ok());
    }

    pub(crate) fn test_pin_verification_failure(mut device: impl PinVerifier) {
        let wrong_pin = Pin::from_str("999999").unwrap();
        assert!(device.verify_pin(&wrong_pin).is_err());
    }
}
