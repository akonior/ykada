use crate::error::{YkadaError, YkadaResult};
use crate::model::{Algorithm, Pin, Slot};
use crate::ports::Signer;

pub(super) struct SignDataParams {
    pub slot: Slot,
    pub pin: Option<Pin>,
}

pub(super) fn sign_data_use_case<S: Signer>(
    signer: &mut S,
    data: &[u8],
    params: SignDataParams,
) -> YkadaResult<[u8; 64]> {
    signer
        .sign(data, params.slot, Algorithm::Ed25519, params.pin.as_ref())
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|v: Vec<u8>| YkadaError::InvalidSignatureLength { actual: v.len() })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::FakeYubiKey;
    use crate::model::{Pin, Slot};
    use crate::ports::{KeyConfig, KeyManager, ManagementKeyVerifier};
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};

    fn yubikey_with_key(signing_key: SigningKey) -> FakeYubiKey {
        let mut yk = FakeYubiKey::new(Pin::default());
        yk.authenticate(None).unwrap();
        let vk = signing_key.verifying_key();
        yk.import_key(
            signing_key,
            vk,
            KeyConfig {
                slot: Slot::Signature,
                pin_policy: crate::model::PinPolicy::Never,
                touch_policy: crate::model::TouchPolicy::Never,
            },
        )
        .unwrap();
        yk
    }

    #[test]
    fn sign_returns_64_bytes() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let mut yk = yubikey_with_key(sk);
        let result = sign_data_use_case(
            &mut yk,
            b"hello",
            SignDataParams {
                slot: Slot::Signature,
                pin: None,
            },
        );
        assert!(result.is_ok());
        let sig = result.unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_produces_valid_ed25519_signature() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let vk: VerifyingKey = sk.verifying_key();
        let mut yk = yubikey_with_key(sk);
        let data = b"cardano transaction";

        let sig_bytes = sign_data_use_case(
            &mut yk,
            data,
            SignDataParams {
                slot: Slot::Signature,
                pin: None,
            },
        )
        .unwrap();

        let signature = Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(data, &signature).is_ok());
    }

    #[test]
    fn sign_missing_key_returns_error() {
        let mut yk = FakeYubiKey::new(Pin::default());
        let result = sign_data_use_case(
            &mut yk,
            b"data",
            SignDataParams {
                slot: Slot::Signature,
                pin: None,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn sign_wrong_pin_returns_error() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let mut yk = yubikey_with_key(sk);
        let wrong_pin = "999999".parse::<Pin>().unwrap();
        let result = sign_data_use_case(
            &mut yk,
            b"data",
            SignDataParams {
                slot: Slot::Signature,
                pin: Some(wrong_pin),
            },
        );
        assert!(result.is_err());
    }
}
