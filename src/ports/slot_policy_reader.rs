use crate::error::YkadaResult;
use crate::model::{PinPolicy, Slot, TouchPolicy};

pub(crate) trait SlotPolicyReader {
    fn read_slot_policy(&mut self, slot: Slot) -> YkadaResult<(PinPolicy, TouchPolicy)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::FakeYubiKey;
    use crate::model::{ManagementKey, Pin};
    use crate::ports::{KeyConfig, KeyManager, ManagementKeyVerifier};

    const TESTING_MANAGEMENT_KEY: ManagementKey = ManagementKey::new([
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
    ]);

    #[test]
    fn test_read_slot_policy_returns_always_after_import_with_those_policies() {
        let mut device = FakeYubiKey::new(Pin::default());
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("auth failed");

        let config = KeyConfig {
            pin_policy: PinPolicy::Always,
            touch_policy: TouchPolicy::Always,
            ..KeyConfig::default()
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let vk = signing_key.verifying_key();
        device
            .import_key(signing_key, vk, config)
            .expect("import failed");

        let (pin_policy, touch_policy) = device
            .read_slot_policy(Slot::Signature)
            .expect("read_slot_policy failed");

        assert_eq!(pin_policy, PinPolicy::Always);
        assert_eq!(touch_policy, TouchPolicy::Always);
    }

    #[test]
    fn test_read_slot_policy_returns_never_when_no_key_imported() {
        let mut device = FakeYubiKey::new(Pin::default());
        let (pin_policy, touch_policy) = device
            .read_slot_policy(Slot::Signature)
            .expect("read_slot_policy failed");

        assert_eq!(pin_policy, PinPolicy::Never);
        assert_eq!(touch_policy, TouchPolicy::Never);
    }
}
