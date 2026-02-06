use crate::ports::{KeyConfig, ManagementKeyVerifier};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::debug;

use crate::ports::{DeviceFinder, KeyManager};
use crate::{DerPrivateKey, ManagementKey, YkadaResult};

pub fn import_private_key_in_der_format<F>(
    finder: &F,
    der: DerPrivateKey,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + ManagementKeyVerifier,
{
    let d: &[u8] = der.0.as_slice();
    let signing_key =
        SigningKey::from_pkcs8_der(d).expect("Failed to parse DER as Ed25519 private key");

    debug!("Imported private key from DER: {:?}", signing_key);

    let mut device = finder.find_first()?;

    device.authenticate(mgmt_key).unwrap();

    device.import_key(signing_key.clone(), config)?;

    debug!("Loaded private key to YubiKey");

    Ok(signing_key.verifying_key())
}
