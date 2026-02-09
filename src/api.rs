use crate::adapters::PivDeviceFinder;
use crate::error::YkadaResult;
pub use crate::model::*;
use crate::ports::KeyConfig;
use crate::use_cases::{
    generate_key as generate_key_use_case,
    import_private_key_from_seed_phrase as import_private_key_from_seed_phrase_use_case,
    import_private_key_in_der_format as import_private_key_in_der_format_use_case,
};

pub fn generate_key() -> YkadaResult<Ed25519PublicKey> {
    generate_key_with_config(KeyConfig::default(), None)
}

pub fn generate_key_with_config(
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<Ed25519PublicKey> {
    let finder = PivDeviceFinder;
    generate_key_use_case(&finder, config, mgmt_key)
}

pub fn import_private_key_in_der_format(
    der: DerPrivateKey,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<Ed25519PublicKey> {
    let finder = PivDeviceFinder;
    import_private_key_in_der_format_use_case(&finder, der, config, mgmt_key)
}

pub fn import_private_key_from_seed_phrase(
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<Ed25519PublicKey> {
    let finder = PivDeviceFinder;
    import_private_key_from_seed_phrase_use_case(
        &finder,
        seed_phrase,
        passphrase,
        path,
        config,
        mgmt_key,
    )
}
