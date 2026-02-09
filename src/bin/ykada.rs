use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use hex;
use std::io::{self, Read, Write};
use tracing::error;

use ykada::{
    api::{PinPolicy, Slot, TouchPolicy},
    DerPrivateKey,
};

#[derive(Parser, Debug)]
#[command(name = "ykada")]
#[command(about = "YubiKey Cardano wallet", version)]
pub struct Cli {
    #[command(flatten)]
    pub verbosity: Verbosity<WarnLevel>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Load a private key (DER) into YubiKey
    ImportKey {
        #[command(flatten)]
        key_options: KeyOptions,
        /// BIP39 seed phrase (mnemonic). If provided, imports from seed instead of DER.
        #[arg(long)]
        seed: Option<String>,
        /// Passphrase for seed phrase (default: empty)
        #[arg(long, default_value = "")]
        passphrase: String,
        /// Derivation path (default: m/1852'/1815'/0'/0/0)
        #[arg(long)]
        path: Option<String>,
    },

    /// Sign data provided via stdin
    Sign,

    /// Generate a new Ed25519 keypair on the YubiKey (Cardano only)
    Generate {
        #[command(flatten)]
        key_options: KeyOptions,
    },

    Info,
}

#[derive(clap::Args, Debug)]
pub struct KeyOptions {
    /// PIV slot to store the key (9a=Authentication, 9c=Signature, 9d=KeyManagement, 9e=CardAuthentication)
    #[arg(long, default_value = "signature")]
    pub slot: SlotArg,

    /// PIN policy (never, once, always)
    #[arg(long, default_value = "always")]
    pub pin_policy: PinPolicyArg,

    /// Touch policy (never, always, cached)
    #[arg(long, default_value = "always")]
    pub touch_policy: TouchPolicyArg,

    /// Management key in hex format (48 hex chars = 24 bytes). Uses default if not provided
    #[arg(long)]
    pub mgmt_key: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SlotArg {
    Authentication,
    Signature,
    KeyManagement,
    CardAuthentication,
}

impl From<SlotArg> for Slot {
    fn from(arg: SlotArg) -> Self {
        match arg {
            SlotArg::Authentication => Slot::Authentication,
            SlotArg::Signature => Slot::Signature,
            SlotArg::KeyManagement => Slot::KeyManagement,
            SlotArg::CardAuthentication => Slot::CardAuthentication,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PinPolicyArg {
    Never,
    Once,
    Always,
}

impl From<PinPolicyArg> for PinPolicy {
    fn from(arg: PinPolicyArg) -> Self {
        match arg {
            PinPolicyArg::Never => PinPolicy::Never,
            PinPolicyArg::Once => PinPolicy::Once,
            PinPolicyArg::Always => PinPolicy::Always,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TouchPolicyArg {
    Never,
    Always,
    Cached,
}

impl From<TouchPolicyArg> for TouchPolicy {
    fn from(arg: TouchPolicyArg) -> Self {
        match arg {
            TouchPolicyArg::Never => TouchPolicy::Never,
            TouchPolicyArg::Always => TouchPolicy::Always,
            TouchPolicyArg::Cached => TouchPolicy::Cached,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(cli.verbosity)
        .init();

    match cli.command {
        Commands::ImportKey {
            key_options,
            seed,
            passphrase,
            path,
        } => {
            let config = ykada::ports::KeyConfig {
                slot: key_options.slot.into(),
                pin_policy: key_options.pin_policy.into(),
                touch_policy: key_options.touch_policy.into(),
            };

            let mgmt_key_opt = key_options.mgmt_key.map(|s| s.try_into()).transpose()?;

            if let Some(seed_phrase) = seed {
                // Import from seed phrase
                let verifying_key = ykada::import_private_key_from_seed_phrase(
                    &seed_phrase,
                    &passphrase,
                    path.as_deref(),
                    config,
                    mgmt_key_opt.as_ref(),
                )
                .context("failed to import key from seed phrase")?;

                // Output public key as hex
                let public_key_hex = hex::encode(verifying_key.as_bytes());
                println!("{}", public_key_hex);
            } else {
                // Import from DER (existing behavior)
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf)?;
                let der_key = DerPrivateKey(buf);
                ykada::import_private_key_in_der_format(der_key, config, mgmt_key_opt.as_ref())
                    .context("failed to load DER private key into YubiKey")?;
            }
        }

        Commands::Sign => {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            let signature = ykada::sign_bin_data(&data);
            std::io::stdout().write_all(&signature)?;
        }
        Commands::Generate { key_options } => {
            let config = ykada::ports::KeyConfig {
                slot: key_options.slot.into(),
                pin_policy: key_options.pin_policy.into(),
                touch_policy: key_options.touch_policy.into(),
            };

            let mgmt_key_opt = key_options.mgmt_key.map(|s| s.try_into()).transpose()?;

            match ykada::generate_key_with_config(config, mgmt_key_opt.as_ref()) {
                Ok(verifying_key) => {
                    // Output public key as hex
                    let public_key_hex = hex::encode(verifying_key.as_bytes());
                    println!("{}", public_key_hex);
                }
                Err(e) => {
                    error!("Failed to generate key: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Info => {
            error!("Not implemented");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_cmd::Command;

    #[test]
    fn test_cli_version_parameter() {
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let assert = cmd.arg("--version").assert();
        assert.success();
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_cli_generate() {
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let result = cmd
            .arg("generate")
            .arg("--mgmt-key")
            .arg("010203040506070801020304050607080102030405060709")
            .assert();

        let output = result.get_output();
        let stdout = String::from_utf8_lossy(&output.stdout);

        println!("stdout: {}", stdout);

        let trimmed = stdout.trim();
        assert_eq!(trimmed.len(), 64, "Public key should be 64 hex characters");
    }
}
