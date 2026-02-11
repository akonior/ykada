use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use std::io::{self, Read, Write};
use tracing::error;

use ykada::{
    api::{Bech32Encodable, PinPolicy, Slot, TouchPolicy},
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
    #[command(about = "Import a private key into the YubiKey")]
    ImportKey {
        #[command(flatten)]
        key_options: KeyOptions,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long)]
        path: Option<String>,
    },

    #[command(about = "Sign data using the YubiKey")]
    Sign,

    #[command(about = "Generate a new key in the YubiKey")]
    Generate {
        #[command(flatten)]
        key_options: KeyOptions,
    },

    #[command(hide = true)]
    Info,
}

#[derive(clap::Args, Debug)]
pub struct KeyOptions {
    #[arg(long, default_value = "signature")]
    pub slot: SlotArg,

    #[arg(long, default_value = "always")]
    pub pin_policy: PinPolicyArg,

    #[arg(long, default_value = "always")]
    pub touch_policy: TouchPolicyArg,

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
        .without_time()
        .with_target(true)
        .with_level(true)
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
                let verifying_key = ykada::import_private_key_from_seed_phrase(
                    &seed_phrase,
                    &passphrase,
                    path.as_deref(),
                    config,
                    mgmt_key_opt.as_ref(),
                )
                .context("failed to import key from seed phrase")?;

                println!("Imported verifying key: {}", verifying_key.to_bech32()?);
            } else {
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
                    println!("Generated verifying key: {}", verifying_key.to_bech32()?);
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
    #[cfg_attr(not(feature = "hardware-tests"), ignore)]
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
        assert!(
            trimmed.starts_with("Generated verifying key: addr_vk1"),
            "Public key should start with 'addr_vk', got: {}",
            trimmed
        );
    }
}
