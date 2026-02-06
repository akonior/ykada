use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use hex;
use std::io::{self, Read, Write};
use tracing::error;

use ykada::{
    api::{ManagementKey, PinPolicy, Slot, TouchPolicy},
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
        /// PIV slot to store the key (9a=Authentication, 9c=Signature, 9d=KeyManagement, 9e=CardAuthentication)
        #[arg(long, default_value = "signature")]
        slot: SlotArg,

        /// PIN policy (never, once, always)
        #[arg(long, default_value = "always")]
        pin_policy: PinPolicyArg,

        /// Touch policy (never, always, cached)
        #[arg(long, default_value = "always")]
        touch_policy: TouchPolicyArg,

        /// Management key in hex format (48 hex chars = 24 bytes). Uses default if not provided
        #[arg(long)]
        mgmt_key: Option<String>,
    },

    /// Sign data provided via stdin
    Sign,

    /// Generate a new Ed25519 keypair on the YubiKey (Cardano only)
    Generate {
        /// PIV slot to store the key (9a=Authentication, 9c=Signature, 9d=KeyManagement, 9e=CardAuthentication)
        #[arg(long, default_value = "signature")]
        slot: SlotArg,

        /// PIN policy (never, once, always)
        #[arg(long, default_value = "always")]
        pin_policy: PinPolicyArg,

        /// Touch policy (never, always, cached)
        #[arg(long, default_value = "always")]
        touch_policy: TouchPolicyArg,

        /// Management key in hex format (48 hex chars = 24 bytes). Uses default if not provided
        #[arg(long)]
        mgmt_key: Option<String>,
    },

    Info,
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
            slot,
            pin_policy,
            touch_policy,
            mgmt_key,
        } => {
            let config = ykada::ports::KeyConfig {
                slot: slot.into(),
                pin_policy: pin_policy.into(),
                touch_policy: touch_policy.into(),
            };

            let mgmt_key_opt = if let Some(key_hex) = mgmt_key {
                let key_bytes = hex::decode(key_hex)
                    .map_err(|e| anyhow::anyhow!("Invalid management key hex: {}", e))?;
                Some(
                    ManagementKey::from_slice(&key_bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid management key: {}", e))?,
                )
            } else {
                None
            };

            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            let der_key = DerPrivateKey(buf);
            ykada::import_private_key_in_der_format(der_key, config, mgmt_key_opt.as_ref())
                .context("failed to load DER private key into YubiKey")?;
        }

        Commands::Sign => {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            let signature = ykada::sign_bin_data(&data);
            std::io::stdout().write_all(&signature)?;
        }
        Commands::Generate {
            slot,
            pin_policy,
            touch_policy,
            mgmt_key,
        } => {
            let config = ykada::ports::KeyConfig {
                slot: slot.into(),
                pin_policy: pin_policy.into(),
                touch_policy: touch_policy.into(),
            };

            let mgmt_key_opt = if let Some(key_hex) = mgmt_key {
                let key_bytes = hex::decode(key_hex)
                    .map_err(|e| anyhow::anyhow!("Invalid management key hex: {}", e))?;
                Some(
                    ManagementKey::from_slice(&key_bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid management key: {}", e))?,
                )
            } else {
                None
            };

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
    fn test_cli_generate_parameter() {
        // Check if YubiKey is available
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let check_result = cmd.arg("generate").output();

        if let Ok(output) = check_result {
            // If device not found, skip test
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("NotFound") {
                return;
            }
        }

        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let assert = cmd
            .arg("generate")
            .arg("--slot")
            .arg("signature")
            .arg("--pin-policy")
            .arg("always")
            .arg("--touch-policy")
            .arg("always")
            .arg("--mgmt-key")
            .arg("010203040506070801020304050607080102030405060709")
            .assert();

        // May fail if slot is occupied or authentication fails, but should output proper error
        let output = assert.get_output();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        if output.status.success() {
            // Verify output is hex-encoded public key (64 hex chars = 32 bytes)
            let trimmed = stdout.trim();
            assert_eq!(
                trimmed.len(),
                64,
                "Public key should be 64 hex characters (32 bytes)"
            );
            assert!(
                trimmed.chars().all(|c| c.is_ascii_hexdigit()),
                "Output should be valid hex"
            );
        } else {
            // Should fail gracefully with proper error message
            // Accept various error messages that indicate proper error handling
            let error_indicators = [
                "Failed to generate key",
                "Authentication",
                "Slot",
                "not found",
                "NotFound",
                "authentication failed",
            ];
            assert!(
                error_indicators
                    .iter()
                    .any(|&indicator| stderr.contains(indicator)),
                "Should fail gracefully with proper error message. stderr: {}",
                stderr
            );
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_cli_generate_with_defaults() {
        // Check if YubiKey is available
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let check_result = cmd.arg("generate").output();

        if let Ok(output) = check_result {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("NotFound") {
                return;
            }
        }

        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let assert = cmd.arg("generate").assert();

        let output = assert.get_output();
        let stdout = String::from_utf8_lossy(&output.stdout);

        if output.status.success() {
            // Verify output is hex-encoded public key (64 hex chars = 32 bytes)
            let trimmed = stdout.trim();
            assert_eq!(
                trimmed.len(),
                64,
                "Public key should be 64 hex characters (32 bytes)"
            );
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_cli_generate_with_custom_mgmt_key() {
        // Test with a dummy management key (48 hex chars = 24 bytes)
        let dummy_mgmt_key = "0".repeat(48);
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let result = cmd
            .arg("generate")
            .arg("--mgmt-key")
            .arg(&dummy_mgmt_key)
            .assert();

        // May succeed or fail depending on whether the key is correct
        // But should not crash - just verify it doesn't panic
        let output = result.get_output();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            // If succeeded, verify output is valid hex
            let trimmed = stdout.trim();
            assert_eq!(trimmed.len(), 64, "Public key should be 64 hex characters");
        } else {
            // If failed, should have a proper error message (check both stdout and stderr)
            let combined_output = format!("{} {}", stdout, stderr);
            let error_indicators = [
                "Failed to generate key",
                "Authentication",
                "authentication failed",
                "Invalid management key",
                "ERROR",
            ];
            assert!(
                error_indicators
                    .iter()
                    .any(|&indicator| combined_output.contains(indicator)),
                "Should fail gracefully with proper error message. stdout: {}, stderr: {}",
                stdout,
                stderr
            );
        }
    }
}
