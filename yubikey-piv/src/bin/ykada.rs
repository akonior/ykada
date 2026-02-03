use clap::{Parser, Subcommand};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use std::io::{self, Read, Write};
use tracing::error;

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
    LoadKey,

    /// Sign data provided via stdin
    Sign,

    /// Generate a new keypair on the YubiKey
    Generate,

    Info,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(cli.verbosity)
        .init();

    match cli.command {
        Commands::LoadKey => {
            // read DER from stdin
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            yubikey_piv::load_der_to_yubikey(&buf);
        }

        Commands::Sign => {
            // read data to sign
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            // println!("Signing {} bytes using yubikey", data.len());
            let signature = yubikey_piv::sign_bin_data(&data);
            // println!("Signature: {:?}", signature);
            std::io::stdout().write_all(&signature)?;
        }
        Commands::Generate => {
            todo!();
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
    #[ignore]
    fn test_cli_generate_parameter() {
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let assert = cmd.arg("generate").assert();
        assert.success();
    }
}
