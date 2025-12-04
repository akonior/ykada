use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};

#[derive(Parser, Debug)]
#[command(name = "yksign")]
#[command(about = "YubiKey signing tool", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Load a private key (DER) into YubiKey
    LoadKey,

    /// Sign data provided via stdin
    Sign,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::LoadKey => {
            // read DER from stdin
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            println!("Loading priv key to yubikey");
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
    }

    Ok(())
}
