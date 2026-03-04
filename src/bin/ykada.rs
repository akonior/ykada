use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use std::io::{self, Read, Write};
use tracing::info;

use ykada::{
    api::{
        Bech32Encodable, Network, Pin, PinPolicy, SeedPhrase, Slot, StakeVerifyingKey, TouchPolicy,
        WalletConfig,
    },
    DerPrivateKey,
};

#[derive(Parser, Debug)]
#[command(name = "ykada")]
#[command(about = "YubiKey Cardano wallet", version)]
#[command(subcommand_required = false, arg_required_else_help = false)]
pub struct Cli {
    #[command(flatten)]
    pub verbosity: Verbosity<WarnLevel>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Import a wallet from a BIP39 seed phrase into the YubiKey")]
    Import {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value = "signature")]
        payment_slot: SlotArg,
        #[arg(long, default_value = "key-management")]
        stake_slot: SlotArg,
        #[arg(long, default_value = "always")]
        pin_policy: PinPolicyArg,
        #[arg(long, default_value = "always")]
        touch_policy: TouchPolicyArg,
        #[arg(long)]
        mgmt_key: Option<String>,
        #[arg(long, default_value = "preview")]
        network: NetworkArg,
    },

    #[command(
        name = "import-key-legacy",
        hide = true,
        about = "Import a private key into the YubiKey (legacy)"
    )]
    ImportKeyLegacy {
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

    #[command(about = "Generate a new wallet: seed, two keys on YubiKey, Cardano address")]
    Generate {
        #[arg(long)]
        seed: Option<String>,
        #[arg(long, default_value = "signature")]
        payment_slot: SlotArg,
        #[arg(long, default_value = "key-management")]
        stake_slot: SlotArg,
        #[arg(long, default_value = "always")]
        pin_policy: PinPolicyArg,
        #[arg(long, default_value = "always")]
        touch_policy: TouchPolicyArg,
        #[arg(long)]
        mgmt_key: Option<String>,
        #[arg(long, default_value = "preview")]
        network: NetworkArg,
    },

    #[command(
        name = "generate-legacy",
        hide = true,
        about = "Generate a new key in the YubiKey (legacy hardware-only)"
    )]
    GenerateLegacy {
        #[command(flatten)]
        key_options: KeyOptions,
    },

    #[command(about = "Show connected YubiKey info and wallet address")]
    Info {
        #[arg(long, default_value = "signature")]
        payment_slot: SlotArg,
        #[arg(long, default_value = "key-management")]
        stake_slot: SlotArg,
        #[arg(long, default_value = "preview")]
        network: NetworkArg,
    },

    #[command(
        about = "Show on-chain ADA and token balance for the wallet address on the connected YubiKey"
    )]
    Balance {
        #[arg(long, default_value = "signature")]
        payment_slot: SlotArg,
        #[arg(long, default_value = "key-management")]
        stake_slot: SlotArg,
        #[arg(long, default_value = "preview")]
        network: NetworkArg,
    },

    #[command(about = "Sign a pre-built transaction from a file (e.g. Eternl export)")]
    SignTx {
        /// Path to the unsigned transaction JSON file (must contain a "cborHex" field)
        #[arg(long)]
        tx_file: String,
        /// Sign and submit to the network (outputs tx hash instead of signed CBOR)
        #[arg(long)]
        send: bool,
        #[arg(long, default_value = "signature")]
        payment_slot: SlotArg,
        #[arg(long, default_value = "key-management")]
        stake_slot: SlotArg,
        #[arg(long, default_value = "preview")]
        network: NetworkArg,
        /// YubiKey PIN (required if the key slot uses PIN-on-sign policy)
        #[arg(long)]
        pin: Option<String>,
    },

    #[command(
        about = "Send ADA to a Cardano address",
        long_about = "Send ADA to a Cardano address.\n\n\
            By default signs via YubiKey and submits to the network.\n\
            Use --dry-run to build the unsigned transaction (CBOR hex) without signing.\n\
            Use --only-sign to sign but not submit (outputs signed CBOR hex)."
    )]
    Send {
        /// Recipient bech32 address
        #[arg(long)]
        to: String,
        /// Amount to send in whole ADA (e.g. 2 = 2 000 000 lovelace)
        #[arg(long, conflicts_with = "lovelace")]
        ada: Option<u64>,
        /// Amount to send in lovelace (exact; use instead of --ada for sub-ADA precision)
        #[arg(long, conflicts_with = "ada")]
        lovelace: Option<u64>,
        /// Transaction fee in lovelace
        #[arg(long, default_value = "200000")]
        fee: u64,
        #[arg(long, default_value = "signature")]
        payment_slot: SlotArg,
        #[arg(long, default_value = "key-management")]
        stake_slot: SlotArg,
        #[arg(long, default_value = "preview")]
        network: NetworkArg,
        /// Build the unsigned transaction only; do not sign or submit
        #[arg(long, conflicts_with = "only_sign")]
        dry_run: bool,
        /// Sign but do not submit; outputs signed CBOR hex
        #[arg(long, conflicts_with = "dry_run")]
        only_sign: bool,
        /// YubiKey PIN
        #[arg(long)]
        pin: Option<String>,
    },
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

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Preprod,
    Preview,
}

impl From<NetworkArg> for Network {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Preprod => Network::Preprod,
            NetworkArg::Preview => Network::Preview,
        }
    }
}

fn print_error(e: &anyhow::Error) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[1;31merror\x1b[0m: {:#}", e);
    } else {
        eprintln!("error: {:#}", e);
    }
}

fn print_banner() {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return;
    }
    println!("\x1b[1;32m  ╻ ╻╻┏ ┏━┓╺┳┓┏━┓\x1b[0m");
    println!("\x1b[1;32m  ┗┳┛┣┻┓┣━┫ ┃┃┣━┫\x1b[0m");
    println!("\x1b[1;32m   ╹ ╹ ╹╹ ╹╺┻┛╹ ╹\x1b[0m  \x1b[1;37mYubiKey Cardano Wallet\x1b[0m");
    println!();
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(cli.verbosity)
        .without_time()
        .with_target(true)
        .with_level(true)
        .init();

    let command = cli.command.unwrap_or(Commands::Info {
        payment_slot: SlotArg::Signature,
        stake_slot: SlotArg::KeyManagement,
        network: NetworkArg::Preview,
    });
    if let Err(e) = run(command) {
        print_error(&e);
        std::process::exit(1);
    }
}

fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Import {
            seed,
            payment_slot,
            stake_slot,
            pin_policy,
            touch_policy,
            mgmt_key,
            network,
        } => {
            let config = WalletConfig {
                payment_slot: payment_slot.into(),
                stake_slot: stake_slot.into(),
                pin_policy: pin_policy.into(),
                touch_policy: touch_policy.into(),
                network: network.into(),
            };
            let mgmt_key_opt = mgmt_key.map(|s| s.try_into()).transpose()?;
            let seed_phrase = SeedPhrase::try_from(seed.as_str()).context("invalid seed phrase")?;
            let wallet = ykada::import_wallet(seed_phrase, config, mgmt_key_opt.as_ref())
                .context("failed to import wallet from seed phrase")?;
            info!(
                "Payment verifying key:   {}",
                wallet.payment_vk.to_bech32()?
            );
            info!(
                "Stake verifying key:     {}",
                StakeVerifyingKey(wallet.stake_vk).to_bech32()?
            );
            println!("Cardano address:         {}", wallet.address.to_bech32()?);
        }

        Commands::ImportKeyLegacy {
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
                let verifying_key =
                    ykada::import_private_key_in_der_format(der_key, config, mgmt_key_opt.as_ref())
                        .context("failed to load DER private key into YubiKey")?;

                println!("Imported verifying key: {}", verifying_key.to_bech32()?);
            }
        }

        Commands::Sign => {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            let signature = ykada::sign_bin_data(&data);
            std::io::stdout().write_all(&signature)?;
        }
        Commands::Generate {
            seed,
            payment_slot,
            stake_slot,
            pin_policy,
            touch_policy,
            mgmt_key,
            network,
        } => {
            let config = WalletConfig {
                payment_slot: payment_slot.into(),
                stake_slot: stake_slot.into(),
                pin_policy: pin_policy.into(),
                touch_policy: touch_policy.into(),
                network: network.into(),
            };
            let mgmt_key_opt = mgmt_key.map(|s| s.try_into()).transpose()?;
            let wallet = match seed {
                Some(phrase) => {
                    let seed_phrase =
                        SeedPhrase::try_from(phrase.as_str()).context("invalid seed phrase")?;
                    ykada::import_wallet(seed_phrase, config, mgmt_key_opt.as_ref())?
                }
                None => ykada::generate_wallet(config, mgmt_key_opt.as_ref())?,
            };
            println!("Mnemonic (store safely): {}", wallet.mnemonic.phrase());
            info!(
                "Payment verifying key:   {}",
                wallet.payment_vk.to_bech32()?
            );
            info!(
                "Stake verifying key:     {}",
                StakeVerifyingKey(wallet.stake_vk).to_bech32()?
            );
            println!("Cardano address:         {}", wallet.address.to_bech32()?);
        }

        Commands::GenerateLegacy { key_options } => {
            let config = ykada::ports::KeyConfig {
                slot: key_options.slot.into(),
                pin_policy: key_options.pin_policy.into(),
                touch_policy: key_options.touch_policy.into(),
            };
            let mgmt_key_opt = key_options.mgmt_key.map(|s| s.try_into()).transpose()?;
            let verifying_key = ykada::generate_key_with_config(config, mgmt_key_opt.as_ref())?;
            println!("Generated verifying key: {}", verifying_key.to_bech32()?);
        }

        Commands::Info {
            payment_slot,
            stake_slot,
            network,
        } => {
            print_banner();
            let info =
                ykada::api::wallet_info(payment_slot.into(), stake_slot.into(), network.into())?;

            let (major, minor, patch) = info.firmware;
            info!("YubiKey serial:          {}", info.serial);
            info!("Firmware version:        {}.{}.{}", major, minor, patch);

            match info.payment_vk {
                Some(vk) => info!("Payment verifying key:   {}", vk.to_bech32()?),
                None => info!("Payment verifying key:   (none)"),
            }
            match info.stake_vk {
                Some(vk) => info!(
                    "Stake verifying key:     {}",
                    StakeVerifyingKey(vk).to_bech32()?
                ),
                None => info!("Stake verifying key:     (none)"),
            }
            match info.address {
                Some(addr) => println!("Cardano address:         {}", addr.to_bech32()?),
                None => println!("Cardano address:         (no wallet — run `ykada generate` or `ykada import` first)"),
            }
        }

        Commands::Balance {
            payment_slot,
            stake_slot,
            network,
        } => {
            let info =
                ykada::api::wallet_info(payment_slot.into(), stake_slot.into(), network.into())?;

            let addr = info.address.ok_or_else(|| {
                anyhow::anyhow!(
                    "No Cardano address found on this YubiKey — import or generate a wallet first"
                )
            })?;

            let balance = ykada::api::fetch_balance(&addr, network.into())
                .context("failed to fetch balance")?;

            println!("Cardano address:  {}", addr.to_bech32()?);
            println!("Account balance:");
            println!("  ADA:            {:.6}", balance.ada());
            for token in &balance.tokens {
                println!(
                    "  {}/{}  ×  {}",
                    token.policy_id, token.asset_name, token.quantity
                );
            }
        }

        Commands::SignTx {
            tx_file,
            send,
            payment_slot,
            stake_slot,
            network,
            pin,
        } => {
            let content = std::fs::read_to_string(&tx_file)
                .with_context(|| format!("failed to read transaction file: {tx_file}"))?;
            let pin = pin.map(|p| p.parse::<Pin>()).transpose()?;
            if send {
                let tx_hash = ykada::api::sign_and_send_external_tx(
                    &content,
                    payment_slot.into(),
                    stake_slot.into(),
                    network.into(),
                    pin,
                )
                .context("failed to sign and submit transaction")?;
                println!("Transaction ID: {tx_hash}");
            } else {
                let cbor = ykada::api::sign_external_tx(
                    &content,
                    payment_slot.into(),
                    stake_slot.into(),
                    network.into(),
                    pin,
                )
                .context("failed to sign transaction")?;
                println!("{}", hex::encode(&cbor));
            }
        }

        Commands::Send {
            to,
            ada,
            lovelace,
            fee,
            payment_slot,
            stake_slot,
            network,
            dry_run,
            only_sign,
            pin,
        } => {
            let send_lovelace = match (ada, lovelace) {
                (Some(a), None) => a * 1_000_000,
                (None, Some(l)) => l,
                _ => anyhow::bail!("provide either --ada or --lovelace"),
            };
            if dry_run {
                let cbor = ykada::api::build_transaction(
                    payment_slot.into(),
                    stake_slot.into(),
                    network.into(),
                    &to,
                    send_lovelace,
                    fee,
                )
                .context("failed to build transaction")?;
                println!("{}", hex::encode(&cbor));
            } else if only_sign {
                let pin = pin.map(|p| p.parse::<Pin>()).transpose()?;
                let cbor = ykada::api::sign_transaction(
                    payment_slot.into(),
                    stake_slot.into(),
                    network.into(),
                    &to,
                    send_lovelace,
                    fee,
                    pin,
                )
                .context("failed to sign transaction")?;
                println!("{}", hex::encode(&cbor));
            } else {
                let pin = pin.map(|p| p.parse::<Pin>()).transpose()?;
                let tx_hash = ykada::api::send_transaction(
                    payment_slot.into(),
                    stake_slot.into(),
                    network.into(),
                    &to,
                    send_lovelace,
                    fee,
                    pin,
                )
                .context("failed to sign and submit transaction")?;
                println!("Transaction ID: {tx_hash}");
            }
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
            .arg("generate-legacy")
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
