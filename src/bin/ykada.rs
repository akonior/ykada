use anyhow::Context;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing::info;

use ykada::api::{
    Bech32Encodable, Network, Pin, PinPolicy, SeedPhrase, SendMode, SendOutcome, Slot,
    StakeVerifyingKey, TouchPolicy, WalletConfig,
};

#[derive(Parser, Debug)]
#[command(name = "ykada")]
#[command(about = "YubiKey Cardano wallet", version)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(flatten)]
    pub verbosity: Verbosity<WarnLevel>,

    #[command(subcommand)]
    pub command: Commands,
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

fn main() {
    let matches = Cli::command()
        .before_long_help(ykada::api::banner())
        .get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    tracing_subscriber::fmt()
        .with_max_level(cli.verbosity)
        .without_time()
        .with_target(true)
        .with_level(true)
        .init();

    if let Err(e) = run(cli.command) {
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
            let seed_phrase = seed
                .map(|p| SeedPhrase::try_from(p.as_str()).context("invalid seed phrase"))
                .transpose()?;
            let wallet =
                ykada::api::generate_or_import_wallet(seed_phrase, config, mgmt_key_opt.as_ref())?;
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

        Commands::Info {
            payment_slot,
            stake_slot,
            network,
        } => {
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
            let mode = if send {
                SendMode::SignAndSubmit
            } else {
                SendMode::SignOnly
            };
            match ykada::api::sign_tx_file(
                &content,
                payment_slot.into(),
                stake_slot.into(),
                network.into(),
                mode,
                pin,
            )
            .context("failed to sign transaction")?
            {
                SendOutcome::Cbor(cbor) => println!("{}", hex::encode(&cbor)),
                SendOutcome::TxHash(hash) => println!("Transaction ID: {hash}"),
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
            let pin = pin.map(|p| p.parse::<Pin>()).transpose()?;
            let mode = match (dry_run, only_sign) {
                (true, _) => SendMode::DryRun,
                (_, true) => SendMode::SignOnly,
                _ => SendMode::SignAndSubmit,
            };
            match ykada::api::send_ada(
                payment_slot.into(),
                stake_slot.into(),
                network.into(),
                &to,
                send_lovelace,
                fee,
                mode,
                pin,
            )
            .context("failed to send ADA")?
            {
                SendOutcome::Cbor(cbor) => println!("{}", hex::encode(&cbor)),
                SendOutcome::TxHash(hash) => println!("Transaction ID: {hash}"),
            }
        }
    }

    Ok(())
}

#[cfg(all(test, feature = "hardware-tests"))]
mod tests {
    use assert_cmd::Command;

    const KNOWN_SEED: &str = "slim fine attend tape wave input head crew shift desk find mutual square cake uncle morning provide naive around brief couple faint alcohol young";
    const KNOWN_ADDR: &str = "addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g";
    const FALLBACK_RECV: &str = "addr_test1qz6vzpsz3knmun4wxe5snhtvqslmujdgua7ralptg339extxmjk336y5qn6w87clfhdmu6nc0hfl4q2q9r0ft20ytdes6f5prn";
    const MGMT_KEY: &str = "010203040506070801020304050607080102030405060709";

    #[test]
    fn test_cli_version_parameter() {
        let mut cmd = Command::cargo_bin("ykada").unwrap();
        let assert = cmd.arg("--version").assert();
        assert.success();
    }

    #[test]
    fn test_info() {
        Command::cargo_bin("ykada")
            .unwrap()
            .args(["info", "--network", "preview"])
            .assert()
            .success()
            .stdout(predicates::str::contains("Cardano address:"))
            .stdout(predicates::str::contains(KNOWN_ADDR));
    }

    #[test]
    fn test_import_predefined_seed() {
        Command::cargo_bin("ykada")
            .unwrap()
            .args([
                "import",
                "--seed",
                KNOWN_SEED,
                "--network",
                "preview",
                "--pin-policy",
                "never",
                "--touch-policy",
                "never",
                "--mgmt-key",
                MGMT_KEY,
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains(KNOWN_ADDR));

        let output = Command::cargo_bin("ykada")
            .unwrap()
            .args(["balance", "--network", "preview"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        assert!(
            stdout.contains("ADA:"),
            "Expected 'ADA:' in output, got: {stdout}"
        );

        let ada_value: f64 = stdout
            .lines()
            .find(|l| l.contains("ADA:"))
            .and_then(|l| l.split("ADA:").nth(1))
            .and_then(|s| s.trim().parse().ok())
            .expect("Could not parse ADA balance as f64");

        assert!(ada_value > 0.0, "Expected ADA balance > 0, got {ada_value}");
    }

    #[test]
    fn test_generate() {
        Command::cargo_bin("ykada")
            .unwrap()
            .args([
                "generate",
                "--network",
                "preview",
                "--pin-policy",
                "never",
                "--touch-policy",
                "never",
                "--mgmt-key",
                MGMT_KEY,
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains("Mnemonic (store safely):"))
            .stdout(predicates::str::contains(
                "Cardano address:         addr_test1",
            ));
    }

    #[test]
    fn test_send() {
        Command::cargo_bin("ykada")
            .unwrap()
            .args([
                "send",
                "--to",
                FALLBACK_RECV,
                "--lovelace",
                "1500000",
                "--network",
                "preview",
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains("Transaction ID:"));
    }
}
