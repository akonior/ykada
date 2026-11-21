use std::io::{IsTerminal, Read, Write};

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use secrecy::ExposeSecret;

use ykada::{
    GeneratedWallet, ManagementKey, Network, Overwrite, Pin, PinPolicy, SeedPhrase, SendAdaParams,
    SendMode, SendOutcome, TouchPolicy, TxSummary, WalletConfig,
};

#[derive(Parser)]
#[command(name = "ykada", about = "YubiKey Cardano wallet", version)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet: fresh 24-word mnemonic, keys stored on the YubiKey
    Generate {
        #[command(flatten)]
        provision: ProvisionArgs,
    },

    /// Restore a wallet from a BIP39 mnemonic into the YubiKey
    Import {
        /// Read the mnemonic from a file [default: hidden prompt]
        #[arg(long)]
        seed_file: Option<String>,
        #[command(flatten)]
        provision: ProvisionArgs,
    },

    /// Show the wallet address stored on the YubiKey (read-only, no PIN)
    Info {
        #[arg(long, value_enum, default_value_t = Network::Preview)]
        network: Network,
    },

    /// Show the on-chain ADA balance of the wallet
    Balance {
        #[arg(long, value_enum, default_value_t = Network::Preview)]
        network: Network,
    },

    /// Build, sign on the YubiKey, and submit an ADA payment
    Send {
        /// Recipient address (addr1… / addr_test1…)
        #[arg(long)]
        to: String,
        /// Amount in whole ADA
        #[arg(
            long,
            conflicts_with = "lovelace",
            required_unless_present = "lovelace"
        )]
        ada: Option<u64>,
        /// Amount in lovelace
        #[arg(long)]
        lovelace: Option<u64>,
        /// Fee in lovelace
        #[arg(long, default_value_t = 200_000)]
        fee: u64,
        /// Build the unsigned transaction only (prints CBOR hex)
        #[arg(long, conflicts_with = "only_sign")]
        dry_run: bool,
        /// Sign but do not submit (prints signed CBOR hex)
        #[arg(long)]
        only_sign: bool,
        #[arg(long, value_enum, default_value_t = Network::Preview)]
        network: Network,
    },

    /// Sign a transaction built elsewhere (Eternl/cardano-cli JSON or CBOR hex)
    SignTx {
        /// Transaction file; omit to read stdin
        #[arg(long)]
        tx_file: Option<String>,
        /// Also submit to the network (prints the transaction ID)
        #[arg(long)]
        send: bool,
        #[arg(long, value_enum, default_value_t = Network::Preview)]
        network: Network,
    },

    /// Decode a transaction and verify its witness signatures locally
    DecodeTx {
        /// Transaction file; omit to read stdin
        #[arg(long)]
        tx_file: Option<String>,
    },
}

#[derive(Args)]
struct ProvisionArgs {
    #[arg(long, value_enum, default_value_t = PinPolicy::Always)]
    pin_policy: PinPolicy,
    #[arg(long, value_enum, default_value_t = TouchPolicy::Always)]
    touch_policy: TouchPolicy,
    /// Read the PIV management key (hex) from a file [default: the factory key]
    #[arg(long)]
    mgmt_key_file: Option<String>,
    /// Replace a wallet already stored on the YubiKey
    #[arg(long)]
    force: bool,
    #[arg(long, value_enum, default_value_t = Network::Preview)]
    network: Network,
}

fn main() {
    if let Err(e) = run(Cli::parse().command) {
        match std::io::stderr().is_terminal() {
            true => eprintln!("\x1b[1;31merror\x1b[0m: {e:#}"),
            false => eprintln!("error: {e:#}"),
        }
        std::process::exit(1);
    }
}

const LOVELACE_PER_ADA: u64 = 1_000_000;

// ykada's PIV key model gives different addresses than other wallets for the same mnemonic.
const MNEMONIC_SCOPE_NOTE: &str = "Note: this mnemonic restores the wallet only with ykada. \
Other Cardano wallets derive a different address from it (see README, \"Keys and addresses\").";

fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Generate { provision } => {
            let wallet = provision_wallet(None, provision)?;
            println!("Mnemonic (store safely): {}", wallet.mnemonic.phrase());
            println!("Cardano address:         {}", wallet.address.to_bech32()?);
            eprintln!("{MNEMONIC_SCOPE_NOTE}");
        }

        Commands::Import {
            seed_file,
            provision,
        } => {
            let wallet = provision_wallet(Some(resolve_seed(seed_file)?), provision)?;
            println!("Cardano address:         {}", wallet.address.to_bech32()?);
            eprintln!("{MNEMONIC_SCOPE_NOTE}");
        }

        Commands::Info { network } => match ykada::wallet_info(network)?.address {
            Some(addr) => println!("Cardano address:         {}", addr.to_bech32()?),
            None => println!("No wallet on this YubiKey — run `ykada generate` or `ykada import`"),
        },

        Commands::Balance { network } => {
            let addr = ykada::wallet_info(network)?
                .address
                .context("no wallet on this YubiKey — run `ykada generate` or `ykada import`")?;
            let balance =
                ykada::fetch_balance(&addr, network).context("failed to fetch balance")?;
            println!("Cardano address:         {}", addr.to_bech32()?);
            println!(
                "Balance:                 {}.{:06} ADA",
                balance / LOVELACE_PER_ADA,
                balance % LOVELACE_PER_ADA
            );
        }

        Commands::Send {
            to,
            ada,
            lovelace,
            fee,
            dry_run,
            only_sign,
            network,
        } => {
            let send_lovelace = match ada {
                Some(ada) => ada
                    .checked_mul(LOVELACE_PER_ADA)
                    .context("--ada value overflows lovelace")?,
                None => lovelace.context("provide --ada or --lovelace")?,
            };
            let mode = match (dry_run, only_sign) {
                (true, _) => SendMode::DryRun,
                (false, true) => SendMode::SignOnly,
                (false, false) => SendMode::SignAndSubmit,
            };
            if mode == SendMode::SignAndSubmit && network == Network::Mainnet {
                confirm_mainnet(&format!(
                    "Send {send_lovelace} lovelace to {to} (fee {fee}) on MAINNET?"
                ))?;
            }
            let pin = match mode {
                SendMode::DryRun => None,
                SendMode::SignOnly | SendMode::SignAndSubmit => prepare_signing()?,
            };
            let outcome = ykada::send_ada(SendAdaParams {
                network,
                recipient: to,
                send_lovelace,
                fee_lovelace: fee,
                mode,
                pin,
            })
            .context("failed to send ADA")?;
            clear_status_line();
            print_outcome(outcome);
        }

        Commands::SignTx {
            tx_file,
            send,
            network,
        } => {
            let content = read_input(tx_file)?;
            // Never sign blind: show what is about to be signed.
            let summary = ykada::decode_tx(&content).context("failed to decode transaction")?;
            eprintln!("Signing transaction:");
            print_summary(&mut std::io::stderr(), &summary)?;
            let mode = match send {
                true => SendMode::SignAndSubmit,
                false => SendMode::SignOnly,
            };
            if send && network == Network::Mainnet {
                confirm_mainnet("Submit this transaction to MAINNET?")?;
            }
            let pin = prepare_signing()?;
            let outcome = ykada::sign_tx(&content, network, mode, pin)
                .context("failed to sign transaction")?;
            clear_status_line();
            print_outcome(outcome);
        }

        Commands::DecodeTx { tx_file } => {
            let summary =
                ykada::decode_tx(&read_input(tx_file)?).context("failed to decode transaction")?;
            print_summary(&mut std::io::stdout(), &summary)?;
            if summary.witnesses_verified < summary.witness_count {
                anyhow::bail!(
                    "{} of {} witness signature(s) failed verification",
                    summary.witness_count - summary.witnesses_verified,
                    summary.witness_count
                );
            }
        }
    }

    Ok(())
}

fn provision_wallet(
    seed: Option<SeedPhrase>,
    args: ProvisionArgs,
) -> anyhow::Result<GeneratedWallet> {
    let mgmt_key = resolve_mgmt_key(args.mgmt_key_file)?;
    if mgmt_key.is_none() {
        eprintln!("Note: no --mgmt-key-file given, trying the default PIV management key. If it works, anyone holding this YubiKey can replace its keys — change it with `ykman piv access change-management-key`.");
    }
    if matches!(args.touch_policy, TouchPolicy::Never) {
        eprintln!("Warning: touch policy 'never' — keys will sign without a physical touch.");
    }
    let config = WalletConfig {
        pin_policy: args.pin_policy,
        touch_policy: args.touch_policy,
        network: args.network,
        overwrite: match args.force {
            true => Overwrite::Allow,
            false => Overwrite::Refuse,
        },
    };
    ykada::generate_or_import_wallet(seed, config, mgmt_key.as_ref())
        .context("failed to store wallet on YubiKey")
}

// Ask for the PIN if the payment slot needs one and tell the user what the key expects.
fn prepare_signing() -> anyhow::Result<Option<Pin>> {
    let (pin_policy, touch_policy) =
        ykada::payment_slot_policy().context("failed to read slot policy")?;
    let pin = match pin_policy {
        PinPolicy::Never => None,
        PinPolicy::Once | PinPolicy::Always => {
            Some(prompt_secret("Enter your YubiKey PIN", "PIN:")?.parse::<Pin>()?)
        }
    };
    if matches!(&pin, Some(p) if p.as_bytes() == Pin::DEFAULT) {
        eprintln!("Warning: using the default PIN (123456). Change it with `ykman piv access change-pin`.");
    }
    if touch_policy != TouchPolicy::Never && std::io::stderr().is_terminal() {
        eprint!("Please touch your YubiKey...");
    }
    Ok(pin)
}

fn clear_status_line() {
    if std::io::stderr().is_terminal() {
        eprint!("\r\x1b[K");
    }
}

fn prompt_secret(description: &str, prompt: &str) -> anyhow::Result<String> {
    let entered = pinentry::PassphraseInput::with_default_binary()
        .context("pinentry not found; install pinentry")?
        .with_description(description)
        .with_prompt(prompt)
        .interact()
        .map_err(|e| anyhow::anyhow!("pinentry error: {e}"))?;
    Ok(entered.expose_secret().to_string())
}

// Mnemonic from a file or a hidden prompt (keeps it out of argv and shell history).
fn resolve_seed(seed_file: Option<String>) -> anyhow::Result<SeedPhrase> {
    let phrase = match seed_file {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read seed file: {path}"))?,
        None => prompt_secret("Enter your BIP39 seed phrase", "Seed phrase:")?,
    };
    SeedPhrase::try_from(phrase.trim()).context("invalid seed phrase")
}

fn resolve_mgmt_key(mgmt_key_file: Option<String>) -> anyhow::Result<Option<ManagementKey>> {
    mgmt_key_file
        .map(|path| {
            let hexed = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read management key file: {path}"))?;
            ManagementKey::try_from(hexed).context("invalid management key")
        })
        .transpose()
}

fn confirm_mainnet(question: &str) -> anyhow::Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "mainnet submission must be confirmed in a terminal (with sign-tx, use --tx-file instead of stdin)"
        );
    }
    eprint!("{question} Type 'yes' to continue: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim().eq_ignore_ascii_case("yes") {
        true => Ok(()),
        false => anyhow::bail!("aborted: mainnet submission not confirmed"),
    }
}

fn read_input(tx_file: Option<String>) -> anyhow::Result<String> {
    match tx_file {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read transaction file: {path}")),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read transaction from stdin")?;
            Ok(buf)
        }
    }
}

fn print_outcome(outcome: SendOutcome) {
    match outcome {
        SendOutcome::TxHash(hash) => println!("Transaction ID: {hash}"),
        SendOutcome::Cbor(cbor) => println!("{}", hex::encode(cbor)),
    }
}

fn print_summary(out: &mut dyn Write, summary: &TxSummary) -> std::io::Result<()> {
    writeln!(out, "Transaction body hash: {}", summary.body_hash_hex)?;
    writeln!(out, "Inputs ({}):", summary.inputs.len())?;
    summary
        .inputs
        .iter()
        .try_for_each(|input| writeln!(out, "  {input}"))?;
    writeln!(out, "Outputs ({}):", summary.outputs.len())?;
    summary.outputs.iter().try_for_each(|o| {
        let tokens = match o.has_tokens {
            true => " + tokens",
            false => "",
        };
        writeln!(out, "  {} lovelace{tokens} -> {}", o.lovelace, o.address)
    })?;
    writeln!(out, "Fee:                   {} lovelace", summary.fee)?;
    if !summary.extras.is_empty() {
        writeln!(out, "Also contains:         {}", summary.extras.join(", "))?;
    }
    match summary.ttl {
        Some(ttl) => writeln!(out, "TTL (invalid_from):    slot {ttl}")?,
        None => writeln!(out, "TTL (invalid_from):    none")?,
    }
    writeln!(
        out,
        "Witnesses verified:    {}/{}",
        summary.witnesses_verified, summary.witness_count
    )
}
