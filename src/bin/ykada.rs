use std::io::{IsTerminal, Read, Write};

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use secrecy::ExposeSecret;

use ykada::{
    GeneratedWallet, ManagementKey, Network, Overwrite, PaymentParams, Pin, PinPolicy, SeedPhrase,
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
    #[command(group(clap::ArgGroup::new("amount").required(true).args(["ada", "lovelace"])))]
    Send {
        /// Recipient address (addr1… / addr_test1…)
        #[arg(long)]
        to: String,
        /// Amount in whole ADA
        #[arg(long, value_parser = parse_whole_ada)]
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
        /// Transaction file; omit (or pass -) to read stdin
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
        /// Transaction file; omit (or pass -) to read stdin
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
        let colored = use_color(
            std::io::stderr().is_terminal(),
            std::env::var_os("NO_COLOR"),
            std::env::var_os("TERM"),
        );
        match colored {
            true => eprintln!("\x1b[1;31merror\x1b[0m: {}", error_text(&e)),
            false => eprintln!("error: {}", error_text(&e)),
        }
        std::process::exit(1);
    }
}

// Color only on a terminal, and not when NO_COLOR is set (https://no-color.org) or TERM=dumb.
fn use_color(
    terminal: bool,
    no_color: Option<std::ffi::OsString>,
    term: Option<std::ffi::OsString>,
) -> bool {
    terminal && no_color.is_none_or(|v| v.is_empty()) && term.is_none_or(|t| t != "dumb")
}

// The error and its causes, without repeating a cause its parent already quotes
// ("YubiKey library error: wrong pin: wrong pin").
fn error_text(e: &anyhow::Error) -> String {
    e.chain()
        .map(|cause| cause.to_string())
        .fold(Vec::<String>::new(), |shown, cause| {
            match shown.last().is_some_and(|last| last.ends_with(&cause)) {
                true => shown,
                false => [shown, vec![cause]].concat(),
            }
        })
        .join(": ")
}

const LOVELACE_PER_ADA: u64 = 1_000_000;

fn parse_whole_ada(value: &str) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| {
        match value.contains(['.', ',']) {
            true => {
                "--ada takes whole ADA; for a fraction use --lovelace (1 ADA = 1000000 lovelace)"
            }
            false => "expected a whole number of ADA",
        }
        .to_string()
    })
}

fn format_ada(lovelace: u64) -> String {
    format!(
        "{}.{:06}",
        lovelace / LOVELACE_PER_ADA,
        lovelace % LOVELACE_PER_ADA
    )
}

// ykada's PIV key model gives different addresses than other wallets for the same mnemonic.
const MNEMONIC_SCOPE_NOTE: &str = "Note: this mnemonic restores the wallet only with ykada. \
Other Cardano wallets derive a different address from it (see https://github.com/akonior/ykada/blob/main/docs/keys-and-addresses.md).";

fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Generate { provision } => {
            let wallet = provision_wallet(None, provision)?;
            let lines = format!(
                "Mnemonic (store safely): {}\nCardano address:         {}",
                wallet.mnemonic.phrase(),
                wallet.address.to_bech32()?
            );
            print_line(&lines).context(
                "the new keys are on the YubiKey, but the mnemonic could not be printed, so \
                 there is no backup: run `ykada generate --force` again for a new wallet",
            )?;
            eprintln!("{MNEMONIC_SCOPE_NOTE}");
        }

        Commands::Import {
            seed_file,
            provision,
        } => {
            let wallet = provision_wallet(Some(resolve_seed(seed_file)?), provision)?;
            print_line(&format!(
                "Cardano address:         {}",
                wallet.address.to_bech32()?
            ))?;
            eprintln!("{MNEMONIC_SCOPE_NOTE}");
        }

        Commands::Info { network } => match ykada::wallet_info(network)?.address {
            Some(addr) => print_line(&format!("Cardano address:         {}", addr.to_bech32()?))?,
            None => {
                print_line("No wallet on this YubiKey — run `ykada generate` or `ykada import`")?
            }
        },

        Commands::Balance { network } => {
            let addr = ykada::wallet_info(network)?
                .address
                .context("no wallet on this YubiKey — run `ykada generate` or `ykada import`")?;
            let balance =
                ykada::fetch_balance(&addr, network).context("failed to fetch balance")?;
            print_line(&format!(
                "Cardano address:         {}\nBalance:                 {} ADA",
                addr.to_bech32()?,
                format_ada(balance)
            ))?;
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
            // Build first: an address, amount or funds problem shows before any PIN prompt.
            let tx = ykada::prepare_payment(PaymentParams {
                network,
                recipient: to.clone(),
                send_lovelace,
                fee_lovelace: fee,
            })
            .context("failed to send ADA")?;
            if mode == SendMode::SignAndSubmit && network == Network::Mainnet {
                confirm_mainnet(&format!(
                    "Send {} ADA to {to} with a fee of {} ADA on MAINNET?",
                    format_ada(send_lovelace),
                    format_ada(fee)
                ))?;
            }
            let pin = match mode {
                SendMode::DryRun => None,
                SendMode::SignOnly | SendMode::SignAndSubmit => prepare_signing()?,
            };
            let outcome = ykada::finish_tx(tx, mode, pin).context("failed to send ADA")?;
            clear_status_line();
            print_outcome(outcome)?;
        }

        Commands::SignTx {
            tx_file,
            send,
            network,
        } => {
            let content = read_input(tx_file)?;
            let (tx, summary) = ykada::prepare_external_tx(&content, network)
                .context("failed to decode transaction")?;
            // Never sign blind: show what is about to be signed.
            eprintln!("Signing transaction:");
            print_summary(&mut std::io::stderr(), &summary)?;
            let (mode, failed) = match send {
                true => (
                    SendMode::SignAndSubmit,
                    "failed to sign and submit transaction",
                ),
                false => (SendMode::SignOnly, "failed to sign transaction"),
            };
            if send && network == Network::Mainnet {
                confirm_mainnet("Submit this transaction to MAINNET?")?;
            }
            let pin = prepare_signing()?;
            let outcome = ykada::finish_tx(tx, mode, pin).context(failed)?;
            clear_status_line();
            print_outcome(outcome)?;
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
    if matches!(args.pin_policy, PinPolicy::Never) {
        eprintln!(
            "Warning: PIN policy 'never' — anyone holding this YubiKey can sign without the PIN."
        );
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
    match (touch_policy, std::io::stderr().is_terminal()) {
        (TouchPolicy::Never, _) => {
            eprintln!("Note: this key signs without a touch (touch policy 'never').")
        }
        (TouchPolicy::Always | TouchPolicy::Cached, true) => {
            eprint!("Please touch your YubiKey...")
        }
        (TouchPolicy::Always | TouchPolicy::Cached, false) => {}
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

// A transaction is at most 16 KiB (32 KiB as hex): far larger input is not one, and reading
// it whole (say, from /dev/zero) would only use up memory.
const MAX_INPUT_BYTES: u64 = 1 << 20;

// `--tx-file -` means stdin, as with other tools.
fn read_input(tx_file: Option<String>) -> anyhow::Result<String> {
    match tx_file.as_deref() {
        None | Some("-") => read_limited(std::io::stdin(), "stdin"),
        Some(path) => std::fs::File::open(path)
            .with_context(|| format!("failed to read transaction file: {path}"))
            .and_then(|file| read_limited(file, path)),
    }
}

fn read_limited(input: impl Read, source: &str) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    input
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read transaction from {source}"))?;
    match bytes.len() as u64 > MAX_INPUT_BYTES {
        true => {
            anyhow::bail!("{source} holds more than 1 MiB; a Cardano transaction is at most 16 KiB")
        }
        false => String::from_utf8(bytes).with_context(|| {
            format!("{source} is not text: expected transaction JSON or CBOR hex")
        }),
    }
}

fn print_outcome(outcome: SendOutcome) -> anyhow::Result<()> {
    match outcome {
        SendOutcome::TxHash(hash) => {
            print_line(&format!("Transaction ID: {hash}")).with_context(|| {
                format!("transaction {hash} was submitted, but its ID could not be printed")
            })
        }
        SendOutcome::Cbor(cbor) => print_line(&hex::encode(cbor)),
    }
}

// stdout carries the result. When its reader is gone (`ykada info | true`) the write fails,
// and that must be an error with the right message, not a panic.
fn print_line(text: &str) -> anyhow::Result<()> {
    write_line(&mut std::io::stdout().lock(), text)
}

fn write_line(out: &mut impl Write, text: &str) -> anyhow::Result<()> {
    writeln!(out, "{text}")
        .and_then(|()| out.flush())
        .context("failed to write to stdout")
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
        let attached: String = [
            (o.has_tokens, " + tokens"),
            (o.has_datum, " + datum"),
            (o.has_script, " + script"),
        ]
        .iter()
        .filter_map(|(present, label)| present.then_some(*label))
        .collect();
        writeln!(out, "  {} lovelace{attached} -> {}", o.lovelace, o.address)
    })?;
    writeln!(out, "Fee:                   {} lovelace", summary.fee)?;
    if !summary.extras.is_empty() {
        writeln!(out, "Also contains:         {}", summary.extras.join(", "))?;
    }
    if !summary.is_valid {
        writeln!(
            out,
            "WARNING:               marked invalid: the scripts are expected to fail and the collateral is taken"
        )?;
    }
    if let Some(start) = summary.validity_start {
        writeln!(out, "Valid from:            slot {start}")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_up_to_the_limit_is_read() {
        let text = "a".repeat(MAX_INPUT_BYTES as usize);
        assert_eq!(read_limited(text.as_bytes(), "test").unwrap(), text);
    }

    // An endless input (like /dev/zero) stops at the limit instead of filling memory.
    #[test]
    fn test_input_over_the_limit_is_refused() {
        let endless = std::io::repeat(b'0');
        let msg = read_limited(endless, "test").unwrap_err().to_string();
        assert!(msg.contains("more than 1 MiB"), "got: {msg}");
    }

    #[test]
    fn test_error_text_drops_a_repeated_cause() {
        let e = anyhow::Error::from(ykada::YkadaError::YubikeyLib(yubikey::Error::NotSupported))
            .context("failed to sign transaction");
        let text = error_text(&e);
        assert_eq!(text.matches("not supported").count(), 1, "got: {text}");
        assert!(
            text.starts_with("failed to sign transaction: "),
            "got: {text}"
        );
    }

    #[test]
    fn test_error_text_keeps_distinct_causes() {
        let e = anyhow::anyhow!("inner").context("outer");
        assert_eq!(error_text(&e), "outer: inner");
    }

    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    // `println!` panics here (exit 101), even after a transaction was submitted.
    #[test]
    fn test_a_closed_pipe_is_an_error_not_a_panic() {
        let msg = write_line(&mut ClosedPipe, "Transaction ID: ab")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("failed to write to stdout"), "got: {msg}");
    }

    #[test]
    fn test_color_only_on_a_terminal_without_no_color() {
        let set = |v: &str| Some(std::ffi::OsString::from(v));
        assert!(use_color(true, None, set("xterm-256color")));
        assert!(use_color(true, set(""), None));
        assert!(!use_color(false, None, None));
        assert!(!use_color(true, set("1"), None));
        assert!(!use_color(true, None, set("dumb")));
    }

    fn parse_error(args: &[&str]) -> String {
        let argv = [&["ykada", "send", "--to", "addr_test1x"][..], args].concat();
        Cli::try_parse_from(argv)
            .err()
            .expect("the arguments must be refused")
            .to_string()
    }

    #[test]
    fn test_fractional_ada_points_to_lovelace() {
        ["1.5", "1,5"].iter().for_each(|amount| {
            let msg = parse_error(&["--ada", amount]);
            assert!(
                msg.contains("for a fraction use --lovelace"),
                "{amount}: {msg}"
            );
        });
    }

    #[test]
    fn test_missing_amount_names_both_options() {
        let msg = parse_error(&[]);
        assert!(
            msg.contains("--ada") && msg.contains("--lovelace"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_ada_and_lovelace_together_are_refused() {
        let msg = parse_error(&["--ada", "1", "--lovelace", "1000000"]);
        assert!(msg.contains("cannot be used with"), "got: {msg}");
    }

    #[test]
    fn test_binary_input_is_refused() {
        let msg = read_limited(&[0xff, 0xfe][..], "test")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("is not text"), "got: {msg}");
    }
}
