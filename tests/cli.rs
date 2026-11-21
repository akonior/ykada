//! Black-box tests of the `ykada` binary: exit codes, messages, what goes to stdout and
//! stderr, and no panics. None of them needs a YubiKey or the network. Every case finishes, or
//! is refused, before ykada looks for a device; `send` cases also pass `--dry-run`, so even a
//! regression that let them reach a plugged-in YubiKey could not sign or submit anything.

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};

const SIGNED_TX: &str = include_str!("fixtures/preview-signed-tx.hex");
const SIGNED_TX_ID: &str = "4aa9417442e9b042075472a425516314005f6c3aeec80a477405420d06200a44";
const TESTNET_ADDRESS: &str = "addr_test1qrfw6ye0m7f2kvqapnkp7jzlfydq0h6j5rnsvj2wm9vlhg0y86x894xrsh5xu8qlm6yld03hp7sx6u552w6uupd799fqz0vpte";

fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ykada"));
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

// Runs ykada with `stdin` fed from a thread, so a large input can't deadlock the pipes.
fn ykada(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = command(args).spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let bytes = stdin.to_vec();
    // ykada may stop reading early (a size limit, a usage error): a broken pipe here is fine.
    let feeder = std::thread::spawn(move || input.write_all(&bytes));
    let output = child.wait_with_output().unwrap();
    let _ = feeder.join();
    output
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// Refused with exit code `code`, a plain message on stderr that contains `reason`, and nothing
// on stdout, where a script would take it for a result.
fn assert_refused(output: &Output, code: i32, reason: &str) {
    let err = stderr(output);
    assert_eq!(output.status.code(), Some(code), "stderr: {err}");
    assert!(err.contains(reason), "expected {reason:?} in: {err}");
    assert!(!err.contains("panicked"), "panic: {err}");
    assert!(!err.contains('\x1b'), "color without a terminal: {err:?}");
    assert!(output.stdout.is_empty(), "stdout: {}", stdout(output));
}

fn temp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ykada-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn decode_tx_verifies_a_signed_transaction() {
    let output = ykada(&["decode-tx"], SIGNED_TX.as_bytes());
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains(&format!("Transaction body hash: {SIGNED_TX_ID}")));
    assert!(stdout(&output).contains("Witnesses verified:    1/1"));
    assert!(output.stderr.is_empty(), "stderr: {}", stderr(&output));
}

// If the scripts fail, the collateral's remainder goes to this address: it must be visible.
#[test]
fn decode_tx_shows_where_collateral_is_returned() {
    use pallas_addresses::Address;
    use pallas_crypto::hash::Hash;
    use pallas_txbuilder::{BuildConway, Input, Output as TxOutput, StagingTransaction};
    let return_address = Address::from_bytes(&[0x60; 29]).unwrap();
    let return_text = return_address.to_bech32().unwrap();
    let tx = StagingTransaction::new()
        .input(Input::new(Hash::new([1; 32]), 0))
        .output(TxOutput::new(
            Address::from_bech32(TESTNET_ADDRESS).unwrap(),
            2_000_000,
        ))
        .fee(200_000)
        .collateral_input(Input::new(Hash::new([2; 32]), 0))
        .collateral_output(TxOutput::new(return_address, 3_000_000))
        .build_conway_raw()
        .unwrap();
    let result = ykada(&["decode-tx"], hex::encode(tx.tx_bytes.0).as_bytes());
    assert!(result.status.success(), "{}", stderr(&result));
    let summary = stdout(&result);
    assert!(summary.contains(TESTNET_ADDRESS), "{summary}");
    assert!(
        summary.contains(&format!(
            "Collateral return:     3000000 lovelace -> {return_text}"
        )),
        "missing collateral recipient {return_text}: {summary}"
    );
}

#[test]
fn decode_tx_reads_a_file_or_a_dash_for_stdin() {
    let path = temp_file("signed.hex", SIGNED_TX.as_bytes());
    let from_file = ykada(&["decode-tx", "--tx-file", path.to_str().unwrap()], b"");
    let from_dash = ykada(&["decode-tx", "--tx-file", "-"], SIGNED_TX.as_bytes());
    std::fs::remove_file(path).unwrap();
    assert_eq!(from_file.status.code(), Some(0), "{}", stderr(&from_file));
    assert_eq!(from_file.stdout, from_dash.stdout);
}

#[test]
fn decode_tx_refuses_bytes_after_the_transaction() {
    let output = ykada(&["decode-tx"], format!("{SIGNED_TX}00").as_bytes());
    assert_refused(&output, 1, "bytes after the end of the transaction");
}

// Reading /dev/zero used to grow without bound.
#[test]
fn decode_tx_refuses_input_over_one_mebibyte() {
    let output = ykada(&["decode-tx"], &vec![b'0'; 2 << 20]);
    assert_refused(&output, 1, "more than 1 MiB");
}

#[test]
fn decode_tx_refuses_what_is_not_a_transaction() {
    let cases: [(&[u8], &str); 4] = [
        (&[0xff, 0xfe, 0x00], "is not text"),
        (b"hello", "neither transaction JSON nor CBOR hex"),
        (b"{\"cborHex\": ", "invalid transaction JSON"),
        (b"", "invalid transaction CBOR"),
    ];
    cases.iter().for_each(|(input, reason)| {
        assert_refused(&ykada(&["decode-tx"], input), 1, reason);
    });
}

#[test]
fn decode_tx_reports_a_bad_signature_with_exit_code_1() {
    let signature_start = SIGNED_TX.len() - 2 - 128;
    let flipped = match &SIGNED_TX[signature_start..signature_start + 1] {
        "0" => "1",
        _ => "0",
    };
    let tampered = [
        &SIGNED_TX[..signature_start],
        flipped,
        &SIGNED_TX[signature_start + 1..],
    ]
    .concat();
    let output = ykada(&["decode-tx"], tampered.as_bytes());
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("Witnesses verified:    0/1"));
    assert!(stderr(&output).contains("1 of 1 witness signature(s) failed verification"));
}

// `ykada ... | head -c1`: a reader that goes away must give an error, not a panic (exit 101).
#[test]
fn a_closed_stdout_is_an_error_not_a_panic() {
    let mut child = command(&["decode-tx"]).spawn().unwrap();
    drop(child.stdout.take());
    let mut input = child.stdin.take().unwrap();
    input.write_all(SIGNED_TX.as_bytes()).unwrap();
    drop(input);
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("Broken pipe"), "stderr: {err}");
    assert!(!err.contains("panicked"), "stderr: {err}");
}

fn dry_run_send(args: &[&str]) -> Output {
    ykada(&[&["send", "--dry-run"][..], args].concat(), b"")
}

// The address, amount and fee are checked before the device: a typo never reaches a PIN prompt.
#[test]
fn send_checks_the_payment_before_looking_for_a_yubikey() {
    let cases: [(&[&str], &str); 5] = [
        (
            &["--to", "addr_test1bogus", "--ada", "2"],
            "invalid recipient address",
        ),
        (
            &[
                "--to",
                TESTNET_ADDRESS,
                "--ada",
                "2",
                "--network",
                "mainnet",
            ],
            "but --network is Mainnet",
        ),
        (
            &["--to", TESTNET_ADDRESS, "--ada", "2", "--fee", "50000000"],
            "more than 1 ADA",
        ),
        (
            &["--to", TESTNET_ADDRESS, "--lovelace", "999999"],
            "below the min-UTxO floor",
        ),
        (
            &[
                "--to",
                &TESTNET_ADDRESS.replace("addr_test1", "foo1"),
                "--ada",
                "2",
            ],
            "invalid recipient address",
        ),
    ];
    cases.iter().for_each(|(args, reason)| {
        let output = dry_run_send(args);
        assert_refused(&output, 1, reason);
        assert!(!stderr(&output).contains("YubiKey"), "{}", stderr(&output));
    });
}

#[test]
fn send_explains_amount_options() {
    let fraction = dry_run_send(&["--to", TESTNET_ADDRESS, "--ada", "1.5"]);
    assert_refused(&fraction, 2, "for a fraction use --lovelace");
    let missing = dry_run_send(&["--to", TESTNET_ADDRESS]);
    assert_refused(&missing, 2, "--lovelace");
    let both = dry_run_send(&["--to", TESTNET_ADDRESS, "--ada", "1", "--lovelace", "1"]);
    assert_refused(&both, 2, "cannot be used with");
}

// A transaction paying a token and donating to the treasury: [body, {}, true, null].
fn token_and_donation_tx() -> String {
    use pallas_codec::minicbor::Encoder;
    let address = bech32::decode(TESTNET_ADDRESS).unwrap().1;
    let mut e = Encoder::new(Vec::new());
    e.array(4).unwrap().map(4).unwrap();
    e.u8(0).unwrap().array(1).unwrap().array(2).unwrap();
    e.bytes(&[1; 32]).unwrap().u8(0).unwrap();
    e.u8(1).unwrap().array(1).unwrap().array(2).unwrap();
    e.bytes(&address)
        .unwrap()
        .array(2)
        .unwrap()
        .u64(2_000_000)
        .unwrap();
    e.map(1).unwrap().bytes(&[7; 28]).unwrap();
    e.map(1).unwrap().bytes(b"MONEY").unwrap().u64(5).unwrap();
    e.u8(2).unwrap().u64(200_000).unwrap();
    e.u8(22).unwrap().u64(25_000_000).unwrap();
    e.map(0).unwrap().bool(true).unwrap().null().unwrap();
    hex::encode(e.into_writer())
}

// The YubiKey has no screen: every token and the donation must be spelled out, with amounts.
#[test]
fn decode_tx_spells_out_tokens_and_a_treasury_donation() {
    let output = ykada(&["decode-tx"], token_and_donation_tx().as_bytes());
    let out = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    let token = format!("      + 5 {}.4d4f4e4559 (\"MONEY\")", hex::encode([7; 28]));
    assert!(out.contains(&token), "{out}");
    assert!(
        out.contains("treasury donation (25000000 lovelace)"),
        "{out}"
    );
}

// The testnet fixture is refused for mainnet before any device is used.
#[test]
fn sign_tx_refuses_a_transaction_for_another_network() {
    let output = ykada(&["sign-tx", "--network", "mainnet"], SIGNED_TX.as_bytes());
    assert_refused(&output, 1, "for Testnet, but --network is Mainnet");
}

#[test]
fn usage_errors_exit_with_code_2() {
    use std::os::unix::ffi::OsStrExt;
    let not_utf8 = std::ffi::OsStr::from_bytes(&[0xff]);
    let output = Command::new(env!("CARGO_BIN_EXE_ykada"))
        .args([
            std::ffi::OsStr::new("info"),
            std::ffi::OsStr::new("--network"),
            not_utf8,
        ])
        .output()
        .unwrap();
    assert_refused(&output, 2, "invalid value");
    assert_refused(&ykada(&["info", "--colour"], b""), 2, "unexpected argument");
    assert_refused(
        &ykada(&["info", "--network", "Preview"], b""),
        2,
        "invalid value",
    );
    assert_refused(&ykada(&["transfer"], b""), 2, "unrecognized subcommand");
}

// docs/commands.md and `--help` list the same options for every command.
#[test]
fn every_documented_option_is_in_the_help_and_back() {
    let docs = include_str!("../docs/commands.md");
    let sections = docs.split("\n## ").skip(1);
    sections.for_each(|section| {
        let name = section.lines().next().unwrap().trim();
        let documented = options_in(section);
        let help = stdout(&ykada(&[name, "--help"], b""));
        let offered = options_in(&help);
        let everywhere = ["--help", "--network"];
        documented.iter().for_each(|option| {
            assert!(
                offered.contains(option),
                "{name}: {option} is documented but not in --help"
            );
        });
        offered
            .iter()
            .filter(|option| !everywhere.contains(&option.as_str()))
            .filter(|option| {
                !(name == "import" && options_in(docs_section(docs, "generate")).contains(option))
            })
            .for_each(|option| {
                assert!(
                    documented.contains(option),
                    "{name}: {option} is in --help but not documented"
                );
            });
    });
}

fn docs_section<'a>(docs: &'a str, name: &str) -> &'a str {
    docs.split("\n## ")
        .find(|section| section.lines().next().map(str::trim) == Some(name))
        .unwrap()
}

fn options_in(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|word| {
            word.strip_prefix("--")
                .is_some_and(|name| name.starts_with(|c: char| c.is_ascii_lowercase()))
        })
        .map(str::to_owned)
        .collect()
}
