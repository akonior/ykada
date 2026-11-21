#!/usr/bin/env python3
"""ykada end-to-end integration test (requires a connected YubiKey 5.7+).

Layered, so it is safe to run on every refactor:

  default       Offline suite. Resets the device, imports a wallet (via --seed-file),
                reads info/balance, builds (--dry-run), signs on-device (--only-sign),
                and signs the same tx via stdin (sign-tx). Every tx is round-tripped
                through `decode-tx`, which re-verifies the Ed25519 witness locally and
                confirms sign-tx preserves the body; a couple of negative checks run too.
                Real hardware signatures, but nothing hits the mempool — fast & deterministic.
  --live        Also submits a real transaction and polls Koios until it confirms.
  --no-reset    Skip the PIV reset + import; run against the wallet already on the
                device (no seed required). Handy for quick iterative runs.

WARNING: a full run wipes all PIV keys on the connected YubiKey (`ykman piv reset`).
It refuses to do so when the key holds a wallet other than YKADA_ADDRESS.

Secrets: the funded seed is NEVER committed. It is read from scripts/.env
(git-ignored). Copy scripts/.env.example to scripts/.env and fill in YKADA_SEED.

Config (env or scripts/.env):
  YKADA_SEED       BIP39 mnemonic to import           (required unless --no-reset)
  YKADA_ADDRESS    testnet address of that wallet; the only wallet the test may wipe
  YKADA_NETWORK    preview | preprod                   (default: preview)
  YKADA_RECIPIENT  destination address                 (default: the wallet itself)
  YKADA_AMOUNT     lovelace to send                    (default: 1500000)
  YKADA_BIN        path to the ykada binary            (default: build & use release)
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
GREEN, BLUE, RED, NC = "\033[0;32m", "\033[0;34m", "\033[0;31m", "\033[0m"

KOIOS = {
    "preview": "https://preview.koios.rest/api/v1",
    "preprod": "https://preprod.koios.rest/api/v1",
}
SCAN = {
    "preview": "https://preview.cardanoscan.io/transaction/",
    "preprod": "https://preprod.cardanoscan.io/transaction/",
}


def step(msg): print(f"{BLUE}==>{NC} {msg}")
def ok(msg): print(f"{GREEN}✔ {msg}{NC}")
def fail(msg) -> NoReturn: sys.exit(f"{RED}✗ {msg}{NC}")


def load_dotenv(path):
    """Minimal KEY=VALUE parser so the funded seed stays out of the repo."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def run(*args, input_text=None, timeout=180):
    """Run a command, returning stripped stdout; abort with stderr on failure.

    A timeout guards against a hung device or network call wedging the suite.
    `input_text` is fed to stdin (used to pipe CBOR into decode-tx / sign-tx).
    """
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, input=input_text, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        fail(f"command timed out after {timeout}s: {' '.join(args)}")
    if result.returncode != 0:
        fail(f"command failed: {' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def run_fail(*args, input_text=None, timeout=60):
    """Run a command expected to FAIL; return its stderr. Abort if it succeeds."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, input=input_text, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        fail(f"command timed out after {timeout}s: {' '.join(args)}")
    if result.returncode == 0:
        fail(f"expected failure but command succeeded: {' '.join(args)}")
    return result.stderr.strip()


def decode_summary(binary, cbor_hex):
    """Decode a tx via the CLI (asserts valid CBOR + locally verifies any witnesses)."""
    return run(binary, "decode-tx", input_text=cbor_hex)


def field_from(output, label):
    for line in output.splitlines():
        if label in line:
            return line.split(":", 1)[1].strip()
    fail(f"decode-tx output missing '{label}'")


def address_from(output):
    for line in output.splitlines():
        if line.startswith("Cardano address"):
            return line.split(":", 1)[1].strip()
    return ""


def ada_from(balance_output):
    for line in balance_output.splitlines():
        if line.startswith("Balance:"):
            return float(line.split()[1])
    fail("could not parse ADA balance")


def koios_confirmations(network, txid):
    url = f"{KOIOS[network]}/tx_status"
    body = json.dumps({"_tx_hashes": [txid]}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.load(resp)
    # `data` is empty until Koios sees the tx; once present, num_confirmations may be null.
    return (data[0].get("num_confirmations") or 0) if data else 0


def is_hex(s):
    return bool(s) and all(c in "0123456789abcdef" for c in s)


def main():
    load_dotenv(ROOT / "scripts" / ".env")
    live = "--live" in sys.argv[1:]
    no_reset = "--no-reset" in sys.argv[1:]

    network = os.environ.get("YKADA_NETWORK", "preview")
    if network not in KOIOS:
        fail(f"unsupported network: {network} (this test runs on preview or preprod only)")
    amount = os.environ.get("YKADA_AMOUNT", "1500000")
    seed = os.environ.get("YKADA_SEED", "")

    if subprocess.run(["ykman", "list"], capture_output=True).returncode != 0:
        fail("no YubiKey detected (is `ykman` installed and a key plugged in?)")

    binary = os.environ.get("YKADA_BIN")
    if not binary:
        step("Building ykada (release)")
        run("cargo", "build", "--bin", "ykada", "--release", "--locked")
        binary = str(ROOT / "target" / "release" / "ykada")
        ok("built")

    if no_reset:
        step("Skipping reset/import (--no-reset); using on-device wallet")
        addr = address_from(run(binary, "info", "--network", network))
        if not addr:
            fail("no wallet on device — run without --no-reset to import one")
    else:
        if not seed:
            fail("YKADA_SEED is not set — copy scripts/.env.example to scripts/.env")
        step("Checking that the YubiKey holds no wallet, or only the test wallet")
        on_device = address_from(run(binary, "info", "--network", network))
        if on_device and on_device != os.environ.get("YKADA_ADDRESS", ""):
            fail(f"the YubiKey holds another wallet ({on_device}); refusing to wipe it. "
                 "If it is the test wallet, set YKADA_ADDRESS to it in scripts/.env; "
                 "otherwise restore your own backup first or use another key")
        ok("safe to reset")

        step("Resetting YubiKey PIV (wipes all keys)")
        run("ykman", "piv", "reset", "--force")
        ok("device reset to defaults")

        step("info on a freshly-reset device reports no wallet")
        if address_from(run(binary, "info", "--network", network)):
            fail("expected no wallet after reset, but info returned an address")
        ok("no wallet present (as expected)")

        step("Importing wallet (via --seed-file; pin/touch disabled for automation)")
        seed_file = ROOT / "scripts" / ".seed.tmp"
        seed_file.touch(mode=0o600)
        seed_file.write_text(seed)
        try:
            addr = address_from(run(binary, "import", "--seed-file", str(seed_file),
                                     "--network", network, "--pin-policy", "never",
                                     "--touch-policy", "never"))
        finally:
            seed_file.unlink(missing_ok=True)
        if not addr:
            fail("import did not print an address")
        ok(f"imported, address: {addr}")

        info_addr = address_from(run(binary, "info", "--network", network))
        if info_addr != addr:
            fail(f"info address ({info_addr}) != import address ({addr})")
        ok("info matches import")

    recipient = os.environ.get("YKADA_RECIPIENT", addr)  # default: send to self

    step("Checking on-chain balance")
    ada = ada_from(run(binary, "balance", "--network", network))
    if ada <= 0:
        fail(f"balance is 0 — fund {addr} from the testnet faucet before running")
    ok(f"funded: {ada} ADA")

    step("Building unsigned transaction (--dry-run)")
    unsigned = run(binary, "send", "--to", recipient, "--lovelace", amount,
                   "--network", network, "--dry-run")
    if not is_hex(unsigned):
        fail("dry-run did not produce hex CBOR")
    unsigned_summary = decode_summary(binary, unsigned)
    unsigned_hash = field_from(unsigned_summary, "body hash")
    if field_from(unsigned_summary, "Witnesses verified") != "0/0":
        fail("unsigned tx unexpectedly carries witnesses")
    ok(f"unsigned tx: {len(unsigned)} hex chars, body {unsigned_hash[:16]}…")

    step("Signing on device (--only-sign, real hardware signature)")
    signed = run(binary, "send", "--to", recipient, "--lovelace", amount,
                 "--network", network, "--only-sign")
    if not is_hex(signed) or len(signed) <= len(unsigned):
        fail("only-sign did not add a signature")
    if field_from(decode_summary(binary, signed), "Witnesses verified") != "1/1":
        fail("only-sign witness failed local verification")
    ok(f"signed tx: {len(signed)} hex chars, witness verifies locally")

    step("Signing the same unsigned tx via stdin (sign-tx path)")
    signtx = run(binary, "sign-tx", "--network", network, input_text=unsigned)
    if not is_hex(signtx):
        fail("sign-tx did not produce hex CBOR")
    signtx_summary = decode_summary(binary, signtx)
    if field_from(signtx_summary, "Witnesses verified") != "1/1":
        fail("sign-tx witness failed local verification")
    if field_from(signtx_summary, "body hash") != unsigned_hash:
        fail("sign-tx altered the transaction body")
    ok("sign-tx preserves the body and the witness verifies")

    step("Negative checks (no funds moved)")
    run_fail(binary, "send", "--to", "addr_test1_not_a_real_address",
             "--lovelace", amount, "--network", network, "--dry-run")
    run_fail(binary, "send", "--to", recipient, "--ada", "1", "--lovelace", "1",
             "--network", network, "--dry-run")
    ok("invalid recipient and --ada/--lovelace conflict are both rejected")

    if not live:
        print()
        ok("OFFLINE SUITE PASSED (nothing submitted). Re-run with --live to submit.")
        return

    step(f"LIVE: submitting transaction to {network}")
    submit_out = run(binary, "send", "--to", recipient, "--lovelace", amount,
                     "--network", network)
    txid = ""
    for line in submit_out.splitlines():
        if line.startswith("Transaction ID:"):
            txid = line.split(":", 1)[1].strip()
    if not txid:
        fail("submit did not return a transaction ID")
    ok(f"submitted: {txid}")
    print(f"    explorer: {SCAN[network]}{txid}")

    step("Polling Koios for confirmation (timeout 300s)")
    for _ in range(60):
        if koios_confirmations(network, txid) >= 1:
            ok("confirmed on-chain")
            print()
            ok("LIVE SUITE PASSED")
            return
        time.sleep(5)
    fail(f"not confirmed within timeout — check {SCAN[network]}{txid}")


if __name__ == "__main__":
    main()
