#!/usr/bin/env python3
"""ykada end-to-end integration test (requires one connected YubiKey 5, firmware 5.7+).

By default it uses the wallet already on the YubiKey and stays offline: it reads info and
balance, builds a transaction (--dry-run), signs it on the device (--only-sign) and signs the
same transaction through sign-tx. Every transaction goes through `decode-tx`, which verifies
the Ed25519 witness locally and confirms that sign-tx keeps the body. Nothing is submitted.

  --reset   First wipe the YubiKey's PIV applet (`ykman piv reset`) and import the test
            wallet from YKADA_SEED. Before the reset it reads the key metadata of every PIV
            key slot on the one connected YubiKey, and resets only if no slot holds a key,
            or if 9c and 9d are the only slots with keys and hold the wallet in
            YKADA_ADDRESS. Anything else, including a check that fails, resets nothing.
  --live    Also submit a transaction and wait until Koios sees it confirmed.

Config (environment or scripts/.env, which is git-ignored; see scripts/.env.example):
  YKADA_SEED       mnemonic of the test wallet           (needed with --reset)
  YKADA_ADDRESS    testnet address of that wallet        (needed with --reset)
  YKADA_NETWORK    preview | preprod                     (default: preview)
  YKADA_RECIPIENT  destination address                   (default: the wallet itself)
  YKADA_AMOUNT     lovelace to send                      (default: 1500000)
  YKADA_BIN        path to the ykada binary              (default: build the release binary)
"""
import argparse
import base64
import hashlib
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


# --- Reset guard -------------------------------------------------------------------------
# `ykman piv reset` deletes every key on the PIV applet, so it runs only after every key
# slot of the one connected YubiKey has been read and holds nothing but the test wallet.

# Slots that can hold a user's private key. 9b is the management key, which a reset sets
# back to its default, and f9 holds the factory attestation key.
KEY_SLOTS = ["9a", "9c", "9d", "9e"] + [f"{n:x}" for n in range(0x82, 0x96)]
WALLET_SLOTS = ["9c", "9d"]
NO_KEY = "No key stored in slot"
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")  # DER prefix of an Ed25519 key
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class ResetRefused(Exception):
    """The YubiKey may hold keys other than the test wallet, or it could not be checked."""


def capture(*args, timeout=60):
    """Run a command and return (exit code, stdout, stderr); the code is None if it did not run."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "", str(e)
    return result.returncode, result.stdout, result.stderr


def only_serial(sh):
    """The serial of the one connected YubiKey."""
    listed = [sh("ykman", "list"), sh("ykman", "list", "--serials")]
    if any(code != 0 for code, _, _ in listed):
        raise ResetRefused("could not list the connected YubiKeys")
    devices, serials = ([line for line in out.splitlines() if line.strip()] for _, out, _ in listed)
    if len(devices) != 1 or len(serials) != 1:
        raise ResetRefused(f"{len(devices)} YubiKeys are connected ({len(serials)} with a "
                           "readable serial); connect only the test key")
    return serials[0].strip()


def slot_has_key(sh, serial, slot):
    """Whether `slot` holds a private key, from its metadata. Anything unclear is an error."""
    code, out, err = sh("ykman", "--device", serial, "piv", "keys", "info", slot)
    if code == 0 and "Algorithm:" in out:
        return True
    if code == 1 and NO_KEY in err:
        return False
    raise ResetRefused(f"could not read the key metadata of slot {slot}: "
                       f"{(err or out).strip() or f'exit code {code}'}")


def slot_public_key(sh, serial, slot):
    """The raw Ed25519 public key that the YubiKey reports for the key in `slot`."""
    code, pem, _ = sh("ykman", "--device", serial, "piv", "keys", "export", slot, "-")
    body = "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))
    try:
        der = base64.b64decode(body, validate=True) if code == 0 else b""
    except ValueError:
        der = b""
    if not der.startswith(ED25519_SPKI) or len(der) != len(ED25519_SPKI) + 32:
        raise ResetRefused(f"could not read an Ed25519 public key from slot {slot}")
    return der[len(ED25519_SPKI):]


def bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            checksum ^= generator[i] if (top >> i) & 1 else 0
    return checksum


def bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_payload(address):
    """The bytes encoded in a bech32 string, after checking its checksum."""
    hrp, _, data = address.lower().rpartition("1")
    if not hrp or len(data) < 6 or any(c not in BECH32 for c in data):
        raise ValueError("not a bech32 string")
    values = [BECH32.index(c) for c in data]
    if bech32_polymod(bech32_hrp_expand(hrp) + values) != 1:
        raise ValueError("bad checksum")
    bits = "".join(f"{v:05b}" for v in values[:-6])
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def wallet_key_hashes(address):
    """The payment and stake key hashes of a base address (header type 0)."""
    try:
        payload = bech32_payload(address)
    except ValueError as e:
        raise ResetRefused(f"YKADA_ADDRESS is not a valid address ({e})")
    if len(payload) != 57 or payload[0] >> 4 != 0:
        raise ResetRefused("YKADA_ADDRESS is not a base address with a payment and a stake key")
    return payload[1:29], payload[29:57]


def key_hash(public_key):
    return hashlib.blake2b(public_key, digest_size=28).digest()


def check_reset_is_safe(sh, test_address):
    """The serial of the YubiKey that may be reset; raises ResetRefused otherwise."""
    serial = only_serial(sh)
    used = [slot for slot in KEY_SLOTS if slot_has_key(sh, serial, slot)]
    others = [slot for slot in used if slot not in WALLET_SLOTS]
    if not used:
        return serial
    if others:
        raise ResetRefused(f"slot {', '.join(others)} holds a key that is not the test wallet")
    if used != WALLET_SLOTS:
        raise ResetRefused(f"only slot {used[0]} holds a key, so it is not the whole test wallet")
    on_device = tuple(key_hash(slot_public_key(sh, serial, slot)) for slot in WALLET_SLOTS)
    if on_device != wallet_key_hashes(test_address):
        raise ResetRefused("the keys in 9c and 9d are not the wallet in YKADA_ADDRESS")
    return serial


def reset_piv(sh, test_address):
    """Reset the PIV applet of the checked YubiKey, and only that one. Returns its serial."""
    serial = check_reset_is_safe(sh, test_address)
    code, _, err = sh("ykman", "--device", serial, "piv", "reset", "--force")
    if code != 0:
        raise RuntimeError(f"ykman piv reset failed: {err.strip()}")
    return serial


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        epilog=__doc__.split("\n\n", 1)[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--reset", action="store_true",
                        help="wipe the PIV applet and import the test wallet first")
    parser.add_argument("--live", action="store_true",
                        help="also submit a transaction and wait for it to be confirmed")
    return parser.parse_args()


def main():
    args = parse_args()
    load_dotenv(ROOT / "scripts" / ".env")

    network = os.environ.get("YKADA_NETWORK", "preview")
    if network not in KOIOS:
        fail(f"unsupported network: {network} (this test runs on preview or preprod only)")
    amount = os.environ.get("YKADA_AMOUNT", "1500000")
    seed = os.environ.get("YKADA_SEED", "")
    test_address = os.environ.get("YKADA_ADDRESS", "")
    if args.reset and not (seed and test_address):
        fail("--reset needs YKADA_SEED and YKADA_ADDRESS — copy scripts/.env.example to "
             "scripts/.env")

    if subprocess.run(["ykman", "list"], capture_output=True).returncode != 0:
        fail("no YubiKey detected (is `ykman` installed and a key plugged in?)")

    binary = os.environ.get("YKADA_BIN")
    if not binary:
        step("Building ykada (release)")
        run("cargo", "build", "--bin", "ykada", "--release", "--locked")
        binary = str(ROOT / "target" / "release" / "ykada")
        ok("built")

    if not args.reset:
        step("Using the wallet already on the YubiKey (no reset)")
        addr = address_from(run(binary, "info", "--network", network))
        if not addr:
            fail("no wallet on the YubiKey — import the test wallet, or run with --reset")
        ok(f"wallet: {addr}")
    else:
        step("Checking every PIV key slot, then resetting the PIV applet (wipes all keys)")
        try:
            serial = reset_piv(capture, test_address)
        except ResetRefused as e:
            fail(f"not resetting: {e}. Nothing was changed. If you are sure that nothing on "
                 "this YubiKey is needed, reset it yourself with `ykman piv reset`")
        except RuntimeError as e:
            fail(str(e))
        ok(f"YubiKey {serial} held no keys other than the test wallet; PIV reset to defaults")

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
        if addr != test_address:
            fail(f"YKADA_SEED gives {addr}, not YKADA_ADDRESS ({test_address})")
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

    if not args.live:
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
