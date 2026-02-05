#!/usr/bin/env bash
set -euo pipefail

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

GREEN="\033[0;32m"

BLUE="\033[0;34m"
NC="\033[0m"

step() {
  echo -e "${BLUE}==>${NC} $1"
}

ok() {
  echo -e "${GREEN}✔ $1${NC}"
}

step "Building ykada in release mode"
cargo build --bin ykada --release
ok "ykada built successfully"

step "Generating Ed25519 keys using OpenSSL (sk.pem, pk.pem, sk.der)"
openssl genpkey -algorithm ed25519 -out "$TMPDIR"/sk.pem
openssl pkey -in "$TMPDIR"/sk.pem -pubout -out "$TMPDIR"/pk.pem
openssl pkey -in "$TMPDIR"/sk.pem -outform DER -out "$TMPDIR"/sk.der

ok "Ed25519 keys generated successfully by OpenSSL"

RELEASE_BIN="target/release/ykada"
if [[ ! -x "$RELEASE_BIN" ]]; then
  echo "ERROR: ykada binary not found at $RELEASE_BIN" >&2
  exit 1
fi

step "Loading private key (sk.der) into YubiKey"
cat "$TMPDIR"/sk.der | "$RELEASE_BIN" import-key
ok "Private key loaded into YubiKey"

step "Preparing example message to sign"
echo "hello yubikey" > "$TMPDIR"/msg.bin
ok "Example message prepared successfully"

step "Signing message using ykada"
cat "$TMPDIR"/msg.bin | "$RELEASE_BIN" sign > "$TMPDIR"/sig.bin
ok "Message signed successfully"

step "Verifying signature using OpenSSL"
openssl pkeyutl \
  -verify \
  -pubin -inkey "$TMPDIR"/pk.pem \
  -in "$TMPDIR"/msg.bin \
  -sigfile "$TMPDIR"/sig.bin
ok "Signature independently verified by OpenSSL successfully"
