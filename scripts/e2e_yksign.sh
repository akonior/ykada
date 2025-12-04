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

step "Building yksign in release mode"
cargo build --bin yksign --release
ok "yksign built successfully"

step "Generating Ed25519 keys (sk.pem, pk.pem, sk.der)"
openssl genpkey -algorithm ed25519 -out "$TMPDIR"/sk.pem
openssl pkey -in "$TMPDIR"/sk.pem -pubout -out "$TMPDIR"/pk.pem
openssl pkey -in "$TMPDIR"/sk.pem -outform DER -out "$TMPDIR"/sk.der

ok "Ed25519 keys generated successfully"

YKSIGN_BIN="target/release/yksign"
if [[ ! -x "$YKSIGN_BIN" ]]; then
  echo "ERROR: yksign binary not found at $YKSIGN_BIN" >&2
  exit 1
fi

step "Loading private key into YubiKey"
cat "$TMPDIR"/sk.der | "$YKSIGN_BIN" load-key
ok "Private key loaded into YubiKey"

step "Preparing message to sign"
echo "hello yubikey" > "$TMPDIR"/msg.bin
ok "Message prepared successfully"

step "Signing message using yksign"
cat "$TMPDIR"/msg.bin | "$YKSIGN_BIN" sign > "$TMPDIR"/sig.bin
ok "Message signed successfully"

step "Verifying signature using OpenSSL"
openssl pkeyutl \
  -verify \
  -pubin -inkey "$TMPDIR"/pk.pem \
  -in "$TMPDIR"/msg.bin \
  -sigfile "$TMPDIR"/sig.bin
ok "Signature independently verified by OpenSSL successfully"
