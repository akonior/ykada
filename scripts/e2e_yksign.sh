#!/usr/bin/env bash
set -euo pipefail

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Using temp dir: $TMPDIR"

openssl genpkey -algorithm ed25519 -out "$TMPDIR"/sk.pem
openssl pkey -in "$TMPDIR"/sk.pem -pubout -out "$TMPDIR"/pk.pem
openssl pkey -in "$TMPDIR"/sk.pem -outform DER -out "$TMPDIR"/sk.der

echo "Generated $TMPDIR/sk.pem, $TMPDIR/pk.pem, $TMPDIR/sk.der"

cargo build --bin yksign --release

YKSIGN_BIN="target/release/yksign"
if [[ ! -x "$YKSIGN_BIN" ]]; then
  echo "ERROR: yksign binary not found at $YKSIGN_BIN" >&2
  exit 1
fi

cat "$TMPDIR"/sk.der | "$YKSIGN_BIN" load-key

echo "hello yubikey" > "$TMPDIR"/msg.bin

cat "$TMPDIR"/msg.bin | "$YKSIGN_BIN" sign > "$TMPDIR"/sig.bin

ls -l "$TMPDIR"/msg.bin "$TMPDIR"/sig.bin "$TMPDIR"/pk.pem

openssl pkeyutl \
  -verify \
  -pubin -inkey "$TMPDIR"/pk.pem \
  -in "$TMPDIR"/msg.bin \
  -sigfile "$TMPDIR"/sig.bin

echo "OK: signature verified successfully"
