#!/usr/bin/env bash

set -euo pipefail

ykman piv reset --force
ykman piv access change-management-key --management-key 010203040506070801020304050607080102030405060708  --new-management-key 010203040506070801020304050607080102030405060709 --force

cargo test --bins --lib --all-features --all --locked --verbose -- --test-threads=1

cargo fmt --check
cargo clippy --locked
