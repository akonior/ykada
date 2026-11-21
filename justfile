# Ykada task runner — run `just` to list recipes.

default:
    @just --list

# Build the release binary (target/release/ykada).
build:
    cargo build --release --locked --bin ykada

# Install this version as `ykada` in ~/.cargo/bin (replaces an older install).
install:
    cargo install --path . --locked --force

# Unit, property, CLI and script tests, fmt and clippy — exactly what CI runs (no YubiKey needed).
check:
    cargo test --all-targets --locked
    python3 -m unittest discover -s scripts
    cargo fmt --check
    cargo clippy --all-targets --all-features --locked -- --deny warnings

# End-to-end CLI test on a real YubiKey (see --help). WARNING: --reset wipes PIV.
itest *args:
    ./scripts/integration_test.py {{args}}
