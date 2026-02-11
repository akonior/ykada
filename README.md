# yubikey-cardano-wallet
Open-source tool enabling Cardano private key storage on YubiKey and secure signing of Cardano transactions.

## Building and Running

To build the project, run:

```sh
cargo build
```

To run the YubiKey Cardano wallet tool, use:

```sh
cargo run --quiet --bin ykada
```

## Installation

You can install the YubiKey Cardano wallet CLI globally using [cargo](https://doc.rust-lang.org/cargo/):

```sh
cargo install --path . --locked
```

![Installation Demo](docs/gif/installation.gif)


This will build and install the `ykada` binary into your Cargo bin directory (typically `~/.cargo/bin`). Make sure this directory is in your `PATH` to run `ykada` from anywhere.

When you run `ykada`, you should see output similar to the following:

```
YubiKey Cardano wallet

Usage: ykada [OPTIONS] <COMMAND>

Commands:
  import-key  Import a private key into the YubiKey
  sign        Sign data using the YubiKey
  generate    Generate a new key in the YubiKey
  help        Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
  -V, --version     Print version
```

## Testing

### Unit Tests (No Hardware Required)

Run unit tests (including mock tests):

```sh
cargo test --lib --bins
```

### Hardware Tests (Requires YubiKey)

Hardware tests are ignored by default. To run them, enable the `hardware-tests` feature flag:

```sh
# Run all hardware tests
cargo test --lib yubikey::piv --features hardware-tests

# Or use the helper script
./scripts/test-hardware.sh

# Run a specific hardware test
cargo test --lib test_pin_verification_success --features hardware-tests

# Run specific test by full path
cargo test --lib yubikey::piv::tests::test_pin_verification_success --features hardware-tests
```

**Note**: Hardware tests require:
- A YubiKey device connected to your computer
- The default PIN (usually `123456`) or your configured PIN
- Physical touch confirmation if Touch Policy is enabled

**How it works**: Tests are conditionally ignored using `#[cfg_attr(not(feature = "hardware-tests"), ignore)]`. 
Without the feature flag, tests are ignored. With `--features hardware-tests`, they run normally.