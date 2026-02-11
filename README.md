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

## Key Generation on YubiKey

You can generate a new Ed25519 key directly inside your YubiKey, ensuring the private key never leaves the device.

### Command

```sh
ykada generate [OPTIONS]
```

### Options

| Option                       | Description                                                                                         | Default            | Possible Values                                                    |
|------------------------------|-----------------------------------------------------------------------------------------------------|--------------------|--------------------------------------------------------------------|
| `--slot <SLOT>`              | Selects the YubiKey slot for the new key.                                                          | `signature`        | authentication, signature, key-management, card-authentication     |
| `--pin-policy <PIN_POLICY>`  | Sets when PIN entry is required (e.g. for signing/using the key).                                  | `always`           | never, once, always                                                |
| `--touch-policy <TOUCH_POLICY>` | Controls when physical touch on YubiKey is required (for signing/using the key).                 | `always`           | never, always, cached                                              |
| `--mgmt-key <MGMT_KEY>`      | Optionally provide a custom management key for key operations.                                     |                    |                                                                    |
| `-v`, `--verbose`            | Increase logging verbosity.                                                                         |                    |                                                                    |
| `-q`, `--quiet`              | Decrease logging verbosity.                                                                         |                    |                                                                    |
| `-h`, `--help`               | Print help message.                                                                                |                    |                                                                    |

### Example

Generate a new key in the *signature* slot with default policies:

```sh
ykada generate
```

![Generate Demo](docs/gif/generate.gif)

Or, generate a key for authentication that only requires PIN verification once, and requires a touch:

```sh
ykada generate --slot authentication --pin-policy once --touch-policy always
```

**Note:**  
- The new key will be stored securely in the selected slot. The public key will be displayed on success.

For more advanced usage and supported features, see:

```sh
ykada generate --help
```

## Importing an Existing Private Key

You can import an existing Ed25519 private key into your YubiKey using the `import-key` command. This is useful for migrating keys generated elsewhere, restoring wallets, or specifying custom keys for Cardano signing.

### Usage

```sh
ykada import-key [OPTIONS]
```

### Options

| Option                           | Description                                                                                           | Default Value | Possible Values                                                  |
|---------------------------------- |-------------------------------------------------------------------------------------------------------|---------------|------------------------------------------------------------------|
| `--slot <SLOT>`                  | Selects YubiKey slot where key will be imported.                                                       | `signature`   | authentication, signature, key-management, card-authentication   |
| `--pin-policy <PIN_POLICY>`      | Sets when PIN entry is required for key usage.                                                         | `always`      | never, once, always                                              |
| `--touch-policy <TOUCH_POLICY>`  | Requires physical touch on YubiKey for key usage.                                                      | `always`      | never, always, cached                                            |
| `--mgmt-key <MGMT_KEY>`          | Optionally provide a custom management key for administrative actions.                                 |               |                                                                  |
| `--seed <SEED>`                  | BIP-39 compatible seed phrase for key derivation (import from seed).                                   |               |                                                                  |
| `--passphrase <PASSPHRASE>`      | Optional passphrase to use with seed phrase (used with `--seed`).                                      | *(empty)*     |                                                                  |
| `--path <PATH>`                  | BIP-32 derivation path (used with seed phrase).                                                        |               |                                                                  |
| `-v`, `--verbose`                | Increase logging verbosity.                                                                            |               |                                                                  |
| `-q`, `--quiet`                  | Decrease logging verbosity.                                                                            |               |                                                                  |
| `-h`, `--help`                   | Print help message.                                                                                   |               |                                                                  |

By default, if no seed is given, the key material is read from standard input as a DER-encoded (PKCS#8) Ed25519 private key.

### Import from Seed Phrase (BIP-39):

Import a key derived from a BIP-39 seed phrase into your YubiKey in the authentication slot:

```sh
ykada import-key --seed "spirit supply whale amount human item harsh scare congress discover talent hamster" --slot authentication
```

Optionally, use a passphrase and a custom derivation path:

```sh
ykada import-key --seed "spirit supply whale ..." --passphrase "extra entropy" --path "m/1852'/1815'/0'/0/0" --slot signature
```

![Import from seed Demo](docs/gif/import-seed.gif)

### Import from DER-encoded Key:

To import a DER-encoded Ed25519 private key from a file:

```sh
cat mykey.der | ykada import-key --slot signature
```

![Import DER Demo](docs/gif/import-der.gif)

You may combine with other options to set PIN/touch policies or management key as needed.

**Note:**
- Supplying the wrong key type or an improperly formatted file may cause the import to fail.

For further information or additional help:

```sh
ykada import-key --help
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