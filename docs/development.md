# Development

## Build from source

You need a current stable [Rust](https://rustup.rs). In a clone,
[`rust-toolchain.toml`](../rust-toolchain.toml) pins the exact version, and rustup installs it on
the first build. On Linux you also need PC/SC: `sudo apt-get install libpcsclite-dev pkg-config pcscd`.

```sh
cargo install --git https://github.com/akonior/ykada --locked
```

From a clone, the [`justfile`](../justfile) has the common tasks:

```sh
just build     # release binary in target/release/ykada
just install   # install this version as ykada in ~/.cargo/bin
just check     # unit, property, CLI and script tests, fmt and clippy: exactly what CI runs
just itest     # end-to-end test on a real YubiKey (see below)
```

## Code layout

| Directory | What is in it |
|-----------|---------------|
| `src/model` | Domain types: mnemonic, keys, PIN, policies, network, UTxO |
| `src/logic` | Pure functions: key derivation, addresses, coin selection, signature checks |
| `src/ports` | Traits for the device and the chain |
| `src/adapters` | The YubiKey (PIV) and Koios implementations, and fakes for tests |
| `src/use_cases` | Wallet creation, building, signing and decoding transactions |
| `src/bin/ykada.rs` | The command-line interface |
| `tests/cli.rs` | Tests that run the `ykada` binary, without a YubiKey |

## Tests

`just check` runs the unit, property and CLI tests and the tests of `scripts/`, without a
YubiKey or the network. GitHub Actions runs them on every push and pull request.
[Testing](testing.md) describes each layer, the rules for new code and the checks to run by
hand before a release.

`just itest` runs the whole CLI against a real YubiKey 5 with firmware 5.7 or later. Connect
only that one YubiKey.

1. Copy `scripts/.env.example` to `scripts/.env` and fill in a **test** wallet's mnemonic and
   address. `scripts/.env` is git-ignored.
2. Run `just itest`. It uses the wallet already on the YubiKey and stays offline: it checks
   `info`, `balance`, `send --dry-run`, `send --only-sign` and `sign-tx`, each verified with
   `decode-tx`.
3. `just itest --reset` first resets the YubiKey's PIV applet and imports the test wallet from
   `scripts/.env`. `just itest --live` also submits a transaction on Preview or PreProd and
   waits for it to be confirmed.

> [!WARNING]
> `--reset` deletes every key in the YubiKey's PIV applet. Before that, the test reads the key
> metadata of every PIV key slot, and resets only if no slot holds a key, or if 9c and 9d are
> the only slots with keys and hold the wallet in `YKADA_ADDRESS`. In any other case, or if a
> check fails, it resets nothing. Never use a YubiKey that holds real funds.

## Releases

Pushing a tag `vX.Y.Z` that matches `version` in `Cargo.toml` starts the release workflow. It
builds the macOS and Linux binaries and the shell installer and publishes them on the
[Releases](https://github.com/akonior/ykada/releases) page.
