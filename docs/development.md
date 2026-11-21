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
just check     # unit tests, fmt and clippy: exactly what CI runs
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

## Tests

`just check` runs the unit tests without a YubiKey or the network. GitHub Actions runs them on
every push and pull request.

`just itest` runs the whole CLI against a real YubiKey 5 with firmware 5.7 or later:

1. Copy `scripts/.env.example` to `scripts/.env` and fill in a **test** wallet's mnemonic and
   address. `scripts/.env` is git-ignored.
2. Run `just itest`. By default it stays offline: it imports the wallet and checks `info`,
   `balance`, `send --dry-run`, `send --only-sign` and `sign-tx`, each verified with
   `decode-tx`.
3. `just itest --live` also submits a transaction on Preview or PreProd and waits for it to be
   confirmed. `just itest --no-reset` uses the wallet already on the YubiKey.

> [!WARNING]
> Without `--no-reset`, the integration test resets the YubiKey's PIV applet, which deletes the
> keys on it. It refuses unless the YubiKey is empty or holds the wallet in `YKADA_ADDRESS`.
> Never use a YubiKey that holds real funds.

## Releases

Pushing a tag `vX.Y.Z` that matches `version` in `Cargo.toml` starts the release workflow. It
builds the macOS binaries and the shell installer and publishes them on the
[Releases](https://github.com/akonior/ykada/releases) page.
