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

You should see output similar to:

```
YubiKey Cardano wallet

Usage: ykada [OPTIONS] <COMMAND>

Commands:
  load-key  Load a private key (DER) into YubiKey
  sign      Sign data provided via stdin
  info
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
  -V, --version     Print version
```

