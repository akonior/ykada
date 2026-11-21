# ykada: YubiKey Cardano Wallet

[![Cargo Test](https://github.com/akonior/ykada/actions/workflows/cargo-test.yml/badge.svg?branch=main)](https://github.com/akonior/ykada/actions/workflows/cargo-test.yml?query=branch%3Amain)

**Turn your YubiKey into a Cardano hardware wallet.** The keys live on the YubiKey, and every
transaction is signed on the device after your PIN and a touch.

> [!CAUTION]
> **Proof of concept, not security-audited.** Provided "as is", without warranty of any kind.
> Do not use it with funds you cannot afford to lose.

## Install

You need a YubiKey 5 with firmware 5.7 or later, and `pinentry` (`brew install pinentry`).

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/akonior/ykada/releases/latest/download/ykada-installer.sh | sh
```

This installs the macOS binary. On other systems, [build from source](docs/development.md).

## Receive and send ADA

```sh
ykada generate                      # create a wallet; write down the 24 words it prints
ykada info                          # your address: share it to receive ADA
ykada balance                       # how much ADA you have
ykada send --to addr_test1... --ada 5   # send: enter your PIN, then touch the YubiKey
```

These commands use the Preview testnet, where ADA is free from the
[faucet](https://docs.cardano.org/cardano-testnets/tools/faucet). Add `--network mainnet` to use
real ADA.

> [!WARNING]
> The 24 words are your only backup, and only ykada can restore the wallet from them. Other
> Cardano wallets derive a different address from the same words.
> [Why?](docs/keys-and-addresses.md)

## Commands

- [`generate`](docs/commands.md#generate): create a new wallet on the YubiKey
- [`import`](docs/commands.md#import): restore a wallet from its 24 words
- [`info`](docs/commands.md#info): show the wallet address
- [`balance`](docs/commands.md#balance): show the ADA balance
- [`send`](docs/commands.md#send): send ADA
- [`sign-tx`](docs/commands.md#sign-tx): sign a transaction built by another tool, such as Eternl
- [`decode-tx`](docs/commands.md#decode-tx): show a transaction and check its signatures

## Learn more

- [Commands](docs/commands.md): every command and option
- [Security model](docs/security.md): what the YubiKey protects, and what it does not
- [Keys and addresses](docs/keys-and-addresses.md): derivation paths, PIV slots, and why the
  address differs from other wallets
- [Development](docs/development.md): build from source, tests and releases
- [Milestone reports](docs/milestones/README.md) for Project Catalyst Fund 14

## License

[Apache 2.0](LICENSE)
