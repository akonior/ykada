# Yubikey Cardano Wallet

**Hardware security. Air-gapped keys. Touch to sign.**
Turn your YubiKey into a Cardano hardware wallet.

> [!CAUTION]
> **Proof of concept — do not use with real funds.**
>
> This software is experimental and has not been security-audited. Key derivation, PIV integration, and transaction signing are research-grade implementations that have not undergone independent security review. The software is provided "as is", without warranty of any kind, express or implied. **Do not run on mainnet or with funds you cannot afford to lose.**

`ykada` stores Cardano signing keys on a YubiKey's PIV slots and uses them to sign Cardano transactions — keeping your keys offline and protected by PIN and physical touch.


## Quick Start

**Generate a wallet**

```
$ ykada generate
Mnemonic (store safely): express crime shrimp theory sword always search orbit present spoil glory ribbon foam juice ten isolate armed buffalo perfect mobile dial box notice regret
Cardano address:         addr_test1qphwrxw2kcu4kasezlh5hxnulvha9ufqs55d7tw0jhvv696d9egjx7sqp0tlfh300e4wn88s4r333yl0reu2njwtqy3qm5zq89
```

Write down the 24-word mnemonic and store it safely. It is the only backup of your wallet.

**Check your balance**

```
$ ykada balance
Cardano address:  addr_test1qphwrxw2kcu4kasezlh5hxnulvha9ufqs55d7tw0jhvv696d9egjx7sqp0tlfh300e4wn88s4r333yl0reu2njwtqy3qm5zq89
Account balance:
  ADA:            0.000000
```

**Send ADA**

```
$ ykada send --ada 1 --to addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
Transaction ID: 8f7334094b3c4df2fc5eee892865c4175841da390fe77a4bbfd94b633085d58e
```

## Install

```sh
cargo install --path . --locked
```

Requires a YubiKey 5 series (firmware 5.7+).

## Commands

### `ykada info`

Show Cardano address associated with keys stored on device.

```
$ ykada info
Cardano address:         addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
```

### `ykada generate`

Create a new wallet: generates a random 24-word BIP39 mnemonic, derives payment and stake keys (CIP-1852), and stores them on the YubiKey.

```
$ ykada generate
Mnemonic (store safely): express crime shrimp theory sword always search orbit present spoil glory ribbon foam juice ten isolate armed buffalo perfect mobile dial box notice regret
Cardano address:         addr_test1qphwrxw2kcu4kasezlh5hxnulvha9ufqs55d7tw0jhvv696d9egjx7sqp0tlfh300e4wn88s4r333yl0reu2njwtqy3qm5zq89
```

For full options (network, PIN policy, touch policy, PIV slots, etc.) run `ykada generate --help`.

### `ykada import`

Restore a wallet from an existing BIP39 seed phrase. Derives the same payment and stake keys and stores them on the YubiKey.

```
$ ykada import --seed "slim fine attend tape wave input head crew shift desk find mutual square cake uncle morning provide naive around brief couple faint alcohol young"
Cardano address:         addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
```

Accepts the same options as `generate` (`--network`, `--pin-policy`, `--touch-policy`, `--payment-slot`, `--stake-slot`, `--mgmt-key`). Run `ykada import --help` for details.

### `ykada balance`

Query on-chain ADA and native token balances for the wallet on the connected YubiKey.

```
$ ykada balance
Cardano address:  addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
Account balance:
  ADA:            91.020067
```

Run `ykada balance --help` for all options.

### `ykada send`

Build, sign, and submit a simple ADA transfer.

```
$ ykada send --ada 5 --to addr_test1qr...
Transaction ID: f9a03b8d...
```

Specify `--to` (recipient), `--ada` or `--lovelace` (amount, not both). Run `ykada send --help` for all options.

### `ykada sign-tx`

Sign a pre-built transaction exported from an external wallet (e.g. Eternl, `cardano-cli`).

```
$ ykada sign-tx --tx-file unsigned.json
84a400...signed-cbor-hex...

$ ykada sign-tx --tx-file unsigned.json --send
Transaction ID: f9a03b8d...
```

The transaction file must contain a `cborHex` field with the unsigned transaction.

Run `ykada sign-tx --help` for all options.

## Workflows

### Generate and fund (testnet)

```sh
ykada generate --network preview
# Copy the address and request tADA from the Cardano testnet faucet
ykada balance
```

### Restore existing wallet

```sh
ykada import --seed "slim fine attend tape wave input head crew shift desk find mutual square cake uncle morning provide naive around brief couple faint alcohol young"
ykada balance
```

### Sign a transaction from Eternl

1. Create a transaction in [Eternl](https://eternl.io) and export the unsigned transaction JSON.
2. Sign with your YubiKey:

```sh
ykada sign-tx --tx-file eternl-tx.json --send --network preview
```

### Inspect before sending

```sh
# Build without signing
ykada send --ada 10 --to addr_test1qr... --dry-run

# Sign without submitting
ykada send --ada 10 --to addr_test1qr... --only-sign

# Full send
ykada send --ada 10 --to addr_test1qr...
```

> [!CAUTION]
> **Key generation and import expose your seed phrase.**
>
> `ykada` is a CLI tool. When you run `ykada generate`, the 24-word mnemonic is printed to your terminal and remains visible in your shell history. When you run `ykada import --seed "..."`, the seed phrase is passed as a command-line argument and is likewise recorded in shell history (e.g. `~/.zsh_history`, `~/.bash_history`). Anyone with access to that history file can steal your funds.
>
> **Recommendations:**
> - Run key generation and import on a dedicated air-gapped machine that never connects to the internet.
> - Use a live, amnesic OS such as [Tails Linux](https://tails.boum.org/) — it leaves no persistent history or filesystem traces after shutdown.
> - If you cannot use an air-gapped machine, at minimum clear your shell history immediately after importing: `history -c && history -w` (bash) or `history -p` (zsh).
> - Never generate or import keys on a shared, networked, or otherwise untrusted machine.
>
> The randomness used during key generation comes from the operating system entropy source (`/dev/urandom` / OS CSPRNG). On a live Tails session this is adequately seeded, but be cautious on freshly booted minimal VMs with limited entropy.

## Security Model

Ykada relies on YubiKey's hardware security for all private key operations:

- **Keys never leave the YubiKey.** The YubiKey stores Ed25519 keys in PIV slots and performs signing internally.
- **PIN protection.** By default (`--pin-policy always`), every signing operation requires your YubiKey PIN.
- **Physical touch.** By default (`--touch-policy always`), signing requires you to physically touch the YubiKey — preventing remote exploitation even if your PIN is compromised.
- **Standard derivation path.** Keys follow CIP-1852 (Cardano Icarus derivation). The derivation path is standard, but see the note below on address compatibility.

> [!WARNING]
> **Your ykada address will NOT match other Cardano wallets — even with the same seed phrase.**
>
> **Why this is unavoidable — a fundamental incompatibility between BIP32-Ed25519 and YubiKey PIV:**
>
> Standard Ed25519 ([RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)) defines a private key as a raw 32-byte *seed*. During signing, the implementation (or hardware) expands it: `SHA-512(seed)` → left 32 bytes (clamped) become the signing scalar, right 32 bytes become the nonce prefix. The YubiKey stores this 32-byte seed and performs the SHA-512 expansion internally on every sign operation.
>
> Cardano key derivation ([BIP32-Ed25519](https://cardano-foundation.github.io/cardano-wallet/design/concepts/Ed25519_BIP.pdf), [CIP-1852](https://cips.cardano.org/cip/CIP-1852)) works differently. Child key derivation operates entirely in the *already-expanded* space — the derived key is the 64-byte pair `(kL, kR)`, where `kL` is already the clamped scalar and `kR` is already the nonce material. **No 32-byte seed is ever produced for a derived key.** The derivation goes directly to the expanded form and never passes through a compressible seed.
>
> This means there is **no way to obtain a valid RFC 8032 seed from a BIP32-Ed25519 derived key**: SHA-512 is a one-way function — `kL` cannot be inverted back to a pre-hash seed. The 32 bytes that YubiKey requires simply do not exist in the derivation.
>
> **ykada's workaround**: it imports `kL` into the YubiKey *as if* it were a seed. The YubiKey then applies SHA-512 again: `SHA-512(kL)[0:32]` becomes the actual signing scalar. This double-hashing produces a different scalar — and therefore a **different public key and Cardano address** — compared to any wallet that uses `kL` directly.
>
> The resulting address is fully valid and usable on-chain, but **it cannot be recovered by restoring your seed phrase into any other wallet.** Your ykada address is only accessible via this tool and the YubiKey it was imported into.

Networks: `mainnet`, `preprod`, `preview` (default). Use `--network` on any command.

## Building from Source

```sh
git clone https://github.com/akonior/ykada.git
cd ykada
cargo build --release
```

### Run tests

```sh
# Unit tests (no hardware required)
cargo test --lib --bins

# Hardware tests (requires connected YubiKey)
./scripts/test_all.sh
```
