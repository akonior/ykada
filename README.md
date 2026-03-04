# ykada

> [!CAUTION]
> **Proof of concept — do not use with real funds.**
>
> This software is experimental and has not been security-audited. Key derivation, PIV integration, and transaction signing are research-grade implementations that have not undergone independent security review. The software is provided "as is", without warranty of any kind, express or implied. **Do not run on mainnet or with funds you cannot afford to lose.**

Hardware wallet for Cardano using YubiKey. Private keys never leave the device.

Ykada stores Ed25519 signing keys on a YubiKey's PIV slots and uses them to sign Cardano transactions — keeping your keys offline and protected by PIN and physical touch.

## Install

```sh
cargo install --path . --locked
```

Requires a YubiKey 5 series (firmware 5.7+) with Ed25519 support.

## Quick Start

**1. Generate a wallet**

```
$ ykada generate
Mnemonic (store safely): express crime shrimp theory sword always search orbit present spoil glory ribbon foam juice ten isolate armed buffalo perfect mobile dial box notice regret
Cardano address:         addr_test1qphwrxw2kcu4kasezlh5hxnulvha9ufqs55d7tw0jhvv696d9egjx7sqp0tlfh300e4wn88s4r333yl0reu2njwtqy3qm5zq89
```

Write down the 24-word mnemonic and store it safely. It is the only backup of your wallet.

**2. Check your balance**

```
$ ykada balance
Cardano address:  addr_test1qphwrxw2kcu4kasezlh5hxnulvha9ufqs55d7tw0jhvv696d9egjx7sqp0tlfh300e4wn88s4r333yl0reu2njwtqy3qm5zq89
Account balance:
  ADA:            0.000000
```

**3. Send ADA**

```
$ ykada send --ada 1 --to addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
Transaction ID: 8f7334094b3c4df2fc5eee892865c4175841da390fe77a4bbfd94b633085d58e
```

## Commands

### `ykada info`

Show connected YubiKey device info and wallet address.

```
$ ykada info
YubiKey serial:          27257069
Firmware version:        5.7.4
Payment slot:            signature
Payment derivation path: m/1852'/1815'/0'/0/0
Stake slot:              key-management
Stake derivation path:   m/1852'/1815'/0'/2/0
Cardano address:         addr_test1qzsm...
```

### `ykada generate`

Create a new wallet: generates a random 24-word BIP39 mnemonic, derives payment and stake keys (CIP-1852), and stores them on the YubiKey.

```
$ ykada generate
Mnemonic (store safely): express crime shrimp theory sword always search orbit present spoil glory ribbon foam juice ten isolate armed buffalo perfect mobile dial box notice regret
Cardano address:         addr_test1qphwrxw2kcu4kasezlh5hxnulvha9ufqs55d7tw0jhvv696d9egjx7sqp0tlfh300e4wn88s4r333yl0reu2njwtqy3qm5zq89
```

| Option | Default | Description |
|---|---|---|
| `--network` | `preview` | `mainnet`, `preprod`, or `preview` |
| `--pin-policy` | `always` | When PIN is required: `never`, `once`, `always` |
| `--touch-policy` | `always` | When physical touch is required: `never`, `always`, `cached` |
| `--payment-slot` | `signature` | YubiKey PIV slot for payment key |
| `--stake-slot` | `key-management` | YubiKey PIV slot for stake key |
| `--mgmt-key` | — | YubiKey management key (hex) |

### `ykada import`

Restore a wallet from an existing BIP39 seed phrase. Derives the same payment and stake keys and stores them on the YubiKey.

```
$ ykada import --seed "slim fine attend tape wave input head crew shift desk find mutual square cake uncle morning provide naive around brief couple faint alcohol young"
Mnemonic (store safely): slim fine attend tape wave input head crew shift desk find mutual square cake uncle morning provide naive around brief couple faint alcohol young
Cardano address:         addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
```

Accepts the same options as `generate` (`--network`, `--pin-policy`, `--touch-policy`, `--payment-slot`, `--stake-slot`, `--mgmt-key`).

| Option | Default | Description |
|---|---|---|
| `--seed` | *(required)* | 24-word BIP39 mnemonic |

### `ykada balance`

Query on-chain ADA and native token balances for the wallet on the connected YubiKey.

```
$ ykada balance
Cardano address:  addr_test1qzsmxwwte2fw6cla5d4c725f3wkmth9k4ds923lgjq6vey0uxtmw20nuadt9qv2ak6adgskdtp3j6jx7xp39gs9wa5hs0z854g
Account balance:
  ADA:            91.020067
```

| Option | Default | Description |
|---|---|---|
| `--network` | `preview` | Network to query |

### `ykada send`

Build, sign, and submit a simple ADA transfer.

```
$ ykada send --ada 5 --to addr_test1qr...
Transaction ID: f9a03b8d...
```

| Option | Default | Description |
|---|---|---|
| `--to` | *(required)* | Recipient address (bech32) |
| `--ada` | — | Amount in ADA (whole units) |
| `--lovelace` | — | Amount in lovelace (1 ADA = 1,000,000 lovelace) |
| `--fee` | `200000` | Transaction fee in lovelace |
| `--network` | `preview` | Network to submit to |
| `--pin` | — | YubiKey PIN (prompted if needed) |
| `--dry-run` | — | Build unsigned transaction only (CBOR hex) |
| `--only-sign` | — | Sign but don't submit (CBOR hex) |

Specify either `--ada` or `--lovelace`, not both.

### `ykada sign-tx`

Sign a pre-built transaction exported from an external wallet (e.g. Eternl, `cardano-cli`).

```
$ ykada sign-tx --tx-file unsigned.json
84a400...signed-cbor-hex...

$ ykada sign-tx --tx-file unsigned.json --send
Transaction ID: f9a03b8d...
```

The transaction file must contain a `cborHex` field with the unsigned transaction.

| Option | Default | Description |
|---|---|---|
| `--tx-file` | *(required)* | Path to unsigned transaction JSON |
| `--send` | — | Submit to the network after signing |
| `--network` | `preview` | Network for submission |
| `--pin` | — | YubiKey PIN |

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

## Security Model

Ykada relies on YubiKey's hardware security for all private key operations:

- **Keys never leave the YubiKey.** Generation, import, and signing all happen on-device. The YubiKey stores Ed25519 keys in PIV slots and performs signing internally.
- **PIN protection.** By default (`--pin-policy always`), every signing operation requires your YubiKey PIN.
- **Physical touch.** By default (`--touch-policy always`), signing requires you to physically touch the YubiKey — preventing remote exploitation even if your PIN is compromised.
- **Standard derivation path.** Keys follow CIP-1852 (Cardano Icarus derivation). The derivation path is standard, but see the note below on address compatibility.

> **Address compatibility note.** Standard Cardano wallets (Yoroi, Eternl, cardano-cli) treat the derived extended private key's left 32 bytes (kL) directly as an Ed25519 scalar when computing the public key (`kL·G`). YubiKey PIV requires a 32-byte seed for Ed25519 import; ykada imports kL as that seed, after which the firmware applies an additional SHA-512 hash to derive the actual scalar (`SHA-512(kL)[0:32]·G`). Because the extra hash changes the scalar, the public key — and therefore the Cardano address — produced by ykada will differ from the address any standard wallet derives from the same mnemonic. The address is fully usable on-chain; it just cannot be recovered by another wallet from the same seed phrase.

## Networks

| Network | Address prefix | Use |
|---|---|---|
| `mainnet` | `addr1...` | Real ADA |
| `preprod` | `addr_test1...` | Long-running testnet |
| `preview` | `addr_test1...` | Fast-moving testnet (default) |

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
cargo test --lib --features hardware-tests
```

## License

Apache 2.0
