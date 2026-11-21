# Milestone 3: Cardano Transaction Signing

ykada builds, hashes (Blake2b-256), signs (Ed25519 on the YubiKey) and submits Conway-era
Cardano transactions. It also signs transactions built by other tools. Signing always happens
on the device, and the keys cannot be read back from it.

## Required outputs

| Output | Where |
|--------|-------|
| CLI that hashes (Blake2b) and signs Cardano transactions, returning a fully signed, broadcastable tx | `ykada send`, `ykada sign-tx` |
| Examples for Preview, PreProd and Mainnet | [Examples](#examples); on-chain transactions in [Evidence](#evidence) |
| Documentation in the docs folder | this file, the [commands](../commands.md), [security model](../security.md), [keys and addresses](../keys-and-addresses.md) and [development](../development.md) pages, and the [README](../../README.md) |
| Unit tests for tx hashing and signing | `src/`, run by [GitHub Actions](https://github.com/akonior/ykada/actions/workflows/cargo-test.yml) |
| YouTube tutorial | [Evidence](#evidence) |
| Project close-out video and report | [Close-out report](./closeout-report.md) |

## How signing works

```
UTxOs (Koios) ─▶ coin selection ─▶ Conway tx body ─▶ Blake2b-256(body) ─▶ YubiKey Ed25519 sign
                                                                               │ PIN + touch
          submit (Koios) ◀── verify signature locally ◀── attach vkey witness ◀┘
```

1. **Build:** largest-first selection over ADA-only UTxOs; recipient output, change output,
   a flat fee and a validity window of 7200 slots, about 2 hours
   (`src/use_cases/build_transaction.rs`). The fee is not estimated: it is 0.2 ADA unless
   `--fee` sets it, which covers an ADA payment with a few inputs (the minimum for a typical
   ykada payment is about 0.17 ADA).
2. **Hash:** Blake2b-256 over the body bytes exactly as they appear in the transaction
   (`src/use_cases/sign_external_tx.rs`).
3. **Sign:** the YubiKey signs the 32-byte hash in PIV slot 9c. With the default policies it
   needs the PIN and a physical touch.
4. **Verify:** the signature is checked against the wallet's public key before anything leaves
   the machine.
5. **Assemble + submit:** the witness is added without re-encoding the body, and the tx is
   posted to Koios. The printed transaction ID is computed locally.

`send` and `sign-tx` share steps 2–5, so a wallet-built tx and an externally built tx are
signed by the same code.

## Examples

The flow is the same on every network; only `--network` changes. Mainnet submissions ask for
confirmation.

```sh
# Preview (default)
ykada send --to addr_test1... --ada 2 --dry-run | ykada decode-tx   # inspect unsigned tx
ykada send --to addr_test1... --ada 2 --only-sign | ykada decode-tx # sign on device, verify 1/1
ykada send --to addr_test1... --ada 2                               # sign + submit

# PreProd
ykada send --network preprod --to addr_test1... --ada 2

# Mainnet
ykada send --network mainnet --to addr1... --ada 2

# A tx built elsewhere (Eternl export / cardano-cli), on any network
ykada sign-tx --network preprod --tx-file unsigned.json --send
```

`decode-tx` works offline. It re-computes the body hash and checks every vkey witness, so any
signed transaction can be verified independently of the device and the network.

## Tests

`cargo test --lib --bins` runs the hardware-free tests on every push and pull request. They cover
body hashing (checked against a transaction confirmed on Preview), signing and witness handling
(body bytes preserved, re-signing is idempotent, a wrong key or PIN is rejected), what each `send`
and `sign-tx` mode submits, coin selection, fees/change/min-UTxO, overflow checks, address
derivation against known vectors, and recipient network checks.
`scripts/integration_test.py` runs the full CLI against a real YubiKey. The `--live` flag also
submits a transaction and waits for confirmation.

## Evidence

Signed on a YubiKey and confirmed on-chain. The Preview and PreProd transactions are the ones
submitted and verified in the YouTube tutorial. The Mainnet transaction and the tutorial link
are added when Milestone 3 is submitted.

| Network | Transaction |
|---------|-------------|
| Preview | [904bd5e3…1072](https://preview.cardanoscan.io/transaction/904bd5e3448e727d3e2d3459464532157483a2ce908897692d87999de78b1072) |
| PreProd | [a7f1d9be…7f39](https://preprod.cardanoscan.io/transaction/a7f1d9be05d7f27ef2d01e09e22bd2dcaf52be1e5074a1f0ad22893ca5a67f39) |
| Mainnet | _to be added at submission_ |

Anyone can check these transactions without a YubiKey: fetch the transaction from the chain
and verify it offline with `decode-tx`. The body hash it prints must equal the transaction
ID, and the witness count must be `1/1`. Some Koios servers answer with an empty list for a
while, so the loop retries until the transaction arrives. If it keeps waiting, the ID is wrong
or belongs to another network: press Ctrl-C.

```sh
TX=<transaction ID from the table>
until curl -s -X POST https://preview.koios.rest/api/v1/tx_cbor \
    -H 'content-type: application/json' -d "{\"_tx_hashes\":[\"$TX\"]}" \
    | jq -er '.[0].cbor' > tx.hex; do sleep 2; done
ykada decode-tx --tx-file tx.hex
```

For PreProd use `https://preprod.koios.rest`, and for Mainnet `https://api.koios.rest`.

- CI: [GitHub Actions — Cargo Test on `main`](https://github.com/akonior/ykada/actions/workflows/cargo-test.yml?query=branch%3Amain)
- YouTube tutorial: _to be added when published_
- Close-out video and report: [closeout-report.md](./closeout-report.md)
