# Commands

Every command except `decode-tx` takes `--network mainnet|preprod|preview`. The default is
`preview`. `ykada <command> --help` lists all options.

## generate

Creates a new wallet: a fresh 24-word mnemonic, and the payment and stake keys derived from it
are stored on the YubiKey.

```sh
ykada generate
```

It prints the mnemonic once, then the address. Write the words down: they are the only backup.
Run it on a computer you trust, ideally offline (see the [security model](security.md)).

| Option | Meaning |
|--------|---------|
| `--pin-policy never\|once\|always` | When the YubiKey asks for the PIN. Default `always`: before every signature |
| `--touch-policy never\|always\|cached` | When it needs a touch. Default `always` |
| `--mgmt-key-file FILE` | The PIV management key in hex, if you changed it from the factory key: 16, 24 or 32 bytes for AES-128, AES-192 or 3DES, and AES-256 |
| `--force` | Replace the keys in slots 9c and 9d. Without it, ykada refuses if either slot already holds a key, from ykada or another tool |

## import

Restores a wallet from its mnemonic. It takes the same options as `generate`, plus:

| Option | Meaning |
|--------|---------|
| `--seed-file FILE` | Read the mnemonic from a file. Without it, ykada asks in a hidden prompt |

Only a mnemonic made by ykada gives back the same address; see
[keys and addresses](keys-and-addresses.md).

## info

Shows the wallet address. It reads only the public keys the YubiKey reports for slots 9c and 9d,
so it needs no PIN and no touch. If only one slot holds a key, or a key doesn't match the public
key ykada stored with it, `info` fails instead of showing an address.

```sh
ykada info --network mainnet
```

## balance

Shows the ADA at the wallet address, read from [Koios](https://koios.rest). Native tokens are
not listed.

```sh
ykada balance --network mainnet
```

## send

Builds a payment, signs it on the YubiKey and submits it. It prints the transaction ID.

```sh
ykada send --network mainnet --to addr1... --ada 5
```

| Option | Meaning |
|--------|---------|
| `--to ADDRESS` | The recipient. It must be an address on the selected network |
| `--ada N` or `--lovelace N` | The amount, in whole ADA or in lovelace (1 ADA = 1,000,000 lovelace) |
| `--fee LOVELACE` | The fee. Default 200000 (0.2 ADA). It is not estimated, but ykada refuses a fee above 1 ADA, and a fee below the minimum for the transaction's size, for which it prints the fee to use |
| `--dry-run` | Only build the transaction and print it unsigned (CBOR hex). No PIN |
| `--only-sign` | Sign on the YubiKey and print the signed transaction, but do not submit it |

ykada checks the address, the amounts and your funds before it asks for the PIN. On mainnet it
then shows the amount and the fee in ADA and the recipient, and submits only after you type
`yes`.

How the transaction is built:

- It spends only UTxOs that hold ADA alone, largest first, and leaves tokens untouched.
- The change goes back to your address. The payment and the change must each be at least 1 ADA.
- The transaction is valid for 7200 slots, about 2 hours.

To check a payment before you send it:

```sh
ykada send --to addr_test1... --ada 2 --dry-run | ykada decode-tx    # what would be signed
ykada send --to addr_test1... --ada 2 --only-sign | ykada decode-tx  # signed, not submitted
```

## sign-tx

Signs a transaction built by another tool, for example `cardano-cli` or a wallet that exports
unsigned transactions, such as Eternl.

```sh
ykada sign-tx --network mainnet --tx-file unsigned.json --send
```

| Option | Meaning |
|--------|---------|
| `--tx-file FILE` | The transaction: a JSON export with a `cborHex` field, or bare CBOR hex (line breaks and a `0x` prefix are fine). Without it, or with `-`, ykada reads stdin. Input larger than 1 MiB, or with bytes after the transaction, is refused |
| `--send` | Also submit the signed transaction and print its ID. Without it, ykada prints the signed CBOR hex |

Before it asks for the PIN, `sign-tx` shows the inputs, the outputs (with any tokens, datum or
script on them), the fee and the validity slots. It also lists everything beyond a plain payment:
certificates, withdrawals and their amount, minting and burning, scripts, collateral and the
collateral return, required signers, reference inputs, votes, governance proposals, treasury
fields, metadata and a network ID, and warns when the transaction is marked invalid, which
forfeits the collateral. Read them, because the YubiKey has no screen.

It adds the wallet's signature and changes nothing else: the body, the other witnesses and
scripts keep their exact bytes, so the transaction ID, any other signatures and a fee computed
for that size stay valid. Signing again replaces ykada's earlier signature. A transaction for
another network than `--network`, by its outputs or its network ID, is refused. A mainnet
`--send` asks you to type `yes`, so it needs `--tx-file` rather than stdin.

## decode-tx

Shows a transaction and checks its signatures, offline.

```sh
ykada decode-tx --tx-file signed.cbor
```

It prints the body hash, which is the transaction ID, and the same summary as `sign-tx`, then
`Witnesses verified: n/m`. It reads `--tx-file`, or stdin when it is omitted, in the
same formats as `sign-tx`. Any signed transaction can be checked this way, without a YubiKey.
