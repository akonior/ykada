# Keys and addresses

## The two keys

ykada follows [CIP-1852](https://cips.cardano.org/cip/CIP-1852) and stores two keys of account 0
on the YubiKey:

| Key | Derivation path | PIV slot | Used for |
|-----|-----------------|----------|----------|
| Payment | `m/1852'/1815'/0'/0/0` | 9c | Spending: it signs every transaction |
| Stake | `m/1852'/1815'/0'/2/0` | 9d | The delegation part of the address (staking rewards, vote delegation) |

Together they form one base address per network: `addr1q…` on mainnet and `addr_test1q…` on the
testnets. Change goes back to the same address. ykada is a single-address wallet, and it does
not build staking or vote-delegation certificates yet.

## Why the address differs from other wallets

> [!WARNING]
> The same mnemonic gives a different address in ykada than in Eternl, Daedalus or other
> Cardano wallets. Only ykada can restore a ykada wallet.

Cardano wallets use BIP32-Ed25519 derivation, which produces an already-expanded private key
`kL` and the public key `kL·G`. A YubiKey cannot import such a key: it accepts only a 32-byte
RFC-8032 seed, and it always hashes that seed before signing. ykada therefore imports `kL` as
the seed, and the public key on the device becomes `clamp(SHA-512(kL))·G` instead of `kL·G`.
This is a limit of the YubiKey, not something ykada can change.

## Recovery

The wallet is fully recoverable from the mnemonic. `ykada import` it into any YubiKey 5 with
firmware 5.7 or later and you get the same keys and the same address again. The derivation is
deterministic and is pinned by a test vector in
[`src/logic/derive_key.rs`](../src/logic/derive_key.rs). Other wallet software cannot spend
from a ykada address.
