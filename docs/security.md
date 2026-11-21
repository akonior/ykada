# Security model

> [!CAUTION]
> ykada is a proof of concept and has not been security-audited. Do not use it with funds you
> cannot afford to lose.

## What protects your ADA

- **The keys cannot be read back from the YubiKey.** They are derived from the mnemonic on your
  computer once, during `generate` or `import`. From then on only the YubiKey can sign.
- **PIN and touch.** By default the YubiKey needs the PIN and a physical touch for every
  signature.
- **Every signature is checked** against the wallet's public key before anything is submitted.
- **No secrets on the command line.** The mnemonic comes from a hidden prompt or a file, the PIN
  from a hidden prompt, and the management key from a file. None of them end up in your shell
  history.
- **The address comes from the keys themselves.** ykada asks the YubiKey for the public keys in
  slots 9c and 9d and builds the address from them. It also keeps its own copy of each public
  key on the YubiKey; if a copy doesn't match its key, for example because someone with the
  management key rewrote it, ykada refuses to show the address or sign.
- **A key is never replaced by accident.** `generate` and `import` write only slots 9c and 9d,
  and refuse if either already holds a key, from ykada or another tool, unless you add
  `--force`.

## What it does not protect against

- **No trusted display.** A YubiKey has no screen, so it signs whatever transaction hash the
  computer sends it. `sign-tx` shows what it is about to sign and `decode-tx` can check any
  transaction, but a compromised computer could still swap the transaction. Sign on a computer
  you trust.
- **The mnemonic is the master key.** Anyone with the 24 words can rebuild the wallet on another
  YubiKey. `generate` prints them once; write them down, keep them offline, and run `generate`
  or `import` on a computer you trust, ideally offline.

## Before you use real ADA

- Change the YubiKey's default PIN (`123456`): `ykman piv access change-pin`.
- Change the default PIV management key: `ykman piv access change-management-key`. Then pass it
  to `generate` and `import` with `--mgmt-key-file`.
- Keep the default PIN and touch policies (`always`).

ykada warns while the default PIN or management key is in use, and when touch is turned off.
