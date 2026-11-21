# Testing

ykada signs with real money behind it, so each kind of mistake has a test layer meant to catch
it before a user does. This page lists the layers, the rules that keep them useful, and the
manual checks to run before a release.

## The layers

| Layer | Where | Runs | Catches |
|-------|-------|------|---------|
| Unit tests | `#[cfg(test)]` next to the code | `just check`, CI | A rule broken in one function: coin selection, fees, address checks, error mapping |
| Use-case tests with fakes | `src/adapters/fake_yubikey.rs`, `fake_chain.rs` | `just check`, CI | Wrong order or wrong data between the YubiKey, the chain and the logic: what is written, signed or submitted, and when |
| Property tests | `proptest!` blocks next to the code | `just check`, CI | Inputs nobody thought of: random and corrupted bytes, text, keys, amounts and UTxO sets |
| CLI tests | `tests/cli.rs` | `just check`, CI | What a user or a script sees: exit codes, messages, stdout vs stderr, panics, help vs docs |
| Script tests | `scripts/test_integration_test.py` | `just check`, CI | The PIV reset guard of the integration test |
| Integration test | `just itest`, `--live` | By hand, with a YubiKey | The real device and network: PC/SC, PIV metadata, signatures, Koios, confirmation |
| Release checks | The checklist below | By hand, before a release | Everything the automated layers can't reach |

`just check` runs every automated layer, plus `cargo fmt` and `cargo clippy`, exactly as CI
does. None of it needs a YubiKey or the network.

## Invariants the property tests hold

- Any text or bytes given to an address, a transaction, a seed phrase, a PIN or a management
  key get an answer or an error, never a panic.
- A recipient is accepted only when it is exactly its own address's encoding: the right prefix,
  no extra bytes, the selected network.
- A built transaction balances: its inputs pay exactly the outputs plus the fee, every output
  holds at least 1 ADA, the payment is the amount asked for, and the fee covers the signed size
  and stays at most 1 ADA.
- Signing keeps the body bytes, adds a witness that verifies, matches the size the fee check
  predicted, and signing again changes nothing.
- Attaching a witness keeps every other witness field byte for byte.
- A signature never verifies after any byte of the body it signed is changed, and bytes after
  a transaction are refused.
- Seed phrase errors never contain a word of the phrase.

## Rules for changes

1. **A bug fix comes with a test that fails without it.** Name the test after the behaviour,
   for example `test_swapped_stake_object_is_refused`.
2. **A new input format gets two properties**: arbitrary input never panics, and whatever is
   accepted means exactly what was typed (it round-trips).
3. **Check before you act.** Validate everything that needs neither the YubiKey nor the network
   first, then read the device, then the chain, and only then ask for the PIN. The CLI tests
   rely on this: they run without a YubiKey and expect the input error, not "No YubiKey".
4. **Results go to stdout through `print_line`**, notes and prompts to stderr. A failed write is
   an error that says what already happened (for example, a submitted transaction's ID).
5. **An error says what to do.** It names the slot, the option or the field, and never repeats a
   secret.
6. **The device is the source of truth.** Anything that can be rewritten without the PIN, such as
   ykada's public-key objects, is only a cross-check.
7. **Documented options match `--help`.** `tests/cli.rs` compares `docs/commands.md` with every
   command's help, both ways.
8. **Keep what a property finds.** When a property fails, proptest saves the failing case under
   `proptest-regressions/`. Commit that file with the fix, so the case is replayed on every run.

## Before a release

Run `just check` and `just itest --live` on Preview, then go through these by hand on a YubiKey
holding only a test wallet. Each line is a class of problem found before; the linked tests
cover what can be automated.

- **Amounts:** zero, negative, fractions with `--ada`, `u64` overflow, above the balance, below
  1 ADA, leaving change under 1 ADA, many small UTxOs (the fee check).
- **Addresses:** wrong checksum, wrong network, other prefixes, extra bytes, stake, Byron and
  script addresses, upper case, invisible characters.
- **Transaction input:** empty, binary, huge, a directory, JSON with the wrong shape, hex with
  line breaks, trailing bytes, other networks, unknown or repeated body fields, Plutus and
  multi-signature transactions built by other tools.
- **Device:** no YubiKey, two YubiKeys, the YubiKey held by gpg (`gpg --card-status`), a wrong
  PIN (one attempt, then the correct PIN), no touch, a slot with a key from another tool, a
  swapped public-key object.
- **Network:** Koios unreachable or slow (`HTTPS_PROXY` to a dead proxy), a rejected submission,
  no answer after the transaction was sent (the outcome must be reported as unknown, with the
  transaction ID, never as "not submitted"), two sends in a row.
- **Process:** a closed pipe (`ykada info | true`), `NO_COLOR=1`, `LANG=C`, non-UTF-8 arguments,
  `--only-sign | decode-tx` keeps stdout clean.
- **Mainnet guard:** `send` and `sign-tx --send` on mainnet refuse without a typed `yes`, and
  refuse stdin input. Never answer `yes` while testing.
