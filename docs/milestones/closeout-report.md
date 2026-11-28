# Project Close-out Report — Yubikey Cardano Wallet

> **Draft.** Milestone 3 is not submitted yet. The completion date, the Mainnet transaction and
> the video links are filled in when it is submitted, and this note is then removed.

## Name of project and Project URL on IdeaScale/Fund

**Yubikey Cardano Wallet** (ykada) — Fund 14, Cardano Open: Developers
https://projectcatalyst.io/funds/14/cardano-open-developers/yubikey-cardano-wallet

## Your Project Number

1400128

## Name of project manager

Arkadiusz Konior

## Date project started

24 November 2025

## Date project completed

_To be added: the day Milestone 3 is submitted._

## List of challenge KPIs and how the project addressed them

The Cardano Open: Developers brief states goals rather than numeric KPIs. Each goal, and how
ykada addresses it:

| Challenge goal | How ykada addresses it |
|---|---|
| Open-source tools that improve the Cardano developer experience | ykada adds hardware-backed signing to developer workflows. It signs transactions built by cardano-cli or exported from wallets, and `decode-tx` verifies any signed transaction offline. |
| Libraries, SDKs, APIs and toolchains | A Rust crate with a small library API plus the `ykada` CLI. Every release ships prebuilt macOS binaries. |
| Open source and publicly available | Developed in public on GitHub under Apache 2.0. Code, docs, tests and CI runs for every milestone are public. |
| Technical deliverables | All outputs are code, tests, documentation and on-chain transactions. |

## List of project KPIs and how the project addressed them

Each milestone's acceptance criteria were the project's KPIs. Milestones 1 and 2 are
approved. Milestone 3 was delivered in November 2026, within the extension to 1 December 2026
agreed with Project Catalyst, and is submitted together with this report.

| Milestone | KPI (acceptance criteria) | Result |
|---|---|---|
| 1. Technical documentation & PoC | Report on YubiKey PIV Ed25519, PIN and touch policy, and OpenPGP feasibility; PoC signs raw bytes, verified by an independent verifier | Met, approved January 2026 — [milestone1.md](./milestone1.md) |
| 2. CLI implementation | CLI generates and imports Ed25519 keys on a YubiKey; PIN and touch policy configured and verified; tests run on every pull request; README with setup and usage | Met, approved February 2026 — [demo video](https://www.youtube.com/watch?v=dTatJ1U6Tv4) |
| 3. Cardano transaction signing | CLI hashes (Blake2b-256) and signs transactions on the device and returns a broadcastable transaction; examples on preview, preprod and mainnet; unit tests in CI; documentation and tutorial | Submitted with this report — [milestone3.md](./milestone3.md), with the on-chain transactions under [Evidence](./milestone3.md#evidence) |

## Key achievements (in particular around collaboration and engagement)

- **A stock YubiKey is a Cardano signer.** The project shows that a standard YubiKey 5
  (firmware 5.7+) signs Cardano transactions with its built-in PIV applet. No custom firmware
  or applet is needed.
- **Works with existing tools.** ykada signs transactions built elsewhere (cardano-cli, wallet
  exports), so it adds a hardware key to existing workflows instead of replacing them.
- **Built on community open source.** Transactions use TxPipe's pallas libraries, and device
  access uses iqlusion's yubikey.rs. The work stays compatible with both.
- **Open development.** A public repository, 20 merged pull requests with tests run in CI,
  tagged releases with prebuilt macOS binaries, and video walkthroughs on YouTube.
- **Security hardening.** A final review found and fixed key-material leaks: debug logs that
  printed private-key bytes, and a third-party trace log that recorded PIN APDUs. Every
  signature is verified locally before a transaction leaves the machine, and wallets are never
  overwritten without `--force`.

This was a single-developer project. Engagement so far comes through the public repository,
releases and videos; growing the user base is part of the next steps.

## Key learnings

- **PIV Ed25519 is enough for Cardano.** The YubiKey signs the 32-byte Blake2b body hash
  directly.
- **BIP32-Ed25519 does not fit PIV.** PIV imports only an RFC-8032 seed and always hashes it
  before signing, while Cardano derivation produces an already-expanded key. A ykada address
  therefore differs from the one other wallets derive from the same mnemonic. It is still
  deterministic and recoverable from the mnemonic, as [Keys and addresses](../keys-and-addresses.md) documents. Matching other
  wallets' addresses was the one goal that turned out to be impossible on this hardware.
- **Sign the exact bytes.** Re-encoding a transaction body can change its hash and invalidate
  signatures, so ykada hashes and keeps the body bytes exactly as received.
- **Touch prevents silent signing.** Malware cannot sign in the background, because every
  signature needs a physical touch. A YubiKey has no screen, though, so the user still has to
  trust the computer to show the right transaction.

## Next steps for the product or service developed

- An independent security review before recommending ykada for real funds.
- Native-token transfers (today ykada sends ADA only and leaves token UTxOs untouched).
- The YubiKey's OpenPGP applet as a second signing backend.
- Linux and Windows builds.

I plan to seek follow-up funding in a future Catalyst round to cover the security review and
token support.

## Final thoughts/comments

Many developers already carry a YubiKey. This project turns it into a Cardano hardware wallet
with no extra purchase, protected by a PIN and a physical touch. Thank you to Project Catalyst,
the milestone reviewers and the voters for making it possible.

## Links to other relevant project sources or documents.

- Repository (Apache 2.0): https://github.com/akonior/ykada
- Milestone documentation: https://github.com/akonior/ykada/tree/main/docs/milestones
- Releases: https://github.com/akonior/ykada/releases
- CI (unit tests on every push and pull request): https://github.com/akonior/ykada/actions/workflows/cargo-test.yml
- Milestone 2 demo video: https://www.youtube.com/watch?v=dTatJ1U6Tv4
- YouTube tutorial: _to be added when published_
- Catalyst Milestone Module: https://milestones.projectcatalyst.io/projects/1400128

## Link to Close-out video - must be either YouTube or Vimeo link only

_To be added when published._
