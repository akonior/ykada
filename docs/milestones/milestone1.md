# Milestone 1: YubiKey Integration for Cardano Transaction Signing

## Table of Contents

- [Milestone 1: YubiKey Integration for Cardano Transaction Signing](#milestone-1-yubikey-integration-for-cardano-transaction-signing)
  - [Table of Contents](#table-of-contents)
  - [TLDR Summary](#tldr-summary)
  - [1. Introduction](#1-introduction)
    - [YubiKey Capabilities](#yubikey-capabilities)
    - [Relevance to Cardano](#relevance-to-cardano)
  - [2. YubiKey PIV Module](#2-yubikey-piv-module)
    - [PIV Overview](#piv-overview)
    - [PIV Slot Architecture](#piv-slot-architecture)
    - [Special Purpose Slots](#special-purpose-slots)
    - [Retired Key Slots](#retired-key-slots)
  - [3. Communication Stack](#3-communication-stack)
    - [Smart Card Protocol](#smart-card-protocol)
    - [APDU Protocol](#apdu-protocol)
    - [Communication Architecture](#communication-architecture)
  - [4. PIV Libraries and Tools](#4-piv-libraries-and-tools)
    - [C Library: ykpiv](#c-library-ykpiv)
    - [Python: ykman](#python-ykman)
    - [Rust: yubikey.rs](#rust-yubikeyrs)
  - [5. PIV Commands for Cardano](#5-piv-commands-for-cardano)
    - [Import Asymmetric Key](#import-asymmetric-key)
    - [Authenticate/Sign](#authenticatesign)
  - [6. Cardano Transaction Signing](#6-cardano-transaction-signing)
    - [Signing Workflow](#signing-workflow)
    - [6.2 EdDSA and Ed25519](#62-eddsa-and-ed25519)
    - [YubiKey Firmware Support](#yubikey-firmware-support)
  - [7. OpenPGP Module Alternative](#7-openpgp-module-alternative)
    - [OpenPGP EdDSA Support](#openpgp-eddsa-support)
    - [OpenPGP Limitations](#openpgp-limitations)
    - [Direct APDU Access](#direct-apdu-access)
    - [Proof of Concept](#proof-of-concept)
  - [8. References](#8-references)
    - [Official YubiKey Documentation](#official-yubikey-documentation)
    - [Standards and Specifications](#standards-and-specifications)
    - [Related Projects](#related-projects)
    - [Additional Resources](#additional-resources)

---

## TLDR Summary

This milestone establishes the foundation for YubiKey-based Cardano transaction signing:

1. **YubiKey PIV module** provides secure Ed25519 key storage (firmware 5.7+)
2. **17 PIV slots** available, with slot 0x9C designated for digital signatures
3. **APDU protocol** enables low-level communication with smart card modules
4. **Multiple library options**: C (ykpiv), Python (ykman), Rust (yubikey.rs)
5. **Two essential operations**: Import private key, sign transaction hash
6. **Cardano compatibility**: Ed25519 signatures on Blake2b-256 hashes
7. **Alternative approach**: OpenPGP module with direct APDU access for signing raw data

## 1. Introduction

### YubiKey Capabilities

A YubiKey is a single physical device that contains **six completely independent logical modules**, each serving different cryptographic and authentication purposes:

1. **PIV (Personal Identity Verification)** – Smart card functionality with X.509 certificate storage
2. **OpenPGP** – PGP-compatible encryption and digital signing
3. **OTP (One-Time Password)** – Generates one-time passwords (Yubico OTP, HOTP)
4. **FIDO U2F** – Universal 2nd Factor for web authentication
5. **FIDO2/WebAuthn** – Passwordless authentication standard
6. **OATH** – TOTP/HOTP time-based authentication codes

Each module operates independently with its own key storage, authentication mechanisms, and protocols.

### Relevance to Cardano

For **Cardano wallet integration**, the **PIV module** is the primary focus because it provides:

- **Cryptographic key operations**: Import and secure storage of private keys
- **Digital signature generation**: Sign transaction hashes using hardware-protected keys
- **PIN protection**: All operations require user authentication via PIN
- **Non-exportable keys**: Private keys stored on the device cannot be extracted

---

## 2. YubiKey PIV Module

### PIV Overview

The PIV (Personal Identity Verification) module implements the **NIST SP 800-73-4** standard for smart card functionality. It provides:

- Secure key storage in tamper-resistant hardware
- Private key operations (signing, decryption) without exposing the key
- Support for multiple cryptographic algorithms including **Ed25519** (since firmware 5.7)
- X.509 certificate storage associated with private keys

### PIV Slot Architecture

The PIV module provides **17 slots** for storing private keys and their associated X.509 certificates. These slot identifiers come from the PIV standard specification and serve different purposes:

| Slot Range | Count | Purpose |
|------------|-------|---------|
| `0x9A`, `0x9C`, `0x9D`, `0x9E` | 4 | Special purpose slots with defined roles |
| `0x82` - `0x95` | 20 | Retired key slots for key history |

### Special Purpose Slots

Four slots have **special designated purposes** according to the PIV standard:

| Slot ID | Name | Purpose |
|---------|------|---------|
| **0x9A** | Authentication | User authentication (login, VPN, SSH) |
| **0x9C** | Digital Signature | Document signing, code signing |
| **0x9D** | Key Management | Encryption and decryption operations |
| **0x9E** | Card Authentication | Card-level authentication without PIN |

**For Cardano transaction signing**, we typically use slot **0x9C (Digital Signature)**, as its purpose aligns with signing transactions.

### Retired Key Slots

Slots **0x82 through 0x95** are designated as "retired key slots" for **key history management**:

- **Purpose**: Store old decryption keys after they expire or are replaced
- **Use case**: Allows decryption of old messages even after key rotation
- **Special command**: PIV module provides a dedicated command to move keys to these slots
- **Alternative use**: These slots can also store any keys and be used for signing operations

This design ensures that encrypted data remains accessible even after key lifecycle changes.

---

## 3. Communication Stack

### Smart Card Protocol

The YubiKey PIV module appears to the operating system as a **smart card device**. Communication with smart card devices uses the **CCID (Chip Card Interface Device)** protocol over USB.

Key characteristics:
- **Standard interface**: Smart card readers implement the ISO 7816 standard
- **PC/SC framework**: Operating systems provide PC/SC (Personal Computer/Smart Card) middleware
  - **macOS**: Built-in support via `CryptoTokenKit`
  - **Linux**: `pcscd` daemon (PC/SC Daemon)
  - **Windows**: Built-in `winscard.dll`

### APDU Protocol

Applications communicate with smart card modules using **APDU (Application Protocol Data Unit)** commands - a binary protocol defined in **ISO 7816-4**.

**APDU structure:**

```
Command APDU:
┌─────┬─────┬────┬────┬────┬──────────────┬────┐
│ CLA │ INS │ P1 │ P2 │ Lc │ Command Data │ Le │
└─────┴─────┴────┴────┴────┴──────────────┴────┘

Response APDU:
┌───────────────┬─────┬─────┐
│ Response Data │ SW1 │ SW2 │
└───────────────┴─────┴─────┘
```

**Components:**
- **CLA** – Class byte (instruction category)
- **INS** – Instruction byte (specific command)
- **P1, P2** – Parameter bytes (command modifiers)
- **Lc** – Length of command data
- **Data** – Command payload
- **Le** – Expected response length
- **SW1, SW2** – Status words (0x9000 = success)

**APDU is a low-level binary protocol** that allows:
- Selecting applications on the card
- Invoking specific functions with specific arguments
- Receiving structured responses with status codes

Both **PIV** and **OpenPGP** modules are smart card applications that communicate via APDU.

### Communication Architecture

The complete communication stack from application to hardware:

```
+-------------------------------+
| High-level applications       |
| ykman / yubico-piv-tool       |
| PKCS#11 / OpenSSL / Browser   |
+-------------------------------+
               |
               v
+-------------------------------+
| PIV library / ykcs11          |
| Converts calls → APDU         |
+-------------------------------+
               |
               v
+-------------------------------+
| APDU (ISO7816-4)              |
| SELECT / VERIFY / SIGN        |
+-------------------------------+
               |
               v
+-------------------------------+
| PC/SC                         |
| Smart Card API                |
+-------------------------------+
               |
               v
+-------------------------------+
| CCID                          |
| USB Smart Card protocol       |
+-------------------------------+
               |
               v
+-------------------------------+
| YubiKey Firmware              |
+-------------------------------+
               |
               v
+-------------------------------+
| PIV Applet                    |
| logic: PIN, keys, signatures  |
+-------------------------------+
```

**Layer responsibilities:**

1. **Application Layer**: High-level cryptographic operations (sign, verify, encrypt)
2. **Library Layer**: Translates API calls to APDU commands
3. **APDU Layer**: Binary protocol commands
4. **PC/SC Layer**: Operating system smart card interface
5. **Transport Layer**: USB CCID protocol
6. **Firmware Layer**: YubiKey operating system
7. **Applet Layer**: PIV application logic (key storage, PIN verification, signing)

---

## 4. PIV Libraries and Tools

### C Library: ykpiv

**yubico-piv-tool** is the official C library and command-line tool:

- **Repository**: https://github.com/Yubico/yubico-piv-tool
- **Purpose**: Wraps APDU commands in a higher-level C API
- **Scope**: PIV functionality only
- **Features**:
  - Key import and generation
  - Certificate management
  - PIN/PUK management
  - Signing and decryption operations

**Command-line usage example:**

```bash
# Generate a key in slot 9a
yubico-piv-tool -a generate -s 9a -A ED25519

# Import a private key
yubico-piv-tool -a import-key -s 9c --key-format PEM -i private.pem

# Sign data
yubico-piv-tool -a verify-pin --pin 123456 --sign -s 9c -A ED25519 -i data.txt
```

### Python: ykman

**YubiKey Manager (ykman)** is a Python library and CLI tool:

- **Repository**: https://github.com/Yubico/yubikey-manager
- **Purpose**: Manage all YubiKey modules (not just PIV)
- **PIV support**: Provides access to PIV functions, but not all low-level operations
- **Limitation**: Some advanced PIV operations are not available

**Usage example:**

```python
ykman piv info
```

### Rust: yubikey.rs

**yubikey.rs** is a Rust library for YubiKey PIV operations:

- **Repository**: https://github.com/iqlusioninc/yubikey.rs
- **Purpose**: Safe Rust bindings for YubiKey PIV

---

## 5. PIV Commands for Cardano

For Cardano transaction signing, two PIV commands are essential:

### Import Asymmetric Key

**Purpose**: Load a private key into a PIV slot

**Documentation**: https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#import-asymmetric

**Key features**:
- Imports externally generated private keys
- Associates key with a slot
- Sets PIN and touch policies
- **Security note**: Key is transmitted once during import, then never leaves the device

**Parameters**:
- **Slot ID**: Where to store the key (e.g., 0x9C for signature)
- **Algorithm**: Key algorithm (Ed25519 for Cardano)
- **Key data**: Private key bytes
- **PIN policy**: When PIN is required (Never/Once/Always)
- **Touch policy**: Whether physical touch is required (Never/Always/Cached)

**Example workflow:**

```bash
# Generate ed25519 priv key
openssl genpkey -algorithm ed25519 -out priv.pem

# Import to YubiKey slot 0x9C
yubico-piv-tool -a import-key \
  -s 9c \
  --key-format PEM \
  --input priv.pem \
  --pin-policy always \
  --touch-policy never
```

### Authenticate/Sign

**Purpose**: Sign data using a private key stored in a PIV slot

**Documentation**: https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#authenticate-sign

**Key features**:
- Signs arbitrary data (typically a hash)
- Requires PIN verification (if policy is set to Always)
- May require physical touch (if touch policy is enabled)
- Returns signature in algorithm-specific format

**For Ed25519**:
- **Input**: 32-byte hash or message
- **Output**: 64-byte signature (R || S)
- **Format**: Raw Ed25519 signature

**Example workflow:**

```bash
# Calculate transaction hash
HASH=$(cardano-cli transaction hash --tx-file tx.raw)

# Sign with YubiKey
echo -n "$HASH" | xxd -r -p | \
  yubico-piv-tool -a verify-pin --pin 123456 --sign -s 9c -A ED25519
```

---

## 6. Cardano Transaction Signing

### Signing Workflow

When a Cardano transaction is received from an external wallet (e.g., **Eternl**, **Nami**), the signing process is:

1. **Receive unsigned transaction** (CBOR format)
2. **Calculate transaction hash** (Blake2b-256)
3. **Sign the hash** using YubiKey-stored private key
4. **Return signature** to the wallet application
5. **Wallet assembles signed transaction** with witness

**Key advantage**: The private key never leaves the YubiKey device, ensuring maximum security.

### 6.2 EdDSA and Ed25519

**Cardano uses EdDSA signatures** based on the Ed25519 curve.

**EdDSA (Edwards-curve Digital Signature Algorithm):**
- **Specification**: RFC 8032
- **Wikipedia**: https://en.wikipedia.org/wiki/EdDSA
- **Curve**: Twisted Edwards curve `edwards25519`
- **Security level**: ~128-bit (equivalent to RSA-3072)
- **Key size**: 32-byte private key, 32-byte public key
- **Signature size**: 64 bytes (R || S)

**Advantages of Ed25519:**
- Fast signature generation and verification
- Small keys and signatures
- Deterministic signatures (no random number generation)
- Resistance to side-channel attacks

### YubiKey Firmware Support

**YubiKey 5.7+ firmware** introduced Ed25519 support for the PIV module:

- **Announcement**: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/5.7-firmware-specifics.html#piv-enhancements
- **Algorithm ID**: Ed25519 is now a supported PIV algorithm
- **Compatibility**: The same curve (edwards25519) used by Cardano
- **Significance**: Enables native Cardano transaction signing without workarounds

**Firmware check:**

```bash
# Check YubiKey firmware version
ykman info

# PIV-specific info
ykman piv info
```

**Requirements for Cardano:**
- YubiKey firmware **5.7 or newer**
- PIV Ed25519 algorithm support
- Sufficient slot availability (e.g., slot 0x9C)

---

## 7. OpenPGP Module Alternative

### OpenPGP EdDSA Support

The **OpenPGP module** on YubiKey also supports Ed25519:

- **Support since**: Firmware 4.3.0
- **Standard**: OpenPGP smart card application v3.3+
- **Specification**: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf

**Key difference from PIV:**
- OpenPGP provides a **PGP-specific interface**, not general-purpose cryptographic operations
- Designed for email and file signing/encryption (GPG/PGP ecosystem)

### OpenPGP Limitations

**Challenge for Cardano signing:**

1. **No raw signature operation**: OpenPGP is designed to sign files or emails, not arbitrary data
2. **Forced hashing**: All data is hashed before signing
3. **Limited hash algorithms**: Only supports:
   - SHA-1
   - RIPEMD-160
   - SHA-256, SHA-384, SHA-512, SHA-224

4. **Cardano uses Blake2b-256**: This hash algorithm is **not supported** by the OpenPGP application interface

**Result**: Standard OpenPGP commands cannot sign Cardano transaction hashes directly.

### Direct APDU Access

**Workaround**: Bypass the OpenPGP application layer and send **raw APDU commands** directly to the card.

**Advantages**:
- Direct access to cryptographic operations
- Can sign pre-hashed data (bypass internal hashing)
- Use Blake2b-256 hashes from Cardano

**Trade-offs**:
- More complex (requires APDU protocol knowledge)
- Bypasses OpenPGP application safeguards
- Less portable than standard GPG tools

### Proof of Concept

**Demonstration**: Signing raw bytes using OpenPGP module via direct APDU commands.

**Test command:**

```bash
opensc-tool --card-driver default \
  -r 0 \
  --send-apdu "00:A4:04:00:06:D2:76:00:01:24:01" \
  --send-apdu "00:20:00:81:06:31:32:33:34:35:36" \
  --send-apdu "00:2A:9E:9A:20:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11"
```

**APDU breakdown:**

| Command | Hex | Description |
|---------|-----|-------------|
| SELECT OpenPGP | `00 A4 04 00 06 D2 76 00 01 24 01` | Select OpenPGP application (AID: D2760001240) |
| VERIFY PIN | `00 20 00 81 06 31 32 33 34 35 36` | Verify PIN PW1 (ref 0x81), PIN: "123456" |
| PSO: SIGN | `00 2A 9E 9A 20 [32 bytes of 0x11]` | Sign 32 bytes of data (0x11 repeated) |

**Result:**

```
Sending: 00 A4 04 00 06 D2 76 00 01 24 01
Received (SW1=0x90, SW2=0x00)

Sending: 00 20 00 81 06 31 32 33 34 35 36
Received (SW1=0x90, SW2=0x00)

Sending: 00 2A 9E 9A 20 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
Received (SW1=0x90, SW2=0x00):
36 C2 38 DF C0 34 F3 CF 42 22 89 0C 39 0A 0B 57 6.8..4..B"..9..W
33 AF 50 DC D9 1B 31 CB 02 0D 79 75 D1 E0 2E 80 3.P...1...yu....
1A 5B 1F D4 7F 70 73 AC 3D FE 2F DC AF DC 4B CE .[...ps.=./...K.
A3 78 05 76 35 38 E5 EB 75 E6 5D 3D 1C 66 AE 07 .x.v58..u.]=.f..
```

**Success indicators:**
- **SW1=0x90, SW2=0x00**: Success status
- **64-byte signature**: Valid Ed25519 signature (R || S)

**Conclusion**: Direct APDU access to the OpenPGP module **successfully signs raw data**, proving that this approach is viable for Cardano transaction signing.

**Practical implementation**: A custom library can use PC/SC to send raw APDU commands and obtain signatures for pre-computed Blake2b-256 hashes.

---

## 8. References

### Official YubiKey Documentation

- **PIV Overview**: https://developers.yubico.com/PIV
- **PIV Guides**: https://developers.yubico.com/PIV/Guides
- **yubico-piv-tool**: https://developers.yubico.com/yubico-piv-tool/
- **PIV Slots Reference**: https://docs.yubico.com/yesdk/users-manual/application-piv/slots.html
- **PIV Commands**: https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html
- **YubiKey 5.7 Firmware**: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/5.7-firmware-specifics.html

### Standards and Specifications

- **OpenPGP Smart Card v3.4.1**: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
- **NIST SP 800-73-4**: PIV standard for smart cards
- **ISO 7816-4**: Smart card APDU protocol
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)

### Related Projects

- **yubikey.rs (Rust)**: https://github.com/iqlusioninc/yubikey.rs
- **Custom fork with Ed25519**: https://github.com/mproofs/yubikey.rs (branch: curve_25519)
- **YubiKey Manager (Python)**: https://github.com/Yubico/yubikey-manager
- **Cardano Node**: https://github.com/IntersectMBO/cardano-node

### Additional Resources

- **EdDSA Wikipedia**: https://en.wikipedia.org/wiki/EdDSA
- **Smart Card APDU**: https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
- **CCID Protocol**: USB smart card reader standard
- **PC/SC Workgroup**: https://pcscworkgroup.com/

---
