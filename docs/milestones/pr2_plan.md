# PR2: Import Raw Private Key (Hex/Bytes)

## Cel
Zaimplementować import surowego klucza prywatnego Ed25519 (hex/bytes) do YubiKey.

## Status PR1
✅ Generowanie kluczy działa
✅ `KeyManager::import_key()` już istnieje (przyjmuje `SigningKey`)
✅ Mock i PIV adaptery mają `import_key()`

## Strategia
- Użyć istniejącego `KeyManager::import_key()` 
- Dodać konwersję hex/bytes → `SigningKey` w `logic/`
- Use case: orchestracja importu
- API: funkcja convenience
- CLI: komenda `import-key` z parametrami

## Kroki

### 1. Logika: `logic/key_import.rs`
- `hex_to_signing_key(hex: &str) -> SigningKey`
- `bytes_to_signing_key(bytes: &[u8]) -> SigningKey`
- Walidacja długości (32 bajty)
- Testy

### 2. Use Case: `use_cases/import_raw_key.rs`
- `import_raw_key<F>(finder, key_data, format, config, mgmt_key) -> VerifyingKey`
- Format: Hex lub Bytes
- Orchestracja: find → authenticate → convert → import
- Testy z mockiem

### 3. API: `api.rs`
- `import_key_from_hex(hex: &str, config, mgmt_key) -> VerifyingKey`
- `import_key_from_bytes(bytes: &[u8], config, mgmt_key) -> VerifyingKey`
- Używa `import_raw_key` use case

### 4. CLI: `bin/ykada.rs`
- Komenda `ImportKey` z subcommandami:
  - `hex <HEX>` - import z hex string
  - `bytes` - import z stdin (raw bytes)
- Parametry: `--slot`, `--pin-policy`, `--touch-policy`, `--mgmt-key`
- Domyślne wartości jak w `generate`

### 5. Testy
- Unit: konwersja hex/bytes
- Use case: import z mockiem
- CLI: testy z mockiem (bez hardware)
- Hardware: testy z `#[ignore]` (opcjonalnie)

## Pliki

**Nowe:**
- `src/logic/key_import.rs` (~80 linii)
- `src/use_cases/import_raw_key.rs` (~100 linii)

**Modyfikacje:**
- `src/logic/mod.rs` - eksport `key_import`
- `src/use_cases/mod.rs` - eksport `import_raw_key`
- `src/api.rs` - dodaj funkcje importu
- `src/lib.rs` - re-eksport API
- `src/bin/ykada.rs` - komenda ImportKey

## Testy (TDD)
- Logika: hex/bytes → SigningKey, walidacja
- Use case: import, błędy (auth, slot occupied)
- CLI: hex import, bytes import, parametry

## Kryteria sukcesu
- [ ] Hex string → YubiKey import działa
- [ ] Raw bytes → YubiKey import działa
- [ ] CLI komenda działa
- [ ] Wszystkie testy zielone
- [ ] Obsługa błędów (invalid hex, wrong length, slot occupied)
