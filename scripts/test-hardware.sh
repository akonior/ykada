#!/bin/bash
# Run hardware tests that require YubiKey device
# Usage: ./scripts/test-hardware.sh [test_name]

set -e

ykman piv reset --force
ykman piv access change-management-key --management-key 010203040506070801020304050607080102030405060708  --new-management-key 010203040506070801020304050607080102030405060709 --force

if [ -z "$1" ]; then
    # Run all hardware tests
    cargo test --lib adapter --features hardware-tests -- --test-threads=1
    cargo test --bins --features hardware-tests -- --test-threads=1
else
    # Run specific test
    cargo test --lib "$1" --features hardware-tests -- --test-threads=1
fi
