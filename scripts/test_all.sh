#!/usr/bin/env bash

set -euo pipefail

cargo test --all --locked --verbose
cargo fmt --check
