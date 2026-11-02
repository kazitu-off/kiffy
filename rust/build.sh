#!/usr/bin/env bash
# Build the Kiffy server WITHOUT cargo — only the rustc that ships with Rust:
#   ./build.sh                 -> ./kiffy_server binary
set -e
cd "$(dirname "$0")"
rustc -O --edition 2021 --crate-name kiffy_server src/main.rs -o kiffy_server
echo "Built ./kiffy_server — run: ./kiffy_server --selftest && ./kiffy_server"
