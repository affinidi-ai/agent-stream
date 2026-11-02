#!/bin/zsh

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

echo "Running checks..."

echo "Running cargo fmt..."
cargo fmt --all

echo "Running cargo check..."
cargo check --all-targets --all-features

echo "Running cargo clippy..."
cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

echo "Running cargo build and cargo test..."
cargo build --all-targets --all-features

echo "Running cargo test with all features enabled..."
cargo test --all-targets --all-features

echo "Running cargo test with all features enabled and no fail fast..."
cargo test --no-fail-fast --all-targets --all-features
