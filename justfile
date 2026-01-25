default:
    @just --list

# Build all packages
build:
    cargo build

# Build all packages in release mode
build-release:
    cargo build --release

# Build a specific package
build-package package:
    cargo build --package {{ package }}

# Run clippy lints
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Run clippy with automatic fixes
fix:
    cargo clippy --fix --allow-dirty --allow-staged

# Format code with rustfmt
format:
    cargo fmt

# Check if code is formatted
format-check:
    cargo fmt -- --check

# Run all checks (format, lint, test)
check: format-check lint test

# Run unit tests (all crates, excludes cli/tests e2e)
test package='':
    {{ if package == '' { 'cargo test --all-features --lib' } else { 'cargo test --all-features --package ' + package + ' --lib' } }}

# Run unit tests with verbose output
testv package='':
    {{ if package == '' { 'cargo test --all-features --lib -- --nocapture' } else { 'cargo test --all-features --package ' + package + ' --lib -- --nocapture' } }}

# Run a specific test in a package
test-name package name:
    cargo test --package {{ package }} -- {{ name }} --exact --nocapture

# Run e2e tests (cli/tests only)
e2e:
    cargo test --package tsumiki-cli --test '*'

# Run e2e tests with verbose output
e2ev:
    cargo test --package tsumiki-cli --test '*' -- --nocapture

# Run all tests (unit + e2e)
test-all: test e2e

# Run rustls integration test (mTLS connection)
test-rustls-integration:
    #!/bin/bash
    set -e
    cargo run --package examples --bin tls-echo-server &
    SERVER_PID=$!
    trap "kill $SERVER_PID 2>/dev/null || true" EXIT
    sleep 2
    cargo run --package examples --bin tls-echo-client -- --message "test" | grep -q "test"
    echo "rustls integration test passed"

# Clean build artifacts
clean:
    cargo clean

# Bump version (updates workspace version in Cargo.toml)
bump-version version:
    cargo install cargo-edit --quiet 2>/dev/null || true
    cargo set-version --workspace {{ version }}

# Show current version
version:
    @cargo metadata --format-version 1 --no-deps | jq -r '.packages[0].version'

# Run CI checks locally
ci: format-check lint test e2e
