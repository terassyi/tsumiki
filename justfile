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
	cargo build --package {{package}}

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

# Run tests (all packages or specific package)
test package='':
	{{ if package == '' { 'cargo test' } else { 'cargo test --package ' + package } }}

# Run tests with verbose output
testv package='':
	{{ if package == '' { 'cargo test -- --nocapture' } else { 'cargo test --package ' + package + ' -- --nocapture' } }}

# Run a specific test in a package
test-name package name:
	cargo test --package {{package}} -- {{name}} --exact --nocapture

# Clean build artifacts
clean:
	cargo clean

# Run CI checks locally
ci: format-check lint test
