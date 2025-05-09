default:
	@just --list

build:
	cargo build

lint:
	cargo clippy

format:
	cargo clippy --fix

# Run tests, optionally for a specific package
test package='':
  #!/usr/bin/env bash
  if [ -z "{{package}}" ]; then
    echo "Running tests for all packages"
    cargo test
  else
    echo "Running tests for package: {{package}}"
    cargo test --package {{package}}
  fi

clean:
  cargo clean
