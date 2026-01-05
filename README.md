# Tsumiki

A pure Rust implementation of X.509 certificate parsing and handling.

## Status

 **Under Development** - This project is actively being developed and APIs may change.

## Features

- X.509 certificate parsing (v1, v2, v3)
- ASN.1 DER/PEM encoding support
- X.509 v3 extensions support
- CLI tool for certificate inspection
- Text and JSON output formats

## Quick Start

```bash
# Build
cargo build --release

# Parse a certificate
./target/release/tsumiki cert decode certificate.pem

# JSON output
./target/release/tsumiki cert decode certificate.pem -o json
```

## Requirements

- Rust 1.86.0 or later

## License

MIT License - see LICENSE file for details.
