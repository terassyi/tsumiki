# tsumiki-cli

[![crates.io](https://img.shields.io/crates/v/tsumiki-cli.svg)](https://crates.io/crates/tsumiki-cli)
[![GitHub Release](https://img.shields.io/github/v/release/terassyi/tsumiki)](https://github.com/terassyi/tsumiki/releases/latest)

Command-line tool for X.509 certificate inspection and PKCS handling.

Part of the [tsumiki](https://github.com/terassyi/tsumiki) PKI toolkit. See the [CLI Usage Guide](https://github.com/terassyi/tsumiki/blob/main/docs/cli-usage.md) for detailed documentation.

## Installation

```bash
cargo install tsumiki-cli
```

Or download pre-built binaries from [GitHub Releases](https://github.com/terassyi/tsumiki/releases).

## Usage

### Inspect certificates

```bash
# From file
tsumiki cert inspect cert.pem

# From remote server
tsumiki cert inspect --remote github.com

# Output as JSON
tsumiki cert inspect cert.pem -o json

# Show only first certificate in chain
tsumiki cert inspect --remote github.com --first
```

### Inspect DER/ASN.1

```bash
# Dump DER structure
tsumiki der dump cert.der

# Inspect ASN.1
tsumiki asn1 inspect cert.der
```

### Inspect PKCS keys

```bash
# Inspect private key
tsumiki pkcs inspect key.pem
```

## Output Formats

- `text` - Human-readable format (default)
- `json` - JSON format
- `yaml` - YAML format
- `brief` - Single-line summary

## Related Crates

- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing library
- [tsumiki-pkcs](https://crates.io/crates/tsumiki-pkcs) - PKCS standards library

## License

MIT License
