# tsumiki-pkcs

[![crates.io](https://img.shields.io/crates/v/tsumiki-pkcs.svg)](https://crates.io/crates/tsumiki-pkcs)
[![docs.rs](https://docs.rs/tsumiki-pkcs/badge.svg)](https://docs.rs/tsumiki-pkcs)

PKCS (Public-Key Cryptography Standards) support for the tsumiki PKI toolkit.

## Supported Standards

- **PKCS#1** ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)) - RSA public and private keys
- **PKCS#8** ([RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958)) - Private-key information syntax
- **PKCS#9** ([RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985)) - Selected attributes
- **SEC1** ([RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915)) - Elliptic Curve private keys

## Features

- Parse RSA, EC, and other private/public keys
- Support for encrypted PKCS#8 keys
- rustls-pki-types integration (optional)
- JSON/YAML serialization (serde)

## Usage

```toml
[dependencies]
tsumiki-pkcs = "0.1"

# With rustls integration
tsumiki-pkcs = { version = "0.1", features = ["rustls"] }
```

```rust
use rustls_pki_types::PrivateKeyDer;
use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};

// Parse a private key from PEM
let pem = std::fs::read_to_string("key.pem")?;
let key = PrivateKey::from_pem(&pem)?;

// Inspect key properties
println!("Algorithm: {}", key.algorithm());
println!("Key size: {} bits", key.key_size());

// Convert to rustls (with "rustls" feature)
let rustls_key: PrivateKeyDer = key.try_into()?;
```

## Related Crates

- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing
- [tsumiki-cli](https://crates.io/crates/tsumiki-cli) - Command-line tool

## License

MIT License
