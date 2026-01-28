# tsumiki-pem

[![crates.io](https://img.shields.io/crates/v/tsumiki-pem.svg)](https://crates.io/crates/tsumiki-pem)
[![docs.rs](https://docs.rs/tsumiki-pem/badge.svg)](https://docs.rs/tsumiki-pem)

PEM (Privacy-Enhanced Mail) format handling for the tsumiki PKI toolkit.

Based on [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) - Textual Encodings of PKIX, PKCS, and CMS Structures.

## Features

- Parse PEM-encoded data (certificates, keys, etc.)
- Encode binary data to PEM format
- Support for multiple PEM blocks in a single file

## Usage

```toml
[dependencies]
tsumiki-pem = "0.1"
```

```rust
use tsumiki_pem::Pem;

// Parse PEM data
let pem_str = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
let pem: Pem = pem_str.parse()?;

// Access the decoded bytes
let der_bytes = pem.contents();
let label = pem.label(); // "CERTIFICATE"
```

## Related Crates

- [tsumiki-der](https://crates.io/crates/tsumiki-der) - DER encoding/decoding
- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing

## License

MIT License
