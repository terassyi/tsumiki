# Tsumiki

A pure Rust PKI toolkit and library for X.509 certificates, ASN.1, and PKCS standards.

> **Status**: Under Development - APIs may change.

## Overview

Tsumiki is a **type-safe**, **RFC-compliant**, full-scratch implementation of PKI (Public Key Infrastructure) components in pure Rust. It provides both a library for programmatic access and a CLI tool for certificate inspection.

### Key Features

- **Type Safety**: Strong typing throughout the API prevents common mistakes
- **RFC Compliance**: Strict adherence to IETF standards
- **rustls Integration**: First-class support for rustls-pki-types
- **JSON/YAML Serialization**: Built-in serde support for all types
- **Zero Unsafe Code**: Memory-safe implementation

## Supported Standards

Tsumiki implements the following RFCs:

- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - X.509 Certificate and CRL Profile
- [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) - Textual Encodings of PKIX, PKCS, and CMS Structures (PEM)
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) - PKCS#1: RSA Cryptography Specifications
- [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958) - PKCS#8: Private-Key Information Syntax
- [RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985) - PKCS#9: Selected Object Classes and Attribute Types
- [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) - SEC1: Elliptic Curve Private Key Structure
- [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) - Elliptic Curve Cryptography
- [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) - DSA, RSA, DH Algorithm Identifiers

## Features

### Implemented

- [x] X.509 certificate parsing (v1, v2, v3)
- [x] X.509 v3 extensions support
  - [x] Basic Constraints
  - [x] Key Usage / Extended Key Usage
  - [x] Subject Alternative Name / Issuer Alternative Name
  - [x] Authority Key Identifier / Subject Key Identifier
  - [x] CRL Distribution Points
  - [x] Authority Info Access (OCSP, CA Issuers)
  - [x] Certificate Policies
  - [x] Name Constraints
  - [x] Policy Mappings / Policy Constraints
  - [x] Inhibit Any Policy
  - [x] Freshest CRL
- [x] Certificate chain handling
- [x] ASN.1 DER parsing and encoding
- [x] PEM format support (RFC 7468)
- [x] PKCS#1 RSA keys
- [x] PKCS#8 private/public keys
- [x] SEC1 EC private keys (RFC 5915)
- [x] rustls-pki-types integration
- [x] JSON/YAML serialization (serde)
- [x] CLI tool for certificate inspection
- [x] Remote certificate fetching via TLS

### Planned

- [ ] Certificate validation
- [ ] Certificate signing
- [ ] CRL (Certificate Revocation List) parsing
- [ ] OCSP support
- [ ] PKCS#1 / PKCS#8 / SEC1 key generation
- [ ] PKCS#7 / CMS
- [ ] PKCS#12

## Crate Structure

```
tsumiki (core traits: Encoder/Decoder)
    |
   pem --> der --> asn1 --> pkix-types --> x509
                      \                /      \
                       --> pkcs ------/        cli
```

| Crate | Description | crates.io |
|-------|-------------|-----------|
| `tsumiki` | Core traits (`Encoder`, `Decoder`) | [![crates.io](https://img.shields.io/crates/v/tsumiki.svg)](https://crates.io/crates/tsumiki) |
| `tsumiki-pem` | PEM format handling (RFC 7468) | [![crates.io](https://img.shields.io/crates/v/tsumiki-pem.svg)](https://crates.io/crates/tsumiki-pem) |
| `tsumiki-der` | DER (Distinguished Encoding Rules) parsing | [![crates.io](https://img.shields.io/crates/v/tsumiki-der.svg)](https://crates.io/crates/tsumiki-der) |
| `tsumiki-asn1` | ASN.1 object representation | [![crates.io](https://img.shields.io/crates/v/tsumiki-asn1.svg)](https://crates.io/crates/tsumiki-asn1) |
| `tsumiki-pkix-types` | PKIX types shared across X.509 and PKCS | [![crates.io](https://img.shields.io/crates/v/tsumiki-pkix-types.svg)](https://crates.io/crates/tsumiki-pkix-types) |
| `tsumiki-x509` | X.509 certificate parsing | [![crates.io](https://img.shields.io/crates/v/tsumiki-x509.svg)](https://crates.io/crates/tsumiki-x509) |
| `tsumiki-pkcs` | PKCS#1, PKCS#8, PKCS#9, SEC1 support | [![crates.io](https://img.shields.io/crates/v/tsumiki-pkcs.svg)](https://crates.io/crates/tsumiki-pkcs) |
| `tsumiki-cli` | Command-line tool | [![crates.io](https://img.shields.io/crates/v/tsumiki-cli.svg)](https://crates.io/crates/tsumiki-cli) |

## Installation

### CLI Tool

```bash
cargo install tsumiki-cli
```

Or download pre-built binaries from [GitHub Releases](https://github.com/terassyi/tsumiki/releases).

### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
tsumiki-x509 = "0.1"
tsumiki-pkcs = { version = "0.1", features = ["rustls"] }
```

## Quick Start

### CLI Usage

```bash
tsumiki cert inspect --remote github.com --first
```

<details>
<summary>Click to see output</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 02:76:56:89:fe:e5:2f:85:c4:c8:a4:76:50:e8:4b:be
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
        Validity
            Not Before: Jan 06 00:00:00 2026 GMT
            Not After : Apr 05 23:59:59 2026 GMT
        Subject: CN=github.com
        Subject Public Key Info:
            Public Key Algorithm: ecPublicKey
                Public-Key: (520 bit)
                04:67:a5:75:50:96:18:07:5f:55:31:24:a8:52:41
                53:b7:9d:38:98:81:37:b1:77:ec:de:52:94:17:e6
                da:ef:d5:4b:79:2c:91:bb:54:87:45:c7:22:93:6c
                26:b7:2d:ab:29:67:f1:31:b3:3b:f8:a8:37:f4:69
                42:3e:93:4b:c2
        X509v3 extensions:
            X509v3 subjectKeyIdentifier:
                58:B9:33:08:11:F3:2F:7B:FD:8F:E4:47:91:6A:22:B8:36:C9:08:93
            X509v3 authorityKeyIdentifier:
                keyid:17:99:A8:04:C1:6F:E4:2D:70:A8:0A:10:3D:03:D3:E9:1A:B8:26:63
            X509v3 basicConstraints: critical
                CA:FALSE
            X509v3 keyUsage: critical
                Digital Signature
            X509v3 extendedKeyUsage:
                TLS Web Server Authentication
            X509v3 subjectAltName:
                DNS:github.com
                DNS:www.github.com
            X509v3 certificatePolicies:
                Policy: 1.3.6.1.4.1.6449.1.2.2.7
                  1.3.6.1.5.5.7.2.1
                Policy: 2.23.140.1.2.1
            X509v3 authorityInfoAccess:
                CA Issuers - URI:http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt
                OCSP - URI:http://ocsp.sectigo.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:7f:77:0b:41:2e:67:81:93:d4:dd:1c:65:c3:98
         bc:b3:93:88:18:65:30:c7:22:13:bd:54:d7:62:1e:9a:c6:c8
         02:20:59:fd:ff:30:af:5e:53:3c:8f:3e:47:5e:7b:82:1e:b6
         6c:ee:57:af:a5:6c:ef:16:18:4c:1f:64:2b:e8:00:b0
```

</details>

See [CLI Usage Guide](docs/cli-usage.md) for more details.

### rustls Integration

tsumiki provides seamless conversion with [rustls-pki-types](https://crates.io/crates/rustls-pki-types):

```rust
use rustls_pki_types::PrivateKeyDer;
use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};

// Convert rustls key to tsumiki for inspection
let rustls_key: PrivateKeyDer = load_private_key()?;
let key = PrivateKey::try_from(rustls_key)?;

println!("Algorithm: {}", key.algorithm());
println!("Key size: {} bits", key.key_size());

// Convert back to rustls
let rustls_key: PrivateKeyDer = key.try_into()?;
```

See [Library Usage Guide](docs/usage.md) for more examples.

## Documentation

- [CLI Usage Guide](docs/cli-usage.md) - Command-line tool usage
- [Library Usage Guide](docs/usage.md) - Library examples and patterns
- [Design Document](docs/design.md) - Architecture and crate design

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
