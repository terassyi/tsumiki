# PKCS - Public-Key Cryptography Standards

Pure Rust implementation of PKCS standards for tsumiki project.

## Supported Standards

### PKCS#8 (RFC 5958)

- PrivateKeyInfo structure
- Asymmetric key packages
- Algorithm-independent private key format

### PKCS#1 (RFC 8017)

- RSAPrivateKey structure
- RSAPublicKey structure
- RSA cryptography specifications

### SEC1 (RFC 5915)

- ECPrivateKey structure
- Elliptic Curve private key format
- Named curve support (P-256, P-384, P-521)

## Features

- RFC-compliant ASN.1 encoding/decoding
- Integration with tsumiki's ASN.1/DER infrastructure
- Type-safe key format handling
- Comprehensive test coverage

## Usage

```rust
use pkcs::pkcs8::PrivateKeyInfo;
use pkcs::pkcs1::RsaPrivateKey;
use pkcs::sec1::EcPrivateKey;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;

// Decode PKCS#8 PrivateKeyInfo
let pki: PrivateKeyInfo = element.decode()?;

// Encode RSA private key
let rsa_key = RsaPrivateKey { /* ... */ };
let element: Element = rsa_key.encode()?;
```

## References

- [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958) - Asymmetric Key Packages
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) - PKCS #1: RSA Cryptography Specifications
- [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) - Elliptic Curve Private Key Structure
