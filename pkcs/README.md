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
use tsumiki_pkcs::pkcs8::OneAsymmetricKey;
use tsumiki_pkcs::pkcs1::RSAPrivateKey;
use tsumiki_pkcs::sec1::ECPrivateKey;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;
use tsumiki_asn1::Element;

// Decode PKCS#8 OneAsymmetricKey
let key: OneAsymmetricKey = element.decode()?;

// Encode RSA private key
let rsa_key: RSAPrivateKey = element.decode()?;
let encoded: Element = rsa_key.encode()?;
```

## References

- [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958) - Asymmetric Key Packages
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) - PKCS #1: RSA Cryptography Specifications
- [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) - Elliptic Curve Private Key Structure
