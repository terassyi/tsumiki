# Tsumiki Design

This document describes the architecture and design of tsumiki.

## Crate Dependencies

```text
tsumiki (core traits)
    |
    v
   pem -----> der -----> asn1 -----> pkix-types -----> x509
                           \                      /       \
                            -------> pkcs -------/         cli
```

### Dependency Flow

1. **tsumiki**: Core traits (`Encoder`, `Decoder`) that define the conversion pattern
2. **pem**: Converts PEM text to raw bytes ([RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468))
3. **der**: Parses DER-encoded bytes into TLV (Tag-Length-Value) structures ([ITU-T X.690](https://www.itu.int/rec/T-REC-X.690))
4. **asn1**: Represents ASN.1 objects as structured `Element` types ([ITU-T X.680](https://www.itu.int/rec/T-REC-X.680))
5. **pkix-types**: PKIX structures shared between X.509 and PKCS ([RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279), [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480))
6. **x509**: X.509 certificate structures ([RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280))
7. **pkcs**: PKCS key formats
   - PKCS#1: RSA key format ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017))
   - PKCS#8: Generic private key format ([RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958))
   - PKCS#9: Attributes ([RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985))
   - SEC1: EC private key format ([RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915))
8. **cli**: Command-line tool

## Core Traits

The `tsumiki` crate defines two core traits that establish the conversion pattern used throughout the codebase.

### Decoder Trait

Converts from a source type `T` to a destination type `D`:

```rust
pub trait Decoder<T, D: DecodableFrom<T>> {
    type Error;
    fn decode(&self) -> Result<D, Self::Error>;
}

pub trait DecodableFrom<T> {}
```

### Encoder Trait

Converts from a source type `T` to an encoded type `E`:

```rust
pub trait Encoder<T, E: EncodableTo<T>> {
    type Error;
    fn encode(&self) -> Result<E, Self::Error>;
}

pub trait EncodableTo<T> {}
```

### Conversion Chain

A typical decoding chain looks like:

```text
Pem -> Vec<u8> -> Der -> ASN1Object -> Certificate
 |        |        |         |            |
 |        |        |         |            +-- x509 crate
 |        |        |         +-- asn1 crate
 |        |        +-- der crate
 |        +-- raw bytes
 +-- pem crate
```

Example:

```rust
use std::str::FromStr;
use tsumiki::decoder::Decoder;
use tsumiki_pem::Pem;

let pem_str = std::fs::read_to_string("cert.pem")?;
let pem = Pem::from_str(&pem_str)?;
let bytes: Vec<u8> = pem.decode()?;
let der: Der = bytes.decode()?;
let asn1: ASN1Object = der.decode()?;
let cert: Certificate = asn1.decode()?;
```

## Crate Details

### tsumiki-pem

Handles PEM format ([RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468)) conversion between text and binary.

Key types:
- `Pem`: PEM-encoded data with label and content
- `Label`: PEM label (Certificate, PrivateKey, etc.)

### tsumiki-der

Handles DER (Distinguished Encoding Rules) parsing using the [nom](https://github.com/rust-bakery/nom) parser combinator library.

Key types:
- `Der`: Container for DER-encoded data
- `Tlv`: Tag-Length-Value structure
- `Tag`: ASN.1 tag (class + number)
- `PrimitiveTag`: Common primitive tags (Integer, OctetString, etc.)

### tsumiki-asn1

Represents ASN.1 objects in a structured way.

Key types:
- `ASN1Object`: Container for ASN.1 elements
- `Element`: Enum representing all ASN.1 types

```rust
pub enum Element {
    Boolean(bool),
    Integer(Integer),
    BitString(BitString),
    OctetString(OctetString),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    UTF8String(String),
    PrintableString(String),
    IA5String(String),
    UTCTime(NaiveDateTime),
    GeneralizedTime(NaiveDateTime),
    Sequence(Vec<Element>),
    Set(Vec<Element>),
    ContextSpecific { slot: u8, constructed: bool, element: Box<Element> },
    // ... and more
}
```

### tsumiki-pkix-types

Shared PKIX types used by both X.509 and PKCS crates.

Related RFCs:
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280): X.509 certificate and CRL profile
- [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279): Algorithm identifiers for X.509
- [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480): Elliptic Curve public key algorithms

Key types:
- `AlgorithmIdentifier`: Algorithm OID with optional parameters
- `Name`: X.500 distinguished name
- `SubjectPublicKeyInfo`: Public key with algorithm info
- `CertificateSerialNumber`: Certificate serial number

#### AlgorithmIdentifier Parameters

The `AlgorithmIdentifier` type includes algorithm parameters that vary by algorithm:

```rust
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<AlgorithmParameters>,
}

pub enum AlgorithmParameters {
    Null,           // RSA algorithms (sha256WithRSAEncryption, etc.)
    Other(RawAlgorithmParameter),  // EC curves, DSA params, etc.
}
```

Examples:
- **RSA**: parameters = `Some(AlgorithmParameters::Null)`
- **ECDSA**: parameters = `Some(AlgorithmParameters::Other(curve_oid))`
- **EdDSA**: parameters = `None` (absent)

Supported parameter types (defined in [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) and [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480)):
- **EC Named Curves** ([RFC 5480 Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1)): secp256r1, secp384r1, secp521r1, etc.
- **DSA Parameters** ([RFC 3279 Section 2.3.2](https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2)): p, q, g values

### tsumiki-x509

X.509 certificate parsing ([RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)) with full v3 extensions support.

Key types:
- `Certificate`: Complete X.509 certificate
- `TBSCertificate`: To-Be-Signed certificate data
- `CertificateChain`: Chain of certificates
- `Extensions`: Container for X.509 extensions

#### Extension Pattern

Extensions implement the `Extension` trait and are accessed via type-safe methods:

```rust
pub trait Extension: Sized {
    const OID: &'static str;
    
    fn from_raw(raw: &RawExtension) -> Result<Self, Error>;
}

// Usage
let bc = cert.extension::<BasicConstraints>()?;
```

#### Supported Extensions

All standard X.509 v3 extensions from [RFC 5280 Section 4.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2) are supported:

| Extension | OID | Critical | Description |
|-----------|-----|----------|-------------|
| **Basic Constraints** | 2.5.29.19 | Yes | CA flag and path length |
| **Key Usage** | 2.5.29.15 | Yes | Key usage bits (digital signature, key encipherment, etc.) |
| **Extended Key Usage** | 2.5.29.37 | No | Purpose (server auth, client auth, code signing, etc.) |
| **Subject Key Identifier** | 2.5.29.14 | No | Hash of subject public key |
| **Authority Key Identifier** | 2.5.29.35 | No | Issuer key identifier |
| **Subject Alternative Name** | 2.5.29.17 | No | DNS names, email addresses, IP addresses, URIs |
| **Issuer Alternative Name** | 2.5.29.18 | No | Issuer alternative names |
| **Name Constraints** | 2.5.29.30 | Yes | Permitted/excluded subtrees |
| **Certificate Policies** | 2.5.29.32 | No | Policy OIDs and qualifiers |
| **Policy Mappings** | 2.5.29.33 | Yes | Policy equivalence mappings |
| **Policy Constraints** | 2.5.29.36 | Yes | Require explicit policy, inhibit policy mapping |
| **CRL Distribution Points** | 2.5.29.31 | No | CRL download URIs |
| **Freshest CRL** | 2.5.29.46 | No | Delta CRL locations |
| **Inhibit Any Policy** | 2.5.29.54 | Yes | Skip certificates count |
| **Authority Info Access** | 1.3.6.1.5.5.7.1.1 | No | OCSP responder, CA issuer URIs |

### tsumiki-pkcs

PKCS standards implementation.

Modules:
- `pkcs1`: RSA key format ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017))
- `pkcs8`: Generic private key format ([RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958))
- `pkcs9`: Attributes
- `sec1`: EC private key format ([RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915))

Key types:
- `RSAPrivateKey`, `RSAPublicKey`: PKCS#1 keys
- `OneAsymmetricKey`, `EncryptedPrivateKeyInfo`: PKCS#8 keys
- `ECPrivateKey`: SEC1 EC keys
- `PrivateKey`: Unified private key type (enum over all formats)

#### rustls Integration

When the `rustls` feature is enabled, conversion traits are implemented for [rustls-pki-types](https://crates.io/crates/rustls-pki-types):

```rust
// PrivateKeyDer -> PrivateKey
impl TryFrom<PrivateKeyDer<'_>> for PrivateKey { ... }

// PrivateKey -> PrivateKeyDer
impl TryFrom<PrivateKey> for PrivateKeyDer<'static> { ... }

// Specific formats
impl TryFrom<PrivatePkcs1KeyDer<'_>> for RSAPrivateKey { ... }
impl TryFrom<PrivateSec1KeyDer<'_>> for ECPrivateKey { ... }
impl TryFrom<PrivatePkcs8KeyDer<'_>> for OneAsymmetricKey { ... }
```

This allows seamless interoperability between tsumiki and rustls.

## Error Handling

Each crate defines its own error type using [thiserror](https://crates.io/crates/thiserror):

```rust
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid version: {0}")]
    InvalidVersion(String),
    
    #[error("missing field: {0}")]
    MissingField(CertificateField),
    
    // ...
}
```

Errors are propagated using the `?` operator. Library code never panics.

### Error Propagation

Error types are converted across crate boundaries:

```rust
// x509::Error wraps lower-level errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("DER decode failed")]
    DerDecode(#[from] tsumiki_der::Error),
    
    #[error("ASN.1 decode failed")]
    Asn1Decode(#[from] tsumiki_asn1::Error),
    
    // ...
}
```

## Serialization

Types implement `serde::Serialize` and `serde::Deserialize` for JSON/YAML output:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    tbs_certificate: TBSCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString,
}
```

Extensions are serialized with their parsed structure when available:

```json
{
  "tbs_certificate": {
    "version": "V3",
    "subject": "CN=example.com",
    "extensions": {
      "basic_constraints": {
        "ca": true,
        "path_len_constraint": 0
      },
      "key_usage": {
        "digital_signature": true,
        "key_cert_sign": true
      }
    }
  }
}
```

## Testing

Tests use the [rstest](https://crates.io/crates/rstest) crate for parameterized testing:

```rust
use rstest::rstest;
use tsumiki_pkcs::sec1::ECPrivateKey;
use tsumiki_pkcs::PrivateKeyExt;
use tsumiki_pkix_types::algorithm::parameters::ec::NamedCurve;

#[rstest]
#[case(NamedCurve::Secp256r1, 256)]
#[case(NamedCurve::Secp384r1, 384)]
#[case(NamedCurve::Secp521r1, 521)]
fn test_key_size(#[case] curve: NamedCurve, #[case] expected: u32) {
    let private_key = vec![0u8; 32]; // dummy key bytes
    let key = ECPrivateKey::new(private_key, Some(curve), None);
    assert_eq!(key.key_size(), expected);
}
```

This pattern allows testing multiple cases with a single test function, improving test coverage and maintainability.

## Coding Style

See [CLAUDE.md](../CLAUDE.md) for detailed coding guidelines. Key points:

- **Functional programming style**: Iterators over loops
- **Immutability**: Avoid `let mut` when possible
- **No panics**: Library code uses `Result` instead of panicking
- **Pattern matching**: For safe access (no index operations)
- **Standard traits**: Implement `From`, `TryFrom`, `Display`, etc.
- **Type inference**: Let the compiler infer types where clear

### Safety

- **No unsafe code**: The entire codebase is memory-safe
- **No unwrap/expect**: Use `?` operator or `ok_or` for error handling
- **Bounds checking**: Use `first()`, `get()` instead of indexing
- **Validated inputs**: Check inputs at public API boundaries

## Performance Considerations

- **Zero-copy parsing**: DER parser uses `nom` for efficient parsing without allocations where possible
- **Lazy extension parsing**: Extensions are only parsed when accessed via `cert.extension::<T>()`
- **Efficient encoding**: Encoder minimizes allocations by pre-calculating buffer sizes
