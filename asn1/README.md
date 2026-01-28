# tsumiki-asn1

[![crates.io](https://img.shields.io/crates/v/tsumiki-asn1.svg)](https://crates.io/crates/tsumiki-asn1)
[![docs.rs](https://docs.rs/tsumiki-asn1/badge.svg)](https://docs.rs/tsumiki-asn1)

ASN.1 (Abstract Syntax Notation One) object representation for the tsumiki PKI toolkit.

## Features

- High-level ASN.1 type representation
- Support for all standard ASN.1 types:
  - Primitive types: Integer, BitString, OctetString, ObjectIdentifier, etc.
  - String types: UTF8String, PrintableString, IA5String, BMPString, etc.
  - Time types: UTCTime, GeneralizedTime
  - Constructed types: Sequence, Set
  - Context-specific tagged types
- Conversion to/from DER encoding

## Usage

```toml
[dependencies]
tsumiki-asn1 = "0.1"
```

```rust
use tsumiki::decoder::Decoder;
use tsumiki_asn1::ASN1Object;
use tsumiki_der::Der;

// Parse DER to ASN.1 object
let der: Der = bytes.decode()?;
let asn1: ASN1Object = der.decode()?;

// Access elements
for element in asn1.elements() {
    println!("{:?}", element);
}
```

## Related Crates

- [tsumiki-der](https://crates.io/crates/tsumiki-der) - DER encoding/decoding
- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing
- [tsumiki-pkcs](https://crates.io/crates/tsumiki-pkcs) - PKCS standards support

## License

MIT License
