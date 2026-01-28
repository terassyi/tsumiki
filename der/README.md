# tsumiki-der

[![crates.io](https://img.shields.io/crates/v/tsumiki-der.svg)](https://crates.io/crates/tsumiki-der)
[![docs.rs](https://docs.rs/tsumiki-der/badge.svg)](https://docs.rs/tsumiki-der)

DER (Distinguished Encoding Rules) parsing and encoding for the tsumiki PKI toolkit.

## Features

- Parse DER-encoded ASN.1 structures
- Encode ASN.1 structures to DER format
- Tag-Length-Value (TLV) representation
- Support for primitive and constructed types

## Usage

```toml
[dependencies]
tsumiki-der = "0.1"
```

```rust
use tsumiki::decoder::Decoder;
use tsumiki_der::Der;

// Parse DER from bytes
let bytes = vec![0x30, 0x00]; // Empty SEQUENCE
let der: Der = bytes.decode()?;

// Access TLV structure
for tlv in der.tlvs() {
    println!("Tag: {:?}, Length: {}", tlv.tag(), tlv.length());
}
```

## Related Crates

- [tsumiki-pem](https://crates.io/crates/tsumiki-pem) - PEM format handling
- [tsumiki-asn1](https://crates.io/crates/tsumiki-asn1) - ASN.1 object representation
- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing

## License

MIT License
