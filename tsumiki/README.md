# tsumiki

[![crates.io](https://img.shields.io/crates/v/tsumiki.svg)](https://crates.io/crates/tsumiki)
[![docs.rs](https://docs.rs/tsumiki/badge.svg)](https://docs.rs/tsumiki)

Core traits for the tsumiki PKI toolkit.

This crate defines the fundamental `Decoder` and `Encoder` traits that establish a type-safe conversion pattern used throughout tsumiki.

## Overview

The conversion pattern flows like this:

```text
PEM -> Vec<u8> -> DER -> ASN1Object -> Certificate
```

Each step uses the `Decoder` trait to convert from one type to the next, and the `Encoder` trait to convert in the reverse direction.

## Usage

```toml
[dependencies]
tsumiki = "0.1"
```

## Related Crates

- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing
- [tsumiki-der](https://crates.io/crates/tsumiki-der) - DER encoding/decoding
- [tsumiki-asn1](https://crates.io/crates/tsumiki-asn1) - ASN.1 object representation
- [tsumiki-pkcs](https://crates.io/crates/tsumiki-pkcs) - PKCS standards support

## License

MIT License
