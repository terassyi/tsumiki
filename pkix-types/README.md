# tsumiki-pkix-types

[![crates.io](https://img.shields.io/crates/v/tsumiki-pkix-types.svg)](https://crates.io/crates/tsumiki-pkix-types)
[![docs.rs](https://docs.rs/tsumiki-pkix-types/badge.svg)](https://docs.rs/tsumiki-pkix-types)

PKIX (Public Key Infrastructure using X.509) types shared across the tsumiki PKI toolkit.

## Features

Common types used by both X.509 and PKCS standards:

- `AlgorithmIdentifier` - Algorithm identification with parameters
- `Name` / `RDNSequence` - Distinguished names (DN)
- `SubjectPublicKeyInfo` - Public key information
- `Validity` - Certificate validity period
- `Extension` - X.509 extension structure

## Usage

```toml
[dependencies]
tsumiki-pkix-types = "0.1"
```

```rust
use tsumiki_pkix_types::{Name, AlgorithmIdentifier};

// Work with distinguished names
let name: Name = cert.subject();
println!("CN: {:?}", name.common_name());
println!("O: {:?}", name.organization());

// Check algorithm
let alg: &AlgorithmIdentifier = cert.signature_algorithm();
println!("Algorithm OID: {}", alg.algorithm());
```

## Related Crates

- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing
- [tsumiki-pkcs](https://crates.io/crates/tsumiki-pkcs) - PKCS standards support

## License

MIT License
