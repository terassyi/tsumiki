# tsumiki-x509

[![crates.io](https://img.shields.io/crates/v/tsumiki-x509.svg)](https://crates.io/crates/tsumiki-x509)
[![docs.rs](https://docs.rs/tsumiki-x509/badge.svg)](https://docs.rs/tsumiki-x509)

X.509 certificate parsing for the tsumiki PKI toolkit.

Based on [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - Internet X.509 Public Key Infrastructure Certificate and CRL Profile.

## Features

- Parse X.509 certificates (v1, v2, v3)
- Full v3 extensions support
- Certificate chain handling
- rustls-pki-types integration (optional)
- JSON/YAML serialization (serde)

### Supported Extensions

- Basic Constraints
- Key Usage / Extended Key Usage
- Subject Alternative Name / Issuer Alternative Name
- Authority Key Identifier / Subject Key Identifier
- CRL Distribution Points
- Authority Info Access (OCSP, CA Issuers)
- Certificate Policies
- Name Constraints
- And more...

## Usage

```toml
[dependencies]
tsumiki-x509 = "0.1"

# With rustls integration
tsumiki-x509 = { version = "0.1", features = ["rustls"] }
```

```rust
use tsumiki_x509::Certificate;

// Parse from PEM
let pem = std::fs::read_to_string("cert.pem")?;
let cert = Certificate::from_pem(&pem)?;

// Access certificate fields
println!("Subject: {}", cert.subject());
println!("Issuer: {}", cert.issuer());
println!("Not Before: {}", cert.validity().not_before());
println!("Not After: {}", cert.validity().not_after());

// Check extensions
if let Some(san) = cert.extension::<SubjectAltName>()? {
    for name in san.names() {
        println!("SAN: {:?}", name);
    }
}
```

### rustls Integration

```rust
use rustls_pki_types::CertificateDer;
use tsumiki_x509::Certificate;

// Parse certificate from PEM
let pem = std::fs::read_to_string("cert.pem")?;
let cert = Certificate::from_pem(&pem)?;

// Inspect certificate
println!("Subject: {}", cert.subject());
println!("Issuer: {}", cert.issuer());

// Convert to rustls
let rustls_cert: CertificateDer = cert.try_into()?;
```

## Related Crates

- [tsumiki-pkcs](https://crates.io/crates/tsumiki-pkcs) - PKCS standards (keys)
- [tsumiki-cli](https://crates.io/crates/tsumiki-cli) - Command-line tool

## License

MIT License
