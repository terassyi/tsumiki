# tsumiki-crl

[![crates.io](https://img.shields.io/crates/v/tsumiki-crl.svg)](https://crates.io/crates/tsumiki-crl)
[![docs.rs](https://docs.rs/tsumiki-crl/badge.svg)](https://docs.rs/tsumiki-crl)

Certificate Revocation List (CRL) handling for the tsumiki PKI toolkit.

Based on [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - Internet X.509 Public Key Infrastructure Certificate and CRL Profile.

## Features

- `DistributionPoints` - CRL distribution points carried in X.509 certificates
- `DistributionPoint` / `DistributionPointName` - Individual distribution point entries
- `ReasonFlags` - Revocation reason flags

## Usage

```toml
[dependencies]
tsumiki-crl = "0.1"
```

```rust
use tsumiki_crl::{DistributionPoints, DistributionPointName};
use tsumiki_x509::Certificate;

let pem = std::fs::read_to_string("cert.pem")?;
let cert = Certificate::from_pem(&pem)?;

if let Some(cdp) = cert.extension::<DistributionPoints>()? {
    for dp in &cdp.distribution_points {
        if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
            for name in names {
                println!("{}", name);
            }
        }
    }
}
```

## Related Crates

- [tsumiki-x509](https://crates.io/crates/tsumiki-x509) - X.509 certificate parsing
- [tsumiki-cli](https://crates.io/crates/tsumiki-cli) - Command-line tool

## License

MIT License
