# Library Usage Guide

This guide demonstrates how to use tsumiki as a library in your Rust projects.

## Installation

Add tsumiki crates to your `Cargo.toml`:

```toml
[dependencies]
# For X.509 certificate parsing
tsumiki-x509 = "0.1"

# For PKCS key handling with rustls integration
tsumiki-pkcs = { version = "0.1", features = ["rustls"] }

# For PEM/DER/ASN.1 lower-level operations
tsumiki-pem = "0.1"
tsumiki-der = "0.1"
tsumiki-asn1 = "0.1"

# For rustls integration
rustls-pki-types = "1"
```

## Quick Start

### Parse a Certificate from PEM

```rust
use std::str::FromStr;
use tsumiki_x509::Certificate;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem_data = std::fs::read_to_string("certificate.pem")?;
    
    // Parse certificate from PEM string
    let cert = Certificate::from_str(&pem_data)?;
    
    // Access certificate fields
    let tbs = cert.tbs_certificate();
    println!("Subject: {}", tbs.subject());
    println!("Issuer: {}", tbs.issuer());
    println!("Serial: {}", tbs.serial_number().format_hex());
    println!("Valid from: {}", tbs.validity().not_before());
    println!("Valid until: {}", tbs.validity().not_after());
    
    Ok(())
}
```

### Parse a Certificate from DER

```rust
use tsumiki::decoder::Decoder;
use tsumiki_x509::Certificate;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let der_bytes = std::fs::read("certificate.der")?;
    
    // Decode DER -> ASN.1 -> Certificate
    let der: tsumiki_der::Der = der_bytes.decode()?;
    let asn1: tsumiki_asn1::ASN1Object = der.decode()?;
    let cert: Certificate = asn1.decode()?;
    
    println!("Certificate: {}", cert);
    
    Ok(())
}
```

## Working with X.509 Extensions

### Type-Safe Extension Access

Extensions are accessed using the `extension::<T>()` method, which returns `Option<T>`:

```rust
use tsumiki_x509::Certificate;
use tsumiki_x509::extensions::{
    BasicConstraints, KeyUsage, ExtendedKeyUsage, 
    SubjectAltName, AuthorityKeyIdentifier,
};

fn inspect_extensions(cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
    // Basic Constraints
    if let Some(bc) = cert.extension::<BasicConstraints>()? {
        println!("Is CA: {}", bc.ca);
        if let Some(path_len) = bc.path_len_constraint {
            println!("Path length constraint: {}", path_len);
        }
    }
    
    // Key Usage
    if let Some(ku) = cert.extension::<KeyUsage>()? {
        println!("Key Usage:");
        if ku.digital_signature {
            println!("  - Digital Signature");
        }
        if ku.key_cert_sign {
            println!("  - Certificate Sign");
        }
        if ku.crl_sign {
            println!("  - CRL Sign");
        }
    }
    
    // Extended Key Usage
    if let Some(eku) = cert.extension::<ExtendedKeyUsage>()? {
        println!("Extended Key Usage:");
        for purpose in &eku.purposes {
            let purpose_str = match purpose.to_string().as_str() {
                ExtendedKeyUsage::SERVER_AUTH => "Server Authentication",
                ExtendedKeyUsage::CLIENT_AUTH => "Client Authentication",
                ExtendedKeyUsage::CODE_SIGNING => "Code Signing",
                ExtendedKeyUsage::EMAIL_PROTECTION => "Email Protection",
                _ => "Other",
            };
            println!("  - {}", purpose_str);
        }
    }
    
    // Subject Alternative Name
    if let Some(san) = cert.extension::<SubjectAltName>()? {
        println!("Subject Alternative Names:");
        use tsumiki_x509::extensions::GeneralName;
        for name in &san.names {
            match name {
                GeneralName::DnsName(dns) => println!("  DNS: {}", dns),
                GeneralName::Rfc822Name(email) => println!("  Email: {}", email),
                GeneralName::Uri(uri) => println!("  URI: {}", uri),
                GeneralName::IpAddress(ip) => println!("  IP: {:?}", ip),
                _ => println!("  Other: {:?}", name),
            }
        }
    }
    
    // Authority Key Identifier
    if let Some(aki) = cert.extension::<AuthorityKeyIdentifier>()? {
        if let Some(key_id) = &aki.key_identifier {
            println!("Authority Key ID: {:02x?}", key_id.as_bytes());
        }
    }
    
    Ok(())
}
```

### List All Extensions

```rust
use tsumiki_x509::Certificate;

fn list_extensions(cert: &Certificate) {
    if let Some(oids) = cert.extension_oids() {
        println!("Extensions present in certificate:");
        for oid in oids {
            println!("  - {}", oid);
        }
    } else {
        println!("No extensions (v1 or v2 certificate)");
    }
}
```

### Check if Certificate is a CA

```rust
use tsumiki_x509::Certificate;
use tsumiki_x509::extensions::BasicConstraints;

fn is_ca_certificate(cert: &Certificate) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(bc) = cert.extension::<BasicConstraints>()? {
        Ok(bc.ca)
    } else {
        Ok(false)
    }
}
```

## Working with Certificate Chains

```rust
use std::str::FromStr;
use tsumiki_x509::CertificateChain;

fn parse_chain(pem_data: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse multiple certificates from PEM
    let chain = CertificateChain::from_str(pem_data)?;
    
    println!("Chain length: {}", chain.len());
    
    // Access end-entity certificate
    if let Some(end_entity) = chain.end_entity() {
        println!("End-entity: {}", end_entity.tbs_certificate().subject());
    }
    
    // Iterate through chain
    for (i, cert) in chain.iter().enumerate() {
        let tbs = cert.tbs_certificate();
        println!("[{}] Subject: {}", i, tbs.subject());
        println!("    Issuer: {}", tbs.issuer());
        println!("    Self-signed: {}", cert.is_self_signed());
    }
    
    // Find root certificate
    if let Some(root) = chain.iter().find(|c| c.is_self_signed()) {
        println!("Root CA: {}", root.tbs_certificate().subject());
    }
    
    Ok(())
}
```

## Serialization to JSON/YAML

All types implement `serde::Serialize`:

```rust
use tsumiki_x509::Certificate;
use std::str::FromStr;

fn serialize_certificate(pem_data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cert = Certificate::from_str(pem_data)?;
    
    // Serialize to JSON
    let json = serde_json::to_string_pretty(&cert)?;
    println!("JSON:\n{}", json);
    
    // Serialize to YAML
    let yaml = serde_yml::to_string(&cert)?;
    println!("YAML:\n{}", yaml);
    
    // Save to file
    std::fs::write("certificate.json", json)?;
    
    Ok(())
}
```

## Working with PKCS Keys

### Parse Private Keys

```rust
use std::str::FromStr;
use tsumiki_pem::Pem;
use tsumiki::decoder::Decoder;
use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};

fn parse_private_key(pem_data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pem = Pem::from_str(pem_data)?;
    
    // Auto-detect format (PKCS#1, PKCS#8, or SEC1)
    let key: PrivateKey = pem.decode()?;
    
    println!("Algorithm: {}", key.algorithm());
    println!("Key size: {} bits", key.key_size());
    
    // Check key type
    match key {
        PrivateKey::Pkcs1(rsa) => {
            println!("RSA Private Key (PKCS#1)");
            println!("  Modulus bits: {}", rsa.key_size());
        }
        PrivateKey::Sec1(ec) => {
            println!("EC Private Key (SEC1)");
            if let Some(params) = &ec.parameters {
                println!("  Curve: {:?}", params);
            }
        }
        PrivateKey::Pkcs8(pkcs8) => {
            println!("Generic Private Key (PKCS#8)");
            println!("  Algorithm: {}", pkcs8.private_key_algorithm.algorithm);
        }
    }
    
    // Extract public key
    if let Some(pub_key) = key.public_key() {
        println!("Public key size: {} bits", pub_key.key_size());
    }
    
    Ok(())
}
```

### Parse Public Keys

```rust
use std::str::FromStr;
use tsumiki_pem::Pem;
use tsumiki::decoder::Decoder;
use tsumiki_pkcs::{PublicKey, PublicKeyExt};

fn parse_public_key(pem_data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pem = Pem::from_str(pem_data)?;
    let pub_key: PublicKey = pem.decode()?;
    
    println!("Key size: {} bits", pub_key.key_size());
    println!("Algorithm: {}", pub_key.algorithm().algorithm);
    
    Ok(())
}
```

### Extract Public Key from Certificate

```rust
use tsumiki_x509::Certificate;
use tsumiki_pkcs::pkcs8::PublicKey;
use tsumiki_pem::ToPem;

fn extract_public_key(cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
    // Get SubjectPublicKeyInfo from certificate
    let spki = cert.tbs_certificate().subject_public_key_info().clone();
    
    // Wrap in PublicKey type
    let pub_key = PublicKey::new(spki);
    
    // Convert to PEM
    let pem = pub_key.to_pem()?;
    println!("{}", pem);
    
    // Save to file
    std::fs::write("public-key.pem", pem.to_string())?;
    
    Ok(())
}
```

## rustls Integration

For complete working examples of rustls integration, see the [examples/](../examples/) directory which contains mTLS echo server/client implementations.

### Convert rustls Certificates to tsumiki

```rust
use rustls_pki_types::CertificateDer;
use tsumiki_x509::{Certificate, CertificateChain};

fn inspect_rustls_cert(rustls_cert: CertificateDer) -> Result<(), Box<dyn std::error::Error>> {
    // Convert to tsumiki type for inspection
    let cert = Certificate::try_from(rustls_cert)?;
    
    let tbs = cert.tbs_certificate();
    println!("Subject: {}", tbs.subject());
    println!("Issuer: {}", tbs.issuer());
    println!("Valid: {} to {}", tbs.validity().not_before(), tbs.validity().not_after());
    
    Ok(())
}

fn inspect_rustls_chain(rustls_certs: Vec<CertificateDer>) -> Result<(), Box<dyn std::error::Error>> {
    // Convert certificate chain
    let chain = CertificateChain::try_from(rustls_certs)?;
    
    for (i, cert) in chain.iter().enumerate() {
        println!("[{}] {}", i, cert.tbs_certificate().subject());
    }
    
    Ok(())
}
```

### Convert tsumiki Certificates to rustls

```rust
use rustls_pki_types::CertificateDer;
use tsumiki_x509::{Certificate, CertificateChain};

fn convert_to_rustls(cert: Certificate) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
    let rustls_cert: CertificateDer = cert.try_into()?;
    Ok(rustls_cert)
}

fn convert_chain_to_rustls(chain: CertificateChain) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let rustls_certs: Vec<CertificateDer> = chain.try_into()?;
    Ok(rustls_certs)
}
```

### Convert rustls Keys to tsumiki

```rust
use rustls_pki_types::PrivateKeyDer;
use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};

fn inspect_rustls_key(rustls_key: PrivateKeyDer) -> Result<(), Box<dyn std::error::Error>> {
    // Convert to tsumiki type for inspection
    let tsumiki_key = PrivateKey::try_from(rustls_key)?;
    
    println!("Algorithm: {}", tsumiki_key.algorithm());
    println!("Key size: {} bits", tsumiki_key.key_size());
    
    Ok(())
}
```

### Convert tsumiki Keys to rustls

```rust
use tsumiki_pkcs::PrivateKey;
use rustls_pki_types::PrivateKeyDer;

fn convert_key_to_rustls(tsumiki_key: PrivateKey) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let rustls_key: PrivateKeyDer = tsumiki_key.try_into()?;
    Ok(rustls_key)
}
```

## Lower-Level Operations

### Working with PEM

```rust
use std::str::FromStr;
use tsumiki_pem::{Pem, Label};

fn pem_operations() -> Result<(), Box<dyn std::error::Error>> {
    // Parse PEM
    let pem_str = std::fs::read_to_string("certificate.pem")?;
    let pem = Pem::from_str(&pem_str)?;
    
    println!("Label: {}", pem.label());
    
    // Check label type
    match pem.label() {
        Label::Certificate => println!("This is a certificate"),
        Label::PrivateKey => println!("This is a private key"),
        Label::PublicKey => println!("This is a public key"),
        _ => println!("Other type"),
    }
    
    // Decode to raw bytes
    use tsumiki::decoder::Decoder;
    let der_bytes: Vec<u8> = pem.decode()?;
    println!("DER length: {} bytes", der_bytes.len());
    
    // Create PEM from bytes
    let new_pem = Pem::from_bytes(Label::Certificate, &der_bytes);
    println!("{}", new_pem);
    
    Ok(())
}
```

### Working with DER

```rust
use tsumiki::decoder::Decoder;
use tsumiki_der::Der;

fn der_operations() -> Result<(), Box<dyn std::error::Error>> {
    let der_bytes = std::fs::read("certificate.der")?;
    
    // Parse DER
    let der: Der = der_bytes.decode()?;
    
    // Decode to ASN.1
    let asn1: tsumiki_asn1::ASN1Object = der.decode()?;
    
    println!("Number of top-level elements: {}", asn1.elements().len());
    
    Ok(())
}
```

### Working with ASN.1

```rust
use tsumiki_asn1::{Element, ASN1Object, Integer, ObjectIdentifier};
use tsumiki::encoder::Encoder;

fn asn1_operations() -> Result<(), Box<dyn std::error::Error>> {
    // Create ASN.1 structure manually
    let elements = vec![
        Element::Integer(Integer::from(vec![0x01])),
        Element::ObjectIdentifier(
            ObjectIdentifier::from_str("1.2.840.113549.1.1.1")?
        ),
        Element::Null,
    ];
    
    let sequence = Element::Sequence(elements);
    let asn1_obj = ASN1Object::new(vec![sequence]);
    
    // Encode to DER
    let der: tsumiki_der::Der = asn1_obj.encode()?;
    let der_bytes: Vec<u8> = der.encode()?;
    
    println!("Encoded {} bytes", der_bytes.len());
    
    Ok(())
}
```

## Best Practices

1. **Error Handling**: Always handle errors properly using `?` or `match`
2. **Type Safety**: Use the extension API for type-safe extension access
3. **Resource Management**: Certificate and key parsing is relatively cheap, but cache parsed results if you access them frequently
4. **Validation**: Always validate certificate dates, key sizes, and other security-relevant properties
5. **Serialization**: Use JSON/YAML serialization for debugging and logging

## See Also

- [CLI Usage Guide](cli-usage.md) - Command-line tool examples
- [Design Document](design.md) - Architecture and crate design
- [API Documentation](https://docs.rs/tsumiki-x509) - Full API reference
