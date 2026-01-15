//! PKIX (Public Key Infrastructure using X.509) Common Types
//!
//! This crate provides common type definitions used across PKI standards,
//! particularly X.509 certificates (RFC 5280) and PKCS standards.
//!
//! These types are defined in various RFCs including:
//! - RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
//! - RFC 4519: Lightweight Directory Access Protocol (LDAP): Schema for User Applications
//! - X.500 Directory Standards

pub mod algorithm;
pub mod directory_string;
pub mod error;
pub mod extension;
pub mod key_identifier;
pub mod name;
pub mod serial_number;
pub mod subject_public_key_info;

pub use algorithm::{AlgorithmIdentifier, AlgorithmParameters};
pub use directory_string::DirectoryString;
pub use error::{Error, Result};
pub use extension::Extension;
pub use key_identifier::KeyIdentifier;
pub use name::{AttributeTypeAndValue, Name, RelativeDistinguishedName};
pub use serial_number::CertificateSerialNumber;
pub use subject_public_key_info::SubjectPublicKeyInfo;
