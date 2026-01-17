//! PKIX (Public Key Infrastructure using X.509) Common Types
//!
//! This crate provides common type definitions used across PKI standards,
//! particularly X.509 certificates (RFC 5280) and PKCS standards.
//!
//! These types are defined in various RFCs including:
//! - RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
//! - RFC 4519: Lightweight Directory Access Protocol (LDAP): Schema for User Applications
//! - X.500 Directory Standards

use std::cell::Cell;

pub mod algorithm;
pub mod directory_string;
pub mod error;
pub mod extension;
pub mod key_identifier;
pub mod name;
pub mod oid_name;
pub mod serial_number;
pub mod subject_public_key_info;

pub use algorithm::{
    parameters::{AlgorithmParameter, DsaParameters, EcParameters, RawAlgorithmParameter},
    AlgorithmIdentifier, AlgorithmParameters,
};
pub use directory_string::DirectoryString;
pub use error::{Error, Result};
pub use extension::Extension;
pub use key_identifier::KeyIdentifier;
pub use name::{AttributeTypeAndValue, Name, RelativeDistinguishedName};
pub use oid_name::OidName;
pub use serial_number::CertificateSerialNumber;
pub use subject_public_key_info::SubjectPublicKeyInfo;

thread_local! {
    /// Global flag to control whether to use OID values or human-readable names in serialization
    static USE_OID_VALUES: Cell<bool> = const { Cell::new(false) };
}

/// Set whether to use OID values instead of human-readable names in serialization
pub fn set_use_oid_values(use_oid: bool) {
    USE_OID_VALUES.with(|flag| flag.set(use_oid));
}

/// Get whether to use OID values instead of human-readable names in serialization
pub fn get_use_oid_values() -> bool {
    USE_OID_VALUES.with(|flag| flag.get())
}
