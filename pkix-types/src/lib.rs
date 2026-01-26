//! # tsumiki-pkix-types
//!
//! Common types for PKIX (Public Key Infrastructure using X.509).
//!
//! This crate provides shared type definitions used by both X.509 certificates
//! and PKCS standards.
//!
//! ## Standards
//!
//! - [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - X.509 Certificate and CRL Profile
//! - [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) - Algorithm identifiers
//! - [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) - Elliptic Curve algorithms
//!
//! ## Key Types
//!
//! - `AlgorithmIdentifier` - Algorithm OID with optional parameters
//! - `Name` - X.500 distinguished name (e.g., "CN=example.com, O=Example Org")
//! - `SubjectPublicKeyInfo` - Public key with algorithm information
//! - `CertificateSerialNumber` - Certificate serial number
//!
//! ## Example
//!
//! ```
//! use std::str::FromStr;
//! use tsumiki_asn1::{Element, ObjectIdentifier};
//! use tsumiki::decoder::Decoder;
//! use tsumiki::encoder::Encoder;
//! use tsumiki_pkix_types::AlgorithmIdentifier;
//!
//! // Create AlgorithmIdentifier for RSA
//! let oid = ObjectIdentifier::from_str("1.2.840.113549.1.1.1")?; // rsaEncryption
//! let alg = AlgorithmIdentifier::new(oid);
//!
//! // Encode and decode
//! let element: Element = alg.encode()?;
//! let decoded: AlgorithmIdentifier = element.decode()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

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
    AlgorithmIdentifier, AlgorithmParameters,
    parameters::{AlgorithmParameter, DsaParameters, EcParameters, RawAlgorithmParameter},
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

/// Set whether to use OID values instead of human-readable names in serialization.
///
/// When set to `true`, types like `AlgorithmIdentifier` and `AttributeTypeAndValue`
/// will serialize using raw OID strings (e.g., "1.2.840.10045.3.1.7").
///
/// When set to `false` (default), they use human-readable names when available
/// (e.g., "secp256r1", "CN").
///
/// # Example
///
/// ```
/// use tsumiki_pkix_types::set_use_oid_values;
///
/// // Use human-readable names (default)
/// set_use_oid_values(false);
///
/// // Use raw OID values
/// set_use_oid_values(true);
/// ```
pub fn set_use_oid_values(use_oid: bool) {
    USE_OID_VALUES.with(|flag| flag.set(use_oid));
}

/// Get whether to use OID values instead of human-readable names in serialization.
///
/// Returns `true` if raw OID values should be used, `false` if human-readable
/// names should be used when available.
///
/// # Example
///
/// ```
/// use tsumiki_pkix_types::{get_use_oid_values, set_use_oid_values};
///
/// set_use_oid_values(true);
/// assert!(get_use_oid_values());
///
/// set_use_oid_values(false);
/// assert!(!get_use_oid_values());
/// ```
pub fn get_use_oid_values() -> bool {
    USE_OID_VALUES.with(|flag| flag.get())
}
