//! PKCS#8: Private-Key Information Syntax Specification
//!
//! This module implements [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958) (Asymmetric Key Packages)
//! which obsoletes RFC 5208 (PKCS#8 v1.2).
//!
//! Provides a generic format for storing private keys with algorithm identification.

mod encrypted;

pub mod error;
pub mod types;

pub use encrypted::EncryptedPrivateKeyInfo;
pub use error::{Error, Result};
pub use tsumiki_pkix_types::{AlgorithmIdentifier, AlgorithmParameters};
pub use types::{
    OID_ED448, OID_ED25519, OneAsymmetricKey, OneAsymmetricKeyAttributes, PrivateKeyInfo,
    PublicKey, Version,
};
