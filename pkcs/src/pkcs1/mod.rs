//! PKCS#1 - RSA Cryptography Specifications.
//!
//! This module implements the RSA key formats defined in
//! [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) (PKCS #1: RSA Cryptography Specifications Version 2.2).
//!
//! # Supported Types
//!
//! - [`RSAPrivateKey`] - RSA private key in PKCS#1 format
//! - [`RSAPublicKey`] - RSA public key in PKCS#1 format
//!
//! # Example
//!
//! ```no_run
//! use tsumiki::decoder::Decoder;
//! use tsumiki_pem::Pem;
//! use tsumiki_pkcs::pkcs1::RSAPrivateKey;
//! use tsumiki_pkcs::PrivateKeyExt;
//!
//! let pem: Pem = "-----BEGIN RSA PRIVATE KEY-----...".parse().unwrap();
//! let key: RSAPrivateKey = pem.decode().unwrap();
//! println!("RSA key size: {} bits", key.key_size());
//! ```

pub mod error;
mod types;

pub use error::{Error, Result};
pub use tsumiki_pem::ToPem;
pub use types::{RSAPrivateKey, RSAPublicKey, Version};
