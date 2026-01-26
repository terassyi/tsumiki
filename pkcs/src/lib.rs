//! # tsumiki-pkcs
//!
//! PKCS (Public Key Cryptography Standards) implementation.
//!
//! This crate provides support for multiple PKCS standards:
//!
//! ## Supported Standards
//!
//! - **PKCS#1** ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)) - RSA key format
//! - **PKCS#8** ([RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958)) - Generic private key format
//! - **PKCS#9** ([RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985)) - Selected attributes
//! - **SEC1** ([RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915)) - EC private key format
//!
//! ## Key Features
//!
//! - Unified `PrivateKey` enum for all key formats
//! - Auto-detection of key format from PEM
//! - Type-safe key inspection (algorithm, size, etc.)
//! - rustls integration (with `rustls` feature)
//!
//! ## Example
//!
//! ```no_run
//! use std::str::FromStr;
//! use tsumiki_pem::Pem;
//! use tsumiki::decoder::Decoder;
//! use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};
//!
//! // PKCS#8 EC private key (P-256)
//! let pem_data = "-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
//! OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
//! 1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
//! -----END PRIVATE KEY-----";
//!
//! let pem = Pem::from_str(pem_data).unwrap();
//! let key: PrivateKey = pem.decode().unwrap();
//!
//! // Inspect key properties
//! println!("Algorithm: {}", key.algorithm());
//! println!("Key size: {} bits", key.key_size());
//! ```
//!
//! ## rustls Integration
//!
//! With the `rustls` feature enabled, you can convert between rustls and tsumiki key types:
//!
//! ```ignore
//! use rustls_pki_types::PrivateKeyDer;
//! use tsumiki_pkcs::PrivateKey;
//!
//! // Convert rustls key to tsumiki
//! let rustls_key: PrivateKeyDer = /* load from file */;
//! let tsumiki_key = PrivateKey::try_from(rustls_key)?;
//!
//! // Convert back to rustls
//! let rustls_key: PrivateKeyDer = tsumiki_key.try_into()?;
//! ```

#![forbid(unsafe_code)]

pub mod error;
pub mod pkcs1;
pub mod pkcs8;
pub mod pkcs9;
mod private_key;
mod public_key;
#[cfg(feature = "rustls")]
pub mod rustls;
pub mod sec1;

pub use error::{Error, Result};
pub use private_key::{KeyAlgorithm, PrivateKey, PrivateKeyExt};
pub use public_key::{PublicKey, PublicKeyExt};
