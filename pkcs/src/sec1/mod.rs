//! SEC1 - Elliptic Curve Private Key Structure
//!
//! This module implements the ECPrivateKey structure as defined in
//! [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) (Elliptic Curve Private Key Format).
//!
//! Provides a format for storing EC private keys with optional public key and curve parameters.

pub mod error;
mod types;

pub use error::{Error, Result};
pub use tsumiki_pem::ToPem;
pub use types::{ECPrivateKey, Version};
