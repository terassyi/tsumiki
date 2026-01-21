//! SEC1 (RFC 5915) - Elliptic Curve Private Key Structure
//!
//! This module implements the ECPrivateKey structure as defined in
//! [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).

pub mod error;
mod types;

pub use error::{Error, Result};
pub use pem::ToPem;
pub use types::{ECPrivateKey, Version};
