//! PKCS#9: Selected Object Classes and Attribute Types
//!
//! This module implements selected PKCS#9 attributes defined in
//! [RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985) commonly used with
//! PKCS#8 private keys, PKCS#10 certificate requests, and CMS/PKCS#7 messages.
//!
//! # Supported Attributes
//!
//! - `contentType` - Content type OID
//! - `messageDigest` - Message digest value
//! - `signingTime` - Signing timestamp
//! - `challengePassword` - Challenge password for CSRs
//! - `unstructuredName` - Free-form name
//! - `unstructuredAddress` - Free-form address
//! - `extensionRequest` - X.509 extensions for CSRs
//! - `friendlyName` - Human-readable key name (PKCS#12)
//! - `localKeyId` - Key identifier (PKCS#12)
//! - `smimeCapabilities` - S/MIME capabilities
//! - `countersignature` - Countersignature information
//!
//! # Example
//!
//! ```no_run
//! use tsumiki_pkcs::pkcs9::attribute::FriendlyName;
//!
//! // FriendlyName attribute for PKCS#12
//! let name = FriendlyName::new("My Key".to_string()).unwrap();
//! println!("Friendly name: {}", name.name());
//! ```

pub mod attribute;
pub mod error;

// Export both the trait and the raw structure
pub use attribute::{Attribute, Attributes, ParsedAttributes, RawAttribute};
pub use error::{Error, Result};

// Re-export DirectoryString from pkix-types for convenience
pub use tsumiki_pkix_types::DirectoryString;
