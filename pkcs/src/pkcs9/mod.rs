/// PKCS#9: Selected Object Classes and Attribute Types
/// RFC 2985
pub mod attribute;
pub mod error;

// Export both the trait and the raw structure
pub use attribute::{Attribute, Attributes, ParsedAttributes, RawAttribute};
pub use error::{Error, Result};

// Re-export DirectoryString from pkix-types for convenience
pub use pkix_types::DirectoryString;
