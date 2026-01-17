//! Algorithm Parameters
//!
//! Provides type-safe wrappers for algorithm-specific parameters
//! defined in various RFCs:
//! - [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) - DSA, RSA, DH
//! - [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) - Elliptic Curve Cryptography

use asn1::Element;

pub mod dsa;
pub mod ec;
pub mod error;

pub use dsa::DsaParameters;
pub use ec::EcParameters;
pub use error::{Error, Result};

/// Trait for algorithm-specific parameters
///
/// This trait provides a uniform interface for parameter types
/// while maintaining type safety and RFC compliance.
pub trait AlgorithmParameter: Sized {
    /// Parse from RawAlgorithmParameter
    fn parse(raw: &RawAlgorithmParameter) -> Result<Self>;
}

/// Raw algorithm parameter wrapper
///
/// This type wraps an ASN.1 Element and provides conversion methods
/// to specific parameter types through standard TryFrom/TryInto traits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAlgorithmParameter {
    element: Element,
}

impl RawAlgorithmParameter {
    /// Create a new RawAlgorithmParameter from an Element
    pub fn new(element: Element) -> Self {
        Self { element }
    }

    /// Get the inner Element
    pub fn element(&self) -> &Element {
        &self.element
    }
}

impl From<Element> for RawAlgorithmParameter {
    fn from(element: Element) -> Self {
        Self::new(element)
    }
}

impl From<RawAlgorithmParameter> for Element {
    fn from(raw: RawAlgorithmParameter) -> Self {
        raw.element
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ObjectIdentifier;
    use std::str::FromStr;

    #[test]
    fn test_raw_parameter_roundtrip() {
        let oid = ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap();
        let element = Element::ObjectIdentifier(oid.clone());
        let raw = RawAlgorithmParameter::new(element.clone());

        assert_eq!(raw.element(), &element);
    }
}
