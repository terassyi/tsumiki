//! Algorithm Parameters
//!
//! Provides type-safe wrappers for algorithm-specific parameters
//! defined in various RFCs:
//! - [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) - DSA, RSA, DH
//! - [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) - Elliptic Curve Cryptography

use tsumiki_asn1::Element;

pub mod dsa;
pub mod ec;
pub mod error;

pub use dsa::DsaParameters;
pub use ec::EcParameters;
pub use error::{Error, Result};

/// Trait for algorithm-specific parameters.
///
/// This trait provides a uniform interface for parameter types
/// while maintaining type safety and RFC compliance.
///
/// Implementations include:
/// - `EcParameters` - Elliptic Curve parameters (RFC 5480)
/// - `DsaParameters` - DSA parameters (RFC 3279)
///
/// # Example
///
/// ```no_run
/// use tsumiki_pkix_types::{AlgorithmParameter, EcParameters, RawAlgorithmParameter};
///
/// # fn example(raw: &RawAlgorithmParameter) -> Result<(), Box<dyn std::error::Error>> {
/// // Parse EC parameters from raw
/// let ec_params = EcParameters::parse(raw)?;
/// println!("Curve: {:?}", ec_params.named_curve());
/// # Ok(())
/// # }
/// ```
pub trait AlgorithmParameter: Sized {
    /// Parse from RawAlgorithmParameter.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw parameter format does not match
    /// the expected structure for this parameter type.
    fn parse(raw: &RawAlgorithmParameter) -> Result<Self>;
}

/// Raw algorithm parameter wrapper.
///
/// This type wraps an ASN.1 Element and provides conversion methods
/// to specific parameter types through standard TryFrom/TryInto traits.
///
/// # Example
///
/// ```
/// use std::str::FromStr;
/// use tsumiki_asn1::{Element, ObjectIdentifier};
/// use tsumiki_pkix_types::RawAlgorithmParameter;
///
/// // Wrap an OID (e.g., for EC curve parameter)
/// let oid = ObjectIdentifier::from_str("1.2.840.10045.3.1.7")?; // secp256r1
/// let element = Element::ObjectIdentifier(oid);
/// let raw = RawAlgorithmParameter::new(element);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAlgorithmParameter {
    element: Element,
}

impl RawAlgorithmParameter {
    /// Create a new RawAlgorithmParameter from an Element.
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_asn1::Element;
    /// use tsumiki_pkix_types::RawAlgorithmParameter;
    ///
    /// let element = Element::Null;
    /// let raw = RawAlgorithmParameter::new(element);
    /// ```
    pub fn new(element: Element) -> Self {
        Self { element }
    }

    /// Get a reference to the inner Element.
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_asn1::Element;
    /// use tsumiki_pkix_types::RawAlgorithmParameter;
    ///
    /// let element = Element::Null;
    /// let raw = RawAlgorithmParameter::new(element.clone());
    /// assert_eq!(raw.element(), &element);
    /// ```
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
    use std::str::FromStr;
    use tsumiki_asn1::ObjectIdentifier;

    #[test]
    fn test_raw_parameter_roundtrip() {
        let oid = ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap();
        let element = Element::ObjectIdentifier(oid.clone());
        let raw = RawAlgorithmParameter::new(element.clone());

        assert_eq!(raw.element(), &element);
    }
}
