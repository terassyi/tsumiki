//! Elliptic Curve Parameters
//!
//! Defined in [RFC 5480 Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1)

use super::{AlgorithmParameter, Error, RawAlgorithmParameter, Result};
use crate::{AlgorithmParameters, OidName};
use serde::{Deserialize, Serialize};
use tsumiki_asn1::{Element, ObjectIdentifier};

/// Well-known elliptic curves defined in [RFC 5480 Section 2.1.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NamedCurve {
    /// secp192r1 (also known as prime192v1 or P-192)
    /// OID: 1.2.840.10045.3.1.1
    Secp192r1,
    /// secp224r1 (also known as P-224)
    /// OID: 1.3.132.0.33
    Secp224r1,
    /// secp256r1 (also known as prime256v1 or P-256)
    /// OID: 1.2.840.10045.3.1.7
    Secp256r1,
    /// secp384r1 (also known as P-384)
    /// OID: 1.3.132.0.34
    Secp384r1,
    /// secp521r1 (also known as P-521)
    /// OID: 1.3.132.0.35
    Secp521r1,
    /// sect163k1
    /// OID: 1.3.132.0.1
    Sect163k1,
    /// sect163r2
    /// OID: 1.3.132.0.15
    Sect163r2,
    /// sect233k1
    /// OID: 1.3.132.0.26
    Sect233k1,
    /// sect233r1
    /// OID: 1.3.132.0.27
    Sect233r1,
    /// sect283k1
    /// OID: 1.3.132.0.16
    Sect283k1,
    /// sect283r1
    /// OID: 1.3.132.0.17
    Sect283r1,
    /// sect409k1
    /// OID: 1.3.132.0.36
    Sect409k1,
    /// sect409r1
    /// OID: 1.3.132.0.37
    Sect409r1,
    /// sect571k1
    /// OID: 1.3.132.0.38
    Sect571k1,
    /// sect571r1
    /// OID: 1.3.132.0.39
    Sect571r1,
}

impl NamedCurve {
    // Elliptic curve OID constants (RFC 5480 Section 2.1.1.1)
    pub const OID_SECP192R1: &'static str = "1.2.840.10045.3.1.1";
    pub const OID_SECP224R1: &'static str = "1.3.132.0.33";
    pub const OID_SECP256R1: &'static str = "1.2.840.10045.3.1.7";
    pub const OID_SECP384R1: &'static str = "1.3.132.0.34";
    pub const OID_SECP521R1: &'static str = "1.3.132.0.35";
    pub const OID_SECT163K1: &'static str = "1.3.132.0.1";
    pub const OID_SECT163R2: &'static str = "1.3.132.0.15";
    pub const OID_SECT233K1: &'static str = "1.3.132.0.26";
    pub const OID_SECT233R1: &'static str = "1.3.132.0.27";
    pub const OID_SECT283K1: &'static str = "1.3.132.0.16";
    pub const OID_SECT283R1: &'static str = "1.3.132.0.17";
    pub const OID_SECT409K1: &'static str = "1.3.132.0.36";
    pub const OID_SECT409R1: &'static str = "1.3.132.0.37";
    pub const OID_SECT571K1: &'static str = "1.3.132.0.38";
    pub const OID_SECT571R1: &'static str = "1.3.132.0.39";

    /// Get the OID string for this named curve.
    ///
    /// Returns the dotted-decimal OID string (e.g., "1.2.840.10045.3.1.7" for secp256r1).
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_pkix_types::algorithm::parameters::ec::NamedCurve;
    ///
    /// assert_eq!(NamedCurve::Secp256r1.oid_str(), "1.2.840.10045.3.1.7");
    /// assert_eq!(NamedCurve::Secp384r1.oid_str(), "1.3.132.0.34");
    /// ```
    pub const fn oid_str(&self) -> &'static str {
        match self {
            Self::Secp192r1 => Self::OID_SECP192R1,
            Self::Secp224r1 => Self::OID_SECP224R1,
            Self::Secp256r1 => Self::OID_SECP256R1,
            Self::Secp384r1 => Self::OID_SECP384R1,
            Self::Secp521r1 => Self::OID_SECP521R1,
            Self::Sect163k1 => Self::OID_SECT163K1,
            Self::Sect163r2 => Self::OID_SECT163R2,
            Self::Sect233k1 => Self::OID_SECT233K1,
            Self::Sect233r1 => Self::OID_SECT233R1,
            Self::Sect283k1 => Self::OID_SECT283K1,
            Self::Sect283r1 => Self::OID_SECT283R1,
            Self::Sect409k1 => Self::OID_SECT409K1,
            Self::Sect409r1 => Self::OID_SECT409R1,
            Self::Sect571k1 => Self::OID_SECT571K1,
            Self::Sect571r1 => Self::OID_SECT571R1,
        }
    }

    /// Get the OID for this named curve.
    ///
    /// Returns an `ObjectIdentifier` parsed from the curve's OID string.
    ///
    /// # Errors
    ///
    /// This function returns an error if the OID string fails to parse.
    /// In practice, this should never happen as all OID strings are statically defined
    /// and known to be valid.
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use tsumiki_asn1::ObjectIdentifier;
    /// use tsumiki_pkix_types::algorithm::parameters::ec::NamedCurve;
    ///
    /// let oid = NamedCurve::Secp256r1.oid()?;
    /// assert_eq!(oid, ObjectIdentifier::from_str("1.2.840.10045.3.1.7")?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn oid(&self) -> Result<ObjectIdentifier> {
        self.oid_str()
            .parse()
            .map_err(|_| Error::InvalidOid(self.oid_str().to_string()))
    }
}

impl OidName for NamedCurve {
    fn oid_name(&self) -> Option<&'static str> {
        let name = match self {
            Self::Secp192r1 => "secp192r1",
            Self::Secp224r1 => "secp224r1",
            Self::Secp256r1 => "secp256r1",
            Self::Secp384r1 => "secp384r1",
            Self::Secp521r1 => "secp521r1",
            Self::Sect163k1 => "sect163k1",
            Self::Sect163r2 => "sect163r2",
            Self::Sect233k1 => "sect233k1",
            Self::Sect233r1 => "sect233r1",
            Self::Sect283k1 => "sect283k1",
            Self::Sect283r1 => "sect283r1",
            Self::Sect409k1 => "sect409k1",
            Self::Sect409r1 => "sect409r1",
            Self::Sect571k1 => "sect571k1",
            Self::Sect571r1 => "sect571r1",
        };
        Some(name)
    }
}

impl TryFrom<&ObjectIdentifier> for NamedCurve {
    type Error = Error;

    fn try_from(oid: &ObjectIdentifier) -> Result<Self> {
        let oid_str = oid.to_string();
        match oid_str.as_str() {
            Self::OID_SECP192R1 => Ok(Self::Secp192r1),
            Self::OID_SECP224R1 => Ok(Self::Secp224r1),
            Self::OID_SECP256R1 => Ok(Self::Secp256r1),
            Self::OID_SECP384R1 => Ok(Self::Secp384r1),
            Self::OID_SECP521R1 => Ok(Self::Secp521r1),
            Self::OID_SECT163K1 => Ok(Self::Sect163k1),
            Self::OID_SECT163R2 => Ok(Self::Sect163r2),
            Self::OID_SECT233K1 => Ok(Self::Sect233k1),
            Self::OID_SECT233R1 => Ok(Self::Sect233r1),
            Self::OID_SECT283K1 => Ok(Self::Sect283k1),
            Self::OID_SECT283R1 => Ok(Self::Sect283r1),
            Self::OID_SECT409K1 => Ok(Self::Sect409k1),
            Self::OID_SECT409R1 => Ok(Self::Sect409r1),
            Self::OID_SECT571K1 => Ok(Self::Sect571k1),
            Self::OID_SECT571R1 => Ok(Self::Sect571r1),
            _ => Err(Error::InvalidEcParameter(format!(
                "Unknown curve OID: {}",
                oid_str
            ))),
        }
    }
}

impl TryFrom<NamedCurve> for ObjectIdentifier {
    type Error = Error;

    fn try_from(curve: NamedCurve) -> Result<Self> {
        curve.oid()
    }
}

/// ECParameters for Elliptic Curve algorithms
///
/// [RFC 5480 Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1):
/// ```asn1
/// ECParameters ::= CHOICE {
///     namedCurve    OBJECT IDENTIFIER,
///     -- implicitCurve  NULL,              -- MUST NOT be used in PKIX
///     -- specifiedCurve SpecifiedECDomain  -- MUST NOT be used in PKIX
/// }
/// ```
///
/// This implementation only supports namedCurve as required by PKIX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcParameters {
    /// Named curve
    pub named_curve: NamedCurve,
}

impl EcParameters {
    /// Create new EC parameters with a named curve.
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_pkix_types::algorithm::parameters::ec::{EcParameters, NamedCurve};
    ///
    /// let params = EcParameters::new(NamedCurve::Secp256r1);
    /// assert_eq!(params.named_curve(), NamedCurve::Secp256r1);
    /// ```
    pub fn new(named_curve: NamedCurve) -> Self {
        Self { named_curve }
    }

    /// Get the named curve.
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_pkix_types::algorithm::parameters::ec::{EcParameters, NamedCurve};
    ///
    /// let params = EcParameters::new(NamedCurve::Secp384r1);
    /// assert_eq!(params.named_curve(), NamedCurve::Secp384r1);
    /// ```
    pub fn named_curve(&self) -> NamedCurve {
        self.named_curve
    }

    /// Get the OID for the named curve.
    ///
    /// # Errors
    ///
    /// Returns an error if the OID string fails to parse (should never happen).
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use tsumiki_asn1::ObjectIdentifier;
    /// use tsumiki_pkix_types::algorithm::parameters::ec::{EcParameters, NamedCurve};
    ///
    /// let params = EcParameters::new(NamedCurve::Secp256r1);
    /// let oid = params.oid()?;
    /// assert_eq!(oid, ObjectIdentifier::from_str("1.2.840.10045.3.1.7")?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn oid(&self) -> Result<ObjectIdentifier> {
        self.named_curve.oid()
    }
}

impl OidName for EcParameters {
    fn oid_name(&self) -> Option<&'static str> {
        self.named_curve.oid_name()
    }
}

impl AlgorithmParameter for EcParameters {
    fn parse(raw: &RawAlgorithmParameter) -> Result<Self> {
        raw.try_into()
    }
}

impl TryFrom<&EcParameters> for RawAlgorithmParameter {
    type Error = Error;

    fn try_from(params: &EcParameters) -> Result<Self> {
        Ok(Self::new(Element::ObjectIdentifier(
            params.named_curve.oid()?,
        )))
    }
}

impl TryFrom<&RawAlgorithmParameter> for EcParameters {
    type Error = Error;

    fn try_from(raw: &RawAlgorithmParameter) -> Result<Self> {
        match raw.element() {
            Element::ObjectIdentifier(oid) => {
                let curve = NamedCurve::try_from(oid)?;
                Ok(Self { named_curve: curve })
            }
            _ => Err(Error::InvalidEcParameter(
                "ECParameters must be an OBJECT IDENTIFIER (namedCurve)".into(),
            )),
        }
    }
}

impl TryFrom<RawAlgorithmParameter> for EcParameters {
    type Error = Error;

    fn try_from(raw: RawAlgorithmParameter) -> Result<Self> {
        (&raw).try_into()
    }
}

impl TryFrom<&EcParameters> for AlgorithmParameters {
    type Error = Error;

    fn try_from(params: &EcParameters) -> Result<Self> {
        Ok(Self::Other(RawAlgorithmParameter::try_from(params)?))
    }
}

impl TryFrom<AlgorithmParameters> for EcParameters {
    type Error = Error;

    fn try_from(params: AlgorithmParameters) -> Result<Self> {
        match params {
            AlgorithmParameters::Null => Err(Error::NullConversion),
            AlgorithmParameters::Other(raw) => Self::try_from(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::parameters::RawAlgorithmParameter;
    use rstest::rstest;

    #[rstest]
    #[case(NamedCurve::Secp192r1)]
    #[case(NamedCurve::Secp224r1)]
    #[case(NamedCurve::Secp256r1)]
    #[case(NamedCurve::Secp384r1)]
    #[case(NamedCurve::Secp521r1)]
    #[allow(clippy::expect_used)]
    fn test_named_curve_from_oid(#[case] expected: NamedCurve) {
        let oid = expected.oid().expect("Valid OID");
        let curve = NamedCurve::try_from(&oid).expect("Valid named curve");
        assert_eq!(curve, expected);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_named_curve_unknown_oid() {
        let oid = "1.2.3.4.5".parse::<ObjectIdentifier>().expect("Valid OID");
        let result = NamedCurve::try_from(&oid);
        assert!(result.is_err());
    }

    #[rstest]
    #[case(NamedCurve::Secp192r1)]
    #[case(NamedCurve::Secp224r1)]
    #[case(NamedCurve::Secp256r1)]
    #[case(NamedCurve::Secp384r1)]
    #[case(NamedCurve::Secp521r1)]
    #[allow(clippy::expect_used)]
    fn test_ec_parameters_roundtrip(#[case] curve: NamedCurve) {
        let params = EcParameters::new(curve);
        let raw = RawAlgorithmParameter::try_from(&params).expect("Valid conversion to raw");
        let decoded: EcParameters = raw.try_into().expect("Valid conversion from raw");
        assert_eq!(params, decoded);
    }

    #[rstest]
    #[case(NamedCurve::Secp256r1)]
    #[case(NamedCurve::Secp384r1)]
    #[case(NamedCurve::Secp521r1)]
    #[allow(clippy::expect_used)]
    fn test_ec_parameters_via_raw(#[case] curve: NamedCurve) {
        let params = EcParameters::new(curve);

        let raw = RawAlgorithmParameter::try_from(&params).expect("Valid conversion to raw");
        let decoded: EcParameters = raw.try_into().expect("Valid conversion from raw");

        assert_eq!(params, decoded);
    }

    #[rstest]
    #[case(Element::Null)]
    #[case(Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])))]
    #[case(Element::OctetString(tsumiki_asn1::OctetString::from(vec![0x01, 0x02])))]
    fn test_ec_parameters_invalid_element(#[case] element: Element) {
        let raw = RawAlgorithmParameter::new(element);
        let result: Result<EcParameters> = raw.try_into();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(NamedCurve::Secp192r1)]
    #[case(NamedCurve::Secp224r1)]
    #[case(NamedCurve::Secp256r1)]
    #[case(NamedCurve::Secp384r1)]
    #[case(NamedCurve::Secp521r1)]
    #[case(NamedCurve::Sect163k1)]
    #[case(NamedCurve::Sect163r2)]
    #[case(NamedCurve::Sect233k1)]
    #[case(NamedCurve::Sect233r1)]
    #[case(NamedCurve::Sect283k1)]
    #[case(NamedCurve::Sect283r1)]
    #[case(NamedCurve::Sect409k1)]
    #[case(NamedCurve::Sect409r1)]
    #[case(NamedCurve::Sect571k1)]
    #[case(NamedCurve::Sect571r1)]
    fn test_named_curves(#[case] curve: NamedCurve) {
        let params = EcParameters::new(curve);
        let result = RawAlgorithmParameter::try_from(&params);
        assert!(result.is_ok());
    }
}
