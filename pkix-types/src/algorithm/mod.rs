//! AlgorithmIdentifier type
//!
//! Defined in [RFC 5280 Section 4.1.1.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2)

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, ObjectIdentifier};

use crate::OidName;
use crate::algorithm::parameters::ec::NamedCurve;

pub mod error;
pub mod parameters;

pub use error::{Error, Result};
pub use parameters::{AlgorithmParameter, RawAlgorithmParameter};

/// Parameters field in AlgorithmIdentifier
///
/// Wrapped in Option:
/// - None: Field not present (OPTIONAL field omitted, 0 bytes)
/// - Some(AlgorithmParameters::Null): Explicit NULL value (common for RSA)
/// - Some(AlgorithmParameters::Other(RawAlgorithmParameter)): Any other ASN.1 element
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmParameters {
    /// Explicit NULL (05 00)
    Null,
    /// Any other ASN.1 element wrapped in RawAlgorithmParameter
    Other(RawAlgorithmParameter),
}

impl Serialize for AlgorithmParameters {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AlgorithmParameters::Null => serializer.serialize_str("Null"),
            AlgorithmParameters::Other(raw) => {
                match raw.element() {
                    Element::ObjectIdentifier(oid) => {
                        let use_oid = crate::get_use_oid_values();
                        let display_value = if use_oid {
                            oid.to_string()
                        } else if let Ok(curve) = NamedCurve::try_from(oid) {
                            curve.oid_name().unwrap_or(&oid.to_string()).to_string()
                        } else {
                            oid.to_string()
                        };
                        serializer.serialize_str(&display_value)
                    }
                    Element::Sequence(elements) => {
                        // For Sequence parameters (e.g., DSA), show structure info
                        let mut state = serializer.serialize_struct("Sequence", 1)?;
                        state.serialize_field("element_count", &elements.len())?;
                        state.end()
                    }
                    Element::OctetString(os) => {
                        // For OctetString parameters, show length
                        let mut state = serializer.serialize_struct("OctetString", 1)?;
                        state.serialize_field("length", &os.as_bytes().len())?;
                        state.end()
                    }
                    Element::Integer(n) => {
                        // For Integer parameters, show the value
                        let mut state = serializer.serialize_struct("Integer", 1)?;
                        state.serialize_field("value", &n.to_string())?;
                        state.end()
                    }
                    _ => {
                        // For other types, just show the type name
                        let type_name = match raw.element() {
                            Element::Boolean(_) => "Boolean",
                            Element::BitString(_) => "BitString",
                            Element::Null => "Null",
                            Element::UTF8String(_) => "UTF8String",
                            Element::Set(_) => "Set",
                            Element::PrintableString(_) => "PrintableString",
                            Element::IA5String(_) => "IA5String",
                            Element::UTCTime(_) => "UTCTime",
                            Element::GeneralizedTime(_) => "GeneralizedTime",
                            Element::BMPString(_) => "BMPString",
                            Element::ContextSpecific { .. } => "ContextSpecific",
                            Element::Unimplemented(_) => "Unimplemented",
                            _ => "Unknown",
                        };
                        serializer.serialize_str(type_name)
                    }
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for AlgorithmParameters {
    fn deserialize<D>(_deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "AlgorithmParameters deserialization not supported",
        ))
    }
}

/// Algorithm Identifier
///
/// [RFC 5280 Section 4.1.1.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2):
/// ```asn1
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm   OBJECT IDENTIFIER,
///     parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
///
/// Used throughout X.509 (certificates), PKCS#8 (private keys),
/// PKCS#10 (CSRs), and other cryptographic structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID
    pub algorithm: ObjectIdentifier,
    /// Optional parameters
    /// - None: Field not present (parameter field omitted, e.g., EdDSA)
    /// - Some(AlgorithmParameters::Null): RSA (NULL parameters)
    /// - Some(AlgorithmParameters::Other(...)): EC (curve OID), DSA, or complex structures
    pub parameters: Option<AlgorithmParameters>,
}

impl AlgorithmIdentifier {
    // Common algorithm OID constants (RFC 3279, RFC 5754, etc.)
    pub const OID_EC_PUBLIC_KEY: &'static str = "1.2.840.10045.2.1";
    pub const OID_ID_DSA: &'static str = "1.2.840.10040.4.1";
    pub const OID_RSA_ENCRYPTION: &'static str = "1.2.840.113549.1.1.1";
    pub const OID_SHA1_WITH_RSA_ENCRYPTION: &'static str = "1.2.840.113549.1.1.5";
    pub const OID_SHA256_WITH_RSA_ENCRYPTION: &'static str = "1.2.840.113549.1.1.11";
    pub const OID_SHA384_WITH_RSA_ENCRYPTION: &'static str = "1.2.840.113549.1.1.12";
    pub const OID_SHA512_WITH_RSA_ENCRYPTION: &'static str = "1.2.840.113549.1.1.13";
    pub const OID_ECDSA_WITH_SHA256: &'static str = "1.2.840.10045.4.3.2";
    pub const OID_ECDSA_WITH_SHA384: &'static str = "1.2.840.10045.4.3.3";
    pub const OID_ECDSA_WITH_SHA512: &'static str = "1.2.840.10045.4.3.4";

    // PKCS#5 Password-Based Encryption Scheme (PBES) OIDs
    // See RFC 2898 and RFC 8018 for details
    pub const OID_PBES1: &'static str = "1.2.840.113549.1.5.1"; // pbeWithMD2AndDES-CBC
    pub const OID_PBES2: &'static str = "1.2.840.113549.1.5.13"; // id-PBES2
    pub const OID_PBES1_MD5_DES: &'static str = "1.2.840.113549.1.5.3"; // pbeWithMD5AndDES-CBC
    pub const OID_PBES1_MD2_RC2: &'static str = "1.2.840.113549.1.5.4"; // pbeWithMD2AndRC2-CBC
    pub const OID_PBES1_MD5_RC2: &'static str = "1.2.840.113549.1.5.6"; // pbeWithMD5AndRC2-CBC
    pub const OID_PBES1_SHA1_DES: &'static str = "1.2.840.113549.1.5.10"; // pbeWithSHA1AndDES-CBC

    // PKCS#12 PBE OIDs (RFC 7292)
    pub const OID_PKCS12_PBE_SHA1_RC4_128: &'static str = "1.2.840.113549.1.12.1.1"; // pbeWithSHA1And128BitRC4
    pub const OID_PKCS12_PBE_SHA1_RC4_40: &'static str = "1.2.840.113549.1.12.1.2"; // pbeWithSHA1And40BitRC4
    pub const OID_PKCS12_PBE_SHA1_3DES: &'static str = "1.2.840.113549.1.12.1.3"; // pbeWithSHA1And3KeyTripleDES-CBC
    pub const OID_PKCS12_PBE_SHA1_2DES: &'static str = "1.2.840.113549.1.12.1.4"; // pbeWithSHA1And2KeyTripleDES-CBC
    pub const OID_PKCS12_PBE_SHA1_RC2_128: &'static str = "1.2.840.113549.1.12.1.5"; // pbeWithSHA1And128BitRC2-CBC
    pub const OID_PKCS12_PBE_SHA1_RC2_40: &'static str = "1.2.840.113549.1.12.1.6"; // pbeWithSHA1And40BitRC2-CBC

    /// Create a new AlgorithmIdentifier with algorithm OID only
    pub fn new(algorithm: ObjectIdentifier) -> Self {
        Self {
            algorithm,
            parameters: None,
        }
    }

    /// Create a new AlgorithmIdentifier with parameters
    pub fn new_with_params(algorithm: ObjectIdentifier, parameters: AlgorithmParameters) -> Self {
        Self {
            algorithm,
            parameters: Some(parameters),
        }
    }

    /// Get the algorithm OID
    pub fn algorithm(&self) -> &ObjectIdentifier {
        &self.algorithm
    }

    /// Get the parameters
    pub fn parameters(&self) -> &Option<AlgorithmParameters> {
        &self.parameters
    }

    /// Get typed parameters
    pub fn parameter<P: AlgorithmParameter>(&self) -> crate::error::Result<Option<P>> {
        match &self.parameters {
            None => Ok(None),
            Some(AlgorithmParameters::Null) => Err(Error::NullParameterNotSupported.into()),
            Some(AlgorithmParameters::Other(raw)) => {
                Ok(Some(P::parse(raw).map_err(Error::ParameterError)?))
            }
        }
    }
}

impl OidName for AlgorithmIdentifier {
    fn oid_name(&self) -> Option<&'static str> {
        let oid = &self.algorithm;
        match oid.to_string().as_str() {
            AlgorithmIdentifier::OID_EC_PUBLIC_KEY => Some("ecPublicKey"),
            AlgorithmIdentifier::OID_ID_DSA => Some("id-dsa"),
            AlgorithmIdentifier::OID_RSA_ENCRYPTION => Some("rsaEncryption"),
            AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION => Some("sha1WithRSAEncryption"),
            AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION => Some("sha256WithRSAEncryption"),
            AlgorithmIdentifier::OID_SHA384_WITH_RSA_ENCRYPTION => Some("sha384WithRSAEncryption"),
            AlgorithmIdentifier::OID_SHA512_WITH_RSA_ENCRYPTION => Some("sha512WithRSAEncryption"),
            AlgorithmIdentifier::OID_ECDSA_WITH_SHA256 => Some("ecdsa-with-SHA256"),
            AlgorithmIdentifier::OID_ECDSA_WITH_SHA384 => Some("ecdsa-with-SHA384"),
            AlgorithmIdentifier::OID_ECDSA_WITH_SHA512 => Some("ecdsa-with-SHA512"),
            AlgorithmIdentifier::OID_PBES1 => Some("pbeWithMD2AndDES-CBC"),
            AlgorithmIdentifier::OID_PBES2 => Some("id-PBES2"),
            AlgorithmIdentifier::OID_PBES1_MD5_DES => Some("pbeWithMD5AndDES-CBC"),
            AlgorithmIdentifier::OID_PBES1_MD2_RC2 => Some("pbeWithMD2AndRC2-CBC"),
            AlgorithmIdentifier::OID_PBES1_MD5_RC2 => Some("pbeWithMD5AndRC2-CBC"),
            AlgorithmIdentifier::OID_PBES1_SHA1_DES => Some("pbeWithSHA1AndDES-CBC"),
            AlgorithmIdentifier::OID_PKCS12_PBE_SHA1_RC4_128 => Some("pbeWithSHA1And128BitRC4"),
            AlgorithmIdentifier::OID_PKCS12_PBE_SHA1_RC4_40 => Some("pbeWithSHA1And40BitRC4"),
            AlgorithmIdentifier::OID_PKCS12_PBE_SHA1_3DES => {
                Some("pbeWithSHA1And3KeyTripleDES-CBC")
            }
            AlgorithmIdentifier::OID_PKCS12_PBE_SHA1_2DES => {
                Some("pbeWithSHA1And2KeyTripleDES-CBC")
            }
            AlgorithmIdentifier::OID_PKCS12_PBE_SHA1_RC2_128 => Some("pbeWithSHA1And128BitRC2-CBC"),
            AlgorithmIdentifier::OID_PKCS12_PBE_SHA1_RC2_40 => Some("pbeWithSHA1And40BitRC2-CBC"),
            _ => None,
        }
    }
}

impl Serialize for AlgorithmIdentifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AlgorithmIdentifier", 2)?;

        // Check if we should use OID values
        let use_oid = crate::get_use_oid_values();

        if use_oid {
            // Use OID value directly
            state.serialize_field("algorithm", &self.algorithm)?;
        } else {
            // Use human-readable name if available, otherwise use OID
            let oid_string = self.algorithm.to_string();
            let algorithm_display = self.oid_name().unwrap_or(&oid_string);
            state.serialize_field("algorithm", &algorithm_display)?;
        }

        // Serialize parameters
        if let Some(ref params) = self.parameters {
            state.serialize_field("parameters", params)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for AlgorithmIdentifier {
    fn deserialize<D>(_deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "AlgorithmIdentifier deserialization not supported",
        ))
    }
}

impl DecodableFrom<Element> for AlgorithmIdentifier {}

impl Decoder<Element, AlgorithmIdentifier> for Element {
    type Error = crate::error::Error;

    fn decode(&self) -> crate::error::Result<AlgorithmIdentifier> {
        match self {
            Element::Sequence(elements) => {
                let algorithm = match elements.first() {
                    Some(Element::ObjectIdentifier(oid)) => oid.clone(),
                    Some(_) => {
                        return Err(Error::ExpectedOidForAlgorithm.into());
                    }
                    None => {
                        return Err(Error::EmptyAlgorithmIdentifier.into());
                    }
                };

                let parameters = match elements.get(1) {
                    Some(Element::Null) => Some(AlgorithmParameters::Null),
                    Some(other) => Some(AlgorithmParameters::Other(RawAlgorithmParameter::new(
                        other.clone(),
                    ))),
                    None => None,
                };

                if elements.len() > 2 {
                    return Err(Error::TooManyElements.into());
                }

                Ok(AlgorithmIdentifier {
                    algorithm,
                    parameters,
                })
            }
            _ => Err(Error::ExpectedSequence.into()),
        }
    }
}

impl EncodableTo<AlgorithmIdentifier> for Element {}

impl Encoder<AlgorithmIdentifier, Element> for AlgorithmIdentifier {
    type Error = crate::error::Error;

    fn encode(&self) -> crate::error::Result<Element> {
        let params_elem = self.parameters.as_ref().map(|params| match params {
            AlgorithmParameters::Null => Element::Null,
            AlgorithmParameters::Other(raw) => raw.element().clone(),
        });

        let elements: Vec<_> = std::iter::once(Element::ObjectIdentifier(self.algorithm.clone()))
            .chain(params_elem)
            .collect();

        Ok(Element::Sequence(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case::rsa_without_params("1.2.840.113549.1.1.1", None)]
    #[case::ec_without_params("1.2.840.10045.2.1", None)]
    fn test_algorithm_identifier_new(
        #[case] oid_str: &str,
        #[case] params: Option<AlgorithmParameters>,
    ) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let alg_id = if let Some(p) = params {
            AlgorithmIdentifier::new_with_params(oid.clone(), p)
        } else {
            AlgorithmIdentifier::new(oid.clone())
        };

        assert_eq!(alg_id.algorithm(), &oid);
    }

    #[rstest]
    #[case::rsa_with_null("1.2.840.113549.1.1.1")]
    fn test_algorithm_identifier_with_null_params(#[case] oid_str: &str) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let alg_id = AlgorithmIdentifier::new_with_params(oid.clone(), AlgorithmParameters::Null);

        assert_eq!(alg_id.algorithm(), &oid);
        assert!(matches!(
            alg_id.parameters(),
            Some(AlgorithmParameters::Null)
        ));
    }

    #[rstest]
    #[case::ecdsa_sha256("1.2.840.10045.4.3.2")]
    #[case::ecdsa_sha384("1.2.840.10045.4.3.3")]
    fn test_algorithm_identifier_decode_without_params(#[case] oid_str: &str) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let elem = Element::Sequence(vec![Element::ObjectIdentifier(oid.clone())]);

        let alg_id: AlgorithmIdentifier = elem.decode().unwrap();
        assert_eq!(alg_id.algorithm(), &oid);
        assert!(alg_id.parameters().is_none());
    }

    #[rstest]
    #[case::rsa_encryption("1.2.840.113549.1.1.1")]
    #[case::sha256_with_rsa("1.2.840.113549.1.1.11")]
    fn test_algorithm_identifier_decode_with_null(#[case] oid_str: &str) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let elem = Element::Sequence(vec![Element::ObjectIdentifier(oid.clone()), Element::Null]);

        let alg_id: AlgorithmIdentifier = elem.decode().unwrap();
        assert_eq!(alg_id.algorithm(), &oid);
        assert!(matches!(
            alg_id.parameters(),
            Some(AlgorithmParameters::Null)
        ));
    }

    #[rstest]
    #[case::ec_secp256r1("1.2.840.10045.2.1", "1.2.840.10045.3.1.7")]
    #[case::ec_secp384r1("1.2.840.10045.2.1", "1.3.132.0.34")]
    fn test_algorithm_identifier_decode_with_oid_params(
        #[case] oid_str: &str,
        #[case] curve_oid_str: &str,
    ) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let curve_oid = ObjectIdentifier::from_str(curve_oid_str).unwrap();
        let elem = Element::Sequence(vec![
            Element::ObjectIdentifier(oid.clone()),
            Element::ObjectIdentifier(curve_oid.clone()),
        ]);

        let alg_id: AlgorithmIdentifier = elem.decode().unwrap();
        assert_eq!(alg_id.algorithm(), &oid);
        if let Some(AlgorithmParameters::Other(raw)) = alg_id.parameters() {
            if let Element::ObjectIdentifier(param_oid) = raw.element() {
                assert_eq!(param_oid, &curve_oid);
            } else {
                panic!("Expected ObjectIdentifier parameter");
            }
        } else {
            panic!("Expected Other parameter");
        }
    }

    #[rstest]
    #[case::rsa_with_null("1.2.840.113549.1.1.1", AlgorithmParameters::Null)]
    fn test_algorithm_identifier_encode_decode_roundtrip(
        #[case] oid_str: &str,
        #[case] params: AlgorithmParameters,
    ) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let alg_id = AlgorithmIdentifier::new_with_params(oid, params);

        let encoded = alg_id.encode().unwrap();
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();

        assert_eq!(alg_id, decoded);
    }

    #[rstest]
    #[case::rsa_with_null("1.2.840.113549.1.1.1", Some(AlgorithmParameters::Null))]
    #[case::ecdsa_without_params("1.2.840.10045.4.3.2", None)]
    #[case::sha256_with_rsa("1.2.840.113549.1.1.11", Some(AlgorithmParameters::Null))]
    fn test_algorithm_identifier_roundtrip(
        #[case] oid_str: &str,
        #[case] params: Option<AlgorithmParameters>,
    ) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let alg_id = if let Some(p) = params {
            AlgorithmIdentifier::new_with_params(oid, p)
        } else {
            AlgorithmIdentifier::new(oid)
        };

        let encoded = alg_id.encode().unwrap();
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();

        assert_eq!(alg_id, decoded);
    }
}
