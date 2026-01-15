//! AlgorithmIdentifier type
//!
//! Defined in RFC 5280 Section 4.1.1.2

use asn1::{Element, ObjectIdentifier};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::{Error, Result};

/// Parameters field in AlgorithmIdentifier
///
/// Wrapped in Option:
/// - None: Field not present (OPTIONAL field omitted, 0 bytes)
/// - Some(AlgorithmParameters::Null): Explicit NULL value (common for RSA)
/// - Some(AlgorithmParameters::Elm(Element)): Any other ASN.1 element
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmParameters {
    /// Explicit NULL (05 00)
    Null,
    /// Any other ASN.1 element (e.g., ObjectIdentifier for EC curves, Sequence for complex structures)
    Elm(Element),
}

impl Serialize for AlgorithmParameters {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AlgorithmParameters::Null => serializer.serialize_str("Null"),
            AlgorithmParameters::Elm(elm) => {
                let type_name = match elm {
                    Element::Boolean(_) => "Boolean",
                    Element::Integer(_) => "Integer",
                    Element::BitString(_) => "BitString",
                    Element::OctetString(_) => "OctetString",
                    Element::Null => "Null",
                    Element::ObjectIdentifier(_) => "ObjectIdentifier",
                    Element::UTF8String(_) => "UTF8String",
                    Element::Sequence(_) => "Sequence",
                    Element::Set(_) => "Set",
                    Element::PrintableString(_) => "PrintableString",
                    Element::IA5String(_) => "IA5String",
                    Element::UTCTime(_) => "UTCTime",
                    Element::GeneralizedTime(_) => "GeneralizedTime",
                    Element::BMPString(_) => "BMPString",
                    Element::ContextSpecific { .. } => "ContextSpecific",
                    Element::Unimplemented(_) => "Unimplemented",
                };
                serializer.serialize_str(type_name)
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
/// RFC 5280 Section 4.1.1.2:
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
    /// - Some(AlgorithmParameters::Elm(ObjectIdentifier)): EC (curve OID)
    /// - Some(AlgorithmParameters::Elm(Sequence)): DSA or complex structures
    pub parameters: Option<AlgorithmParameters>,
}

impl AlgorithmIdentifier {
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
}

impl Serialize for AlgorithmIdentifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AlgorithmIdentifier", 2)?;
        state.serialize_field("algorithm", &self.algorithm)?;
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
    type Error = Error;

    fn decode(&self) -> Result<AlgorithmIdentifier> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() || elements.len() > 2 {
                    return Err(Error::InvalidAlgorithmIdentifier(
                        "AlgorithmIdentifier must have 1 or 2 elements".into(),
                    ));
                }

                // First element: algorithm OID
                let algorithm = match &elements[0] {
                    Element::ObjectIdentifier(oid) => oid.clone(),
                    _ => {
                        return Err(Error::InvalidAlgorithmIdentifier(
                            "AlgorithmIdentifier algorithm must be OBJECT IDENTIFIER".into(),
                        ));
                    }
                };

                // Second element: optional parameters
                let parameters = if elements.len() == 2 {
                    Some(match &elements[1] {
                        Element::Null => AlgorithmParameters::Null,
                        other => AlgorithmParameters::Elm(other.clone()),
                    })
                } else {
                    None
                };

                Ok(AlgorithmIdentifier {
                    algorithm,
                    parameters,
                })
            }
            _ => Err(Error::InvalidAlgorithmIdentifier(
                "AlgorithmIdentifier must be a SEQUENCE".into(),
            )),
        }
    }
}

impl EncodableTo<AlgorithmIdentifier> for Element {}

impl Encoder<AlgorithmIdentifier, Element> for AlgorithmIdentifier {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let mut elements = vec![Element::ObjectIdentifier(self.algorithm.clone())];
        if let Some(params) = &self.parameters {
            elements.push(match params {
                AlgorithmParameters::Null => Element::Null,
                AlgorithmParameters::Elm(elm) => elm.clone(),
            });
        }

        Ok(Element::Sequence(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case("1.2.840.113549.1.1.1", None)] // RSA without params
    #[case("1.2.840.10045.2.1", None)] // EC without params
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

    #[test]
    fn test_algorithm_identifier_with_null_params() {
        let oid = ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
        let alg_id = AlgorithmIdentifier::new_with_params(oid.clone(), AlgorithmParameters::Null);

        assert_eq!(alg_id.algorithm(), &oid);
        assert!(matches!(
            alg_id.parameters(),
            Some(AlgorithmParameters::Null)
        ));
    }

    #[test]
    fn test_algorithm_identifier_decode_without_params() {
        let oid = ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap();
        let elem = Element::Sequence(vec![Element::ObjectIdentifier(oid.clone())]);

        let alg_id: AlgorithmIdentifier = elem.decode().unwrap();
        assert_eq!(alg_id.algorithm(), &oid);
        assert!(alg_id.parameters().is_none());
    }

    #[test]
    fn test_algorithm_identifier_decode_with_null() {
        let oid = ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
        let elem = Element::Sequence(vec![Element::ObjectIdentifier(oid.clone()), Element::Null]);

        let alg_id: AlgorithmIdentifier = elem.decode().unwrap();
        assert_eq!(alg_id.algorithm(), &oid);
        assert!(matches!(
            alg_id.parameters(),
            Some(AlgorithmParameters::Null)
        ));
    }

    #[test]
    fn test_algorithm_identifier_decode_with_oid_params() {
        let oid = ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap();
        let curve_oid = ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap(); // secp256r1
        let elem = Element::Sequence(vec![
            Element::ObjectIdentifier(oid.clone()),
            Element::ObjectIdentifier(curve_oid.clone()),
        ]);

        let alg_id: AlgorithmIdentifier = elem.decode().unwrap();
        assert_eq!(alg_id.algorithm(), &oid);
        if let Some(AlgorithmParameters::Elm(Element::ObjectIdentifier(param_oid))) =
            alg_id.parameters()
        {
            assert_eq!(param_oid, &curve_oid);
        } else {
            panic!("Expected ObjectIdentifier parameter");
        }
    }

    #[test]
    fn test_algorithm_identifier_encode_decode_roundtrip() {
        let oid = ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
        let alg_id = AlgorithmIdentifier::new_with_params(oid, AlgorithmParameters::Null);

        let encoded = alg_id.encode().unwrap();
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();

        assert_eq!(alg_id, decoded);
    }

    #[rstest]
    #[case("1.2.840.113549.1.1.1", Some(AlgorithmParameters::Null))] // RSA with NULL
    #[case("1.2.840.10045.4.3.2", None)] // ECDSA without params
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
