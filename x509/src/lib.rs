use asn1::{ASN1Object, BitString, Element, Integer, ObjectIdentifier};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;

pub(crate) mod error;

/*
https://datatracker.ietf.org/doc/html/rfc5280#section-4.1

Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}
 */

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Certificate {
    tbs_certificate: TBSCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString, // BIT STRING
}

impl DecodableFrom<ASN1Object> for Certificate {}

impl Decoder<ASN1Object, Certificate> for Certificate {
    type Error = Error;

    fn decode(&self) -> Result<Certificate, Self::Error> {
        unimplemented!()
    }
}

/*
TBSCertificate  ::=  SEQUENCE  {
     version         [0]  EXPLICIT Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                              -- If present, version MUST be v2 or v3
     extensions      [3]  EXPLICIT Extensions OPTIONAL
                              -- If present, version MUST be v3
}
 */

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TBSCertificate {
    version: Version,
    serial_number: CertificateSerialNumber,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    // subject_public_key_info: SubjectPublicKeyInfo,
    // issuer_unique_id: Option<UniqueIdentifier>,
    // subject_unique_id: Option<UniqueIdentifier>,
    // extensions: Option<Extensions>,
}

impl DecodableFrom<ASN1Object> for TBSCertificate {}

impl Decoder<ASN1Object, TBSCertificate> for TBSCertificate {
    type Error = Error;

    fn decode(&self) -> Result<TBSCertificate, Self::Error> {
        unimplemented!()
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
/*
AlgorithmIdentifier  ::=  SEQUENCE  {
    algorithm               OBJECT IDENTIFIER,
    parameters              ANY DEFINED BY algorithm OPTIONAL
}
 */

/// Parameters field in AlgorithmIdentifier
///
/// Wrapped in Option:
/// - None: Field not present (OPTIONAL field omitted, 0 bytes) - Absent
/// - Some(Data(Element::Null)): Explicit NULL value - Common for RSA
/// - Some(Data(Element::ObjectIdentifier)): OID - Used for ECDSA curve parameters
/// - Some(Data(Element::Sequence)): Complex SEQUENCE structure - Used for DSA, RSASSA-PSS
/// - Some(Data(Element::OctetString)): Arbitrary octet string data
/// - Some(Elm(other)): Any other ASN.1 element
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AlgorithmParameters {
    Null,         // Explicit NULL (05 00)
    Elm(Element), // Any other ASN.1 element
}

impl Serialize for AlgorithmParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AlgorithmParameters::Null => serializer.serialize_str("NULL"),
            AlgorithmParameters::Elm(elm) => {
                // TODO: Serialize based on the actual element type
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
                    Element::ContextSpecific { .. } => "ContextSpecific",
                    Element::Unimplemented(_) => "Unimplemented",
                };
                serializer.serialize_str(type_name)
            }
        }
    }
}

impl<'de> Deserialize<'de> for AlgorithmParameters {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "AlgorithmParameters deserialization not supported",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier, // OBJECT IDENTIFIER
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<AlgorithmParameters>,
}

impl DecodableFrom<Element> for AlgorithmIdentifier {}

impl Decoder<Element, AlgorithmIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AlgorithmIdentifier, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() || elements.len() > 2 {
                    return Err(Error::InvalidAlgorithmIdentifier(
                        "expected 1 or 2 elements in sequence".to_string(),
                    ));
                }

                let algorithm = if let Element::ObjectIdentifier(oid) = &elements[0] {
                    oid.clone()
                } else {
                    return Err(Error::InvalidAlgorithmIdentifier(
                        "expected ObjectIdentifier for algorithm".to_string(),
                    ));
                };

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
                "expected Sequence for AlgorithmIdentifier".to_string(),
            )),
        }
    }
}

/*
Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER


Time ::= CHOICE {
    utcTime        UTCTime,
    generalTime    GeneralizedTime
}

UniqueIdentifier  ::=  BIT STRING

SubjectPublicKeyInfo  ::=  SEQUENCE  {
    algorithm            AlgorithmIdentifier,
    subjectPublicKey     BIT STRING
}

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::=  SEQUENCE  {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
                -- contains the DER encoding of an ASN.1 value
                -- corresponding to the extension type identified
                -- by extnID
}
*/

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

impl DecodableFrom<Element> for Version {}

impl Decoder<Element, Version> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Version, Self::Error> {
        match self {
            Element::Integer(i) => {
                let value_str = i.to_string();
                let value = value_str
                    .parse::<u8>()
                    .map_err(|_| Error::InvalidVersion("version must be 0, 1, or 2".to_string()))?;
                match value {
                    0 => Ok(Version::V1),
                    1 => Ok(Version::V2),
                    2 => Ok(Version::V3),
                    v => Err(Error::InvalidVersion(format!(
                        "unknown version value: {}",
                        v
                    ))),
                }
            }
            _ => Err(Error::InvalidVersion(
                "expected Integer for Version".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct CertificateSerialNumber {
    inner: Integer,
}

impl DecodableFrom<Element> for CertificateSerialNumber {}

impl Decoder<Element, CertificateSerialNumber> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificateSerialNumber, Self::Error> {
        match self {
            Element::Integer(i) => Ok(CertificateSerialNumber { inner: i.clone() }),
            _ => Err(Error::InvalidCertificateSerialNumber(
                "expected Integer for CertificateSerialNumber".to_string(),
            )),
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Name {
    rdn_sequence: Vec<RelativeDistinguishedName>,
}

impl DecodableFrom<Element> for Name {}

impl Decoder<Element, Name> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Name, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let rdn_sequence = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<RelativeDistinguishedName>, _>>()?;
                Ok(Name { rdn_sequence })
            }
            _ => Err(Error::InvalidName("expected Sequence for Name".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelativeDistinguishedName {
    attribute: Vec<AttributeTypeAndValue>,
}

impl DecodableFrom<Element> for RelativeDistinguishedName {}

impl Decoder<Element, RelativeDistinguishedName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RelativeDistinguishedName, Self::Error> {
        match self {
            Element::Set(elements) => {
                let attribute = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<AttributeTypeAndValue>, _>>()?;
                Ok(RelativeDistinguishedName { attribute })
            }
            _ => Err(Error::InvalidRelativeDistinguishedName(
                "expected Set for RelativeDistinguishedName".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttributeTypeAndValue {
    attribute_type: ObjectIdentifier, // OBJECT IDENTIFIER
    attribute_value: String,          // ANY DEFINED BY type_
}

impl DecodableFrom<Element> for AttributeTypeAndValue {}

impl Decoder<Element, AttributeTypeAndValue> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AttributeTypeAndValue, Self::Error> {
        if let Element::Sequence(seq) = self {
            if seq.len() != 2 {
                return Err(Error::InvalidAttributeTypeAndValue(
                    "expected 2 elements in sequence".to_string(),
                ));
            }
            let attribute_type = if let Element::ObjectIdentifier(oid) = &seq[0] {
                oid.clone()
            } else {
                return Err(Error::InvalidAttributeType(
                    "expected ObjectIdentifier".to_string(),
                ));
            };

            // attribute_value can be various types depending on the attribute_type
            // Most X.509 attributes are strings (DirectoryString)
            let attribute_value = match &seq[1] {
                Element::UTF8String(s) => s.clone(),
                Element::PrintableString(s) => s.clone(),
                Element::IA5String(s) => s.clone(),
                Element::OctetString(data) => {
                    // Convert to UTF-8 string, return error if not valid UTF-8
                    String::from_utf8(data.as_bytes().to_vec()).map_err(|e| {
                        Error::InvalidAttributeValue(format!(
                            "OctetString is not valid UTF-8: {}",
                            e
                        ))
                    })?
                }
                Element::Integer(int) => int.to_string(),
                _ => {
                    return Err(Error::InvalidAttributeValue(format!(
                        "unsupported attribute value type: {:?}",
                        seq[1]
                    )));
                }
            };

            Ok(AttributeTypeAndValue {
                attribute_type,
                attribute_value,
            })
        } else {
            Err(Error::InvalidAttributeTypeAndValue(
                "expected sequence".to_string(),
            ))
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#sectioで-4.1.2.5
/*
Validity ::= SEQUENCE {
    notBefore      Time,
    notAfter       Time
}
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Validity {
    not_before: NaiveDateTime,
    not_after: NaiveDateTime,
}

impl DecodableFrom<Element> for Validity {}

impl Decoder<Element, Validity> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Validity, Self::Error> {
        if let Element::Sequence(elements) = self {
            if elements.len() != 2 {
                return Err(Error::InvalidValidity(
                    "expected 2 elements in sequence".to_string(),
                ));
            }
            let not_before = match &elements[0] {
                Element::UTCTime(dt) => *dt,
                Element::GeneralizedTime(dt) => *dt,
                _ => return Err(Error::InvalidValidity("invalid notBefore time".to_string())),
            };
            let not_after = match &elements[1] {
                Element::UTCTime(dt) => *dt,
                Element::GeneralizedTime(dt) => *dt,
                _ => return Err(Error::InvalidValidity("invalid notAfter time".to_string())),
            };
            Ok(Validity {
                not_before,
                not_after,
            })
        } else {
            Err(Error::InvalidValidity(
                "expected sequence for Validity".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;
    use rstest::rstest;
    use std::str::FromStr;

    // AlgorithmIdentifier tests
    #[rstest(
        input,
        expected,
        // Test case: Algorithm without parameters (None = Absent)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()), // sha256WithRSAEncryption
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap(),
                parameters: None,
            }
        ),
        // Test case: Algorithm with NULL parameters
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()),
                Element::Null,
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap(),
                parameters: Some(AlgorithmParameters::Null),
            }
        ),
        // Test case: Algorithm with OctetString parameters
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap()), // ecdsa-with-SHA256
                Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03])),
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap(),
                parameters: Some(AlgorithmParameters::Elm(
                    Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03]))
                )),
            }
        ),
        // Test case: Algorithm with OID parameters - ECDSA curve
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap()), // ecPublicKey
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap()), // secp256r1 (prime256v1)
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap(),
                parameters: Some(AlgorithmParameters::Elm(
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap())
                )),
            }
        )
    )]
    fn test_algorithm_identifier_decode_success(input: Element, expected: AlgorithmIdentifier) {
        let result: AlgorithmIdentifier = input.decode().unwrap();
        assert_eq!(result, expected);
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "InvalidAlgorithmIdentifier"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "InvalidAlgorithmIdentifier"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()),
                Element::Null,
                Element::Integer(Integer::from(vec![0x01])),
            ]),
            "InvalidAlgorithmIdentifier"
        ),
        // Test case: First element is not ObjectIdentifier
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
            ]),
            "InvalidAlgorithmIdentifier"
        )
    )]
    fn test_algorithm_identifier_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<AlgorithmIdentifier, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // Version tests
    #[rstest]
    #[case::v1(Element::Integer(Integer::from(vec![0x00])), Version::V1)]
    #[case::v2(Element::Integer(Integer::from(vec![0x01])), Version::V2)]
    #[case::v3(Element::Integer(Integer::from(vec![0x02])), Version::V3)]
    fn test_version_decode_success(#[case] input: Element, #[case] expected: Version) {
        let result: Result<Version, Error> = input.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case::null(Element::Null, "InvalidVersion")]
    #[case::invalid_version_value(Element::Integer(Integer::from(vec![0x03])), "InvalidVersion")]
    #[case::octet_string(Element::OctetString(asn1::OctetString::from(vec![0x00])), "InvalidVersion")]
    #[case::utf8_string(Element::UTF8String("v1".to_string()), "InvalidVersion")]
    fn test_version_decode_failure(#[case] input: Element, #[case] expected_error_variant: &str) {
        let result: Result<Version, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // CertificateSerialNumber tests
    #[rstest]
    #[case::simple_serial(
        Element::Integer(Integer::from(vec![0x01])),
        CertificateSerialNumber { inner: Integer::from(vec![0x01]) }
    )]
    #[case::medium_serial(
        Element::Integer(Integer::from(vec![0x01, 0x02, 0x03, 0x04])),
        CertificateSerialNumber { inner: Integer::from(vec![0x01, 0x02, 0x03, 0x04]) }
    )]
    #[case::long_serial(
        Element::Integer(Integer::from(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
            0x74, 0x7b, 0xb0, 0x50, 0xc9, 0x16, 0xea, 0xae,
            0x99, 0xd6, 0x8f, 0x82
        ])),
        CertificateSerialNumber { inner: Integer::from(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
            0x74, 0x7b, 0xb0, 0x50, 0xc9, 0x16, 0xea, 0xae,
            0x99, 0xd6, 0x8f, 0x82
        ]) }
    )]
    fn test_certificate_serial_number_decode_success(
        #[case] input: Element,
        #[case] expected: CertificateSerialNumber,
    ) {
        let result: Result<CertificateSerialNumber, Error> = input.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case::null(Element::Null, "InvalidCertificateSerialNumber")]
    #[case::octet_string(Element::OctetString(asn1::OctetString::from(vec![0x01])), "InvalidCertificateSerialNumber")]
    #[case::object_identifier(Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()), "InvalidCertificateSerialNumber")]
    #[case::utf8_string(Element::UTF8String("test".to_string()), "InvalidCertificateSerialNumber")]
    fn test_certificate_serial_number_decode_failure(
        #[case] input: Element,
        #[case] expected_error_variant: &str,
    ) {
        let result: Result<CertificateSerialNumber, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // Validity tests
    #[rstest(
        not_before_element,
        not_after_element,
        expected_not_before,
        expected_not_after,
        // Test case: Both UTCTime
        case(
            Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
            Element::UTCTime(NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
            NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap(),
            NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()
        ),
        // Test case: Both GeneralizedTime
        case(
            Element::GeneralizedTime(NaiveDateTime::parse_from_str("2025-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()),
            Element::GeneralizedTime(NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()),
            NaiveDateTime::parse_from_str("2025-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
            NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()
        ),
        // Test case: Mixed UTCTime and GeneralizedTime
        case(
            Element::UTCTime(NaiveDateTime::parse_from_str("2020-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap()),
            Element::GeneralizedTime(NaiveDateTime::parse_from_str("2030-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap()),
            NaiveDateTime::parse_from_str("2020-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap(),
            NaiveDateTime::parse_from_str("2030-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap()
        )
    )]
    fn test_validity_decode_success(
        not_before_element: Element,
        not_after_element: Element,
        expected_not_before: NaiveDateTime,
        expected_not_after: NaiveDateTime,
    ) {
        let sequence = Element::Sequence(vec![not_before_element, not_after_element]);
        let validity: Validity = sequence.decode().unwrap();

        assert_eq!(validity.not_before, expected_not_before);
        assert_eq!(validity.not_after, expected_not_after);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "expected 2 elements in sequence"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap())
            ]),
            "expected 2 elements in sequence"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
                Element::UTCTime(NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
                Element::UTCTime(NaiveDateTime::parse_from_str("2025-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap())
            ]),
            "expected 2 elements in sequence"
        ),
        // Test case: Not a sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "expected sequence for Validity"
        ),
        // Test case: Invalid notBefore (not a time element)
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
                Element::UTCTime(NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap())
            ]),
            "invalid notBefore time"
        ),
        // Test case: Invalid notAfter (not a time element)
        case(
            Element::Sequence(vec![
                Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
                Element::Integer(Integer::from(vec![0x01]))
            ]),
            "invalid notAfter time"
        )
    )]
    fn test_validity_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Validity, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        #[allow(irrefutable_let_patterns)]
        if let Error::InvalidValidity(msg) = err {
            assert!(
                msg.contains(expected_error_msg),
                "Expected error message to contain '{}', but got '{}'",
                expected_error_msg,
                msg
            );
        } else {
            panic!("Expected InvalidValidity error, but got {:?}", err);
        }
    }

    #[test]
    fn test_validity_roundtrip_serialization() {
        let validity = Validity {
            not_before: NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            not_after: NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
        };

        let json = serde_json::to_string(&validity).unwrap();
        let deserialized: Validity = serde_json::from_str(&json).unwrap();

        assert_eq!(validity, deserialized);
    }

    // AttributeTypeAndValue tests
    #[rstest(
        attribute_type_oid,
        attribute_value_element,
        expected_value_str,
        // Test case: UTF8String value
        case(
            ObjectIdentifier::from_str("2.5.4.3").unwrap(), // CN (Common Name)
            Element::UTF8String("example.com".to_string()),
            "example.com"
        ),
        // Test case: PrintableString value
        case(
            ObjectIdentifier::from_str("2.5.4.6").unwrap(), // C (Country)
            Element::PrintableString("US".to_string()),
            "US"
        ),
        // Test case: IA5String value
        case(
            ObjectIdentifier::from_str("1.2.840.113549.1.9.1").unwrap(), // emailAddress
            Element::IA5String("user@example.com".to_string()),
            "user@example.com"
        )
    )]
    fn test_attribute_type_and_value_decode_success(
        attribute_type_oid: ObjectIdentifier,
        attribute_value_element: Element,
        expected_value_str: &str,
    ) {
        let sequence = Element::Sequence(vec![
            Element::ObjectIdentifier(attribute_type_oid.clone()),
            attribute_value_element,
        ]);

        let attr: AttributeTypeAndValue = sequence.decode().unwrap();

        assert_eq!(attr.attribute_type, attribute_type_oid);
        assert_eq!(attr.attribute_value, expected_value_str);
    }

    #[rstest(
        input,
        expected_error_type,
        // Test case: Not a sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap())
            ]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Invalid attribute type (not an OID)
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
                Element::UTF8String("value".to_string())
            ]),
            "InvalidAttributeType"
        )
    )]
    fn test_attribute_type_and_value_decode_failure(input: Element, expected_error_type: &str) {
        let result: Result<AttributeTypeAndValue, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_type),
            "Expected error type '{}', but got '{}'",
            expected_error_type,
            err_str
        );
    }

    // RelativeDistinguishedName tests
    #[rstest(
        input,
        expected,
        // Test case: Single attribute
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                    Element::UTF8String("example.com".to_string()),
                ])
            ]),
            RelativeDistinguishedName {
                attribute: vec![
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                        attribute_value: "example.com".to_string(),
                    }
                ]
            }
        ),
        // Test case: Multiple attributes
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                    Element::UTF8String("example.com".to_string()),
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.6").unwrap()),
                    Element::PrintableString("US".to_string()),
                ])
            ]),
            RelativeDistinguishedName {
                attribute: vec![
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                        attribute_value: "example.com".to_string(),
                    },
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                        attribute_value: "US".to_string(),
                    }
                ]
            }
        ),
        // Test case: Empty set
        case(
            Element::Set(vec![]),
            RelativeDistinguishedName {
                attribute: vec![]
            }
        )
    )]
    fn test_rdn_decode_success(input: Element, expected: RelativeDistinguishedName) {
        let rdn: RelativeDistinguishedName = input.decode().unwrap();
        assert_eq!(rdn, expected);
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Set (should return RDN error)
        case(
            Element::Sequence(vec![]),
            "InvalidRelativeDistinguishedName"
        ),
        // Test case: Invalid attribute (should propagate AttributeTypeAndValue error)
        case(
            Element::Set(vec![Element::Integer(Integer::from(vec![0x01]))]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Set with partially invalid attributes
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                    Element::UTF8String("example.com".to_string()),
                ]),
                Element::Integer(Integer::from(vec![0x01])) // Invalid
            ]),
            "InvalidAttributeTypeAndValue"
        )
    )]
    fn test_rdn_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<RelativeDistinguishedName, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // Name tests
    #[rstest(
        input,
        expected,
        // Test case: Single RDN
        case(
            Element::Sequence(vec![
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                        Element::UTF8String("example.com".to_string()),
                    ])
                ])
            ]),
            Name {
                rdn_sequence: vec![
                    RelativeDistinguishedName {
                        attribute: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                                attribute_value: "example.com".to_string(),
                            }
                        ]
                    }
                ]
            }
        ),
        // Test case: Multiple RDNs
        case(
            Element::Sequence(vec![
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                        Element::UTF8String("example.com".to_string()),
                    ])
                ]),
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.6").unwrap()),
                        Element::PrintableString("US".to_string()),
                    ])
                ])
            ]),
            Name {
                rdn_sequence: vec![
                    RelativeDistinguishedName {
                        attribute: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                                attribute_value: "example.com".to_string(),
                            }
                        ]
                    },
                    RelativeDistinguishedName {
                        attribute: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                                attribute_value: "US".to_string(),
                            }
                        ]
                    }
                ]
            }
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            Name {
                rdn_sequence: vec![]
            }
        )
    )]
    fn test_name_decode_success(input: Element, expected: Name) {
        let name: Name = input.decode().unwrap();
        assert_eq!(name, expected);
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Sequence (should return Name error)
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "InvalidName"
        ),
        // Test case: Invalid RDN (should propagate RDN error)
        case(
            Element::Sequence(vec![Element::Integer(Integer::from(vec![0x01]))]),
            "InvalidRelativeDistinguishedName"
        ),
        // Test case: Invalid AttributeTypeAndValue (should propagate through the chain)
        case(
            Element::Sequence(vec![
                Element::Set(vec![Element::Integer(Integer::from(vec![0x01]))])
            ]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Multiple RDNs with one invalid (should fail on first error)
        case(
            Element::Sequence(vec![
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                        Element::UTF8String("example.com".to_string()),
                    ])
                ]),
                Element::Integer(Integer::from(vec![0x01])) // Invalid RDN
            ]),
            "InvalidRelativeDistinguishedName"
        )
    )]
    fn test_name_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<Name, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }
}
