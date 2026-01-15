use asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::Error;
use crate::extensions::Extension;

/*
RFC 5280 Section 4.2.1.12
ExtendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
KeyPurposeId ::= OBJECT IDENTIFIER
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {
    pub purposes: Vec<ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    // Common KeyPurposeId OIDs (RFC 5280)
    /// TLS WWW server authentication (1.3.6.1.5.5.7.3.1)
    pub const SERVER_AUTH: &'static str = "1.3.6.1.5.5.7.3.1";
    /// TLS WWW client authentication (1.3.6.1.5.5.7.3.2)
    pub const CLIENT_AUTH: &'static str = "1.3.6.1.5.5.7.3.2";
    /// Code signing (1.3.6.1.5.5.7.3.3)
    pub const CODE_SIGNING: &'static str = "1.3.6.1.5.5.7.3.3";
    /// Email protection (1.3.6.1.5.5.7.3.4)
    pub const EMAIL_PROTECTION: &'static str = "1.3.6.1.5.5.7.3.4";
    /// Time stamping (1.3.6.1.5.5.7.3.8)
    pub const TIME_STAMPING: &'static str = "1.3.6.1.5.5.7.3.8";
    /// OCSP signing (1.3.6.1.5.5.7.3.9)
    pub const OCSP_SIGNING: &'static str = "1.3.6.1.5.5.7.3.9";
}

impl DecodableFrom<OctetString> for ExtendedKeyUsage {}

impl Decoder<OctetString, ExtendedKeyUsage> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<ExtendedKeyUsage, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidExtendedKeyUsage("empty sequence".to_string()));
        }

        // The first element should be a Sequence
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for ExtendedKeyUsage {}

impl Decoder<Element, ExtendedKeyUsage> for Element {
    type Error = Error;

    fn decode(&self) -> Result<ExtendedKeyUsage, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidExtendedKeyUsage(
                        "empty sequence - at least one KeyPurposeId required".to_string(),
                    ));
                }

                let mut purposes = Vec::new();
                for elem in elements {
                    match elem {
                        Element::ObjectIdentifier(oid) => {
                            purposes.push(oid.clone());
                        }
                        _ => {
                            return Err(Error::InvalidExtendedKeyUsage(format!(
                                "expected ObjectIdentifier, got {:?}",
                                elem
                            )));
                        }
                    }
                }

                Ok(ExtendedKeyUsage { purposes })
            }
            _ => Err(Error::InvalidExtendedKeyUsage(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl EncodableTo<ExtendedKeyUsage> for Element {}

impl Encoder<ExtendedKeyUsage, Element> for ExtendedKeyUsage {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.purposes.is_empty() {
            return Err(Error::InvalidExtendedKeyUsage(
                "at least one KeyPurposeId required".to_string(),
            ));
        }

        let elements = self
            .purposes
            .iter()
            .map(|oid| Element::ObjectIdentifier(oid.clone()))
            .collect();

        Ok(Element::Sequence(elements))
    }
}

impl Extension for ExtendedKeyUsage {
    /// OID for ExtendedKeyUsage extension (2.5.29.37)
    const OID: &'static str = "2.5.29.37";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RawExtension;
    use asn1::OctetString;
    use asn1::{Element, ObjectIdentifier};
    use rstest::rstest;
    use std::str::FromStr;

    // ========== ExtendedKeyUsage Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Single purpose - serverAuth
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
                ],
            }
        ),
        // Test case: Multiple purposes - serverAuth and clientAuth
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
                    ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap(),
                ],
            }
        ),
        // Test case: Multiple purposes - serverAuth, clientAuth, codeSigning
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap()),
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::CODE_SIGNING).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
                    ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap(),
                    ObjectIdentifier::from_str(ExtendedKeyUsage::CODE_SIGNING).unwrap(),
                ],
            }
        ),
        // Test case: emailProtection
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::EMAIL_PROTECTION).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::EMAIL_PROTECTION).unwrap(),
                ],
            }
        ),
    )]
    fn test_extended_key_usage_decode_success(input: Element, expected: ExtendedKeyUsage) {
        let result: Result<ExtendedKeyUsage, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence (at least one required)
        case(
            Element::Sequence(vec![]),
            "empty sequence - at least one KeyPurposeId required"
        ),
        // Test case: Not a Sequence
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02])),
            "expected Sequence"
        ),
        // Test case: Sequence with non-OID element
        case(
            Element::Sequence(vec![
                Element::Integer(asn1::Integer::from(vec![0x01])),
            ]),
            "expected ObjectIdentifier"
        ),
        // Test case: Mixed OID and non-OID
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::OctetString(OctetString::from(vec![0x01])),
            ]),
            "expected ObjectIdentifier"
        ),
    )]
    fn test_extended_key_usage_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<ExtendedKeyUsage, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{}", err);
        assert!(
            err_str.contains(expected_error_msg),
            "Expected error message containing '{}', but got '{}'",
            expected_error_msg,
            err_str
        );
    }

    #[test]
    fn test_extended_key_usage_parse_from_real_der() {
        // Real DER-encoded ExtendedKeyUsage with serverAuth and clientAuth
        // 30 14: SEQUENCE, length 20
        // 06 08 2B 06 01 05 05 07 03 01: OID 1.3.6.1.5.5.7.3.1 (serverAuth)
        // 06 08 2B 06 01 05 05 07 03 02: OID 1.3.6.1.5.5.7.3.2 (clientAuth)
        let der_bytes = vec![
            0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08,
            0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(ExtendedKeyUsage::OID).unwrap(),
            false,
            octet_string,
        );

        let result = extension.parse::<ExtendedKeyUsage>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let eku = result.unwrap();

        assert_eq!(eku.purposes.len(), 2);
        assert_eq!(eku.purposes[0].to_string(), ExtendedKeyUsage::SERVER_AUTH);
        assert_eq!(eku.purposes[1].to_string(), ExtendedKeyUsage::CLIENT_AUTH);
    }
}
