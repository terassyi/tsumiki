use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;

/*
RFC 5280 Section 4.2.1.12: Extended Key Usage
https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12

ExtendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
KeyPurposeId ::= OBJECT IDENTIFIER
*/

/// Extended Key Usage extension ([RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)).
///
/// Indicates one or more purposes for which the certified public key may be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {
    pub purposes: Vec<ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    // Common KeyPurposeId OIDs (RFC 5280)

    /// TLS WWW server authentication (id-kp-serverAuth)
    /// OID: 1.3.6.1.5.5.7.3.1
    pub const SERVER_AUTH: &'static str = "1.3.6.1.5.5.7.3.1";

    /// TLS WWW client authentication (id-kp-clientAuth)
    /// OID: 1.3.6.1.5.5.7.3.2
    pub const CLIENT_AUTH: &'static str = "1.3.6.1.5.5.7.3.2";

    /// Code signing (id-kp-codeSigning)
    /// OID: 1.3.6.1.5.5.7.3.3
    pub const CODE_SIGNING: &'static str = "1.3.6.1.5.5.7.3.3";

    /// Email protection (id-kp-emailProtection)
    /// OID: 1.3.6.1.5.5.7.3.4
    pub const EMAIL_PROTECTION: &'static str = "1.3.6.1.5.5.7.3.4";

    /// Time stamping (id-kp-timeStamping)
    /// OID: 1.3.6.1.5.5.7.3.8
    pub const TIME_STAMPING: &'static str = "1.3.6.1.5.5.7.3.8";

    /// OCSP signing (id-kp-OCSPSigning)
    /// OID: 1.3.6.1.5.5.7.3.9
    pub const OCSP_SIGNING: &'static str = "1.3.6.1.5.5.7.3.9";
}

impl DecodableFrom<OctetString> for ExtendedKeyUsage {}

impl Decoder<OctetString, ExtendedKeyUsage> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<ExtendedKeyUsage, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        // The first element should be a Sequence
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::ExtendedKeyUsage).into()),
        }
    }
}

impl DecodableFrom<Element> for ExtendedKeyUsage {}

impl Decoder<Element, ExtendedKeyUsage> for Element {
    type Error = Error;

    fn decode(&self) -> Result<ExtendedKeyUsage, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::ExtendedKeyUsageEmpty.into());
                }

                let purposes = elements
                    .iter()
                    .map(|elem| match elem {
                        Element::ObjectIdentifier(oid) => Ok(oid.clone()),
                        _ => Err(error::Error::ExtendedKeyUsageExpectedOid),
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(ExtendedKeyUsage { purposes })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::ExtendedKeyUsage).into()),
        }
    }
}

impl EncodableTo<ExtendedKeyUsage> for Element {}

impl Encoder<ExtendedKeyUsage, Element> for ExtendedKeyUsage {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.purposes.is_empty() {
            return Err(error::Error::ExtendedKeyUsageEmpty.into());
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

impl OidName for ExtendedKeyUsage {
    fn oid_name(&self) -> Option<&'static str> {
        Some("extendedKeyUsage")
    }
}

impl fmt::Display for ExtendedKeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("extendedKeyUsage");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        let purposes = self
            .purposes
            .iter()
            .map(|oid| match oid.to_string().as_str() {
                Self::SERVER_AUTH => "TLS Web Server Authentication",
                Self::CLIENT_AUTH => "TLS Web Client Authentication",
                Self::CODE_SIGNING => "Code Signing",
                Self::EMAIL_PROTECTION => "E-mail Protection",
                Self::TIME_STAMPING => "Time Stamping",
                Self::OCSP_SIGNING => "OCSP Signing",
                _ => "Unknown",
            })
            .collect::<Vec<_>>();
        writeln!(f, "                {}", purposes.join(", "))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RawExtension;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::OctetString;
    use tsumiki_asn1::{Element, ObjectIdentifier};

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
            "at least one KeyPurposeId required"
        ),
        // Test case: Not a Sequence
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02])),
            "expected SEQUENCE"
        ),
        // Test case: Sequence with non-OID element
        case(
            Element::Sequence(vec![
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
            ]),
            "all elements must be OBJECT IDENTIFIER"
        ),
        // Test case: Mixed OID and non-OID
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::OctetString(OctetString::from(vec![0x01])),
            ]),
            "all elements must be OBJECT IDENTIFIER"
        ),
    )]
    fn test_extended_key_usage_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<ExtendedKeyUsage, _> = input.decode();
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

    #[rstest]
    #[case(ExtendedKeyUsage {
        purposes: vec![
            ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
        ],
    })]
    #[case(ExtendedKeyUsage {
        purposes: vec![
            ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
            ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap(),
        ],
    })]
    #[case(ExtendedKeyUsage {
        purposes: vec![
            ObjectIdentifier::from_str(ExtendedKeyUsage::CODE_SIGNING).unwrap(),
            ObjectIdentifier::from_str(ExtendedKeyUsage::EMAIL_PROTECTION).unwrap(),
            ObjectIdentifier::from_str(ExtendedKeyUsage::TIME_STAMPING).unwrap(),
        ],
    })]
    fn test_extended_key_usage_encode_decode(#[case] original: ExtendedKeyUsage) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<ExtendedKeyUsage, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
