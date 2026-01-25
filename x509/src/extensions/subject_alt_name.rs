use asn1::{ASN1Object, Element, OctetString};
use pkix_types::OidName;
use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::error;
use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.1.6
SubjectAltName ::= GeneralNames
GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectAltName {
    pub names: Vec<GeneralName>,
}

impl SubjectAltName {
    /// OID for SubjectAltName extension (2.5.29.17)
    pub const OID: &'static str = "2.5.29.17";
}

impl DecodableFrom<OctetString> for SubjectAltName {}

impl Decoder<OctetString, SubjectAltName> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectAltName, Self::Error> {
        // SubjectAltName -> ASN1Object -> Element (Sequence) -> SubjectAltName
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;

        // The first element should be a Sequence (GeneralNames)
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::SubjectAltName).into()),
        }
    }
}

impl DecodableFrom<Element> for SubjectAltName {}

impl Decoder<Element, SubjectAltName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectAltName, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::AtLeastOneGeneralNameRequired(
                        error::Kind::SubjectAltName,
                    )
                    .into());
                }

                let names = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<GeneralName>, _>>()?;

                Ok(SubjectAltName { names })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::SubjectAltName).into()),
        }
    }
}

impl EncodableTo<SubjectAltName> for Element {}

impl Encoder<SubjectAltName, Element> for SubjectAltName {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.names.is_empty() {
            return Err(
                error::Error::AtLeastOneGeneralNameRequired(error::Kind::SubjectAltName).into(),
            );
        }

        let elements = self
            .names
            .iter()
            .map(|name| name.encode())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Element::Sequence(elements))
    }
}

impl Extension for SubjectAltName {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for SubjectAltName {
    fn oid_name(&self) -> Option<&'static str> {
        Some("subjectAltName")
    }
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("subjectAltName");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for name in &self.names {
            writeln!(f, "                {}", name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RawExtension;
    use asn1::OctetString;
    use asn1::{Element, ObjectIdentifier};
    use rstest::rstest;
    use std::net::IpAddr;
    use std::str::FromStr;

    // ========== SubjectAltName Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Single dNSName
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::DnsName("example.com".to_string())],
            }
        ),
        // Test case: Multiple dNSNames
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"example.com".to_vec()))),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"www.example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![
                    GeneralName::DnsName("example.com".to_string()),
                    GeneralName::DnsName("www.example.com".to_string()),
                ],
            }
        ),
        // Test case: IPv4 address
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2, 1]))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::IpAddress(
                    crate::extensions::IpAddressOrRange::Address(IpAddr::from([192, 0, 2, 1]))
                )],
            }
        ),
        // Test case: IPv6 address
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![
                        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                    ]))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::IpAddress(
                    crate::extensions::IpAddressOrRange::Address(IpAddr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                    ]))
                )],
            }
        ),
        // Test case: URI
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"https://example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::Uri("https://example.com".to_string())],
            }
        ),
        // Test case: rfc822Name (email)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 1,
                    element: Box::new(Element::OctetString(OctetString::from(b"user@example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::Rfc822Name("user@example.com".to_string())],
            }
        ),
        // Test case: Mixed types
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"example.com".to_vec()))),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2, 1]))),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"https://example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![
                    GeneralName::DnsName("example.com".to_string()),
                    GeneralName::IpAddress(
                        crate::extensions::IpAddressOrRange::Address(IpAddr::from([192, 0, 2, 1]))
                    ),
                    GeneralName::Uri("https://example.com".to_string()),
                ],
            }
        ),
    )]
    fn test_subject_alt_name_decode_success(input: Element, expected: SubjectAltName) {
        let result: Result<SubjectAltName, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "at least one GeneralName required"
        ),
        // Test case: Not a Sequence
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02])),
            "expected SEQUENCE"
        ),
        // Test case: Invalid IP address length (3 bytes)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2]))),
                },
            ]),
            "iPAddress must be 4, 8, 16, or 32 bytes"
        ),
        // Test case: Non-context-specific element
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(b"example.com".to_vec())),
            ]),
            "unexpected element type"
        ),
    )]
    fn test_subject_alt_name_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectAltName, _> = input.decode();
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

    #[rstest]
    #[case(SubjectAltName {
        names: vec![
            GeneralName::DnsName("example.com".to_string()),
        ],
    })]
    #[case(SubjectAltName {
        names: vec![
            GeneralName::DnsName("www.example.com".to_string()),
            GeneralName::DnsName("mail.example.com".to_string()),
        ],
    })]
    #[case(SubjectAltName {
        names: vec![
            GeneralName::Rfc822Name("user@example.com".to_string()),
            GeneralName::Uri("https://example.com".to_string()),
        ],
    })]
    fn test_subject_alt_name_encode_decode(#[case] original: SubjectAltName) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<SubjectAltName, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }

    #[test]
    fn test_subject_alt_name_parse_from_real_der() {
        // Real DER-encoded SubjectAltName with dNSName
        // 30 0D: SEQUENCE, length 13 (0x0D)
        // 82 0B: [2] IMPLICIT (dNSName), length 11 (0x0B)
        // "example.com" (11 bytes: 0x65 0x78 0x61 0x6d 0x70 0x6c 0x65 0x2e 0x63 0x6f 0x6d)
        let der_bytes = vec![
            0x30, 0x0D, // SEQUENCE, length 13
            0x82, 0x0B, // [2] IMPLICIT, length 11
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(SubjectAltName::OID).unwrap(),
            false,
            octet_string,
        );

        let result = extension.parse::<SubjectAltName>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let san = result.unwrap();

        assert_eq!(san.names.len(), 1);
        match &san.names[0] {
            GeneralName::DnsName(name) => assert_eq!(name, "example.com"),
            _ => panic!("Expected DnsName"),
        }
    }

    #[test]
    fn test_general_name_other_name() {
        // Test OtherName with a simple structure
        // SEQUENCE {
        //   type-id: OID 1.2.3.4
        //   value: [0] EXPLICIT UTF8String "test"
        // }
        let other_name_elem = Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
            Element::ContextSpecific {
                constructed: true,
                slot: 0,
                element: Box::new(Element::UTF8String("test".to_string())),
            },
        ]);

        let gn = GeneralName::parse_from_context_specific(0, &Box::new(other_name_elem));
        assert!(gn.is_ok(), "Failed to parse OtherName: {:?}", gn);

        match gn.unwrap() {
            GeneralName::OtherName(on) => {
                assert_eq!(on.type_id, ObjectIdentifier::from_str("1.2.3.4").unwrap());
                // value should contain some representation of "test"
                assert!(!on.value.is_empty());
            }
            _ => panic!("Expected OtherName"),
        }
    }

    #[test]
    fn test_general_name_edi_party_name() {
        // Test EDIPartyName with nameAssigner and partyName
        // SEQUENCE {
        //   [0] nameAssigner (DirectoryString)
        //   [1] partyName (DirectoryString)
        // }
        let edi_elem = Element::Sequence(vec![
            Element::ContextSpecific {
                constructed: true,
                slot: 0,
                element: Box::new(Element::UTF8String("Assigner".to_string())),
            },
            Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::UTF8String("Party".to_string())),
            },
        ]);

        let gn = GeneralName::parse_from_context_specific(5, &Box::new(edi_elem));
        assert!(gn.is_ok(), "Failed to parse EDIPartyName: {:?}", gn);

        match gn.unwrap() {
            GeneralName::EdiPartyName(epn) => {
                assert_eq!(epn.name_assigner, Some("Assigner".to_string()));
                assert_eq!(epn.party_name, "Party".to_string());
            }
            _ => panic!("Expected EdiPartyName"),
        }
    }

    #[test]
    fn test_general_name_edi_party_name_no_assigner() {
        // Test EDIPartyName with only partyName (nameAssigner is OPTIONAL)
        let edi_elem = Element::Sequence(vec![Element::ContextSpecific {
            constructed: false,
            slot: 1,
            element: Box::new(Element::PrintableString("Party Only".to_string())),
        }]);

        let gn = GeneralName::parse_from_context_specific(5, &Box::new(edi_elem));
        assert!(gn.is_ok(), "Failed to parse EDIPartyName: {:?}", gn);

        match gn.unwrap() {
            GeneralName::EdiPartyName(epn) => {
                assert_eq!(epn.name_assigner, None);
                assert_eq!(epn.party_name, "Party Only".to_string());
            }
            _ => panic!("Expected EdiPartyName"),
        }
    }

    #[test]
    fn test_general_name_x400_address() {
        // Test x400Address (stored as raw bytes)
        let x400_elem = Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03]));

        let gn = GeneralName::parse_from_context_specific(3, &Box::new(x400_elem));
        assert!(gn.is_ok(), "Failed to parse x400Address: {:?}", gn);

        match gn.unwrap() {
            GeneralName::X400Address(bytes) => {
                assert_eq!(bytes, vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("Expected X400Address"),
        }
    }

    #[test]
    fn test_general_name_registered_id() {
        // Test registeredID [8] - IMPLICIT OID
        let oid_bytes = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]; // 1.2.840.113549
        let reg_id_elem = Element::OctetString(asn1::OctetString::from(oid_bytes));

        let gn = GeneralName::parse_from_context_specific(8, &Box::new(reg_id_elem));
        assert!(gn.is_ok(), "Failed to parse registeredID: {:?}", gn);

        match gn.unwrap() {
            GeneralName::RegisteredId(oid) => {
                assert_eq!(oid, ObjectIdentifier::from_str("1.2.840.113549").unwrap());
            }
            _ => panic!("Expected RegisteredId"),
        }
    }
}
