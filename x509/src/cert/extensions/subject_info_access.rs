use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::AccessDescription;
use super::error;
use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.2.2: Subject Information Access
https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.2

id-pe-subjectInfoAccess OBJECT IDENTIFIER ::= { id-pe 11 }
SubjectInfoAccessSyntax  ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

AccessDescription  ::=  SEQUENCE {
    accessMethod          OBJECT IDENTIFIER,
    accessLocation        GeneralName
}

id-ad-caRepository  OBJECT IDENTIFIER ::= { id-ad 5 }
id-ad-timeStamping  OBJECT IDENTIFIER ::= { id-ad 3 }
*/

/// Subject Information Access extension ([RFC 5280 §4.2.2.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.2)).
///
/// Conveys information about how to access additional information about the
/// subject of the certificate (typically the subordinate CA's repository or
/// a timestamping service).
///
/// MUST be marked non-critical per RFC 5280.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectInfoAccess {
    pub descriptors: Vec<AccessDescription>,
}

impl SubjectInfoAccess {
    /// CA Repository access method (id-ad-caRepository)
    /// OID: 1.3.6.1.5.5.7.48.5
    pub const CA_REPOSITORY: &'static str = "1.3.6.1.5.5.7.48.5";

    /// Time Stamping access method (id-ad-timeStamping)
    /// OID: 1.3.6.1.5.5.7.48.3
    pub const TIME_STAMPING: &'static str = "1.3.6.1.5.5.7.48.3";
}

impl DecodableFrom<OctetString> for SubjectInfoAccess {}

impl Decoder<OctetString, SubjectInfoAccess> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectInfoAccess, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;

        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::SubjectInfoAccessEmpty.into()),
        }
    }
}

impl DecodableFrom<Element> for SubjectInfoAccess {}

// AccessDescription is shared with AuthorityInfoAccess as a type (RFC 5280 §4.2.2.1
// and §4.2.2.2 use the identical SEQUENCE), but its decoding is duplicated here so
// that error variants reference SubjectInfoAccess rather than AuthorityInfoAccess.
// This mirrors the existing crate pattern where each extension owns its own
// decode/error wiring (cf. `general_name.rs`).
fn decode_access_description(elem: &Element) -> Result<AccessDescription, Error> {
    match elem {
        Element::Sequence(elements) => match elements.as_slice() {
            [Element::ObjectIdentifier(oid), location_elem] => {
                let access_location: GeneralName = location_elem.decode()?;
                Ok(AccessDescription {
                    access_method: oid.clone(),
                    access_location,
                })
            }
            [_, _] => Err(error::Error::SubjectInfoAccessExpectedOid.into()),
            _ => Err(error::Error::SubjectInfoAccessInvalidStructure.into()),
        },
        _ => Err(error::Error::ExpectedSequence(error::Kind::SubjectInfoAccess).into()),
    }
}

impl Decoder<Element, SubjectInfoAccess> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectInfoAccess, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::SubjectInfoAccessEmpty.into());
                }

                let descriptors = elements
                    .iter()
                    .map(decode_access_description)
                    .collect::<Result<Vec<AccessDescription>, _>>()?;

                Ok(SubjectInfoAccess { descriptors })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::SubjectInfoAccess).into()),
        }
    }
}

impl EncodableTo<SubjectInfoAccess> for Element {}

impl Encoder<SubjectInfoAccess, Element> for SubjectInfoAccess {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.descriptors.is_empty() {
            return Err(error::Error::SubjectInfoAccessEmpty.into());
        }

        let desc_elements = self
            .descriptors
            .iter()
            .map(|desc| desc.encode())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Element::Sequence(desc_elements))
    }
}

impl Extension for SubjectInfoAccess {
    /// OID for SubjectInfoAccess extension (1.3.6.1.5.5.7.1.11)
    const OID: &'static str = "1.3.6.1.5.5.7.1.11";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for SubjectInfoAccess {
    fn oid_name(&self) -> Option<&'static str> {
        Some("subjectInfoAccess")
    }
}

impl fmt::Display for SubjectInfoAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("subjectInfoAccess");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for desc in &self.descriptors {
            let method = match desc.access_method.to_string().as_str() {
                Self::CA_REPOSITORY => "CA Repository",
                Self::TIME_STAMPING => "Time Stamping",
                _ => "Unknown",
            };
            writeln!(f, "                {} - {}", method, desc.access_location)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RawExtension;
    use crate::extensions::general_name::GeneralName;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::ObjectIdentifier;

    #[rstest(input, expected)]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(SubjectInfoAccess::CA_REPOSITORY).unwrap()),
                Element::ContextSpecific {
                    constructed: false,
                    slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://ca.example.com/repo".to_vec()))),
                },
            ]),
        ]),
        SubjectInfoAccess {
            descriptors: vec![AccessDescription {
                access_method: ObjectIdentifier::from_str(SubjectInfoAccess::CA_REPOSITORY).unwrap(),
                access_location: GeneralName::Uri("http://ca.example.com/repo".to_string()),
            }],
        }
    )]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(SubjectInfoAccess::TIME_STAMPING).unwrap()),
                Element::ContextSpecific {
                    constructed: false,
                    slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://tsa.example.com".to_vec()))),
                },
            ]),
        ]),
        SubjectInfoAccess {
            descriptors: vec![AccessDescription {
                access_method: ObjectIdentifier::from_str(SubjectInfoAccess::TIME_STAMPING).unwrap(),
                access_location: GeneralName::Uri("http://tsa.example.com".to_string()),
            }],
        }
    )]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(SubjectInfoAccess::CA_REPOSITORY).unwrap()),
                Element::ContextSpecific {
                    constructed: false,
                    slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://ca.example.com/repo".to_vec()))),
                },
            ]),
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(SubjectInfoAccess::TIME_STAMPING).unwrap()),
                Element::ContextSpecific {
                    constructed: false,
                    slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://tsa.example.com".to_vec()))),
                },
            ]),
        ]),
        SubjectInfoAccess {
            descriptors: vec![
                AccessDescription {
                    access_method: ObjectIdentifier::from_str(SubjectInfoAccess::CA_REPOSITORY).unwrap(),
                    access_location: GeneralName::Uri("http://ca.example.com/repo".to_string()),
                },
                AccessDescription {
                    access_method: ObjectIdentifier::from_str(SubjectInfoAccess::TIME_STAMPING).unwrap(),
                    access_location: GeneralName::Uri("http://tsa.example.com".to_string()),
                },
            ],
        }
    )]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.3.6.1.5.5.7.48.99").unwrap()),
                Element::ContextSpecific {
                    constructed: false,
                    slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"info.example.com".to_vec()))),
                },
            ]),
        ]),
        SubjectInfoAccess {
            descriptors: vec![AccessDescription {
                access_method: ObjectIdentifier::from_str("1.3.6.1.5.5.7.48.99").unwrap(),
                access_location: GeneralName::DnsName("info.example.com".to_string()),
            }],
        }
    )]
    fn test_subject_info_access_decode_success(input: Element, expected: SubjectInfoAccess) {
        let result: Result<SubjectInfoAccess, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        assert_eq!(expected, result.unwrap());
    }

    #[rstest]
    #[case(Element::Sequence(vec![]))]
    fn test_subject_info_access_decode_empty(#[case] input: Element) {
        let result: Result<SubjectInfoAccess, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::CertExtensionError(
                error::Error::SubjectInfoAccessEmpty
            ))
        ));
    }

    #[rstest]
    #[case(Element::Sequence(vec![
        Element::Sequence(vec![
            Element::OctetString(OctetString::from(vec![0x01])),
            Element::ContextSpecific {
                constructed: false,
                slot: 6,
                element: Box::new(Element::OctetString(OctetString::from(b"http://example.com".to_vec()))),
            },
        ]),
    ]))]
    fn test_subject_info_access_decode_method_not_oid(#[case] input: Element) {
        let result: Result<SubjectInfoAccess, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::CertExtensionError(
                error::Error::SubjectInfoAccessExpectedOid
            ))
        ));
    }

    #[rstest]
    #[case(Element::OctetString(OctetString::from(vec![0x01, 0x02])))]
    fn test_subject_info_access_decode_not_sequence(#[case] input: Element) {
        let result: Result<SubjectInfoAccess, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::CertExtensionError(error::Error::ExpectedSequence(
                error::Kind::SubjectInfoAccess
            )))
        ));
    }

    #[rstest]
    #[case(SubjectInfoAccess {
        descriptors: vec![
            AccessDescription {
                access_method: ObjectIdentifier::from_str(SubjectInfoAccess::CA_REPOSITORY).unwrap(),
                access_location: GeneralName::Uri("http://ca.example.com/repo".to_string()),
            },
        ],
    })]
    #[case(SubjectInfoAccess {
        descriptors: vec![
            AccessDescription {
                access_method: ObjectIdentifier::from_str(SubjectInfoAccess::CA_REPOSITORY).unwrap(),
                access_location: GeneralName::Uri("http://ca.example.com/repo".to_string()),
            },
            AccessDescription {
                access_method: ObjectIdentifier::from_str(SubjectInfoAccess::TIME_STAMPING).unwrap(),
                access_location: GeneralName::Uri("http://tsa.example.com".to_string()),
            },
        ],
    })]
    fn test_subject_info_access_encode_decode(#[case] original: SubjectInfoAccess) {
        let encoded = original.encode().expect("encode failed");
        let decoded: SubjectInfoAccess = encoded.decode().expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_subject_info_access_parse_from_real_der() {
        // SEQUENCE { SEQUENCE { OID 1.3.6.1.5.5.7.48.5, [6] "http://ca.example.com/repo" } }
        let der_bytes = vec![
            0x30, 0x28, // outer SEQUENCE, length 40
            0x30, 0x26, // inner SEQUENCE, length 38
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05, // OID caRepository
            0x86, 0x1A, // [6] IMPLICIT, length 26
            0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x2E, 0x65, 0x78, 0x61, 0x6D,
            0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x72, 0x65, 0x70,
            0x6F, // "http://ca.example.com/repo"
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(SubjectInfoAccess::OID).unwrap(),
            false,
            octet_string,
        );

        let sia = extension
            .parse::<SubjectInfoAccess>()
            .expect("parse failed");

        assert_eq!(sia.descriptors.len(), 1);
        let desc = sia.descriptors.first().expect("descriptors empty");
        assert_eq!(
            desc.access_method.to_string(),
            SubjectInfoAccess::CA_REPOSITORY
        );
        match &desc.access_location {
            GeneralName::Uri(uri) => assert_eq!(uri, "http://ca.example.com/repo"),
            _ => panic!("Expected Uri"),
        }
    }

    #[test]
    fn test_subject_info_access_der_bytes_roundtrip() {
        // Same DER as test_subject_info_access_parse_from_real_der; verifies that
        // parse → encode → der bytes produces the original input bytes exactly
        // (RFC 5280 / X.690 DER canonical encoding).
        let der_bytes = vec![
            0x30, 0x28, 0x30, 0x26, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05,
            0x86, 0x1A, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x2E, 0x65, 0x78,
            0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x72, 0x65, 0x70, 0x6F,
        ];

        let octet_string = OctetString::from(der_bytes.clone());
        let sia: SubjectInfoAccess = octet_string.decode().expect("decode failed");

        let encoded_elem = sia.encode().expect("encode failed");
        let tlv: tsumiki_der::Tlv = encoded_elem.encode().expect("tlv conversion failed");
        let encoded_bytes: Vec<u8> = tlv.encode().expect("der encode failed");

        assert_eq!(encoded_bytes, der_bytes);
    }
}
