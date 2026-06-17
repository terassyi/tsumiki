use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.2.1: Authority Information Access
https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1

id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
AuthorityInfoAccessSyntax  ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

AccessDescription  ::=  SEQUENCE {
    accessMethod          OBJECT IDENTIFIER,
    accessLocation        GeneralName
}

id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
*/

/// AccessDescription represents a single access method and location
///
/// RFC 5280: AccessDescription ::= SEQUENCE { accessMethod, accessLocation }
///
/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDescription {
    pub access_method: ObjectIdentifier,
    pub access_location: GeneralName,
}

impl AccessDescription {
    /// OCSP responder access method (id-ad-ocsp)
    /// OID: 1.3.6.1.5.5.7.48.1
    pub const OCSP: &'static str = "1.3.6.1.5.5.7.48.1";

    /// CA Issuers access method (id-ad-caIssuers)
    /// OID: 1.3.6.1.5.5.7.48.2
    pub const CA_ISSUERS: &'static str = "1.3.6.1.5.5.7.48.2";
}

impl DecodableFrom<Element> for AccessDescription {}

impl Decoder<Element, AccessDescription> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AccessDescription, Self::Error> {
        match self {
            Element::Sequence(elements) => match elements.as_slice() {
                [Element::ObjectIdentifier(oid), location_elem] => {
                    let access_location: GeneralName = location_elem.decode()?;
                    Ok(AccessDescription {
                        access_method: oid.clone(),
                        access_location,
                    })
                }
                [_, _] => Err(error::Error::AccessDescriptionExpectedOid.into()),
                _ => Err(error::Error::AccessDescriptionInvalidStructure.into()),
            },
            _ => Err(error::Error::ExpectedSequence(error::Kind::AuthorityInfoAccess).into()),
        }
    }
}

impl EncodableTo<AccessDescription> for Element {}

impl Encoder<AccessDescription, Element> for AccessDescription {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let access_method_elem = Element::ObjectIdentifier(self.access_method.clone());
        let access_location_elem = self.access_location.encode()?;
        Ok(Element::Sequence(vec![
            access_method_elem,
            access_location_elem,
        ]))
    }
}

/// Authority Information Access extension ([RFC 5280 Section 4.2.2.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1)).
///
/// Contains information about how to access CA information and services,
/// such as OCSP responders and CA certificate issuers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityInfoAccess {
    pub descriptors: Vec<AccessDescription>,
}

impl AuthorityInfoAccess {
    /// OCSP responder access method (id-ad-ocsp)
    /// OID: 1.3.6.1.5.5.7.48.1
    pub const OCSP: &'static str = "1.3.6.1.5.5.7.48.1";

    /// CA Issuers access method (id-ad-caIssuers)
    /// OID: 1.3.6.1.5.5.7.48.2
    pub const CA_ISSUERS: &'static str = "1.3.6.1.5.5.7.48.2";
}

impl DecodableFrom<OctetString> for AuthorityInfoAccess {}

impl Decoder<OctetString, AuthorityInfoAccess> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityInfoAccess, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;

        // The first element should be a Sequence
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::AuthorityInfoAccess).into()),
        }
    }
}

impl DecodableFrom<Element> for AuthorityInfoAccess {}

impl Decoder<Element, AuthorityInfoAccess> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityInfoAccess, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::AuthorityInfoAccessEmpty.into());
                }

                let descriptors = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<AccessDescription>, _>>()?;

                Ok(AuthorityInfoAccess { descriptors })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::AuthorityInfoAccess).into()),
        }
    }
}

impl EncodableTo<AuthorityInfoAccess> for Element {}

impl Encoder<AuthorityInfoAccess, Element> for AuthorityInfoAccess {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.descriptors.is_empty() {
            return Err(error::Error::AuthorityInfoAccessEmpty.into());
        }

        let desc_elements = self
            .descriptors
            .iter()
            .map(|desc| desc.encode())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Element::Sequence(desc_elements))
    }
}

impl Extension for AuthorityInfoAccess {
    /// OID for AuthorityInfoAccess extension (1.3.6.1.5.5.7.1.1)
    const OID: &'static str = "1.3.6.1.5.5.7.1.1";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for AuthorityInfoAccess {
    fn oid_name(&self) -> Option<&'static str> {
        Some("authorityInfoAccess")
    }
}

impl fmt::Display for AuthorityInfoAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("authorityInfoAccess");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for desc in &self.descriptors {
            let method = match desc.access_method.to_string().as_str() {
                Self::OCSP => "OCSP",
                Self::CA_ISSUERS => "CA Issuers",
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
    use crate::extensions::{Extension, RawExtension};
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::OctetString;
    use tsumiki_asn1::{Element, ObjectIdentifier};

    #[rstest(input, expected)]
    #[case(
        Element::Sequence(vec![
        Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
            Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp.example.com".to_vec()))),
                },
            ]),
        ]),
        AuthorityInfoAccess {
            descriptors: vec![AccessDescription {
                access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                access_location: GeneralName::Uri("http://ocsp.example.com".to_string()),
            }],
        }
    )]
    #[case(
        Element::Sequence(vec![
        Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap()),
            Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://ca.example.com/cert.crt".to_vec()))),
                },
            ]),
        ]),
        AuthorityInfoAccess {
            descriptors: vec![AccessDescription {
                access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap(),
                access_location: GeneralName::Uri("http://ca.example.com/cert.crt".to_string()),
            }],
        }
    )]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        constructed: false,
            slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp.example.com".to_vec()))),
                    },
                ]),
            Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap()),
                    Element::ContextSpecific {
                        constructed: false,
            slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ca.example.com/cert.crt".to_vec()))),
                    },
                ]),
            ]),
        AuthorityInfoAccess {
            descriptors: vec![
                AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                        access_location: GeneralName::Uri("http://ocsp.example.com".to_string()),
                    },
                AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap(),
                        access_location: GeneralName::Uri("http://ca.example.com/cert.crt".to_string()),
                    },
                ],
            }
    )]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        constructed: false,
            slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp1.example.com".to_vec()))),
                    },
                ]),
            Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        constructed: false,
            slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp2.example.com".to_vec()))),
                    },
                ]),
            ]),
        AuthorityInfoAccess {
            descriptors: vec![
                AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                        access_location: GeneralName::Uri("http://ocsp1.example.com".to_string()),
                    },
                AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                        access_location: GeneralName::Uri("http://ocsp2.example.com".to_string()),
                    },
                ],
            }
    )]
    #[case(
        Element::Sequence(vec![
            Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        constructed: false,
            slot: 2,
                        element: Box::new(Element::OctetString(OctetString::from(b"ocsp.example.com".to_vec()))),
                    },
                ]),
            ]),
        AuthorityInfoAccess {
            descriptors: vec![AccessDescription {
                    access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                    access_location: GeneralName::DnsName("ocsp.example.com".to_string()),
                }],
            }
    )]
    fn test_authority_info_access_decode_success(input: Element, expected: AuthorityInfoAccess) {
        let result: Result<AuthorityInfoAccess, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(input, expected_error_msg)]
    #[case(
        Element::Sequence(vec![]),
        "at least one AccessDescription required"
    )]
    #[case(
        Element::OctetString(OctetString::from(vec![0x01, 0x02])),
        "AuthorityInfoAccess: expected SEQUENCE"
    )]
    #[case(
        Element::Sequence(vec![
        Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
            ]),
        ]),
        "AccessDescription must be SEQUENCE with 2 elements"
    )]
    #[case(
        Element::Sequence(vec![
        Element::Sequence(vec![
            Element::OctetString(OctetString::from(vec![0x01])),
            Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp.example.com".to_vec()))),
                },
            ]),
        ]),
        "accessMethod must be OBJECT IDENTIFIER"
    )]
    #[case(
        Element::Sequence(vec![
        Element::OctetString(OctetString::from(vec![0x01])),
        ]),
        "AuthorityInfoAccess: expected SEQUENCE"
    )]
    fn test_authority_info_access_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<AuthorityInfoAccess, _> = input.decode();
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
    #[case(AuthorityInfoAccess {
        descriptors: vec![
            AccessDescription {
                access_method: ObjectIdentifier::from_str("1.3.6.1.5.5.7.48.1").unwrap(),
                access_location: GeneralName::Uri("http://ocsp.example.com".to_string()),
            },
        ],
    })]
    #[case(AuthorityInfoAccess {
        descriptors: vec![
            AccessDescription {
                access_method: ObjectIdentifier::from_str("1.3.6.1.5.5.7.48.2").unwrap(),
                access_location: GeneralName::Uri("http://ca.example.com/cert.crt".to_string()),
            },
            AccessDescription {
                access_method: ObjectIdentifier::from_str("1.3.6.1.5.5.7.48.1").unwrap(),
                access_location: GeneralName::Uri("http://ocsp.example.com".to_string()),
            },
        ],
    })]
    fn test_authority_info_access_encode_decode(#[case] original: AuthorityInfoAccess) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<AuthorityInfoAccess, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }

    #[test]
    fn test_authority_info_access_parse_from_real_der() {
        // Real DER-encoded AuthorityInfoAccess with OCSP and CA Issuers
        // 30 46: SEQUENCE, length 70 (0x46)
        //   30 20: SEQUENCE, length 32 (0x20) - AccessDescription #1
        //     06 08 2B 06 01 05 05 07 30 01: OID 1.3.6.1.5.5.7.48.1 (OCSP)
        //     86 14: [6] IMPLICIT (uniformResourceIdentifier), length 20 (0x14)
        //     "http://ocsp.example.com" (23 bytes)
        //   30 22: SEQUENCE, length 34 (0x22) - AccessDescription #2
        //     06 08 2B 06 01 05 05 07 30 02: OID 1.3.6.1.5.5.7.48.2 (CA Issuers)
        //     86 16: [6] IMPLICIT (uniformResourceIdentifier), length 22 (0x16)
        //     "http://ca.example.com/cert.crt" (31 bytes)
        let der_bytes = vec![
            0x30, 0x60, // SEQUENCE, length 96 (updated)
            // AccessDescription #1: OCSP
            0x30, 0x2B, // SEQUENCE, length 43
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, // OID OCSP
            0x86, 0x1F, // [6] IMPLICIT, length 31
            0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x65, 0x78,
            0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x6F, 0x63, 0x73, 0x70,
            0x2D, 0x73, 0x65, // "http://ocsp.example.com/ocsp-se"
            // AccessDescription #2: CA Issuers
            0x30, 0x31, // SEQUENCE, length 49
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, // OID CA Issuers
            0x86, 0x25, // [6] IMPLICIT, length 37
            0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x2E, 0x65, 0x78, 0x61, 0x6D,
            0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72,
            0x2F, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x72,
            0x74, // "http://ca.example.com/issuer/cert.crt"
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(AuthorityInfoAccess::OID).unwrap(),
            false,
            octet_string,
        );

        let result = extension.parse::<AuthorityInfoAccess>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let aia = result.unwrap();

        assert_eq!(aia.descriptors.len(), 2);

        // Check first descriptor (OCSP)
        assert_eq!(
            aia.descriptors[0].access_method.to_string(),
            AuthorityInfoAccess::OCSP
        );
        match &aia.descriptors[0].access_location {
            GeneralName::Uri(uri) => {
                assert!(uri.starts_with("http://ocsp.example.com"));
            }
            _ => panic!("Expected Uri for OCSP"),
        }

        // Check second descriptor (CA Issuers)
        assert_eq!(
            aia.descriptors[1].access_method.to_string(),
            AuthorityInfoAccess::CA_ISSUERS
        );
        match &aia.descriptors[1].access_location {
            GeneralName::Uri(uri) => {
                assert!(uri.starts_with("http://ca.example.com"));
            }
            _ => panic!("Expected Uri for CA Issuers"),
        }
    }
}
