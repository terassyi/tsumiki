use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::{CertificateSerialNumber, KeyIdentifier, OidName};

use super::error;
use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.1.1
AuthorityKeyIdentifier ::= SEQUENCE {
    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
}

KeyIdentifier ::= OCTET STRING
CertificateSerialNumber ::= INTEGER
*/

// KeyIdentifier is already imported above, no need to re-export here

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthorityKeyIdentifier {
    /// KeyIdentifier: typically a SHA-1 hash of the CA's public key
    pub key_identifier: Option<KeyIdentifier>,
    /// GeneralNames: issuer name(s) of the CA certificate
    pub authority_cert_issuer: Option<Vec<GeneralName>>,
    /// CertificateSerialNumber: serial number of the CA certificate
    pub authority_cert_serial_number: Option<CertificateSerialNumber>,
}

impl Serialize for AuthorityKeyIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AuthorityKeyIdentifier", 3)?;
        // Serialize key_identifier as hex string
        if let Some(ref key_id) = self.key_identifier {
            let hex_string = key_id
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            state.serialize_field("key_identifier", &hex_string)?;
        } else {
            state.serialize_field("key_identifier", &self.key_identifier)?;
        }
        state.serialize_field("authority_cert_issuer", &self.authority_cert_issuer)?;
        state.serialize_field(
            "authority_cert_serial_number",
            &self.authority_cert_serial_number,
        )?;
        state.end()
    }
}

impl Extension for AuthorityKeyIdentifier {
    /// OID for AuthorityKeyIdentifier extension (2.5.29.35)
    const OID: &'static str = "2.5.29.35";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (Sequence) -> AuthorityKeyIdentifier
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;

        // The first element should be a Sequence
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::AuthorityKeyIdentifier).into()),
        }
    }
}

impl DecodableFrom<Element> for AuthorityKeyIdentifier {}

impl Decoder<Element, AuthorityKeyIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityKeyIdentifier, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (key_identifier, authority_cert_issuer, authority_cert_serial_number) =
                    elements.iter().try_fold(
                        (None, None, None),
                        |(key_id, cert_issuer, serial), elem| -> Result<_, Error> {
                            match elem {
                                // [0] IMPLICIT KeyIdentifier (OCTET STRING)
                                Element::ContextSpecific {
                                    slot: 0, element, ..
                                } => {
                                    if let Element::OctetString(os) = element.as_ref() {
                                        Ok((Some(os.clone()), cert_issuer, serial))
                                    } else {
                                        Err(error::Error::AkiKeyIdentifierNotOctetString.into())
                                    }
                                }
                                // [1] IMPLICIT GeneralNames (SEQUENCE OF GeneralName)
                                Element::ContextSpecific {
                                    slot: 1, element, ..
                                } => match element.as_ref() {
                                    Element::Sequence(names) => {
                                        let parsed_names: Vec<GeneralName> = names
                                            .iter()
                                            .map(|e| e.decode())
                                            .collect::<Result<Vec<GeneralName>, Error>>()?;
                                        Ok((key_id, Some(parsed_names), serial))
                                    }
                                    _ => {
                                        Err(error::Error::AkiAuthorityCertIssuerNotSequence.into())
                                    }
                                },
                                // [2] IMPLICIT CertificateSerialNumber (INTEGER)
                                Element::ContextSpecific {
                                    slot: 2, element, ..
                                } => {
                                    if let Element::OctetString(os) = element.as_ref() {
                                        Ok((
                                            key_id,
                                            cert_issuer,
                                            Some(CertificateSerialNumber::from_bytes(
                                                os.as_bytes().to_vec(),
                                            )),
                                        ))
                                    } else if let Element::Integer(i) = element.as_ref() {
                                        Ok((
                                            key_id,
                                            cert_issuer,
                                            Some(CertificateSerialNumber::from(i.clone())),
                                        ))
                                    } else {
                                        Err(error::Error::AkiSerialNumberInvalidType.into())
                                    }
                                }
                                _ => Err(error::Error::UnexpectedElementType(
                                    error::Kind::AuthorityKeyIdentifier,
                                )
                                .into()),
                            }
                        },
                    )?;

                Ok(AuthorityKeyIdentifier {
                    key_identifier,
                    authority_cert_issuer,
                    authority_cert_serial_number,
                })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::AuthorityKeyIdentifier).into()),
        }
    }
}

impl EncodableTo<AuthorityKeyIdentifier> for Element {}

impl Encoder<AuthorityKeyIdentifier, Element> for AuthorityKeyIdentifier {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let key_id_elem = self
            .key_identifier
            .as_ref()
            .map(|key_id| Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::OctetString(key_id.clone())),
            });

        let issuer_elem = match &self.authority_cert_issuer {
            Some(issuers) => {
                let issuer_elements = issuers
                    .iter()
                    .map(|name| name.encode())
                    .collect::<Result<Vec<_>, _>>()?;
                Some(Element::ContextSpecific {
                    constructed: true,
                    slot: 1,
                    element: Box::new(Element::Sequence(issuer_elements)),
                })
            }
            None => None,
        };

        let serial_elem = self.authority_cert_serial_number.as_ref().map(|serial| {
            let serial_bytes = serial.as_ref().to_signed_bytes_be();
            Element::ContextSpecific {
                constructed: false,
                slot: 2,
                element: Box::new(Element::OctetString(OctetString::from(serial_bytes))),
            }
        });

        let elements = key_id_elem
            .into_iter()
            .chain(issuer_elem)
            .chain(serial_elem)
            .collect();

        Ok(Element::Sequence(elements))
    }
}

impl OidName for AuthorityKeyIdentifier {
    fn oid_name(&self) -> Option<&'static str> {
        Some("authorityKeyIdentifier")
    }
}

impl fmt::Display for AuthorityKeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("authorityKeyIdentifier");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        if let Some(ref key_id) = self.key_identifier {
            let hex_str = key_id
                .as_bytes()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>();
            writeln!(f, "                keyid:{}", hex_str.join(":"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertificateSerialNumber;
    use crate::extensions::RawExtension;

    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::OctetString;
    use tsumiki_asn1::{Element, ObjectIdentifier};

    // AuthorityKeyIdentifier tests
    #[rstest(
        input,
        expected,
        // Test case: Only keyIdentifier [0]
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 0,
                    element: Box::new(Element::OctetString(OctetString::from(vec![0x01, 0x02, 0x03, 0x04]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::from(vec![0x01, 0x02, 0x03, 0x04])),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            }
        ),
        // Test case: Only serialNumber [2]
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::Integer(tsumiki_asn1::Integer::from(vec![0x01, 0x23, 0x45]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: None,
                authority_cert_issuer: None,
                authority_cert_serial_number: Some(CertificateSerialNumber::from_bytes(vec![0x01, 0x23, 0x45])),
            }
        ),
        // Test case: keyIdentifier and serialNumber
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 0,
                    element: Box::new(Element::OctetString(OctetString::from(vec![0xAA, 0xBB, 0xCC]))),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::Integer(tsumiki_asn1::Integer::from(vec![0xFF]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::from(vec![0xAA, 0xBB, 0xCC])),
                authority_cert_issuer: None,
                authority_cert_serial_number: Some(CertificateSerialNumber::from_bytes(vec![0xFF])),
            }
        ),
        // Test case: Empty sequence (all fields OPTIONAL)
        case(
            Element::Sequence(vec![]),
            AuthorityKeyIdentifier {
                key_identifier: None,
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            }
        ),
    )]
    fn test_authority_key_identifier_decode_success(
        input: Element,
        expected: AuthorityKeyIdentifier,
    ) {
        let result: Result<AuthorityKeyIdentifier, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a Sequence
        case(
            Element::Boolean(true),
            "expected SEQUENCE"
        ),
        // Test case: keyIdentifier [0] is not OctetString
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 0,
                    element: Box::new(Element::Integer(tsumiki_asn1::Integer::from(vec![0x01]))),
                },
            ]),
            "keyIdentifier must be OCTET STRING"
        ),
        // Test case: serialNumber [2] is invalid type (BitString)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::BitString(tsumiki_asn1::BitString::try_from(vec![0x00, 0x01]).unwrap())),
                },
            ]),
            "serialNumber must be OCTET STRING or INTEGER"
        ),
    )]
    fn test_authority_key_identifier_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<AuthorityKeyIdentifier, _> = input.decode();
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
    fn test_authority_key_identifier_parse_with_real_values() {
        // Test with actual values from OpenSSL-generated certificate
        // keyid:78:D4:81:76:CD:F7:8D:59:6D:D4:C4:86:A4:1D:23:0A:53:CE:CD:D7
        let key_id = vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];

        // Create Element structure directly (simulating parsed DER)
        let element = Element::Sequence(vec![Element::ContextSpecific {
            constructed: false,
            slot: 0,
            element: Box::new(Element::OctetString(OctetString::from(key_id.clone()))),
        }]);

        let result: Result<AuthorityKeyIdentifier, Error> = element.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let aki = result.unwrap();
        assert_eq!(aki.key_identifier, Some(OctetString::from(key_id)));
        assert_eq!(aki.authority_cert_issuer, None);
        assert_eq!(aki.authority_cert_serial_number, None);
    }

    #[test]
    fn test_authority_key_identifier_parse_from_real_der() {
        // Real DER-encoded AuthorityKeyIdentifier from OpenSSL-generated certificate
        // 30 16: SEQUENCE, length 22
        // 80 14: [0] IMPLICIT (context-specific primitive 0), length 20
        // 78D4...CDD7: keyIdentifier value (20 bytes SHA-1 hash)
        let der_bytes = vec![
            0x30, 0x16, 0x80, 0x14, 0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
            0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(AuthorityKeyIdentifier::OID).unwrap(),
            false,
            octet_string,
        );

        let result = extension.parse::<AuthorityKeyIdentifier>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let aki = result.unwrap();

        let expected_key_id = OctetString::from(vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ]);
        assert_eq!(aki.key_identifier, Some(expected_key_id));
        assert_eq!(aki.authority_cert_issuer, None);
        assert_eq!(aki.authority_cert_serial_number, None);
    }

    #[rstest]
    #[case(AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::from(vec![0x01, 0x02, 0x03])),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    })]
    #[case(AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::from(vec![0xAA, 0xBB])),
        authority_cert_issuer: Some(vec![GeneralName::DnsName("ca.example.com".to_string())]),
        authority_cert_serial_number: Some(CertificateSerialNumber::from_bytes(vec![123u8])),
    })]
    #[case(AuthorityKeyIdentifier {
        key_identifier: None,
        authority_cert_issuer: Some(vec![GeneralName::DnsName("issuer.example.com".to_string())]),
        authority_cert_serial_number: Some(CertificateSerialNumber::from_bytes(vec![0x01, 0xC8])),
    })]
    fn test_authority_key_identifier_encode_decode(#[case] original: AuthorityKeyIdentifier) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<AuthorityKeyIdentifier, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
