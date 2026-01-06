use asn1::{ASN1Object, Element, OctetString};
use serde::{Deserialize, Serialize, Serializer};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::CertificateSerialNumber;
use crate::error::Error;
use crate::extensions::StandardExtension;
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

/// KeyIdentifier is an OCTET STRING used to identify a public key
/// Typically a SHA-1 hash of the SubjectPublicKeyInfo (20 bytes)
pub type KeyIdentifier = Vec<u8>;

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
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AuthorityKeyIdentifier", 3)?;
        // Serialize key_identifier as hex string
        if let Some(ref key_id) = self.key_identifier {
            let hex_string = key_id
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

impl StandardExtension for AuthorityKeyIdentifier {
    /// OID for AuthorityKeyIdentifier extension (2.5.29.35)
    const OID: &'static str = "2.5.29.35";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (Sequence) -> AuthorityKeyIdentifier
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidAuthorityKeyIdentifier(
                "empty sequence".to_string(),
            ));
        }

        // The first element should be a Sequence
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for AuthorityKeyIdentifier {}

impl Decoder<Element, AuthorityKeyIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityKeyIdentifier, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut key_identifier = None;
                let mut authority_cert_issuer = None;
                let mut authority_cert_serial_number = None;

                for elem in elements {
                    match elem {
                        // [0] IMPLICIT KeyIdentifier (OCTET STRING)
                        Element::ContextSpecific { slot: 0, element, .. } => {
                            if let Element::OctetString(os) = element.as_ref() {
                                key_identifier = Some(os.as_bytes().to_vec());
                            } else {
                                return Err(Error::InvalidAuthorityKeyIdentifier(
                                    "keyIdentifier must be OctetString".to_string(),
                                ));
                            }
                        }
                        // [1] IMPLICIT GeneralNames (SEQUENCE OF GeneralName)
                        Element::ContextSpecific { slot: 1, element, .. } => {
                            // GeneralNames is a SEQUENCE OF GeneralName
                            match element.as_ref() {
                                Element::Sequence(names) => {
                                    let mut parsed_names = Vec::new();
                                    for name_elem in names {
                                        // Each GeneralName is a context-specific tagged element
                                        let general_name: GeneralName = name_elem.decode()?;
                                        parsed_names.push(general_name);
                                    }
                                    authority_cert_issuer = Some(parsed_names);
                                }
                                _ => {
                                    return Err(Error::InvalidAuthorityKeyIdentifier(
                                        "authorityCertIssuer must be Sequence (GeneralNames)"
                                            .to_string(),
                                    ));
                                }
                            }
                        }
                        // [2] IMPLICIT CertificateSerialNumber (INTEGER)
                        Element::ContextSpecific { slot: 2, element, .. } => {
                            // IMPLICIT tagging: OctetString wrapper around raw INTEGER bytes
                            if let Element::OctetString(os) = element.as_ref() {
                                authority_cert_serial_number = Some(
                                    CertificateSerialNumber::from_bytes(os.as_bytes().to_vec()),
                                );
                            } else if let Element::Integer(i) = element.as_ref() {
                                // EXPLICIT tagging (less common but valid)
                                authority_cert_serial_number =
                                    Some(CertificateSerialNumber::from(i.clone()));
                            } else {
                                return Err(Error::InvalidAuthorityKeyIdentifier(
                                    "serialNumber must be OctetString (IMPLICIT) or Integer (EXPLICIT)".to_string(),
                                ));
                            }
                        }
                        _ => {
                            return Err(Error::InvalidAuthorityKeyIdentifier(format!(
                                "unexpected element: {:?}",
                                elem
                            )));
                        }
                    }
                }

                Ok(AuthorityKeyIdentifier {
                    key_identifier,
                    authority_cert_issuer,
                    authority_cert_serial_number,
                })
            }
            _ => Err(Error::InvalidAuthorityKeyIdentifier(
                "expected Sequence".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertificateSerialNumber, extensions::Extension};
    use asn1::OctetString;
    use asn1::{Element, ObjectIdentifier};
    use rstest::rstest;
    use std::str::FromStr;

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
                key_identifier: Some(vec![0x01, 0x02, 0x03, 0x04]),
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
                    element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01, 0x23, 0x45]))),
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
                    element: Box::new(Element::Integer(asn1::Integer::from(vec![0xFF]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: Some(vec![0xAA, 0xBB, 0xCC]),
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
            "expected Sequence"
        ),
        // Test case: keyIdentifier [0] is not OctetString
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 0,
                    element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01]))),
                },
            ]),
            "keyIdentifier must be OctetString"
        ),
        // Test case: serialNumber [2] is invalid type (BitString)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::BitString(asn1::BitString::try_from(vec![0x00, 0x01]).unwrap())),
                },
            ]),
            "serialNumber must be OctetString (IMPLICIT) or Integer (EXPLICIT)"
        ),
    )]
    fn test_authority_key_identifier_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<AuthorityKeyIdentifier, Error> = input.decode();
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
        assert_eq!(aki.key_identifier, Some(key_id));
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

        let extension = Extension {
            id: ObjectIdentifier::from_str(AuthorityKeyIdentifier::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<AuthorityKeyIdentifier>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let aki = result.unwrap();

        let expected_key_id = vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        assert_eq!(aki.key_identifier, Some(expected_key_id));
        assert_eq!(aki.authority_cert_issuer, None);
        assert_eq!(aki.authority_cert_serial_number, None);
    }
}
