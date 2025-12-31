use asn1::{ASN1Object, Element, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::{error::Error, extensions::StandardExtension};

/*
RFC 5280 Section 4.2.1.2
SubjectKeyIdentifier ::= KeyIdentifier
KeyIdentifier ::= OCTET STRING

The SubjectKeyIdentifier extension provides a means of identifying certificates
that contain a particular public key. Typically, this is a SHA-1 hash of the
subjectPublicKey (excluding the tag, length, and number of unused bits).
*/

/// KeyIdentifier is an OCTET STRING used to identify a public key
/// Typically a SHA-1 hash of the SubjectPublicKeyInfo (20 bytes)
pub type KeyIdentifier = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectKeyIdentifier {
    /// KeyIdentifier: typically a SHA-1 hash of the subject's public key (20 bytes)
    pub key_identifier: KeyIdentifier,
}

impl DecodableFrom<OctetString> for SubjectKeyIdentifier {}

impl Decoder<OctetString, SubjectKeyIdentifier> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectKeyIdentifier, Self::Error> {
        // SubjectKeyIdentifier is an OCTET STRING containing another OCTET STRING
        // The outer OCTET STRING is the extension value wrapper (handled by Extension)
        // Parse the inner DER structure
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidSubjectKeyIdentifier(
                "empty content".to_string(),
            ));
        }

        // The first element should be an OctetString
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for SubjectKeyIdentifier {}

impl Decoder<Element, SubjectKeyIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectKeyIdentifier, Self::Error> {
        match self {
            Element::OctetString(os) => Ok(SubjectKeyIdentifier {
                key_identifier: os.as_bytes().to_vec(),
            }),
            _ => Err(Error::InvalidSubjectKeyIdentifier(
                "expected OctetString".to_string(),
            )),
        }
    }
}

impl StandardExtension for SubjectKeyIdentifier {
    /// OID for SubjectKeyIdentifier extension (2.5.29.14)
    const OID: &'static str = "2.5.29.14";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::Extension;
    use asn1::Element;
    use asn1::{ObjectIdentifier, OctetString};
    use rstest::rstest;
    use std::str::FromStr;

    // ========== SubjectKeyIdentifier Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Typical 20-byte SHA-1 hash
        case(
            Element::OctetString(OctetString::from(vec![
                0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
                0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
            ])),
            SubjectKeyIdentifier {
                key_identifier: vec![
                    0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
                    0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
                ],
            }
        ),
        // Test case: Shorter identifier (4 bytes)
        case(
            Element::OctetString(OctetString::from(vec![0xAA, 0xBB, 0xCC, 0xDD])),
            SubjectKeyIdentifier {
                key_identifier: vec![0xAA, 0xBB, 0xCC, 0xDD],
            }
        ),
        // Test case: Single byte identifier
        case(
            Element::OctetString(OctetString::from(vec![0x42])),
            SubjectKeyIdentifier {
                key_identifier: vec![0x42],
            }
        ),
    )]
    fn test_subject_key_identifier_decode_success(input: Element, expected: SubjectKeyIdentifier) {
        let result: Result<SubjectKeyIdentifier, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not an OctetString (Integer)
        case(
            Element::Integer(asn1::Integer::from(vec![0x01, 0x02])),
            "expected OctetString"
        ),
        // Test case: Not an OctetString (Sequence)
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(vec![0x01]))
            ]),
            "expected OctetString"
        ),
    )]
    fn test_subject_key_identifier_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectKeyIdentifier, Error> = input.decode();
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
    fn test_subject_key_identifier_parse_from_real_der() {
        // Real DER-encoded SubjectKeyIdentifier from OpenSSL-generated certificate
        // 04 14: OCTET STRING, length 20
        // 78D4...CDD7: keyIdentifier value (20 bytes SHA-1 hash)
        let der_bytes = vec![
            0x04, 0x14, 0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86,
            0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = Extension {
            id: ObjectIdentifier::from_str(SubjectKeyIdentifier::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<SubjectKeyIdentifier>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let ski = result.unwrap();

        let expected_key_id = vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        assert_eq!(ski.key_identifier, expected_key_id);
    }
}
