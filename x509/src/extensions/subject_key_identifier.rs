use asn1::{ASN1Object, Element, OctetString};
use pkix_types::OidName;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::error;
use crate::error::Error;
use crate::extensions::Extension;

/*
RFC 5280 Section 4.2.1.2
SubjectKeyIdentifier ::= KeyIdentifier
KeyIdentifier ::= OCTET STRING

The SubjectKeyIdentifier extension provides a means of identifying certificates
that contain a particular public key. Typically, this is a SHA-1 hash of the
subjectPublicKey (excluding the tag, length, and number of unused bits).
*/

// Re-export KeyIdentifier from pkix-types for backward compatibility
pub use pkix_types::KeyIdentifier;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SubjectKeyIdentifier {
    /// KeyIdentifier: typically a SHA-1 hash of the subject's public key (20 bytes)
    pub key_identifier: KeyIdentifier,
}

impl Serialize for SubjectKeyIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SubjectKeyIdentifier", 1)?;
        let hex_string = self
            .key_identifier
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        state.serialize_field("key_identifier", &hex_string)?;
        state.end()
    }
}

impl DecodableFrom<OctetString> for SubjectKeyIdentifier {}

impl Decoder<OctetString, SubjectKeyIdentifier> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectKeyIdentifier, Self::Error> {
        // SubjectKeyIdentifier is an OCTET STRING containing another OCTET STRING
        // The outer OCTET STRING is the extension value wrapper (handled by Extension)
        // Parse the inner DER structure
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;

        // The first element should be an OctetString
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(error::Kind::SubjectKeyIdentifier).into()),
        }
    }
}

impl DecodableFrom<Element> for SubjectKeyIdentifier {}

impl Decoder<Element, SubjectKeyIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectKeyIdentifier, Self::Error> {
        match self {
            Element::OctetString(os) => Ok(SubjectKeyIdentifier {
                key_identifier: os.clone(),
            }),
            _ => Err(error::Error::ExpectedOctetString(error::Kind::SubjectKeyIdentifier).into()),
        }
    }
}

impl EncodableTo<SubjectKeyIdentifier> for Element {}

impl Encoder<SubjectKeyIdentifier, Element> for SubjectKeyIdentifier {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::OctetString(self.key_identifier.clone()))
    }
}

impl Extension for SubjectKeyIdentifier {
    /// OID for SubjectKeyIdentifier extension (2.5.29.14)
    const OID: &'static str = "2.5.29.14";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for SubjectKeyIdentifier {
    fn oid_name(&self) -> Option<&'static str> {
        Some("subjectKeyIdentifier")
    }
}

impl fmt::Display for SubjectKeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("subjectKeyIdentifier");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        let hex_str = self
            .key_identifier
            .as_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>();
        writeln!(f, "                {}", hex_str.join(":"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RawExtension;
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
                key_identifier: OctetString::from(vec![
                    0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
                    0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
                ]),
            }
        ),
        // Test case: Shorter identifier (4 bytes)
        case(
            Element::OctetString(OctetString::from(vec![0xAA, 0xBB, 0xCC, 0xDD])),
            SubjectKeyIdentifier {
                key_identifier: OctetString::from(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            }
        ),
        // Test case: Single byte identifier
        case(
            Element::OctetString(OctetString::from(vec![0x42])),
            SubjectKeyIdentifier {
                key_identifier: OctetString::from(vec![0x42]),
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
            "expected OCTET STRING"
        ),
        // Test case: Not an OctetString (Sequence)
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(vec![0x01]))
            ]),
            "expected OCTET STRING"
        ),
    )]
    fn test_subject_key_identifier_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectKeyIdentifier, _> = input.decode();
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
    #[case(SubjectKeyIdentifier { key_identifier: OctetString::from(vec![0x01, 0x02, 0x03, 0x04]) })]
    #[case(SubjectKeyIdentifier { key_identifier: OctetString::from(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) })]
    #[case(SubjectKeyIdentifier { key_identifier: OctetString::from(vec![
        0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
        0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
    ]) })]
    fn test_subject_key_identifier_encode_decode(#[case] original: SubjectKeyIdentifier) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<SubjectKeyIdentifier, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
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

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(SubjectKeyIdentifier::OID).unwrap(),
            false,
            octet_string,
        );

        let result = extension.parse::<SubjectKeyIdentifier>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let ski = result.unwrap();

        let expected_key_id = OctetString::from(vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ]);
        assert_eq!(ski.key_identifier, expected_key_id);
    }
}
