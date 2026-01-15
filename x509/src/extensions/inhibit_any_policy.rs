use asn1::OctetString;
use asn1::{ASN1Object, Element, Integer};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::Error;

use super::{Extension, policy_constraints::SkipCerts};

/*
RFC 5280 Section 4.2.1.14

InhibitAnyPolicy ::= SkipCerts

SkipCerts ::= INTEGER (0..MAX)

The inhibitAnyPolicy extension can be used in certificates issued to CAs.
The inhibitAnyPolicy extension indicates that the special anyPolicy OID,
with the value { 2 5 29 32 0 }, is not considered an explicit match for
other certificate policies except when it appears in an intermediate
self-issued CA certificate.

The value indicates the number of additional certificates that may appear
in the path before anyPolicy is no longer permitted. For example, a value
of one indicates that anyPolicy may be processed in certificates issued by
the subject of this certificate, but not in additional certificates in the path.
*/

/// InhibitAnyPolicy extension
/// OID: 2.5.29.54
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InhibitAnyPolicy {
    /// Number of additional certificates that may appear in the path
    /// before anyPolicy is no longer permitted
    pub skip_certs: SkipCerts,
}

impl Extension for InhibitAnyPolicy {
    /// OID for InhibitAnyPolicy extension (2.5.29.54)
    const OID: &'static str = "2.5.29.54";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidInhibitAnyPolicy("empty content".to_string()));
        }

        elements[0].decode()
    }
}

impl DecodableFrom<Element> for InhibitAnyPolicy {}

impl Decoder<Element, InhibitAnyPolicy> for Element {
    type Error = Error;

    fn decode(&self) -> Result<InhibitAnyPolicy, Self::Error> {
        match self {
            Element::Integer(int) => {
                let skip_certs = int.to_u32().ok_or_else(|| {
                    Error::InvalidInhibitAnyPolicy(
                        "skipCerts value out of range for u32".to_string(),
                    )
                })?;
                Ok(InhibitAnyPolicy { skip_certs })
            }
            _ => Err(Error::InvalidInhibitAnyPolicy(
                "expected Integer".to_string(),
            )),
        }
    }
}

impl EncodableTo<InhibitAnyPolicy> for Element {}

impl Encoder<InhibitAnyPolicy, Element> for InhibitAnyPolicy {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let bytes = self.skip_certs.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let slice = bytes.get(start..).unwrap_or(&bytes);
        Ok(Element::Integer(Integer::from(slice)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::Integer;
    use rstest::rstest;

    #[rstest]
    #[case(0, vec![0x02, 0x01, 0x00])] // INTEGER 0
    #[case(1, vec![0x02, 0x01, 0x01])] // INTEGER 1
    #[case(5, vec![0x02, 0x01, 0x05])] // INTEGER 5
    #[case(255, vec![0x02, 0x02, 0x00, 0xFF])] // INTEGER 255
    fn test_inhibit_any_policy_decode_success(#[case] expected_skip: u32, #[case] input: Vec<u8>) {
        let elem = Element::Integer(Integer::from(input[2..].to_vec()));
        let result: Result<InhibitAnyPolicy, Error> = elem.decode();

        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let policy = result.unwrap();
        assert_eq!(policy.skip_certs, expected_skip);
    }

    #[rstest]
    #[case("OctetString instead of Integer")] // OctetString instead of Integer
    #[case("Null instead of Integer")] // Null instead of Integer
    #[case("UTF8String instead of Integer")] // UTF8String instead of Integer
    fn test_inhibit_any_policy_decode_failure(#[case] test_name: &str) {
        let elem = match test_name {
            "OctetString instead of Integer" => {
                Element::OctetString(asn1::OctetString::from(vec![0x00]))
            }
            "Null instead of Integer" => Element::Null,
            "UTF8String instead of Integer" => Element::UTF8String("0".to_string()),
            _ => panic!("Unknown test case"),
        };

        let result: Result<InhibitAnyPolicy, Error> = elem.decode();

        assert!(result.is_err(), "Expected error but got: {:?}", result);
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("expected Integer"),
            "Error message 'expected Integer' not found in '{}'",
            err_str
        );
    }

    #[test]
    fn test_inhibit_any_policy_parse() {
        // Test full parsing through Extension::parse
        // DER: OCTET STRING containing INTEGER 3
        let octet_string = OctetString::from(vec![0x02, 0x01, 0x03]);

        let result = InhibitAnyPolicy::parse(&octet_string);
        assert!(result.is_ok(), "Failed to parse: {:?}", result);

        let policy = result.unwrap();
        assert_eq!(policy.skip_certs, 3);
    }

    #[test]
    fn test_inhibit_any_policy_zero() {
        // Special case: skip_certs = 0 means anyPolicy is immediately prohibited
        let elem = Element::Integer(Integer::from(vec![0x00]));
        let result: Result<InhibitAnyPolicy, Error> = elem.decode();

        assert!(result.is_ok());
        let policy = result.unwrap();
        assert_eq!(policy.skip_certs, 0);
    }

    #[test]
    fn test_inhibit_any_policy_large_value() {
        // Test with larger value (e.g., 1000 = 0x03E8)
        let elem = Element::Integer(Integer::from(vec![0x03, 0xE8]));
        let result: Result<InhibitAnyPolicy, Error> = elem.decode();

        assert!(result.is_ok());
        let policy = result.unwrap();
        assert_eq!(policy.skip_certs, 1000);
    }
}
