//! PKCS#9 messageDigest attribute (OID: 1.2.840.113549.1.9.4)
//!
//! Defined in RFC 2985 Section 5.3.2
//!
//! ```asn1
//! messageDigest ATTRIBUTE ::= {
//!     WITH SYNTAX MessageDigest
//!     EQUALITY MATCHING RULE octetStringMatch
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-messageDigest
//! }
//!
//! MessageDigest ::= OCTET STRING
//! ```
//!
//! The messageDigest attribute type specifies the message digest of the
//! contents octets of the DER-encoding of the content field of the
//! ContentInfo value being signed in PKCS #7 digitally signed data.
//! The message-digest attribute type is required in these cases if there
//! are any PKCS #7 authenticated attributes present.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};
use std::fmt;
use tsumiki_asn1::{Element, OctetString};

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, extract_single_value};

/// messageDigest attribute
///
/// Contains an OCTET STRING that specifies the message digest
/// computed over the content being signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDigest {
    digest: OctetString,
}

impl MessageDigest {
    /// Create a new MessageDigest attribute
    pub fn new(digest: OctetString) -> Result<Self> {
        if digest.as_ref().is_empty() {
            return Err(Error::EmptyValue("messageDigest".into()));
        }
        Ok(Self { digest })
    }

    /// Get the message digest as OctetString
    pub fn digest(&self) -> &OctetString {
        &self.digest
    }
}

impl fmt::Display for MessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: Vec<String> = self
            .digest
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        write!(f, "{}", hex.join(":"))
    }
}

impl Serialize for MessageDigest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MessageDigest", 1)?;
        state.serialize_field("messageDigest", &self.digest.hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MessageDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            MessageDigest,
        }

        struct MessageDigestVisitor;

        impl<'de> de::Visitor<'de> for MessageDigestVisitor {
            type Value = MessageDigest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct MessageDigest")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MessageDigest, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut digest = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::MessageDigest => {
                            if digest.is_some() {
                                return Err(de::Error::duplicate_field("messageDigest"));
                            }
                            let hex_str: String = map.next_value()?;
                            let bytes = (0..hex_str.len())
                                .step_by(2)
                                .map(|i| {
                                    u8::from_str_radix(&hex_str[i..i + 2], 16)
                                        .map_err(de::Error::custom)
                                })
                                .collect::<std::result::Result<Vec<u8>, _>>()?;
                            digest = Some(OctetString::from(bytes));
                        }
                    }
                }
                let digest = digest.ok_or_else(|| de::Error::missing_field("messageDigest"))?;
                MessageDigest::new(digest).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["messageDigest"];
        deserializer.deserialize_struct("MessageDigest", FIELDS, MessageDigestVisitor)
    }
}

impl Attribute for MessageDigest {
    /// OID for messageDigest: 1.2.840.113549.1.9.4
    const OID: &'static str = "1.2.840.113549.1.9.4";

    fn parse(values: &OctetString) -> Result<Self> {
        let value = extract_single_value(values, "messageDigest")?;

        // The value should be an OCTET STRING
        let Element::OctetString(octet_string) = value else {
            return Err(Error::InvalidMessageDigestExpectedOctetString);
        };

        Self::new(octet_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tsumiki::encoder::Encoder;
    use tsumiki_asn1::ASN1Object;

    #[rstest]
    #[case(vec![0x01, 0x02, 0x03, 0x04], "01020304")]
    #[case(vec![0xff, 0xee, 0xdd, 0xcc], "ffeeddcc")]
    #[case(vec![0x00], "00")]
    #[case(vec![0xab, 0xcd, 0xef], "abcdef")]
    fn test_message_digest_new(#[case] input: Vec<u8>, #[case] expected_hex: &str) {
        let digest = MessageDigest::new(OctetString::from(input.clone())).unwrap();
        assert_eq!(digest.digest().as_ref(), input.as_slice());
        assert_eq!(digest.digest().hex(), expected_hex);
    }

    #[rstest]
    #[case(MessageDigest::new(OctetString::from(vec![0x01, 0x02, 0x03])).unwrap(), vec![0x01, 0x02, 0x03])]
    #[case(MessageDigest::new(OctetString::from(vec![0xaa, 0xbb, 0xcc, 0xdd])).unwrap(), vec![0xaa, 0xbb, 0xcc, 0xdd])]
    #[case(MessageDigest::new(OctetString::from(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])).unwrap(), vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])]
    fn test_message_digest_encode_decode(#[case] input: MessageDigest, #[case] expected: Vec<u8>) {
        // Create a SET containing the OCTET STRING
        let set_elem = Element::Set(vec![Element::OctetString(input.digest().clone())]);
        let set_obj = ASN1Object::new(vec![set_elem]);
        let der = set_obj.encode().unwrap();
        let encoded = der.encode().unwrap();

        let decoded = MessageDigest::parse(&OctetString::from(encoded)).unwrap();
        assert_eq!(decoded.digest().as_ref(), expected.as_slice());
    }

    #[rstest]
    #[case(MessageDigest::new(OctetString::from(vec![0x01, 0x02, 0x03, 0x04])).unwrap(), "01020304")]
    #[case(MessageDigest::new(OctetString::from(vec![0xde, 0xad, 0xbe, 0xef])).unwrap(), "deadbeef")]
    #[case(MessageDigest::new(OctetString::from(vec![0xff, 0x00, 0xaa])).unwrap(), "ff00aa")]
    fn test_message_digest_serde_roundtrip(#[case] input: MessageDigest, #[case] expected: &str) {
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("messageDigest"));
        assert!(json.contains(expected));

        let decoded: MessageDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.digest().hex(), expected);
    }
}
