//! PKCS#9 localKeyId attribute (OID: 1.2.840.113549.1.9.21)
//!
//! Defined in RFC 2985 Section 5.5.2
//!
//! ```asn1
//! localKeyId ATTRIBUTE ::= {
//!     WITH SYNTAX OCTET STRING
//!     EQUALITY MATCHING RULE octetStringMatch
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-localKeyId
//! }
//! ```
//!
//! The localKeyId attribute type specifies a unique identifier
//! for a key or certificate. This is commonly used in PKCS#12
//! to link private keys with their corresponding certificates.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};
use std::fmt;
use tsumiki_asn1::{Element, OctetString};

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, extract_single_value};

/// localKeyId attribute
///
/// Contains an OCTET STRING value that uniquely identifies
/// a key or certificate within a PKCS#12 structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeyId {
    /// The key identifier as an OCTET STRING
    key_id: OctetString,
}

impl LocalKeyId {
    /// Create a new LocalKeyId
    pub fn new(key_id: OctetString) -> Result<Self> {
        if key_id.as_ref().is_empty() {
            return Err(Error::EmptyValue("localKeyId".into()));
        }
        Ok(Self { key_id })
    }

    /// Get the key identifier
    pub fn key_id(&self) -> &OctetString {
        &self.key_id
    }
}

impl fmt::Display for LocalKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: Vec<String> = self
            .key_id
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        write!(f, "{}", hex.join(":"))
    }
}

impl Serialize for LocalKeyId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LocalKeyId", 1)?;
        state.serialize_field("localKeyId", &self.key_id.hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for LocalKeyId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            LocalKeyId,
        }

        struct LocalKeyIdVisitor;

        impl<'de> de::Visitor<'de> for LocalKeyIdVisitor {
            type Value = LocalKeyId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct LocalKeyId")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<LocalKeyId, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut hex_string: Option<String> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::LocalKeyId => {
                            if hex_string.is_some() {
                                return Err(de::Error::duplicate_field("localKeyId"));
                            }
                            hex_string = Some(map.next_value()?);
                        }
                    }
                }
                let hex_string =
                    hex_string.ok_or_else(|| de::Error::missing_field("localKeyId"))?;

                // Parse hex string to bytes
                let bytes: Vec<u8> = (0..hex_string.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16))
                    .collect::<std::result::Result<Vec<u8>, _>>()
                    .map_err(|e| de::Error::custom(format!("Invalid hex: {}", e)))?;

                LocalKeyId::new(OctetString::from(bytes)).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["localKeyId"];
        deserializer.deserialize_struct("LocalKeyId", FIELDS, LocalKeyIdVisitor)
    }
}

impl Attribute for LocalKeyId {
    const OID: &'static str = "1.2.840.113549.1.9.21";

    fn parse(values: &OctetString) -> Result<Self> {
        let value = extract_single_value(values, "localKeyId")?;

        // The value should be an OCTET STRING
        let Element::OctetString(octet_string) = value else {
            return Err(Error::InvalidLocalKeyIdExpectedOctetString);
        };

        Ok(Self {
            key_id: octet_string,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;
    use tsumiki_asn1::{ASN1Object, Element, ObjectIdentifier};

    use crate::pkcs9::attribute::RawAttribute;

    #[rstest]
    #[case(vec![0x01, 0x02, 0x03, 0x04], "01020304")]
    #[case(vec![0xff, 0xee, 0xdd, 0xcc], "ffeeddcc")]
    #[case(vec![0x00], "00")]
    #[case(vec![0xab, 0xcd, 0xef], "abcdef")]
    fn test_local_key_id_new(#[case] key_id: Vec<u8>, #[case] expected_hex: &str) {
        let local_key_id = LocalKeyId::new(OctetString::from(key_id.clone())).unwrap();
        assert_eq!(local_key_id.key_id().as_ref(), key_id.as_slice());
        assert_eq!(local_key_id.key_id().hex(), expected_hex);
    }

    #[test]
    fn test_local_key_id_empty() {
        let result = LocalKeyId::new(OctetString::from(vec![]));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::EmptyValue(_)));
    }

    #[rstest]
    #[case(vec![0x01, 0x02, 0x03])]
    #[case(vec![0xaa, 0xbb, 0xcc, 0xdd])]
    #[case(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])]
    fn test_local_key_id_parse(#[case] key_id: Vec<u8>) {
        // Create an OCTET STRING element
        let octet_value = Element::OctetString(OctetString::from(key_id.clone()));

        // Wrap in SET
        let set = Element::Set(vec![octet_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse as LocalKeyId
        let local_key_id = LocalKeyId::parse(&octet_string).unwrap();
        assert_eq!(local_key_id.key_id().as_ref(), key_id.as_slice());
    }

    #[rstest]
    #[case(vec![0x11, 0x22, 0x33, 0x44])]
    #[case(vec![0xde, 0xad, 0xbe, 0xef])]
    #[case(vec![0x00, 0x11, 0x22, 0x33])]
    fn test_local_key_id_via_raw_attribute(#[case] key_id: Vec<u8>) {
        // Create a complete RawAttribute with localKeyId
        let octet_value = Element::OctetString(OctetString::from(key_id.clone()));
        let set = Element::Set(vec![octet_value]);
        let oid = ObjectIdentifier::from_str(LocalKeyId::OID).unwrap();

        let attr_seq = Element::Sequence(vec![Element::ObjectIdentifier(oid), set]);

        // Decode as RawAttribute
        let raw_attr: RawAttribute = attr_seq.decode().unwrap();

        // Parse as LocalKeyId
        let local_key_id: LocalKeyId = raw_attr.parse().unwrap();
        assert_eq!(local_key_id.key_id().as_ref(), key_id.as_slice());
    }

    #[rstest]
    #[case(vec![0x01, 0x02, 0x03, 0x04], "01020304")]
    #[case(vec![0xff, 0xff, 0xff, 0xff], "ffffffff")]
    #[case(vec![0x00, 0x00, 0x00, 0x00], "00000000")]
    fn test_local_key_id_hex_format(#[case] key_id: Vec<u8>, #[case] expected: &str) {
        let local_key_id = LocalKeyId::new(OctetString::from(key_id)).unwrap();
        assert_eq!(local_key_id.key_id().hex(), expected);
    }

    #[rstest]
    #[case(vec![0x01, 0x02, 0x03, 0x04])]
    #[case(vec![0xde, 0xad, 0xbe, 0xef])]
    #[case(vec![0xff, 0x00, 0xaa])]
    fn test_local_key_id_serde(#[case] key_id: Vec<u8>) {
        let local_key_id = LocalKeyId::new(OctetString::from(key_id.clone())).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&local_key_id).unwrap();
        assert!(json.contains("localKeyId"));
        assert!(json.contains(&local_key_id.key_id().hex()));

        // Deserialize back
        let deserialized: LocalKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, local_key_id);
        assert_eq!(deserialized.key_id().as_ref(), key_id.as_slice());
    }
}
