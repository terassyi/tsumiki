//! PKCS#9 friendlyName attribute (OID: 1.2.840.113549.1.9.20)
//!
//! Defined in RFC 2985 Section 5.5.1
//!
//! ```asn1
//! friendlyName ATTRIBUTE ::= {
//!     WITH SYNTAX BMPString (SIZE(1..pkcs-9-ub-friendlyName))
//!     EQUALITY MATCHING RULE caseIgnoreMatch
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-friendlyName
//! }
//! ```
//!
//! The friendlyName attribute type specifies a user-friendly name
//! for the object it belongs to. This is commonly used in PKCS#12
//! to provide human-readable names for certificates and private keys.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};
use std::fmt;
use tsumiki_asn1::{Element, OctetString};

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, extract_single_value};

/// friendlyName attribute
///
/// Contains a BMPString (Basic Multilingual Plane string) value
/// that provides a user-friendly name for an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendlyName {
    /// The friendly name as a BMPString
    name: String,
}

impl FriendlyName {
    /// Maximum length for friendlyName (pkcs-9-ub-friendlyName)
    const MAX_LENGTH: usize = 255;

    /// Create a new FriendlyName
    pub fn new(name: String) -> Result<Self> {
        if name.is_empty() {
            return Err(Error::EmptyValue("friendlyName".into()));
        }
        if name.len() > Self::MAX_LENGTH {
            return Err(Error::ValueTooLong {
                max: Self::MAX_LENGTH,
                actual: name.len(),
            });
        }
        Ok(Self { name })
    }

    /// Get the friendly name
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for FriendlyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Serialize for FriendlyName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FriendlyName", 1)?;
        state.serialize_field("friendlyName", &self.name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for FriendlyName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            FriendlyName,
        }

        struct FriendlyNameVisitor;

        impl<'de> de::Visitor<'de> for FriendlyNameVisitor {
            type Value = FriendlyName;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct FriendlyName")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<FriendlyName, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut name = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::FriendlyName => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("friendlyName"));
                            }
                            name = Some(map.next_value()?);
                        }
                    }
                }
                let name = name.ok_or_else(|| de::Error::missing_field("friendlyName"))?;
                FriendlyName::new(name).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["friendlyName"];
        deserializer.deserialize_struct("FriendlyName", FIELDS, FriendlyNameVisitor)
    }
}

impl Attribute for FriendlyName {
    /// OID for friendlyName: 1.2.840.113549.1.9.20
    const OID: &'static str = "1.2.840.113549.1.9.20";

    fn parse(values: &OctetString) -> Result<Self> {
        let value = extract_single_value(values, "friendlyName")?;

        // The value should be a BMPString
        let Element::BMPString(bmp_string) = &value else {
            return Err(Error::InvalidFriendlyNameExpectedBmpString);
        };

        let name = bmp_string
            .try_into_string()
            .map_err(|e| Error::InvalidFriendlyNameBmpStringConversion(e.to_string()))?;
        Self::new(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;
    use tsumiki_asn1::{ASN1Object, ObjectIdentifier};

    use crate::pkcs9::attribute::RawAttribute;

    #[rstest]
    #[case("My Certificate", "My Certificate")]
    #[case("Test Name", "Test Name")]
    #[case("日本語証明書", "日本語証明書")]
    #[case("a", "a")]
    fn test_friendly_name_new(#[case] input: &str, #[case] expected: &str) {
        let name = FriendlyName::new(input.to_string()).unwrap();
        assert_eq!(name.name(), expected);
    }

    #[test]
    fn test_friendly_name_new_max_length() {
        let max_name = "x".repeat(255);
        let name = FriendlyName::new(max_name.clone()).unwrap();
        assert_eq!(name.name(), max_name);
    }

    #[rstest]
    #[case("Test Name")]
    #[case("My Certificate")]
    #[case("日本語")]
    #[case("Hello World")]
    fn test_friendly_name_parse(#[case] name: &str) {
        // Create a BMPString element
        let bmp_value = Element::BMPString(tsumiki_asn1::BMPString::new(name).unwrap());

        // Wrap in SET
        let set = Element::Set(vec![bmp_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse as FriendlyName
        let friendly_name = FriendlyName::parse(&octet_string).unwrap();
        assert_eq!(friendly_name.name(), name);
    }

    #[rstest]
    #[case("My Key")]
    #[case("Test Certificate")]
    #[case("証明書")]
    fn test_friendly_name_via_raw_attribute(#[case] name: &str) {
        // Create a complete RawAttribute with friendlyName
        let bmp_value = Element::BMPString(tsumiki_asn1::BMPString::new(name).unwrap());
        let set = Element::Set(vec![bmp_value]);
        let oid = ObjectIdentifier::from_str(FriendlyName::OID).unwrap();

        let attr_seq = Element::Sequence(vec![Element::ObjectIdentifier(oid), set]);

        // Decode as RawAttribute
        let raw_attr: RawAttribute = attr_seq.decode().unwrap();

        // Parse as FriendlyName
        let friendly_name: FriendlyName = raw_attr.parse().unwrap();
        assert_eq!(friendly_name.name(), name);
    }

    #[rstest]
    #[case("日本語証明書")]
    #[case("한국어")]
    #[case("中文")]
    #[case("Ελληνικά")]
    fn test_friendly_name_unicode(#[case] name: &str) {
        // BMPString supports Unicode (UCS-2)
        let bmp_value = Element::BMPString(tsumiki_asn1::BMPString::new(name).unwrap());
        let set = Element::Set(vec![bmp_value]);

        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        let friendly_name = FriendlyName::parse(&octet_string).unwrap();
        assert_eq!(friendly_name.name(), name);
    }

    #[rstest]
    #[case("Test 😀")]
    #[case("🎉")]
    #[case("Hello 👋 World")]
    fn test_friendly_name_emoji_not_supported(#[case] input: &str) {
        // Emoji (U+1F600 and above) are outside BMP and should fail
        let result = tsumiki_asn1::BMPString::new(input);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("My Certificate")]
    #[case("Test Key")]
    #[case("日本語証明書")]
    fn test_friendly_name_serde_roundtrip(#[case] name: &str) {
        let friendly_name = FriendlyName::new(name.to_string()).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&friendly_name).unwrap();
        assert!(json.contains("friendlyName"));
        assert!(json.contains(name));

        // Deserialize back
        let deserialized: FriendlyName = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, friendly_name);
        assert_eq!(deserialized.name(), name);
    }
}
