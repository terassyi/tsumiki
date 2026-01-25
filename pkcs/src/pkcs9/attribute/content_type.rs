//! PKCS#9 contentType attribute (OID: 1.2.840.113549.1.9.3)
//!
//! Defined in RFC 2985 Section 5.3.1
//!
//! ```asn1
//! contentType ATTRIBUTE ::= {
//!     WITH SYNTAX ContentType
//!     EQUALITY MATCHING RULE objectIdentifierMatch
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-contentType
//! }
//!
//! ContentType ::= OBJECT IDENTIFIER
//! ```
//!
//! The contentType attribute type specifies the content type of the
//! ContentInfo value being signed in PKCS #7 (or S/MIME CMS) digitally
//! signed data. In such data, the contentType attribute type is
//! required if there are any PKCS #7 authenticated attributes.

use asn1::{Element, ObjectIdentifier, OctetString};
use pkix_types::OidName;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};
use std::fmt;
use std::str::FromStr;

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, extract_single_value};

/// contentType attribute
///
/// Contains an OBJECT IDENTIFIER that specifies the content type
/// of the ContentInfo value being signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentType {
    content_type: ObjectIdentifier,
}

impl ContentType {
    // Well-known Content Type OIDs from RFC 5652 (CMS) and PKCS#7

    /// id-data: 1.2.840.113549.1.7.1
    /// Arbitrary octet string data
    pub const DATA_OID: &'static str = "1.2.840.113549.1.7.1";

    /// id-signedData: 1.2.840.113549.1.7.2
    /// Signed data content type
    pub const SIGNED_DATA_OID: &'static str = "1.2.840.113549.1.7.2";

    /// id-envelopedData: 1.2.840.113549.1.7.3
    /// Enveloped (encrypted) data content type
    pub const ENVELOPED_DATA_OID: &'static str = "1.2.840.113549.1.7.3";

    /// id-digestedData: 1.2.840.113549.1.7.5
    /// Digested data content type
    pub const DIGESTED_DATA_OID: &'static str = "1.2.840.113549.1.7.5";

    /// id-encryptedData: 1.2.840.113549.1.7.6
    /// Encrypted data content type
    pub const ENCRYPTED_DATA_OID: &'static str = "1.2.840.113549.1.7.6";

    /// id-ct-authData: 1.2.840.113549.1.9.16.1.2
    /// Authenticated data content type (CMS)
    pub const AUTHENTICATED_DATA_OID: &'static str = "1.2.840.113549.1.9.16.1.2";

    /// Create a new ContentType attribute
    pub fn new(content_type: ObjectIdentifier) -> Result<Self> {
        Ok(Self { content_type })
    }

    /// Get the content type OID
    pub fn content_type(&self) -> &ObjectIdentifier {
        &self.content_type
    }
}

impl OidName for ContentType {
    fn oid_name(&self) -> Option<&'static str> {
        match self.content_type.to_string().as_str() {
            Self::DATA_OID => Some("data"),
            Self::SIGNED_DATA_OID => Some("signedData"),
            Self::ENVELOPED_DATA_OID => Some("envelopedData"),
            Self::DIGESTED_DATA_OID => Some("digestedData"),
            Self::ENCRYPTED_DATA_OID => Some("encryptedData"),
            Self::AUTHENTICATED_DATA_OID => Some("authData"),
            _ => None,
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.oid_name() {
            write!(f, "{} ({})", name, self.content_type)
        } else {
            write!(f, "{}", self.content_type)
        }
    }
}

impl Serialize for ContentType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let use_oid = pkix_types::get_use_oid_values();
        let display_value = if use_oid {
            self.content_type.to_string()
        } else {
            self.oid_name()
                .unwrap_or(&self.content_type.to_string())
                .to_string()
        };

        let mut state = serializer.serialize_struct("ContentType", 1)?;
        state.serialize_field("contentType", &display_value)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            ContentType,
        }

        struct ContentTypeVisitor;

        impl<'de> de::Visitor<'de> for ContentTypeVisitor {
            type Value = ContentType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ContentType")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ContentType, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut content_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ContentType => {
                            if content_type.is_some() {
                                return Err(de::Error::duplicate_field("contentType"));
                            }
                            content_type = Some(map.next_value::<String>()?);
                        }
                    }
                }
                let content_type_str =
                    content_type.ok_or_else(|| de::Error::missing_field("contentType"))?;
                let oid = ObjectIdentifier::from_str(&content_type_str)
                    .map_err(|e| de::Error::custom(format!("Invalid OID: {}", e)))?;
                ContentType::new(oid).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["contentType"];
        deserializer.deserialize_struct("ContentType", FIELDS, ContentTypeVisitor)
    }
}

impl Attribute for ContentType {
    /// OID for contentType: 1.2.840.113549.1.9.3
    const OID: &'static str = "1.2.840.113549.1.9.3";

    fn parse(values: &OctetString) -> Result<Self> {
        let value = extract_single_value(values, "contentType")?;

        // The value should be an OBJECT IDENTIFIER
        let Element::ObjectIdentifier(oid) = value else {
            return Err(Error::InvalidContentTypeExpectedOid);
        };

        Self::new(oid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ASN1Object;
    use rstest::rstest;
    use tsumiki::encoder::Encoder;

    use crate::pkcs9::attribute::RawAttribute;

    #[rstest]
    #[case(ContentType::DATA_OID, ContentType::DATA_OID)]
    #[case(ContentType::SIGNED_DATA_OID, ContentType::SIGNED_DATA_OID)]
    #[case(ContentType::ENVELOPED_DATA_OID, ContentType::ENVELOPED_DATA_OID)]
    #[case(ContentType::DIGESTED_DATA_OID, ContentType::DIGESTED_DATA_OID)]
    fn test_content_type_new(#[case] input: &str, #[case] expected: &str) {
        let oid = ObjectIdentifier::from_str(input).unwrap();
        let content_type = ContentType::new(oid).unwrap();
        assert_eq!(content_type.content_type().to_string(), expected);
    }

    #[test]
    fn test_content_type_oid() {
        assert_eq!(ContentType::OID, "1.2.840.113549.1.9.3");
    }

    #[rstest]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::DATA_OID).unwrap()).unwrap(), ContentType::DATA_OID)]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::SIGNED_DATA_OID).unwrap()).unwrap(), ContentType::SIGNED_DATA_OID)]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::ENVELOPED_DATA_OID).unwrap()).unwrap(), ContentType::ENVELOPED_DATA_OID)]
    fn test_content_type_encode_decode(#[case] input: ContentType, #[case] expected: &str) {
        // Create a SET containing the OID
        let set_elem = Element::Set(vec![Element::ObjectIdentifier(
            input.content_type().clone(),
        )]);
        let set_obj = ASN1Object::new(vec![set_elem]);
        let der = set_obj.encode().unwrap();
        let encoded = der.encode().unwrap();

        let decoded = ContentType::parse(&OctetString::from(encoded)).unwrap();
        assert_eq!(decoded.content_type().to_string(), expected);
    }

    #[rstest]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::DATA_OID).unwrap()).unwrap(), ContentType::DATA_OID)]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::SIGNED_DATA_OID).unwrap()).unwrap(), ContentType::SIGNED_DATA_OID)]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::ENVELOPED_DATA_OID).unwrap()).unwrap(), ContentType::ENVELOPED_DATA_OID)]
    fn test_content_type_via_raw_attribute(#[case] input: ContentType, #[case] expected: &str) {
        // Create a SET containing the OID
        let set_elem = Element::Set(vec![Element::ObjectIdentifier(
            input.content_type().clone(),
        )]);
        let set_obj = ASN1Object::new(vec![set_elem]);
        let der = set_obj.encode().unwrap();
        let encoded = der.encode().unwrap();

        let raw_attr = RawAttribute {
            attribute_type: ObjectIdentifier::from_str(ContentType::OID).unwrap(),
            values: OctetString::from(encoded),
        };

        let decoded: ContentType = raw_attr.parse().unwrap();
        assert_eq!(decoded.content_type().to_string(), expected);
    }

    #[rstest]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::DATA_OID).unwrap()).unwrap(), "data", ContentType::DATA_OID)]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::SIGNED_DATA_OID).unwrap()).unwrap(), "signedData", ContentType::SIGNED_DATA_OID)]
    #[case(ContentType::new(ObjectIdentifier::from_str(ContentType::ENVELOPED_DATA_OID).unwrap()).unwrap(), "envelopedData", ContentType::ENVELOPED_DATA_OID)]
    fn test_content_type_serde_roundtrip(
        #[case] input: ContentType,
        #[case] expected_name: &str,
        #[case] expected_oid: &str,
    ) {
        // Test default behavior (conventional name)
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("contentType"));
        assert!(json.contains(expected_name));

        // Deserialization expects OID format
        let json_with_oid = format!(r#"{{"contentType":"{}"}}"#, expected_oid);
        let decoded: ContentType = serde_json::from_str(&json_with_oid).unwrap();
        assert_eq!(decoded.content_type().to_string(), expected_oid);
    }
}
