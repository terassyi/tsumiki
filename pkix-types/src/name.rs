//! Name and related types
//!
//! Defined in RFC 5280 Section 4.1.2.4
//!
//! ```asn1
//! Name ::= CHOICE { -- only one possibility for now --
//!     rdnSequence  RDNSequence
//! }
//!
//! RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//!
//! RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
//!
//! AttributeTypeAndValue ::= SEQUENCE {
//!     type     AttributeType,
//!     value    AttributeValue
//! }
//!
//! AttributeType ::= OBJECT IDENTIFIER
//! AttributeValue ::= ANY -- DEFINED BY AttributeType
//! ```

use std::fmt;

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, ObjectIdentifier};

use crate::OidName;
use crate::directory_string::DirectoryString;
use crate::error::{Error, Result};

/// X.509 Distinguished Name
///
/// A Name identifies an entity in an X.509 certificate. It consists of
/// a sequence of Relative Distinguished Names (RDNs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Name {
    pub rdn_sequence: Vec<RelativeDistinguishedName>,
}

impl Name {
    /// Create a new Name with the given RDN sequence
    pub fn new(rdn_sequence: Vec<RelativeDistinguishedName>) -> Self {
        Self { rdn_sequence }
    }

    /// Get a reference to the RDN sequence
    pub fn rdn_sequence(&self) -> &[RelativeDistinguishedName] {
        &self.rdn_sequence
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let formatted = self
            .rdn_sequence
            .iter()
            .map(|rdn| {
                rdn.attributes
                    .iter()
                    .map(|attr| {
                        let key = if let Some(name) = attr.oid_name() {
                            name.to_string()
                        } else {
                            attr.attribute_type.to_string()
                        };
                        format!("{}={}", key, attr.attribute_value)
                    })
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", formatted)
    }
}

impl DecodableFrom<Element> for Name {}

impl Decoder<Element, Name> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Name> {
        match self {
            Element::Sequence(elements) => {
                let rdn_sequence = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<RelativeDistinguishedName>>>()?;
                Ok(Name { rdn_sequence })
            }
            _ => Err(Error::NameExpectedSequence),
        }
    }
}

impl EncodableTo<Name> for Element {}

impl Encoder<Name, Element> for Name {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let rdn_elements: Result<Vec<Element>> =
            self.rdn_sequence.iter().map(|rdn| rdn.encode()).collect();
        Ok(Element::Sequence(rdn_elements?))
    }
}

/// Relative Distinguished Name (RDN)
///
/// A set of attribute-value pairs that together form one component of a Name.
/// Typically contains a single AttributeTypeAndValue, but can contain multiple
/// for multi-valued RDNs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelativeDistinguishedName {
    pub attributes: Vec<AttributeTypeAndValue>,
}

impl RelativeDistinguishedName {
    /// Create a new RDN with a single attribute
    pub fn new_single(attribute: AttributeTypeAndValue) -> Self {
        Self {
            attributes: vec![attribute],
        }
    }

    /// Create a new RDN with multiple attributes
    pub fn new(attributes: Vec<AttributeTypeAndValue>) -> Self {
        Self { attributes }
    }
}

impl DecodableFrom<Element> for RelativeDistinguishedName {}

impl Decoder<Element, RelativeDistinguishedName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RelativeDistinguishedName> {
        match self {
            Element::Set(elements) => {
                let attributes = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<AttributeTypeAndValue>>>()?;
                Ok(RelativeDistinguishedName { attributes })
            }
            _ => Err(Error::RdnExpectedSet),
        }
    }
}

impl EncodableTo<RelativeDistinguishedName> for Element {}

impl Encoder<RelativeDistinguishedName, Element> for RelativeDistinguishedName {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let attr_elements: Result<Vec<Element>> =
            self.attributes.iter().map(|attr| attr.encode()).collect();
        Ok(Element::Set(attr_elements?))
    }
}

/// Attribute Type and Value pair
///
/// Represents a single attribute in an X.509 Name, such as CN=example.com
/// or O=Example Organization.
///
/// The attribute value preserves its original encoding (PrintableString,
/// UTF8String, etc.) to enable byte-identical re-encoding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AttributeTypeAndValue {
    pub attribute_type: ObjectIdentifier,
    #[serde(deserialize_with = "deserialize_attribute_value")]
    pub attribute_value: DirectoryString,
}

fn deserialize_attribute_value<'de, D>(
    deserializer: D,
) -> std::result::Result<DirectoryString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(DirectoryString::new(s))
}

impl AttributeTypeAndValue {
    /// OID for commonName (CN)
    pub const OID_COMMON_NAME: &'static str = "2.5.4.3";
    /// OID for countryName (C)
    pub const OID_COUNTRY_NAME: &'static str = "2.5.4.6";
    /// OID for localityName (L)
    pub const OID_LOCALITY_NAME: &'static str = "2.5.4.7";
    /// OID for stateOrProvinceName (ST)
    pub const OID_STATE_OR_PROVINCE_NAME: &'static str = "2.5.4.8";
    /// OID for organizationName (O)
    pub const OID_ORGANIZATION_NAME: &'static str = "2.5.4.10";
    /// OID for organizationalUnitName (OU)
    pub const OID_ORGANIZATIONAL_UNIT_NAME: &'static str = "2.5.4.11";
    /// OID for serialNumber
    pub const OID_SERIAL_NUMBER: &'static str = "2.5.4.5";
    /// OID for surname (SN)
    pub const OID_SURNAME: &'static str = "2.5.4.4";
    /// OID for givenName (GN)
    pub const OID_GIVEN_NAME: &'static str = "2.5.4.42";
    /// OID for initials
    pub const OID_INITIALS: &'static str = "2.5.4.43";
    /// OID for generationQualifier
    pub const OID_GENERATION_QUALIFIER: &'static str = "2.5.4.44";
    /// OID for title
    pub const OID_TITLE: &'static str = "2.5.4.12";
    /// OID for dnQualifier
    pub const OID_DN_QUALIFIER: &'static str = "2.5.4.46";
    /// OID for pseudonym
    pub const OID_PSEUDONYM: &'static str = "2.5.4.65";
    /// OID for domainComponent (DC)
    pub const OID_DOMAIN_COMPONENT: &'static str = "0.9.2342.19200300.100.1.25";
    /// OID for emailAddress
    pub const OID_EMAIL_ADDRESS: &'static str = "1.2.840.113549.1.9.1";

    /// Create a new AttributeTypeAndValue with default UTF8String encoding
    pub fn new(
        attribute_type: ObjectIdentifier,
        attribute_value: impl Into<DirectoryString>,
    ) -> Self {
        Self {
            attribute_type,
            attribute_value: attribute_value.into(),
        }
    }

    /// Get the string value of the attribute
    pub fn value_str(&self) -> &str {
        self.attribute_value.as_str()
    }
}

impl OidName for AttributeTypeAndValue {
    fn oid_name(&self) -> Option<&'static str> {
        match self.attribute_type.to_string().as_str() {
            Self::OID_COMMON_NAME => Some("CN"),
            Self::OID_COUNTRY_NAME => Some("C"),
            Self::OID_LOCALITY_NAME => Some("L"),
            Self::OID_STATE_OR_PROVINCE_NAME => Some("ST"),
            Self::OID_ORGANIZATION_NAME => Some("O"),
            Self::OID_ORGANIZATIONAL_UNIT_NAME => Some("OU"),
            Self::OID_SERIAL_NUMBER => Some("serialNumber"),
            Self::OID_SURNAME => Some("SN"),
            Self::OID_GIVEN_NAME => Some("GN"),
            Self::OID_INITIALS => Some("initials"),
            Self::OID_GENERATION_QUALIFIER => Some("generationQualifier"),
            Self::OID_TITLE => Some("title"),
            Self::OID_DN_QUALIFIER => Some("dnQualifier"),
            Self::OID_PSEUDONYM => Some("pseudonym"),
            Self::OID_DOMAIN_COMPONENT => Some("DC"),
            Self::OID_EMAIL_ADDRESS => Some("emailAddress"),
            _ => None,
        }
    }
}

impl Serialize for AttributeTypeAndValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AttributeTypeAndValue", 2)?;

        // Check if we should use OID values
        let use_oid = crate::get_use_oid_values();

        let type_name = if use_oid {
            // Use OID value directly
            self.attribute_type.to_string()
        } else {
            // Try to use human-readable name, fall back to OID string
            self.oid_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| self.attribute_type.to_string())
        };

        state.serialize_field("attribute_type", &type_name)?;
        // Serialize just the string value, not the full DirectoryString
        state.serialize_field("attribute_value", self.attribute_value.as_str())?;
        state.end()
    }
}

impl DecodableFrom<Element> for AttributeTypeAndValue {}

impl Decoder<Element, AttributeTypeAndValue> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AttributeTypeAndValue> {
        let Element::Sequence(seq) = self else {
            return Err(Error::AttributeTypeAndValueExpectedSequence);
        };

        // attribute_value can be various types depending on the attribute_type
        // Most X.509 attributes are strings (DirectoryString)
        // DirectoryString preserves the original encoding
        let (attribute_type, attribute_value) = match seq.as_slice() {
            [Element::ObjectIdentifier(oid), value_elem] => (oid.clone(), value_elem.decode()?),
            [_, _] => {
                return Err(Error::AttributeTypeAndValueExpectedOid);
            }
            _ => {
                return Err(Error::AttributeTypeAndValueInvalidElementCount);
            }
        };

        Ok(AttributeTypeAndValue {
            attribute_type,
            attribute_value,
        })
    }
}

impl EncodableTo<AttributeTypeAndValue> for Element {}

impl Encoder<AttributeTypeAndValue, Element> for AttributeTypeAndValue {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let oid_elm = Element::ObjectIdentifier(self.attribute_type.clone());
        let value_elm = self.attribute_value.encode()?;
        Ok(Element::Sequence(vec![oid_elm, value_elm]))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use rstest::rstest;

    #[test]
    fn test_name_display() {
        let name = Name {
            rdn_sequence: vec![
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                        attribute_value: "US".into(),
                    }],
                },
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.10").unwrap(),
                        attribute_value: "Example Org".into(),
                    }],
                },
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                        attribute_value: "example.com".into(),
                    }],
                },
            ],
        };

        assert_eq!(name.to_string(), "C=US, O=Example Org, CN=example.com");
    }

    #[rstest]
    #[case("2.5.4.3", Some("CN"))]
    #[case("2.5.4.6", Some("C"))]
    #[case("2.5.4.10", Some("O"))]
    #[case("2.5.4.11", Some("OU"))]
    #[case("1.2.3.4", None)]
    fn test_oid_name(#[case] oid_str: &str, #[case] expected: Option<&str>) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let attr = AttributeTypeAndValue::new(oid, "value".to_string());
        assert_eq!(attr.oid_name(), expected);
    }

    #[test]
    fn test_attribute_type_and_value_encode_decode() {
        let attr = AttributeTypeAndValue {
            attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
            attribute_value: "Test".into(),
        };

        let encoded = attr.encode().unwrap();
        let decoded: AttributeTypeAndValue = encoded.decode().unwrap();

        assert_eq!(decoded, attr);
    }
}
