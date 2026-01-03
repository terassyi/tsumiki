use asn1::{Element, ObjectIdentifier};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;

/*
RFC 5280 Section 4.1.2.4
DirectoryString ::= CHOICE {
  teletexString     TeletexString (SIZE (1..MAX)),
  printableString   PrintableString (SIZE (1..MAX)),
  universalString   UniversalString (SIZE (1..MAX)),
  utf8String        UTF8String (SIZE (1..MAX)),
  bmpString         BMPString (SIZE (1..MAX))
}
*/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryString {
    inner: String,
}

impl Serialize for DirectoryString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DirectoryString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = String::deserialize(deserializer)?;
        Ok(DirectoryString { inner })
    }
}

impl DirectoryString {
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn into_string(self) -> String {
        self.inner
    }
}

impl From<String> for DirectoryString {
    fn from(value: String) -> Self {
        Self { inner: value }
    }
}

impl From<&str> for DirectoryString {
    fn from(value: &str) -> Self {
        Self {
            inner: value.to_string(),
        }
    }
}

impl std::fmt::Display for DirectoryString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl DecodableFrom<Element> for DirectoryString {}

impl Decoder<Element, DirectoryString> for Element {
    type Error = Error;

    fn decode(&self) -> Result<DirectoryString, Self::Error> {
        let value = match self {
            Element::UTF8String(s) => s.clone(),
            Element::PrintableString(s) => s.clone(),
            Element::IA5String(s) => s.clone(),
            Element::OctetString(os) => {
                // May come as OctetString due to IMPLICIT tagging
                String::from_utf8(os.as_bytes().to_vec()).map_err(|e| {
                    Error::InvalidAttributeValue(format!("invalid DirectoryString: {}", e))
                })?
            }
            Element::Integer(int) => int.to_string(),
            _ => {
                return Err(Error::InvalidAttributeValue(format!(
                    "DirectoryString must be a string type, got {:?}",
                    self
                )));
            }
        };
        Ok(DirectoryString { inner: value })
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Name {
    pub(crate) rdn_sequence: Vec<RelativeDistinguishedName>,
}

impl DecodableFrom<Element> for Name {}

impl Decoder<Element, Name> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Name, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let rdn_sequence = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<RelativeDistinguishedName>, _>>()?;
                Ok(Name { rdn_sequence })
            }
            _ => Err(Error::InvalidName("expected Sequence for Name".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelativeDistinguishedName {
    pub(crate) attribute: Vec<AttributeTypeAndValue>,
}

impl DecodableFrom<Element> for RelativeDistinguishedName {}

impl Decoder<Element, RelativeDistinguishedName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RelativeDistinguishedName, Self::Error> {
        match self {
            Element::Set(elements) => {
                let attribute = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<AttributeTypeAndValue>, _>>()?;
                Ok(RelativeDistinguishedName { attribute })
            }
            _ => Err(Error::InvalidRelativeDistinguishedName(
                "expected Set for RelativeDistinguishedName".to_string(),
            )),
        }
    }
}

/// Map common X.509 attribute OIDs to human-readable names
pub(crate) fn oid_to_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    match oid.to_string().as_str() {
        "2.5.4.3" => Some("CN"),  // commonName
        "2.5.4.6" => Some("C"),   // countryName
        "2.5.4.7" => Some("L"),   // localityName
        "2.5.4.8" => Some("ST"),  // stateOrProvinceName
        "2.5.4.10" => Some("O"),  // organizationName
        "2.5.4.11" => Some("OU"), // organizationalUnitName
        "2.5.4.5" => Some("serialNumber"),
        "2.5.4.4" => Some("SN"),  // surname
        "2.5.4.42" => Some("GN"), // givenName
        "2.5.4.43" => Some("initials"),
        "2.5.4.44" => Some("generationQualifier"),
        "2.5.4.12" => Some("title"),
        "2.5.4.46" => Some("dnQualifier"),
        "2.5.4.65" => Some("pseudonym"),
        "0.9.2342.19200300.100.1.25" => Some("DC"), // domainComponent
        "1.2.840.113549.1.9.1" => Some("emailAddress"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct AttributeTypeAndValue {
    pub(crate) attribute_type: ObjectIdentifier, // OBJECT IDENTIFIER
    pub(crate) attribute_value: String,          // ANY DEFINED BY type_
}

impl Serialize for AttributeTypeAndValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AttributeTypeAndValue", 2)?;
        
        // Try to use human-readable name, fall back to OID string
        let type_name = oid_to_name(&self.attribute_type)
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.attribute_type.to_string());
        
        state.serialize_field("attribute_type", &type_name)?;
        state.serialize_field("attribute_value", &self.attribute_value)?;
        state.end()
    }
}

impl DecodableFrom<Element> for AttributeTypeAndValue {}

impl Decoder<Element, AttributeTypeAndValue> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AttributeTypeAndValue, Self::Error> {
        if let Element::Sequence(seq) = self {
            if seq.len() != 2 {
                return Err(Error::InvalidAttributeTypeAndValue(
                    "expected 2 elements in sequence".to_string(),
                ));
            }
            let attribute_type = if let Element::ObjectIdentifier(oid) = &seq[0] {
                oid.clone()
            } else {
                return Err(Error::InvalidAttributeType(
                    "expected ObjectIdentifier".to_string(),
                ));
            };

            // attribute_value can be various types depending on the attribute_type
            // Most X.509 attributes are strings (DirectoryString)
            let dir_string: DirectoryString = seq[1].decode()?;
            let attribute_value = dir_string.into_string();

            Ok(AttributeTypeAndValue {
                attribute_type,
                attribute_value,
            })
        } else {
            Err(Error::InvalidAttributeTypeAndValue(
                "expected sequence".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::Integer;
    use rstest::rstest;
    use std::str::FromStr;

    // DirectoryString tests
    #[rstest(
        input,
        expected_str,
        case(
            Element::UTF8String("example.com".to_string()),
            "example.com"
        ),
        case(
            Element::PrintableString("CN=Test User".to_string()),
            "CN=Test User"
        ),
        case(
            Element::IA5String("test@example.com".to_string()),
            "test@example.com"
        ),
        case(
            Element::OctetString(asn1::OctetString::from("UTF8 bytes".as_bytes())),
            "UTF8 bytes"
        ),
        case(
            Element::Integer(Integer::from(vec![0x7B])), // 123
            "123"
        )
    )]
    fn test_directory_string_decode_success(input: Element, expected_str: &str) {
        let result: DirectoryString = input.decode().unwrap();
        assert_eq!(result.as_str(), expected_str);
        assert_eq!(result.to_string(), expected_str);
    }

    #[rstest(
        input,
        case(Element::Null),
        case(Element::Boolean(true)),
        case(Element::BitString(asn1::BitString::new(0, vec![0xFF]))),
    )]
    fn test_directory_string_decode_failure(input: Element) {
        let result: Result<DirectoryString, Error> = input.decode();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidAttributeValue(_)
        ));
    }

    // AttributeTypeAndValue tests
    #[rstest(
        attribute_type_oid,
        attribute_value_element,
        expected_value_str,
        case(
            ObjectIdentifier::from_str("2.5.4.3").unwrap(), // commonName (CN)
            Element::UTF8String("example.com".to_string()),
            "example.com"
        ),
        case(
            ObjectIdentifier::from_str("2.5.4.6").unwrap(), // countryName (C)
            Element::PrintableString("US".to_string()),
            "US"
        ),
        case(
            ObjectIdentifier::from_str("1.2.840.113549.1.9.1").unwrap(), // emailAddress
            Element::IA5String("user@example.com".to_string()),
            "user@example.com"
        )
    )]
    fn test_attribute_type_and_value_decode_success(
        attribute_type_oid: ObjectIdentifier,
        attribute_value_element: Element,
        expected_value_str: &str,
    ) {
        let sequence = Element::Sequence(vec![
            Element::ObjectIdentifier(attribute_type_oid.clone()),
            attribute_value_element,
        ]);

        let attr: AttributeTypeAndValue = sequence.decode().unwrap();

        assert_eq!(attr.attribute_type, attribute_type_oid);
        assert_eq!(attr.attribute_value, expected_value_str);
    }

    #[rstest(
        input,
        expected_error_type,
        // Test case: Not a sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap())
            ]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Invalid attribute type (not an OID)
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
                Element::UTF8String("value".to_string())
            ]),
            "InvalidAttributeType"
        )
    )]
    fn test_attribute_type_and_value_decode_failure(input: Element, expected_error_type: &str) {
        let result: Result<AttributeTypeAndValue, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_type),
            "Expected error type '{}', but got '{}'",
            expected_error_type,
            err_str
        );
    }

    // RelativeDistinguishedName tests
    #[rstest(
        input,
        expected,
        // Test case: Single attribute
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                    Element::UTF8String("example.com".to_string()),
                ])
            ]),
            RelativeDistinguishedName {
                attribute: vec![
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                        attribute_value: "example.com".to_string(),
                    }
                ]
            }
        ),
        // Test case: Multiple attributes
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                    Element::UTF8String("example.com".to_string()),
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.6").unwrap()),
                    Element::PrintableString("US".to_string()),
                ])
            ]),
            RelativeDistinguishedName {
                attribute: vec![
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                        attribute_value: "example.com".to_string(),
                    },
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                        attribute_value: "US".to_string(),
                    }
                ]
            }
        ),
        // Test case: Empty set
        case(
            Element::Set(vec![]),
            RelativeDistinguishedName {
                attribute: vec![]
            }
        )
    )]
    fn test_rdn_decode_success(input: Element, expected: RelativeDistinguishedName) {
        let rdn: RelativeDistinguishedName = input.decode().unwrap();
        assert_eq!(rdn, expected);
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Set (should return RDN error)
        case(
            Element::Sequence(vec![]),
            "InvalidRelativeDistinguishedName"
        ),
        // Test case: Invalid attribute (should propagate AttributeTypeAndValue error)
        case(
            Element::Set(vec![Element::Integer(Integer::from(vec![0x01]))]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Set with partially invalid attributes
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                    Element::UTF8String("example.com".to_string()),
                ]),
                Element::Integer(Integer::from(vec![0x01])) // Invalid
            ]),
            "InvalidAttributeTypeAndValue"
        )
    )]
    fn test_rdn_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<RelativeDistinguishedName, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // Name tests
    #[rstest(
        input,
        expected,
        // Test case: Single RDN
        case(
            Element::Sequence(vec![
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                        Element::UTF8String("example.com".to_string()),
                    ])
                ])
            ]),
            Name {
                rdn_sequence: vec![
                    RelativeDistinguishedName {
                        attribute: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                                attribute_value: "example.com".to_string(),
                            }
                        ]
                    }
                ]
            }
        ),
        // Test case: Multiple RDNs
        case(
            Element::Sequence(vec![
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                        Element::UTF8String("example.com".to_string()),
                    ])
                ]),
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.6").unwrap()),
                        Element::PrintableString("US".to_string()),
                    ])
                ])
            ]),
            Name {
                rdn_sequence: vec![
                    RelativeDistinguishedName {
                        attribute: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                                attribute_value: "example.com".to_string(),
                            }
                        ]
                    },
                    RelativeDistinguishedName {
                        attribute: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                                attribute_value: "US".to_string(),
                            }
                        ]
                    }
                ]
            }
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            Name {
                rdn_sequence: vec![]
            }
        )
    )]
    fn test_name_decode_success(input: Element, expected: Name) {
        let name: Name = input.decode().unwrap();
        assert_eq!(name, expected);
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Sequence (should return Name error)
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "InvalidName"
        ),
        // Test case: Invalid RDN (should propagate RDN error)
        case(
            Element::Sequence(vec![Element::Integer(Integer::from(vec![0x01]))]),
            "InvalidRelativeDistinguishedName"
        ),
        // Test case: Invalid AttributeTypeAndValue (should propagate through the chain)
        case(
            Element::Sequence(vec![
                Element::Set(vec![Element::Integer(Integer::from(vec![0x01]))])
            ]),
            "InvalidAttributeTypeAndValue"
        ),
        // Test case: Multiple RDNs with one invalid (should fail on first error)
        case(
            Element::Sequence(vec![
                Element::Set(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
                        Element::UTF8String("example.com".to_string()),
                    ])
                ]),
                Element::Integer(Integer::from(vec![0x01])) // Invalid RDN
            ]),
            "InvalidRelativeDistinguishedName"
        )
    )]
    fn test_name_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<Name, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }
}
