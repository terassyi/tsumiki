//! X.509 Name and related types
//!
//! These types have been moved to pkix-types crate for reuse across
//! X.509, PKCS, CMS, and other PKI standards.

use asn1::ObjectIdentifier;

// Re-export types that are now in pkix-types for backward compatibility
#[allow(unused_imports)]
pub use pkix_types::{AttributeTypeAndValue, Name, RelativeDistinguishedName};

// OID mapping function - delegate to pkix-types implementation
/// Map common X.509 attribute OIDs to human-readable names
#[allow(dead_code)]
pub(crate) fn oid_to_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    pkix_types::name::oid_to_name(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::{Element, Integer};
    use pkix_types::DirectoryString;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;

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
        )
    )]
    fn test_directory_string_decode_success(input: Element, expected_str: &str) {
        let result: DirectoryString = input.decode().unwrap();
        assert_eq!(result.as_ref(), expected_str);
        assert_eq!(result.to_string(), expected_str);
    }

    #[rstest(
        input,
        case(Element::Null),
        case(Element::Boolean(true)),
        case(Element::BitString(asn1::BitString::new(0, vec![0xFF]))),
    )]
    fn test_directory_string_decode_failure(input: Element) {
        let result: Result<DirectoryString, pkix_types::Error> = input.decode();
        assert!(result.is_err());
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
            "InvalidAttributeTypeAndValue"
        )
    )]
    fn test_attribute_type_and_value_decode_failure(input: Element, expected_error_type: &str) {
        let result: Result<AttributeTypeAndValue, pkix_types::Error> = input.decode();
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
                attributes: vec![
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
                attributes: vec![
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
                attributes: vec![]
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
        let result: Result<RelativeDistinguishedName, pkix_types::Error> = input.decode();
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
                        attributes: vec![
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
                        attributes: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                                attribute_value: "example.com".to_string(),
                            }
                        ]
                    },
                    RelativeDistinguishedName {
                        attributes: vec![
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
        let result: Result<Name, pkix_types::Error> = input.decode();
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
