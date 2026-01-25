//! X.509 Name and related types
//!
//! These types have been moved to pkix-types crate for reuse across
//! X.509, PKCS, CMS, and other PKI standards.

// Re-export types that are now in pkix-types for backward compatibility
#[allow(unused_imports)]
pub use tsumiki_pkix_types::{AttributeTypeAndValue, Name, RelativeDistinguishedName};

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use rstest::rstest;
    use tsumiki_asn1::{Element, Integer, ObjectIdentifier};
    use tsumiki_pkix_types::DirectoryString;

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
            Element::OctetString(tsumiki_asn1::OctetString::from("UTF8 bytes".as_bytes())),
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
        case(Element::BitString(tsumiki_asn1::BitString::new(0, vec![0xFF]))),
    )]
    fn test_directory_string_decode_failure(input: Element) {
        let result: Result<DirectoryString, tsumiki_pkix_types::Error> = input.decode();
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
        assert_eq!(attr.attribute_value.as_str(), expected_value_str);
    }

    #[rstest(
        input,
        expected_error_type,
        // Test case: Not a sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "AttributeTypeAndValueExpectedSequence"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "AttributeTypeAndValueInvalidElementCount"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap())
            ]),
            "AttributeTypeAndValueInvalidElementCount"
        ),
        // Test case: Invalid attribute type (not an OID)
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
                Element::UTF8String("value".to_string())
            ]),
            "AttributeTypeAndValueExpectedOid"
        )
    )]
    fn test_attribute_type_and_value_decode_failure(input: Element, expected_error_type: &str) {
        let result: Result<AttributeTypeAndValue, tsumiki_pkix_types::Error> = input.decode();
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
                        attribute_value: "example.com".into(),
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
                        attribute_value: "example.com".into(),
                    },
                    AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                        attribute_value: "US".into(),
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
        assert_eq!(rdn.attributes.len(), expected.attributes.len());
        for (actual, exp) in rdn.attributes.iter().zip(expected.attributes.iter()) {
            assert_eq!(actual.attribute_type, exp.attribute_type);
            assert_eq!(
                actual.attribute_value.as_str(),
                exp.attribute_value.as_str()
            );
        }
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Set (should return RDN error)
        case(
            Element::Sequence(vec![]),
            "RdnExpectedSet"
        ),
        // Test case: Invalid attribute (should propagate AttributeTypeAndValue error)
        case(
            Element::Set(vec![Element::Integer(Integer::from(vec![0x01]))]),
            "AttributeTypeAndValueExpectedSequence"
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
            "AttributeTypeAndValueExpectedSequence"
        )
    )]
    fn test_rdn_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<RelativeDistinguishedName, tsumiki_pkix_types::Error> = input.decode();
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
                                attribute_value: "example.com".into(),
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
                                attribute_value: "example.com".into(),
                            }
                        ]
                    },
                    RelativeDistinguishedName {
                        attributes: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                                attribute_value: "US".into(),
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
        assert_eq!(name.rdn_sequence.len(), expected.rdn_sequence.len());
        for (actual_rdn, exp_rdn) in name.rdn_sequence.iter().zip(expected.rdn_sequence.iter()) {
            assert_eq!(actual_rdn.attributes.len(), exp_rdn.attributes.len());
            for (actual, exp) in actual_rdn.attributes.iter().zip(exp_rdn.attributes.iter()) {
                assert_eq!(actual.attribute_type, exp.attribute_type);
                assert_eq!(
                    actual.attribute_value.as_str(),
                    exp.attribute_value.as_str()
                );
            }
        }
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Sequence (should return Name error)
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "NameExpectedSequence"
        ),
        // Test case: Invalid RDN (should propagate RDN error)
        case(
            Element::Sequence(vec![Element::Integer(Integer::from(vec![0x01]))]),
            "RdnExpectedSet"
        ),
        // Test case: Invalid AttributeTypeAndValue (should propagate through the chain)
        case(
            Element::Sequence(vec![
                Element::Set(vec![Element::Integer(Integer::from(vec![0x01]))])
            ]),
            "AttributeTypeAndValueExpectedSequence"
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
            "RdnExpectedSet"
        )
    )]
    fn test_name_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<Name, tsumiki_pkix_types::Error> = input.decode();
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
