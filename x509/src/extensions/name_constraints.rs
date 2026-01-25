use asn1::{ASN1Object, Element, Integer, OctetString};
use pkix_types::OidName;
use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::error;
use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.1.10

NameConstraints ::= SEQUENCE {
    permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    excludedSubtrees        [1]     GeneralSubtrees OPTIONAL
}

GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

GeneralSubtree ::= SEQUENCE {
    base                    GeneralName,
    minimum         [0]     BaseDistance DEFAULT 0,
    maximum         [1]     BaseDistance OPTIONAL
}

BaseDistance ::= INTEGER (0..MAX)

The NameConstraints extension indicates a name space within which all subject names
in subsequent certificates in a certification path MUST be located.
Restrictions apply to the subject distinguished name and apply to subject alternative names.
Restrictions of the form directoryName apply only to the subject distinguished name.
*/

/// GeneralSubtree represents a single namespace constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralSubtree {
    /// base: The base name that defines the namespace
    pub base: GeneralName,
    /// minimum: Minimum number of intermediate CAs (default 0)
    /// RFC 5280: "CAs MUST NOT include the minimum field"
    pub minimum: u32,
    /// maximum: Maximum number of intermediate CAs (OPTIONAL)
    /// RFC 5280: "CAs MUST NOT include the maximum field"
    pub maximum: Option<u32>,
}

impl DecodableFrom<Element> for GeneralSubtree {}

impl Decoder<Element, GeneralSubtree> for Element {
    type Error = Error;

    fn decode(&self) -> Result<GeneralSubtree, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                // First element: base (GeneralName), rest are optional minimum/maximum
                let (base_elem, rest) = match elements.as_slice() {
                    [base, rest @ ..] => (base, rest),
                    [] => {
                        return Err(
                            error::Error::EmptySequence(error::Kind::NameConstraints).into()
                        );
                    }
                };

                let base: GeneralName = base_elem.decode()?;

                // Process optional minimum [0] and maximum [1] fields
                let (minimum, maximum) =
                    rest.iter()
                        .try_fold((0u32, None), |(min, max), elem| match elem {
                            Element::ContextSpecific {
                                slot: 0, element, ..
                            } => {
                                // minimum [0] IMPLICIT INTEGER DEFAULT 0
                                match element.as_ref() {
                                    Element::OctetString(os) => {
                                        let integer = Integer::from(os.as_bytes());
                                        let value = integer.to_u32().ok_or(
                                            error::Error::ValueOutOfRangeU32(
                                                error::Kind::NameConstraints,
                                            ),
                                        )?;
                                        Ok((value, max))
                                    }
                                    _ => Err(error::Error::ExpectedInteger(
                                        error::Kind::NameConstraints,
                                    )),
                                }
                            }
                            Element::ContextSpecific {
                                slot: 1, element, ..
                            } => {
                                // maximum [1] IMPLICIT INTEGER OPTIONAL
                                match element.as_ref() {
                                    Element::OctetString(os) => {
                                        let integer = Integer::from(os.as_bytes());
                                        let value = integer.to_u32().ok_or(
                                            error::Error::ValueOutOfRangeU32(
                                                error::Kind::NameConstraints,
                                            ),
                                        )?;
                                        Ok((min, Some(value)))
                                    }
                                    _ => Err(error::Error::ExpectedInteger(
                                        error::Kind::NameConstraints,
                                    )),
                                }
                            }
                            _ => Err(error::Error::NameConstraintsInvalidElement),
                        })?;

                Ok(GeneralSubtree {
                    base,
                    minimum,
                    maximum,
                })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::NameConstraints).into()),
        }
    }
}

impl EncodableTo<GeneralSubtree> for Element {}

impl Encoder<GeneralSubtree, Element> for GeneralSubtree {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let base_elem = self.base.encode()?;

        let minimum_elem = if self.minimum != 0 {
            let bytes = self.minimum.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let slice = bytes.get(start..).unwrap_or(&bytes);
            let integer = Integer::from(slice);
            Some(Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::OctetString(integer.to_signed_bytes_be().into())),
            })
        } else {
            None
        };

        let maximum_elem = self.maximum.map(|max| {
            let bytes = max.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let slice = bytes.get(start..).unwrap_or(&bytes);
            let integer = Integer::from(slice);
            Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::OctetString(integer.to_signed_bytes_be().into())),
            }
        });

        let elements: Vec<_> = std::iter::once(base_elem)
            .chain(minimum_elem)
            .chain(maximum_elem)
            .collect();

        Ok(Element::Sequence(elements))
    }
}

/// NameConstraints extension (RFC 5280 Section 4.2.1.10)
/// Defines name spaces within which all subject names in subsequent certificates must be located
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameConstraints {
    /// permittedSubtrees [0]: Names that are permitted
    pub permitted_subtrees: Option<Vec<GeneralSubtree>>,
    /// excludedSubtrees [1]: Names that are excluded
    pub excluded_subtrees: Option<Vec<GeneralSubtree>>,
}

impl DecodableFrom<OctetString> for NameConstraints {}

impl Decoder<OctetString, NameConstraints> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<NameConstraints, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;

        // The first element should be a Sequence
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::NameConstraints).into()),
        }
    }
}

impl DecodableFrom<Element> for NameConstraints {}

impl Decoder<Element, NameConstraints> for Element {
    type Error = Error;

    fn decode(&self) -> Result<NameConstraints, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (permitted_subtrees, excluded_subtrees) =
                    elements.iter().try_fold(
                        (None, None),
                        |(permitted, excluded), elem| -> Result<_, Error> {
                            match elem {
                                Element::ContextSpecific {
                                    slot: 0, element, ..
                                } => {
                                    // permittedSubtrees [0] IMPLICIT GeneralSubtrees
                                    match element.as_ref() {
                                        Element::Sequence(subtrees) => {
                                            if subtrees.is_empty() {
                                                return Err(error::Error::EmptySequence(
                                                    error::Kind::NameConstraints,
                                                )
                                                .into());
                                            }
                                            let parsed_subtrees = subtrees
                                                .iter()
                                                .map(|e| e.decode())
                                                .collect::<Result<Vec<GeneralSubtree>, _>>()?;
                                            Ok((Some(parsed_subtrees), excluded))
                                        }
                                        _ => Err(error::Error::ExpectedSequence(
                                            error::Kind::NameConstraints,
                                        )
                                        .into()),
                                    }
                                }
                                Element::ContextSpecific {
                                    slot: 1, element, ..
                                } => {
                                    // excludedSubtrees [1] IMPLICIT GeneralSubtrees
                                    match element.as_ref() {
                                        Element::Sequence(subtrees) => {
                                            if subtrees.is_empty() {
                                                return Err(error::Error::EmptySequence(
                                                    error::Kind::NameConstraints,
                                                )
                                                .into());
                                            }
                                            let parsed_subtrees = subtrees
                                                .iter()
                                                .map(|e| e.decode())
                                                .collect::<Result<Vec<GeneralSubtree>, _>>()?;
                                            Ok((permitted, Some(parsed_subtrees)))
                                        }
                                        _ => Err(error::Error::ExpectedSequence(
                                            error::Kind::NameConstraints,
                                        )
                                        .into()),
                                    }
                                }
                                _ => Err(error::Error::NameConstraintsInvalidElement.into()),
                            }
                        },
                    )?;

                // RFC 5280: At least one of permittedSubtrees or excludedSubtrees MUST be present
                if permitted_subtrees.is_none() && excluded_subtrees.is_none() {
                    return Err(error::Error::NameConstraintsEmptyContent.into());
                }

                Ok(NameConstraints {
                    permitted_subtrees,
                    excluded_subtrees,
                })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::NameConstraints).into()),
        }
    }
}

impl EncodableTo<NameConstraints> for Element {}

impl Encoder<NameConstraints, Element> for NameConstraints {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.permitted_subtrees.is_none() && self.excluded_subtrees.is_none() {
            return Err(error::Error::NameConstraintsEmptyContent.into());
        }

        let permitted_elem = match &self.permitted_subtrees {
            Some(subtrees) => {
                let encoded_subtrees = subtrees
                    .iter()
                    .map(|s| s.encode())
                    .collect::<Result<Vec<_>, _>>()?;
                Some(Element::ContextSpecific {
                    constructed: true,
                    slot: 0,
                    element: Box::new(Element::Sequence(encoded_subtrees)),
                })
            }
            None => None,
        };

        let excluded_elem = match &self.excluded_subtrees {
            Some(subtrees) => {
                let encoded_subtrees = subtrees
                    .iter()
                    .map(|s| s.encode())
                    .collect::<Result<Vec<_>, _>>()?;
                Some(Element::ContextSpecific {
                    constructed: true,
                    slot: 1,
                    element: Box::new(Element::Sequence(encoded_subtrees)),
                })
            }
            None => None,
        };

        let elements = permitted_elem.into_iter().chain(excluded_elem).collect();

        Ok(Element::Sequence(elements))
    }
}

impl Extension for NameConstraints {
    const OID: &'static str = "2.5.29.30";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for NameConstraints {
    fn oid_name(&self) -> Option<&'static str> {
        Some("nameConstraints")
    }
}

impl fmt::Display for NameConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("nameConstraints");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        if let Some(ref permitted) = self.permitted_subtrees {
            writeln!(f, "                Permitted:")?;
            for subtree in permitted {
                writeln!(f, "                  {}", subtree.base)?;
            }
        }
        if let Some(ref excluded) = self.excluded_subtrees {
            writeln!(f, "                Excluded:")?;
            for subtree in excluded {
                writeln!(f, "                  {}", subtree.base)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::{Element, OctetString};
    use rstest::rstest;

    // ========== NameConstraints Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Only permittedSubtrees with single dNSName
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: true,
            slot: 0,
                    element: Box::new(Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ContextSpecific {
                                constructed: false,
            slot: 2,
                                element: Box::new(Element::OctetString(OctetString::from(b".example.com".to_vec()))),
                            },
                        ]),
                    ])),
                },
            ]),
            NameConstraints {
                permitted_subtrees: Some(vec![
                    GeneralSubtree {
                        base: GeneralName::DnsName(".example.com".to_string()),
                        minimum: 0,
                        maximum: None,
                    },
                ]),
                excluded_subtrees: None,
            }
        ),
        // Test case: Only excludedSubtrees with single dNSName
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 1,
                    element: Box::new(Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ContextSpecific {
                                constructed: false,
            slot: 2,
                                element: Box::new(Element::OctetString(OctetString::from(b".forbidden.com".to_vec()))),
                            },
                        ]),
                    ])),
                },
            ]),
            NameConstraints {
                permitted_subtrees: None,
                excluded_subtrees: Some(vec![
                    GeneralSubtree {
                        base: GeneralName::DnsName(".forbidden.com".to_string()),
                        minimum: 0,
                        maximum: None,
                    },
                ]),
            }
        ),
        // Test case: Both permitted and excluded subtrees
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: true,
            slot: 0,
                    element: Box::new(Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ContextSpecific {
                                constructed: false,
            slot: 2,
                                element: Box::new(Element::OctetString(OctetString::from(b".example.com".to_vec()))),
                            },
                        ]),
                    ])),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 1,
                    element: Box::new(Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ContextSpecific {
                                constructed: false,
            slot: 2,
                                element: Box::new(Element::OctetString(OctetString::from(b".bad.example.com".to_vec()))),
                            },
                        ]),
                    ])),
                },
            ]),
            NameConstraints {
                permitted_subtrees: Some(vec![
                    GeneralSubtree {
                        base: GeneralName::DnsName(".example.com".to_string()),
                        minimum: 0,
                        maximum: None,
                    },
                ]),
                excluded_subtrees: Some(vec![
                    GeneralSubtree {
                        base: GeneralName::DnsName(".bad.example.com".to_string()),
                        minimum: 0,
                        maximum: None,
                    },
                ]),
            }
        ),
        // Test case: Multiple permitted subtrees with different GeneralName types
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: true,
            slot: 0,
                    element: Box::new(Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ContextSpecific {
                                constructed: false,
            slot: 2,
                                element: Box::new(Element::OctetString(OctetString::from(b".example.com".to_vec()))),
                            },
                        ]),
                        Element::Sequence(vec![
                            Element::ContextSpecific {
                                constructed: false,
            slot: 7,
                                element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2, 0]))),
                            },
                        ]),
                    ])),
                },
            ]),
            NameConstraints {
                permitted_subtrees: Some(vec![
                    GeneralSubtree {
                        base: GeneralName::DnsName(".example.com".to_string()),
                        minimum: 0,
                        maximum: None,
                    },
                    GeneralSubtree {
                        base: GeneralName::IpAddress(
                            crate::extensions::IpAddressOrRange::Address(std::net::IpAddr::from([192, 0, 2, 0]))
                        ),
                        minimum: 0,
                        maximum: None,
                    },
                ]),
                excluded_subtrees: None,
            }
        ),
    )]
    fn test_name_constraints_decode_success(input: Element, expected: NameConstraints) {
        let result: Result<NameConstraints, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest]
    // Test case: Empty sequence (neither permitted nor excluded)
    #[case(
        Element::Sequence(vec![]),
        "at least one of permittedSubtrees or excludedSubtrees must be present"
    )]
    // Test case: Not a Sequence
    #[case(
        Element::OctetString(OctetString::from(vec![0x01, 0x02])),
        "expected SEQUENCE"
    )]
    // Test case: permittedSubtrees with empty sequence
    #[case(
        Element::Sequence(vec![
            Element::ContextSpecific {
                constructed: true,
        slot: 0,
                element: Box::new(Element::Sequence(vec![])),
            },
        ]),
        "empty sequence"
    )]
    // Test case: excludedSubtrees with empty sequence
    #[case(
        Element::Sequence(vec![
            Element::ContextSpecific {
                constructed: false,
        slot: 1,
                element: Box::new(Element::Sequence(vec![])),
            },
        ]),
        "empty sequence"
    )]
    fn test_name_constraints_decode_failure(
        #[case] input: Element,
        #[case] expected_error_msg: &str,
    ) {
        let result: Result<NameConstraints, _> = input.decode();
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

    #[test]
    fn test_general_subtree_with_minimum_maximum() {
        // Test GeneralSubtree with minimum and maximum fields
        // Note: RFC 5280 says CAs MUST NOT include these fields, but we should parse them
        let input = Element::Sequence(vec![
            Element::ContextSpecific {
                constructed: false,
                slot: 2,
                element: Box::new(Element::OctetString(OctetString::from(
                    b".example.com".to_vec(),
                ))),
            },
            Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::OctetString(OctetString::from(vec![0x01]))),
            },
            Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::OctetString(OctetString::from(vec![0x05]))),
            },
        ]);

        let result: Result<GeneralSubtree, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let subtree = result.unwrap();

        match &subtree.base {
            GeneralName::DnsName(name) => assert_eq!(name, ".example.com"),
            _ => panic!("Expected DnsName"),
        }
        assert_eq!(subtree.minimum, 1);
        assert_eq!(subtree.maximum, Some(5));
    }

    #[test]
    fn test_name_constraints_with_ipv4_network() {
        // Test NameConstraints with IPv4 network (8 bytes: 4 for address, 4 for netmask)
        // This is typically used as: IP address (4 bytes) || Netmask (4 bytes)
        // Example: 192.0.2.0/24 = [192, 0, 2, 0] || [255, 255, 255, 0]
        let input = Element::Sequence(vec![Element::ContextSpecific {
            constructed: true,
            slot: 0,
            element: Box::new(Element::Sequence(vec![Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
                    slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![
                        192, 0, 2, 0, 255, 255, 255, 0,
                    ]))),
                },
            ])])),
        }]);

        let result: Result<NameConstraints, Error> = input.decode();
        assert!(
            result.is_ok(),
            "Failed to decode IPv4 network: {:?}",
            result.err()
        );

        let nc = result.unwrap();
        assert!(nc.permitted_subtrees.is_some());
        let permitted = nc.permitted_subtrees.as_ref().unwrap();
        assert_eq!(permitted.len(), 1);

        // Verify it's a Network with correct CIDR notation
        match &permitted[0].base {
            GeneralName::IpAddress(crate::extensions::IpAddressOrRange::Network(net)) => {
                assert_eq!(net.to_string(), "192.0.2.0/24");
            }
            _ => panic!("Expected IpAddress Network, got {:?}", permitted[0].base),
        }
    }

    #[test]
    fn test_name_constraints_decode_with_dns() {
        // NameConstraints with permitted dNSName ".example.com"
        let input = Element::Sequence(vec![Element::ContextSpecific {
            constructed: true,
            slot: 0,
            element: Box::new(Element::Sequence(vec![Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
                    slot: 2,
                    element: Box::new(Element::IA5String(".example.com".to_string())),
                },
            ])])),
        }]);

        let result: Result<NameConstraints, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result.err());

        let nc = result.unwrap();
        assert!(nc.permitted_subtrees.is_some());
        assert_eq!(nc.permitted_subtrees.as_ref().unwrap().len(), 1);
    }

    #[rstest]
    #[case(NameConstraints {
        permitted_subtrees: Some(vec![
            GeneralSubtree {
                base: GeneralName::DnsName(".example.com".to_string()),
                minimum: 0,
                maximum: None,
            },
        ]),
        excluded_subtrees: None,
    })]
    #[case(NameConstraints {
        permitted_subtrees: None,
        excluded_subtrees: Some(vec![
            GeneralSubtree {
                base: GeneralName::DnsName(".badsite.com".to_string()),
                minimum: 0,
                maximum: None,
            },
        ]),
    })]
    #[case(NameConstraints {
        permitted_subtrees: Some(vec![
            GeneralSubtree {
                base: GeneralName::DnsName(".example.com".to_string()),
                minimum: 0,
                maximum: Some(3),
            },
        ]),
        excluded_subtrees: Some(vec![
            GeneralSubtree {
                base: GeneralName::DnsName(".test.example.com".to_string()),
                minimum: 0,
                maximum: None,
            },
        ]),
    })]
    fn test_name_constraints_encode_decode(#[case] original: NameConstraints) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<NameConstraints, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
