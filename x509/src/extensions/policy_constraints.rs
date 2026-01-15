use asn1::{ASN1Object, Element, Integer, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::Error;
use crate::extensions::Extension;

/// The number of certificates that may appear in the path before a specific constraint
/// becomes effective. This is commonly used in policy-related extensions.
///
/// Defined in RFC 5280 Section 4.2.1.11:
/// SkipCerts ::= INTEGER (0..MAX)
pub type SkipCerts = u32;

/*
RFC 5280 Section 4.2.1.11

PolicyConstraints ::= SEQUENCE {
    requireExplicitPolicy    [0] SkipCerts OPTIONAL,
    inhibitPolicyMapping     [1] SkipCerts OPTIONAL }

SkipCerts ::= INTEGER (0..MAX)

The policy constraints extension can be used in certificates issued to CAs.
The policy constraints extension constrains path validation in two ways:

- It can be used to prohibit policy mapping.
- It can be used to require that each certificate in a path contain
  an acceptable policy identifier.

If the requireExplicitPolicy field is present, the value of the field indicates
the number of additional certificates that may appear in the path before an
explicit policy is required for the entire path.

If the inhibitPolicyMapping field is present, the value indicates the number
of additional certificates that may appear in the path before policy mapping
is no longer permitted.
*/

/// PolicyConstraints extension
/// OID: 2.5.29.36
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConstraints {
    /// Number of additional certificates that may appear in the path
    /// before an explicit policy is required for the entire path
    pub require_explicit_policy: Option<SkipCerts>,
    /// Number of additional certificates that may appear in the path
    /// before policy mapping is no longer permitted
    pub inhibit_policy_mapping: Option<SkipCerts>,
}

impl Extension for PolicyConstraints {
    /// OID for PolicyConstraints extension (2.5.29.36)
    const OID: &'static str = "2.5.29.36";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidPolicyConstraints("empty content".to_string()));
        }

        elements[0].decode()
    }
}

impl DecodableFrom<Element> for PolicyConstraints {}

impl Decoder<Element, PolicyConstraints> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyConstraints, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidPolicyConstraints(
                        "PolicyConstraints must have at least one field".to_string(),
                    ));
                }

                let mut require_explicit_policy = None;
                let mut inhibit_policy_mapping = None;

                for elem in elements {
                    match elem {
                        Element::ContextSpecific { slot, element, .. } => match slot {
                            0 => {
                                // requireExplicitPolicy [0]
                                if let Element::Integer(int) = element.as_ref() {
                                    let value = int.to_u32().ok_or_else(|| {
                                        Error::InvalidPolicyConstraints(
                                            "requireExplicitPolicy value out of range for u32"
                                                .to_string(),
                                        )
                                    })?;
                                    require_explicit_policy = Some(value);
                                } else {
                                    return Err(Error::InvalidPolicyConstraints(
                                        "requireExplicitPolicy must be Integer".to_string(),
                                    ));
                                }
                            }
                            1 => {
                                // inhibitPolicyMapping [1]
                                if let Element::Integer(int) = element.as_ref() {
                                    let value = int.to_u32().ok_or_else(|| {
                                        Error::InvalidPolicyConstraints(
                                            "inhibitPolicyMapping value out of range for u32"
                                                .to_string(),
                                        )
                                    })?;
                                    inhibit_policy_mapping = Some(value);
                                } else {
                                    return Err(Error::InvalidPolicyConstraints(
                                        "inhibitPolicyMapping must be Integer".to_string(),
                                    ));
                                }
                            }
                            _ => {
                                return Err(Error::InvalidPolicyConstraints(format!(
                                    "unexpected context-specific tag: {}",
                                    slot
                                )));
                            }
                        },
                        _ => {
                            return Err(Error::InvalidPolicyConstraints(
                                "expected context-specific element".to_string(),
                            ));
                        }
                    }
                }

                // At least one field must be present
                if require_explicit_policy.is_none() && inhibit_policy_mapping.is_none() {
                    return Err(Error::InvalidPolicyConstraints(
                        "at least one field must be present".to_string(),
                    ));
                }

                Ok(PolicyConstraints {
                    require_explicit_policy,
                    inhibit_policy_mapping,
                })
            }
            _ => Err(Error::InvalidPolicyConstraints(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl EncodableTo<PolicyConstraints> for Element {}

impl Encoder<PolicyConstraints, Element> for PolicyConstraints {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.require_explicit_policy.is_none() && self.inhibit_policy_mapping.is_none() {
            return Err(Error::InvalidPolicyConstraints(
                "at least one field must be present".to_string(),
            ));
        }

        let require_elem = self.require_explicit_policy.map(|value| {
            let bytes = value.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let slice = bytes.get(start..).unwrap_or(&bytes);
            Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::Integer(Integer::from(slice))),
            }
        });

        let inhibit_elem = self.inhibit_policy_mapping.map(|value| {
            let bytes = value.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let slice = bytes.get(start..).unwrap_or(&bytes);
            Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::Integer(Integer::from(slice))),
            }
        });

        let elements = require_elem.into_iter().chain(inhibit_elem).collect();

        Ok(Element::Sequence(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::Integer;
    use rstest::rstest;

    #[rstest]
    #[case(Some(0), None, "requireExplicitPolicy only with value 0")]
    #[case(Some(1), None, "requireExplicitPolicy only with value 1")]
    #[case(Some(5), None, "requireExplicitPolicy only with value 5")]
    #[case(None, Some(0), "inhibitPolicyMapping only with value 0")]
    #[case(None, Some(1), "inhibitPolicyMapping only with value 1")]
    #[case(None, Some(3), "inhibitPolicyMapping only with value 3")]
    #[case(Some(0), Some(0), "both fields with value 0")]
    #[case(Some(1), Some(0), "requireExplicitPolicy=1, inhibitPolicyMapping=0")]
    #[case(Some(2), Some(1), "requireExplicitPolicy=2, inhibitPolicyMapping=1")]
    fn test_policy_constraints_decode_success(
        #[case] require_explicit: Option<u32>,
        #[case] inhibit_mapping: Option<u32>,
        #[case] _description: &str,
    ) {
        let mut elements = Vec::new();

        if let Some(value) = require_explicit {
            elements.push(Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::Integer(Integer::from(vec![value as u8]))),
            });
        }

        if let Some(value) = inhibit_mapping {
            elements.push(Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::Integer(Integer::from(vec![value as u8]))),
            });
        }

        let elem = Element::Sequence(elements);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let pc = result.unwrap();
        assert_eq!(pc.require_explicit_policy, require_explicit);
        assert_eq!(pc.inhibit_policy_mapping, inhibit_mapping);
    }

    #[rstest]
    #[case("empty Sequence")]
    #[case("no fields present")]
    fn test_policy_constraints_decode_failure_empty(#[case] _description: &str) {
        let elem = Element::Sequence(vec![]);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err(), "Expected error but got: {:?}", result);
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("at least one field"),
            "Error message should mention 'at least one field': '{}'",
            err_str
        );
    }

    #[test]
    fn test_policy_constraints_decode_failure_wrong_type() {
        // Not a Sequence
        let elem = Element::Integer(Integer::from(vec![0x00]));
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("expected Sequence"));
    }

    #[test]
    fn test_policy_constraints_decode_failure_invalid_tag() {
        // Invalid context-specific tag [2]
        let elem = Element::Sequence(vec![Element::ContextSpecific {
            constructed: true,
            slot: 2,
            element: Box::new(Element::Integer(Integer::from(vec![0x00]))),
        }]);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("unexpected context-specific tag"));
    }

    #[test]
    fn test_policy_constraints_decode_failure_not_context_specific() {
        // Direct Integer instead of context-specific
        let elem = Element::Sequence(vec![Element::Integer(Integer::from(vec![0x00]))]);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("expected context-specific element"));
    }

    #[test]
    fn test_policy_constraints_decode_failure_wrong_inner_type() {
        // Context-specific but inner is not Integer
        let elem = Element::Sequence(vec![Element::ContextSpecific {
            constructed: false,
            slot: 0,
            element: Box::new(Element::OctetString(asn1::OctetString::from(vec![0x00]))),
        }]);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("must be Integer"));
    }

    #[test]
    fn test_policy_constraints_parse() {
        // Test full parsing through StandardExtension::parse
        // DER: SEQUENCE { [0] INTEGER 2 }
        // 30 05 A0 03 02 01 02
        let octet_string = OctetString::from(vec![0x30, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x02]);

        let result = PolicyConstraints::parse(&octet_string);
        assert!(result.is_ok(), "Failed to parse: {:?}", result);

        let pc = result.unwrap();
        assert_eq!(pc.require_explicit_policy, Some(2));
        assert_eq!(pc.inhibit_policy_mapping, None);
    }

    #[test]
    fn test_policy_constraints_large_values() {
        // Test with larger values
        let elem = Element::Sequence(vec![
            Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::Integer(Integer::from(vec![0x03, 0xE8]))), // 1000
            },
            Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::Integer(Integer::from(vec![0x01, 0xF4]))), // 500
            },
        ]);

        let result: Result<PolicyConstraints, Error> = elem.decode();
        assert!(result.is_ok());

        let pc = result.unwrap();
        assert_eq!(pc.require_explicit_policy, Some(1000));
        assert_eq!(pc.inhibit_policy_mapping, Some(500));
    }

    #[test]
    fn test_policy_constraints_both_zero() {
        // Both fields with value 0 (immediate constraint)
        let elem = Element::Sequence(vec![
            Element::ContextSpecific {
                constructed: false,
                slot: 0,
                element: Box::new(Element::Integer(Integer::from(vec![0x00]))),
            },
            Element::ContextSpecific {
                constructed: false,
                slot: 1,
                element: Box::new(Element::Integer(Integer::from(vec![0x00]))),
            },
        ]);

        let result: Result<PolicyConstraints, Error> = elem.decode();
        assert!(result.is_ok());

        let pc = result.unwrap();
        assert_eq!(pc.require_explicit_policy, Some(0));
        assert_eq!(pc.inhibit_policy_mapping, Some(0));
    }
}
