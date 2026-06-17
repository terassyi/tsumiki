use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, Integer, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
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

/// Policy Constraints extension ([RFC 5280 Section 4.2.1.11](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.11)).
///
/// Constrains path validation by requiring explicit policy or inhibiting policy mapping.
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

        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(error::Kind::PolicyConstraints).into()),
        }
    }
}

impl DecodableFrom<Element> for PolicyConstraints {}

impl Decoder<Element, PolicyConstraints> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyConstraints, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::EmptyContent(error::Kind::PolicyConstraints).into());
                }

                let (require_explicit_policy, inhibit_policy_mapping) = elements.iter().try_fold(
                    (None, None),
                    |(req_explicit, inhibit_mapping), elem| match elem {
                        Element::ContextSpecific { slot, element, .. } => match slot {
                            0 => {
                                // requireExplicitPolicy [0]
                                if let Element::Integer(int) = element.as_ref() {
                                    let value =
                                        int.to_u32().ok_or(error::Error::ValueOutOfRangeU32(
                                            error::Kind::PolicyConstraints,
                                        ))?;
                                    Ok((Some(value), inhibit_mapping))
                                } else {
                                    Err(error::Error::ExpectedInteger(
                                        error::Kind::PolicyConstraints,
                                    ))
                                }
                            }
                            1 => {
                                // inhibitPolicyMapping [1]
                                if let Element::Integer(int) = element.as_ref() {
                                    let value =
                                        int.to_u32().ok_or(error::Error::ValueOutOfRangeU32(
                                            error::Kind::PolicyConstraints,
                                        ))?;
                                    Ok((req_explicit, Some(value)))
                                } else {
                                    Err(error::Error::ExpectedInteger(
                                        error::Kind::PolicyConstraints,
                                    ))
                                }
                            }
                            _ => Err(error::Error::ExpectedContextTag {
                                kind: error::Kind::PolicyConstraints,
                                expected: 0,
                            }),
                        },
                        _ => Err(error::Error::UnexpectedElementType(
                            error::Kind::PolicyConstraints,
                        )),
                    },
                )?;

                // At least one field must be present
                if require_explicit_policy.is_none() && inhibit_policy_mapping.is_none() {
                    return Err(error::Error::EmptyContent(error::Kind::PolicyConstraints).into());
                }

                Ok(PolicyConstraints {
                    require_explicit_policy,
                    inhibit_policy_mapping,
                })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::PolicyConstraints).into()),
        }
    }
}

impl EncodableTo<PolicyConstraints> for Element {}

impl Encoder<PolicyConstraints, Element> for PolicyConstraints {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.require_explicit_policy.is_none() && self.inhibit_policy_mapping.is_none() {
            return Err(error::Error::EmptyContent(error::Kind::PolicyConstraints).into());
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

impl OidName for PolicyConstraints {
    fn oid_name(&self) -> Option<&'static str> {
        Some("policyConstraints")
    }
}

impl fmt::Display for PolicyConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("policyConstraints");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        if let Some(require) = self.require_explicit_policy {
            writeln!(f, "                Require Explicit Policy: {}", require)?;
        }
        if let Some(inhibit) = self.inhibit_policy_mapping {
            writeln!(f, "                Inhibit Policy Mapping: {}", inhibit)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tsumiki_asn1::Integer;

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
        let require_elem = require_explicit.map(|value| Element::ContextSpecific {
            constructed: false,
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![value as u8]))),
        });

        let inhibit_elem = inhibit_mapping.map(|value| Element::ContextSpecific {
            constructed: false,
            slot: 1,
            element: Box::new(Element::Integer(Integer::from(vec![value as u8]))),
        });

        let elements: Vec<_> = require_elem.into_iter().chain(inhibit_elem).collect();
        let elem = Element::Sequence(elements);
        let result: Result<PolicyConstraints, _> = elem.decode();

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
            err_str.contains("EmptyContent"),
            "Error message should mention 'EmptyContent': '{}'",
            err_str
        );
    }

    #[test]
    fn test_policy_constraints_decode_failure_wrong_type() {
        // Not a Sequence
        let elem = Element::Integer(Integer::from(vec![0x00]));
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(err_str.contains("expected SEQUENCE"));
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
        assert!(err_str.contains("ExpectedContextTag"));
    }

    #[test]
    fn test_policy_constraints_decode_failure_not_context_specific() {
        // Direct Integer instead of context-specific
        let elem = Element::Sequence(vec![Element::Integer(Integer::from(vec![0x00]))]);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("UnexpectedElementType"));
    }

    #[test]
    fn test_policy_constraints_decode_failure_wrong_inner_type() {
        // Context-specific but inner is not Integer
        let elem = Element::Sequence(vec![Element::ContextSpecific {
            constructed: false,
            slot: 0,
            element: Box::new(Element::OctetString(tsumiki_asn1::OctetString::from(vec![
                0x00,
            ]))),
        }]);
        let result: Result<PolicyConstraints, Error> = elem.decode();

        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("ExpectedInteger"));
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

    #[rstest]
    #[case(PolicyConstraints {
        require_explicit_policy: Some(5),
        inhibit_policy_mapping: None,
    })]
    #[case(PolicyConstraints {
        require_explicit_policy: None,
        inhibit_policy_mapping: Some(3),
    })]
    #[case(PolicyConstraints {
        require_explicit_policy: Some(10),
        inhibit_policy_mapping: Some(20),
    })]
    #[case(PolicyConstraints {
        require_explicit_policy: Some(0),
        inhibit_policy_mapping: Some(0),
    })]
    fn test_policy_constraints_encode_decode(#[case] original: PolicyConstraints) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<PolicyConstraints, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
