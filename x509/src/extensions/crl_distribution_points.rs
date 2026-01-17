use asn1::{ASN1Object, BitString, Element, OctetString};
use pkix_types::{OidName, RelativeDistinguishedName};
use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.1.13

CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

DistributionPoint ::= SEQUENCE {
    distributionPoint       [0]     DistributionPointName OPTIONAL,
    reasons                 [1]     ReasonFlags OPTIONAL,
    cRLIssuer               [2]     GeneralNames OPTIONAL }

DistributionPointName ::= CHOICE {
    fullName                [0]     GeneralNames,
    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

ReasonFlags ::= BIT STRING {
    unused                  (0),
    keyCompromise           (1),
    cACompromise            (2),
    affiliationChanged      (3),
    superseded              (4),
    cessationOfOperation    (5),
    certificateHold         (6),
    privilegeWithdrawn      (7),
    aACompromise            (8) }
*/

/// CRLDistributionPoints represents the CRL Distribution Points extension
/// OID: 2.5.29.31
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CRLDistributionPoints {
    pub distribution_points: Vec<DistributionPoint>,
}

/// DistributionPoint represents a single distribution point
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionPoint {
    pub distribution_point: Option<DistributionPointName>,
    pub reasons: Option<ReasonFlags>,
    pub crl_issuer: Option<Vec<GeneralName>>,
}

/// DistributionPointName is a CHOICE between fullName and nameRelativeToCRLIssuer
///
/// RFC 5280 Section 4.2.1.13:
/// DistributionPointName ::= CHOICE {
///     fullName                [0]     GeneralNames,
///     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionPointName {
    /// Full name as a sequence of GeneralNames
    FullName(Vec<GeneralName>),
    /// Name relative to the CRL issuer
    NameRelativeToCRLIssuer(RelativeDistinguishedName),
}

/// ReasonFlags represents the reasons for certificate revocation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasonFlags {
    pub key_compromise: bool,
    pub ca_compromise: bool,
    pub affiliation_changed: bool,
    pub superseded: bool,
    pub cessation_of_operation: bool,
    pub certificate_hold: bool,
    pub privilege_withdrawn: bool,
    pub aa_compromise: bool,
}

impl From<asn1::BitString> for ReasonFlags {
    fn from(bit_string: asn1::BitString) -> Self {
        let bytes = bit_string.as_bytes();
        let unused_bits = bit_string.unused_bits();

        if bytes.is_empty() {
            return Self {
                key_compromise: false,
                ca_compromise: false,
                affiliation_changed: false,
                superseded: false,
                cessation_of_operation: false,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: false,
            };
        }

        let total_bits = bytes.len() * 8 - unused_bits as usize;

        // Helper function to check if a specific bit is set
        // RFC 5280: Bit 0 is unused, bit 1 is keyCompromise, etc.
        // Bits are numbered from most significant bit of first byte (MSB first)
        let is_bit_set = |bit_num: usize| -> bool {
            if total_bits <= bit_num {
                return false;
            }
            let byte_index = bit_num / 8;
            let bit_offset = 7 - (bit_num % 8);
            byte_index < bytes.len() && (bytes[byte_index] & (1 << bit_offset)) != 0
        };

        Self {
            key_compromise: is_bit_set(1),
            ca_compromise: is_bit_set(2),
            affiliation_changed: is_bit_set(3),
            superseded: is_bit_set(4),
            cessation_of_operation: is_bit_set(5),
            certificate_hold: is_bit_set(6),
            privilege_withdrawn: is_bit_set(7),
            aa_compromise: is_bit_set(8),
        }
    }
}

impl EncodableTo<ReasonFlags> for Element {}

impl Encoder<ReasonFlags, Element> for ReasonFlags {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let flags = [
            false,
            self.key_compromise,
            self.ca_compromise,
            self.affiliation_changed,
            self.superseded,
            self.cessation_of_operation,
            self.certificate_hold,
            self.privilege_withdrawn,
            self.aa_compromise,
        ];

        let last_set = flags.iter().rposition(|&b| b).unwrap_or(0);
        let num_bytes = (last_set + 1).div_ceil(8);
        let unused_bits = num_bytes * 8 - (last_set + 1);

        let bytes: Vec<u8> = (0..num_bytes)
            .map(|byte_idx| {
                let mut byte = 0u8;
                for bit_idx in 0..8 {
                    let flag_idx = byte_idx * 8 + bit_idx;
                    if flags.get(flag_idx).copied().unwrap_or(false) {
                        byte |= 1u8 << (7 - bit_idx);
                    }
                }
                byte
            })
            .collect();

        Ok(Element::BitString(BitString::new(unused_bits as u8, bytes)))
    }
}

impl DecodableFrom<OctetString> for CRLDistributionPoints {}

impl Decoder<OctetString, CRLDistributionPoints> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<CRLDistributionPoints, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidCRLDistributionPoints(
                "empty sequence".to_string(),
            ));
        }

        elements[0].decode()
    }
}

impl DecodableFrom<Element> for CRLDistributionPoints {}

impl Decoder<Element, CRLDistributionPoints> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CRLDistributionPoints, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidCRLDistributionPoints(
                        "empty sequence - at least one DistributionPoint required".to_string(),
                    ));
                }

                let mut distribution_points = Vec::new();
                for elem in elements {
                    let dp: DistributionPoint = elem.decode()?;
                    distribution_points.push(dp);
                }

                Ok(CRLDistributionPoints {
                    distribution_points,
                })
            }
            _ => Err(Error::InvalidCRLDistributionPoints(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl EncodableTo<CRLDistributionPoints> for Element {}

impl Encoder<CRLDistributionPoints, Element> for CRLDistributionPoints {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.distribution_points.is_empty() {
            return Err(Error::InvalidCRLDistributionPoints(
                "at least one DistributionPoint required".to_string(),
            ));
        }

        let dp_elements = self
            .distribution_points
            .iter()
            .map(|dp| dp.encode())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Element::Sequence(dp_elements))
    }
}

impl DecodableFrom<Element> for DistributionPoint {}

impl Decoder<Element, DistributionPoint> for Element {
    type Error = Error;

    fn decode(&self) -> Result<DistributionPoint, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut distribution_point = None;
                let mut reasons = None;
                let mut crl_issuer = None;

                for elem in elements {
                    match elem {
                        Element::ContextSpecific { slot, element, .. } => match slot {
                            0 => {
                                // distributionPoint [0] DistributionPointName
                                distribution_point = Some(element.as_ref().decode()?);
                            }
                            1 => {
                                // reasons [1] ReasonFlags (BIT STRING)
                                if let Element::BitString(bit_string) = element.as_ref() {
                                    reasons = Some(bit_string.clone().into());
                                } else {
                                    return Err(Error::InvalidCRLDistributionPoints(
                                        "reasons must be BIT STRING".to_string(),
                                    ));
                                }
                            }
                            2 => {
                                // cRLIssuer [2] GeneralNames
                                if let Element::Sequence(names) = element.as_ref() {
                                    let mut general_names = Vec::new();
                                    for name_elem in names {
                                        general_names.push(name_elem.decode()?);
                                    }
                                    crl_issuer = Some(general_names);
                                } else {
                                    return Err(Error::InvalidCRLDistributionPoints(
                                        "cRLIssuer must be Sequence of GeneralName".to_string(),
                                    ));
                                }
                            }
                            _ => {
                                return Err(Error::InvalidCRLDistributionPoints(format!(
                                    "unexpected context-specific tag: {}",
                                    slot
                                )));
                            }
                        },
                        _ => {
                            return Err(Error::InvalidCRLDistributionPoints(
                                "expected context-specific element".to_string(),
                            ));
                        }
                    }
                }

                Ok(DistributionPoint {
                    distribution_point,
                    reasons,
                    crl_issuer,
                })
            }
            _ => Err(Error::InvalidCRLDistributionPoints(
                "expected Sequence for DistributionPoint".to_string(),
            )),
        }
    }
}

impl EncodableTo<DistributionPoint> for Element {}

impl Encoder<DistributionPoint, Element> for DistributionPoint {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let dp_elem = if let Some(dp) = &self.distribution_point {
            let inner = dp.encode()?;
            Some(Element::ContextSpecific {
                constructed: true,
                slot: 0,
                element: Box::new(inner),
            })
        } else {
            None
        };

        let reasons_elem = match &self.reasons {
            Some(r) => {
                let bit_string = r.encode()?;
                Some(Element::ContextSpecific {
                    constructed: false,
                    slot: 1,
                    element: Box::new(bit_string),
                })
            }
            None => None,
        };

        let issuer_elem = match &self.crl_issuer {
            Some(issuers) => {
                let encoded = issuers
                    .iter()
                    .map(|i| i.encode())
                    .collect::<Result<Vec<_>, _>>()?;
                Some(Element::ContextSpecific {
                    constructed: true,
                    slot: 2,
                    element: Box::new(Element::Sequence(encoded)),
                })
            }
            None => None,
        };

        let elements = dp_elem
            .into_iter()
            .chain(reasons_elem)
            .chain(issuer_elem)
            .collect();

        Ok(Element::Sequence(elements))
    }
}

impl DecodableFrom<Element> for DistributionPointName {}

impl Decoder<Element, DistributionPointName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<DistributionPointName, Self::Error> {
        match self {
            Element::ContextSpecific {
                slot,
                element,
                constructed,
            } => match slot {
                0 => {
                    // fullName [0] GeneralNames
                    // RFC 5280: fullName [0] IMPLICIT GeneralNames
                    // GeneralNames ::= SEQUENCE OF GeneralName
                    //
                    // With IMPLICIT tagging, the SEQUENCE tag is replaced by [0]
                    // The element field contains what would be inside the SEQUENCE
                    if *constructed {
                        // For IMPLICIT SEQUENCE, the element contains the sequence contents
                        // which could be:
                        // 1. A Sequence element (if explicitly parsed)
                        // 2. Individual GeneralName elements (if parsed as contents)
                        match element.as_ref() {
                            Element::Sequence(names) => {
                                // Case 1: Parser created an explicit Sequence
                                let mut general_names = Vec::new();
                                for name_elem in names {
                                    general_names.push(name_elem.decode()?);
                                }
                                Ok(DistributionPointName::FullName(general_names))
                            }
                            // Case 2: element is a single GeneralName (single element sequence)
                            other => {
                                // Treat it as a single-element sequence
                                let general_name: GeneralName = other.decode()?;
                                Ok(DistributionPointName::FullName(vec![general_name]))
                            }
                        }
                    } else {
                        Err(Error::InvalidCRLDistributionPoints(
                            "fullName must be constructed (contain Sequence)".to_string(),
                        ))
                    }
                }
                1 => {
                    // nameRelativeToCRLIssuer [1] RelativeDistinguishedName
                    let rdn: RelativeDistinguishedName = element.decode()?;
                    Ok(DistributionPointName::NameRelativeToCRLIssuer(rdn))
                }
                _ => Err(Error::InvalidCRLDistributionPoints(format!(
                    "unexpected context-specific tag for DistributionPointName: {}",
                    slot
                ))),
            },
            _ => Err(Error::InvalidCRLDistributionPoints(
                "expected context-specific element for DistributionPointName".to_string(),
            )),
        }
    }
}

impl EncodableTo<DistributionPointName> for Element {}

impl Encoder<DistributionPointName, Element> for DistributionPointName {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        match self {
            DistributionPointName::FullName(names) => {
                let encoded_names = names
                    .iter()
                    .map(|n| n.encode())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Element::ContextSpecific {
                    constructed: true,
                    slot: 0,
                    element: Box::new(Element::Sequence(encoded_names)),
                })
            }
            DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                let rdn_element = rdn.encode()?;
                Ok(Element::ContextSpecific {
                    constructed: true,
                    slot: 1,
                    element: Box::new(rdn_element),
                })
            }
        }
    }
}

impl fmt::Display for DistributionPointName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DistributionPointName::FullName(names) => {
                writeln!(f, "Full Name:")?;
                for name in names {
                    writeln!(f, "  {}", name)?;
                }
                Ok(())
            }
            DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                writeln!(f, "Relative Name: {:?}", rdn)
            }
        }
    }
}

impl Extension for CRLDistributionPoints {
    const OID: &'static str = "2.5.29.31";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for CRLDistributionPoints {
    fn oid_name(&self) -> Option<&'static str> {
        Some("CRLDistributionPoints")
    }
}

impl fmt::Display for CRLDistributionPoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("CRLDistributionPoints");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for point in &self.distribution_points {
            if let Some(ref dist_point) = point.distribution_point {
                match dist_point {
                    DistributionPointName::FullName(full_name) => {
                        writeln!(f, "                Full Name:")?;
                        for name in full_name {
                            writeln!(f, "                  {}", name)?;
                        }
                    }
                    DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                        writeln!(f, "                Relative Name:")?;
                        writeln!(f, "                  {:?}", rdn)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::{Element, ObjectIdentifier, OctetString};
    use pkix_types::AttributeTypeAndValue;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest(
        input,
        expected,
        // Test case: Single distribution point with URI
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ContextSpecific {
                        constructed: true,
            slot: 0,
                        element: Box::new(Element::ContextSpecific {
                            constructed: true,
            slot: 0,
                            element: Box::new(Element::Sequence(vec![
                                Element::ContextSpecific {
                                    constructed: false,
            slot: 6,
                                    element: Box::new(Element::OctetString(OctetString::from(b"http://crl.example.com/ca.crl".to_vec()))),
                                },
                            ])),
                        }),
                    },
                ]),
            ]),
            CRLDistributionPoints {
                distribution_points: vec![
                    DistributionPoint {
                        distribution_point: Some(DistributionPointName::FullName(vec![
                            GeneralName::Uri("http://crl.example.com/ca.crl".to_string()),
                        ])),
                        reasons: None,
                        crl_issuer: None,
                    },
                ],
            }
        ),
        // Test case: Multiple URIs in one distribution point
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ContextSpecific {
                        constructed: true,
            slot: 0,
                        element: Box::new(Element::ContextSpecific {
                            constructed: true,
            slot: 0,
                            element: Box::new(Element::Sequence(vec![
                                Element::ContextSpecific {
                                    constructed: false,
            slot: 6,
                                    element: Box::new(Element::OctetString(OctetString::from(b"http://crl1.example.com/ca.crl".to_vec()))),
                                },
                                Element::ContextSpecific {
                                    constructed: false,
            slot: 6,
                                    element: Box::new(Element::OctetString(OctetString::from(b"http://crl2.example.com/ca.crl".to_vec()))),
                                },
                            ])),
                        }),
                    },
                ]),
            ]),
            CRLDistributionPoints {
                distribution_points: vec![
                    DistributionPoint {
                        distribution_point: Some(DistributionPointName::FullName(vec![
                            GeneralName::Uri("http://crl1.example.com/ca.crl".to_string()),
                            GeneralName::Uri("http://crl2.example.com/ca.crl".to_string()),
                        ])),
                        reasons: None,
                        crl_issuer: None,
                    },
                ],
            }
        ),
        // Test case: Multiple distribution points
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ContextSpecific {
                        constructed: true,
            slot: 0,
                        element: Box::new(Element::ContextSpecific {
                            constructed: true,
            slot: 0,
                            element: Box::new(Element::Sequence(vec![
                                Element::ContextSpecific {
                                    constructed: false,
            slot: 6,
                                    element: Box::new(Element::OctetString(OctetString::from(b"http://crl1.example.com/ca.crl".to_vec()))),
                                },
                            ])),
                        }),
                    },
                ]),
                Element::Sequence(vec![
                    Element::ContextSpecific {
                        constructed: true,
            slot: 0,
                        element: Box::new(Element::ContextSpecific {
                            constructed: true,
            slot: 0,
                            element: Box::new(Element::Sequence(vec![
                                Element::ContextSpecific {
                                    constructed: false,
            slot: 6,
                                    element: Box::new(Element::OctetString(OctetString::from(b"http://crl2.example.com/ca.crl".to_vec()))),
                                },
                            ])),
                        }),
                    },
                ]),
            ]),
            CRLDistributionPoints {
                distribution_points: vec![
                    DistributionPoint {
                        distribution_point: Some(DistributionPointName::FullName(vec![
                            GeneralName::Uri("http://crl1.example.com/ca.crl".to_string()),
                        ])),
                        reasons: None,
                        crl_issuer: None,
                    },
                    DistributionPoint {
                        distribution_point: Some(DistributionPointName::FullName(vec![
                            GeneralName::Uri("http://crl2.example.com/ca.crl".to_string()),
                        ])),
                        reasons: None,
                        crl_issuer: None,
                    },
                ],
            }
        ),
        // Test case: Distribution point with reasons
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ContextSpecific {
                        constructed: true,
            slot: 0,
                        element: Box::new(Element::ContextSpecific {
                            constructed: true,
            slot: 0,
                            element: Box::new(Element::Sequence(vec![
                                Element::ContextSpecific {
                                    constructed: false,
            slot: 6,
                                    element: Box::new(Element::OctetString(OctetString::from(b"http://crl.example.com/ca.crl".to_vec()))),
                                },
                            ])),
                        }),
                    },
                    Element::ContextSpecific {
                        constructed: false,
            slot: 1,
                        element: Box::new(Element::BitString(
                            // unused_bits=6 means 2 bits are valid: bit 0 (unused) and bit 1 (keyCompromise)
                            // 0b01000000 sets bit 1 (keyCompromise)
                            asn1::BitString::new(6, vec![0b0100_0000])
                        )),
                    },
                ]),
            ]),
            CRLDistributionPoints {
                distribution_points: vec![
                    DistributionPoint {
                        distribution_point: Some(DistributionPointName::FullName(vec![
                            GeneralName::Uri("http://crl.example.com/ca.crl".to_string()),
                        ])),
                        reasons: Some(ReasonFlags {
                            key_compromise: true,
                            ca_compromise: false,
                            affiliation_changed: false,
                            superseded: false,
                            cessation_of_operation: false,
                            certificate_hold: false,
                            privilege_withdrawn: false,
                            aa_compromise: false,
                        }),
                        crl_issuer: None,
                    },
                ],
            }
        ),
    )]
    fn test_crl_distribution_points_decode_success(
        input: Element,
        expected: CRLDistributionPoints,
    ) {
        let result: Result<CRLDistributionPoints, _> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "empty sequence"
        ),
        // Test case: Not a Sequence
        case(
            Element::Boolean(true),
            "expected Sequence"
        ),
    )]
    fn test_crl_distribution_points_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<CRLDistributionPoints, Error> = input.decode();
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

    #[rstest(
        input,
        expected,
        // Test case: Empty bit string
        case(
            asn1::BitString::new(0, vec![]),
            ReasonFlags {
                key_compromise: false,
                ca_compromise: false,
                affiliation_changed: false,
                superseded: false,
                cessation_of_operation: false,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: false,
            }
        ),
        // Test case: Only keyCompromise (bit 1)
        case(
            asn1::BitString::new(6, vec![0b0100_0000]),
            ReasonFlags {
                key_compromise: true,
                ca_compromise: false,
                affiliation_changed: false,
                superseded: false,
                cessation_of_operation: false,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: false,
            }
        ),
        // Test case: cACompromise (bit 2)
        case(
            asn1::BitString::new(5, vec![0b0010_0000]),
            ReasonFlags {
                key_compromise: false,
                ca_compromise: true,
                affiliation_changed: false,
                superseded: false,
                cessation_of_operation: false,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: false,
            }
        ),
        // Test case: Multiple flags (bits 1, 2, 4)
        case(
            asn1::BitString::new(3, vec![0b0110_1000]),
            ReasonFlags {
                key_compromise: true,
                ca_compromise: true,
                affiliation_changed: false,
                superseded: true,
                cessation_of_operation: false,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: false,
            }
        ),
        // Test case: All flags in first byte (bits 1-7)
        case(
            asn1::BitString::new(0, vec![0b0111_1111]),
            ReasonFlags {
                key_compromise: true,
                ca_compromise: true,
                affiliation_changed: true,
                superseded: true,
                cessation_of_operation: true,
                certificate_hold: true,
                privilege_withdrawn: true,
                aa_compromise: false,
            }
        ),
        // Test case: aaCompromise (bit 8, second byte)
        case(
            asn1::BitString::new(7, vec![0b0000_0000, 0b1000_0000]),
            ReasonFlags {
                key_compromise: false,
                ca_compromise: false,
                affiliation_changed: false,
                superseded: false,
                cessation_of_operation: false,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: true,
            }
        ),
        // Test case: All flags including aaCompromise
        case(
            asn1::BitString::new(7, vec![0b0111_1111, 0b1000_0000]),
            ReasonFlags {
                key_compromise: true,
                ca_compromise: true,
                affiliation_changed: true,
                superseded: true,
                cessation_of_operation: true,
                certificate_hold: true,
                privilege_withdrawn: true,
                aa_compromise: true,
            }
        ),
        // Test case: cessationOfOperation only (bit 5)
        case(
            asn1::BitString::new(2, vec![0b0000_0100]),
            ReasonFlags {
                key_compromise: false,
                ca_compromise: false,
                affiliation_changed: false,
                superseded: false,
                cessation_of_operation: true,
                certificate_hold: false,
                privilege_withdrawn: false,
                aa_compromise: false,
            }
        ),
    )]
    fn test_reason_flags_from_bit_string(input: asn1::BitString, expected: ReasonFlags) {
        let result: ReasonFlags = input.into();
        assert_eq!(expected, result);
    }

    #[rstest]
    #[case(CRLDistributionPoints {
        distribution_points: vec![
            DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::Uri("http://crl.example.com/crl.pem".to_string()),
                ])),
                reasons: None,
                crl_issuer: None,
            },
        ],
    })]
    #[case(CRLDistributionPoints {
        distribution_points: vec![
            DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::Uri("http://crl1.example.com/crl.pem".to_string()),
                    GeneralName::Uri("http://crl2.example.com/crl.pem".to_string()),
                ])),
                reasons: None,
                crl_issuer: None,
            },
        ],
    })]
    #[case(CRLDistributionPoints {
        distribution_points: vec![
            DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::Uri("http://crl.example.com/crl.pem".to_string()),
                ])),
                reasons: Some(ReasonFlags {
                    key_compromise: true,
                    ca_compromise: false,
                    affiliation_changed: false,
                    superseded: false,
                    cessation_of_operation: false,
                    certificate_hold: false,
                    privilege_withdrawn: false,
                    aa_compromise: false,
                }),
                crl_issuer: None,
            },
        ],
    })]
    #[case(CRLDistributionPoints {
        distribution_points: vec![
            DistributionPoint {
                distribution_point: Some(DistributionPointName::NameRelativeToCRLIssuer(
                    RelativeDistinguishedName {
                        attributes: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(), // CN
                                attribute_value: "CRL1".to_string(),
                            },
                        ],
                    },
                )),
                reasons: None,
                crl_issuer: None,
            },
        ],
    })]
    #[case(CRLDistributionPoints {
        distribution_points: vec![
            DistributionPoint {
                distribution_point: Some(DistributionPointName::NameRelativeToCRLIssuer(
                    RelativeDistinguishedName {
                        attributes: vec![
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.10").unwrap(), // O
                                attribute_value: "Example Org".to_string(),
                            },
                            AttributeTypeAndValue {
                                attribute_type: ObjectIdentifier::from_str("2.5.4.11").unwrap(), // OU
                                attribute_value: "CRL Department".to_string(),
                            },
                        ],
                    },
                )),
                reasons: Some(ReasonFlags {
                    key_compromise: true,
                    ca_compromise: false,
                    affiliation_changed: false,
                    superseded: false,
                    cessation_of_operation: false,
                    certificate_hold: false,
                    privilege_withdrawn: false,
                    aa_compromise: false,
                }),
                crl_issuer: None,
            },
        ],
    })]
    fn test_crl_distribution_points_encode_decode(#[case] original: CRLDistributionPoints) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<CRLDistributionPoints, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }

    #[rstest]
    #[case(
        RelativeDistinguishedName {
            attributes: vec![AttributeTypeAndValue {
                attribute_type: ObjectIdentifier::from_str("2.5.4.3").unwrap(),
                attribute_value: "CRL1".to_string(),
            }],
        }
    )]
    #[case(
        RelativeDistinguishedName {
            attributes: vec![
                AttributeTypeAndValue {
                    attribute_type: ObjectIdentifier::from_str("2.5.4.10").unwrap(),
                    attribute_value: "Example Org".to_string(),
                },
                AttributeTypeAndValue {
                    attribute_type: ObjectIdentifier::from_str("2.5.4.11").unwrap(),
                    attribute_value: "Engineering".to_string(),
                },
            ],
        }
    )]
    #[case(
        RelativeDistinguishedName {
            attributes: vec![
                AttributeTypeAndValue {
                    attribute_type: ObjectIdentifier::from_str("2.5.4.6").unwrap(),
                    attribute_value: "US".to_string(),
                },
                AttributeTypeAndValue {
                    attribute_type: ObjectIdentifier::from_str("2.5.4.8").unwrap(),
                    attribute_value: "California".to_string(),
                },
                AttributeTypeAndValue {
                    attribute_type: ObjectIdentifier::from_str("2.5.4.7").unwrap(),
                    attribute_value: "San Francisco".to_string(),
                },
            ],
        }
    )]
    fn test_distribution_point_name_relative_display(#[case] rdn: RelativeDistinguishedName) {
        let name = DistributionPointName::NameRelativeToCRLIssuer(rdn.clone());
        let output = format!("{}", name);
        assert!(output.contains("Relative Name:"));
        assert!(output.contains(&format!("{:?}", rdn)));
    }
}
