use asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;
use crate::extensions::StandardExtension;

/*
RFC 5280 Section 4.2.1.4

CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

PolicyInformation ::= SEQUENCE {
    policyIdentifier   CertPolicyId,
    policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }

CertPolicyId ::= OBJECT IDENTIFIER

PolicyQualifierInfo ::= SEQUENCE {
    policyQualifierId  PolicyQualifierId,
    qualifier          ANY DEFINED BY policyQualifierId }

PolicyQualifierId ::= OBJECT IDENTIFIER

-- Qualifier types defined in RFC 5280
id-qt-cps      OBJECT IDENTIFIER ::= { id-qt 1 }  -- 1.3.6.1.5.5.7.2.1
id-qt-unotice  OBJECT IDENTIFIER ::= { id-qt 2 }  -- 1.3.6.1.5.5.7.2.2

UserNotice ::= SEQUENCE {
    noticeRef        NoticeReference OPTIONAL,
    explicitText     DisplayText OPTIONAL }

NoticeReference ::= SEQUENCE {
    organization     DisplayText,
    noticeNumbers    SEQUENCE OF INTEGER }

DisplayText ::= CHOICE {
    ia5String        IA5String      (SIZE (1..200)),
    visibleString    VisibleString  (SIZE (1..200)),
    bmpString        BMPString      (SIZE (1..200)),
    utf8String       UTF8String     (SIZE (1..200)) }
*/

/// CertPolicyId is an Object Identifier representing a certificate policy (RFC 5280)
pub type CertPolicyId = ObjectIdentifier;

/// CertificatePolicies represents the Certificate Policies extension
/// OID: 2.5.29.32
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificatePolicies {
    pub policies: Vec<PolicyInformation>,
}

impl CertificatePolicies {
    /// OID for anyPolicy - represents any certificate policy (RFC 5280)
    /// This is a special policy identifier that matches all certificate policies
    pub const ANY_POLICY: &'static str = "2.5.29.32.0";
}

/// PolicyInformation represents a single policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInformation {
    pub policy_identifier: CertPolicyId,
    pub policy_qualifiers: Option<Vec<PolicyQualifierInfo>>,
}

/// PolicyQualifierInfo contains additional policy information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyQualifierInfo {
    pub policy_qualifier_id: ObjectIdentifier,
    pub qualifier: Qualifier,
}

/// Qualifier represents the qualifier data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Qualifier {
    /// CPS URI (id-qt-cps: 1.3.6.1.5.5.7.2.1)
    CpsUri(String),
    /// User Notice (id-qt-unotice: 1.3.6.1.5.5.7.2.2)
    UserNotice(UserNotice),
    /// Other qualifier types (stored as raw bytes)
    Other(Vec<u8>),
}

/// UserNotice represents a user notice
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNotice {
    pub notice_ref: Option<NoticeReference>,
    pub explicit_text: Option<String>,
}

/// NoticeReference references a specific notice
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeReference {
    pub organization: String,
    pub notice_numbers: Vec<i64>,
}

impl PolicyQualifierInfo {
    /// OID for CPS Pointer qualifier
    pub const ID_QT_CPS: &'static str = "1.3.6.1.5.5.7.2.1";
    /// OID for User Notice qualifier
    pub const ID_QT_UNOTICE: &'static str = "1.3.6.1.5.5.7.2.2";
}

impl DecodableFrom<OctetString> for CertificatePolicies {}

impl Decoder<OctetString, CertificatePolicies> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<CertificatePolicies, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidCertificatePolicies(
                "empty sequence".to_string(),
            ));
        }

        elements[0].decode()
    }
}

impl DecodableFrom<Element> for CertificatePolicies {}

impl Decoder<Element, CertificatePolicies> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificatePolicies, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidCertificatePolicies(
                        "empty sequence - at least one PolicyInformation required".to_string(),
                    ));
                }

                let mut policies = Vec::new();
                for elem in elements {
                    let policy: PolicyInformation = elem.decode()?;
                    policies.push(policy);
                }

                Ok(CertificatePolicies { policies })
            }
            _ => Err(Error::InvalidCertificatePolicies(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl DecodableFrom<Element> for PolicyInformation {}

impl Decoder<Element, PolicyInformation> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyInformation, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut iter = elements.iter();

                // First element: policyIdentifier (OBJECT IDENTIFIER)
                let policy_identifier = match iter.next() {
                    Some(Element::ObjectIdentifier(oid)) => oid.clone(),
                    Some(_) => {
                        return Err(Error::InvalidCertificatePolicies(
                            "expected ObjectIdentifier for policyIdentifier".to_string(),
                        ));
                    }
                    None => {
                        return Err(Error::InvalidCertificatePolicies(
                            "PolicyInformation must have at least policyIdentifier".to_string(),
                        ));
                    }
                };

                // Second element (optional): policyQualifiers (SEQUENCE)
                let policy_qualifiers = match iter.next() {
                    Some(Element::Sequence(qualifiers)) => {
                        let mut result = Vec::new();
                        for qualifier_elem in qualifiers {
                            result.push(qualifier_elem.decode()?);
                        }
                        Some(result)
                    }
                    Some(_) => {
                        return Err(Error::InvalidCertificatePolicies(
                            "expected Sequence for policyQualifiers".to_string(),
                        ));
                    }
                    None => None,
                };

                Ok(PolicyInformation {
                    policy_identifier,
                    policy_qualifiers,
                })
            }
            _ => Err(Error::InvalidCertificatePolicies(
                "expected Sequence for PolicyInformation".to_string(),
            )),
        }
    }
}

impl DecodableFrom<Element> for PolicyQualifierInfo {}

impl Decoder<Element, PolicyQualifierInfo> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyQualifierInfo, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut iter = elements.iter();

                // First element: policyQualifierId (OBJECT IDENTIFIER)
                let policy_qualifier_id = match iter.next() {
                    Some(Element::ObjectIdentifier(oid)) => oid.clone(),
                    Some(_) => {
                        return Err(Error::InvalidCertificatePolicies(
                            "expected ObjectIdentifier for policyQualifierId".to_string(),
                        ));
                    }
                    None => {
                        return Err(Error::InvalidCertificatePolicies(
                            "PolicyQualifierInfo must have policyQualifierId".to_string(),
                        ));
                    }
                };

                // Second element: qualifier (depends on policyQualifierId)
                let qualifier_elem = match iter.next() {
                    Some(elem) => elem,
                    None => {
                        return Err(Error::InvalidCertificatePolicies(
                            "PolicyQualifierInfo must have qualifier".to_string(),
                        ));
                    }
                };

                let qualifier = match policy_qualifier_id.to_string().as_str() {
                    PolicyQualifierInfo::ID_QT_CPS => {
                        // CPS URI is an IA5String
                        if let Element::IA5String(s) = qualifier_elem {
                            Qualifier::CpsUri(s.clone())
                        } else {
                            return Err(Error::InvalidCertificatePolicies(
                                "expected IA5String for CPS URI".to_string(),
                            ));
                        }
                    }
                    PolicyQualifierInfo::ID_QT_UNOTICE => {
                        // User Notice is a SEQUENCE
                        let user_notice: UserNotice = qualifier_elem.decode()?;
                        Qualifier::UserNotice(user_notice)
                    }
                    _ => {
                        // Unknown qualifier type - store as raw bytes
                        let bytes = format!("{:?}", qualifier_elem).into_bytes();
                        Qualifier::Other(bytes)
                    }
                };

                Ok(PolicyQualifierInfo {
                    policy_qualifier_id,
                    qualifier,
                })
            }
            _ => Err(Error::InvalidCertificatePolicies(
                "expected Sequence for PolicyQualifierInfo".to_string(),
            )),
        }
    }
}

impl DecodableFrom<Element> for UserNotice {}

impl Decoder<Element, UserNotice> for Element {
    type Error = Error;

    fn decode(&self) -> Result<UserNotice, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut notice_ref = None;
                let mut explicit_text = None;

                for elem in elements {
                    match elem {
                        Element::Sequence(_) => {
                            // This is NoticeReference
                            notice_ref = Some(elem.decode()?);
                        }
                        Element::IA5String(s) | Element::UTF8String(s) => {
                            explicit_text = Some(s.clone());
                        }
                        Element::PrintableString(s) => {
                            explicit_text = Some(s.clone());
                        }
                        _ => {
                            return Err(Error::InvalidCertificatePolicies(
                                "unexpected element in UserNotice".to_string(),
                            ));
                        }
                    }
                }

                Ok(UserNotice {
                    notice_ref,
                    explicit_text,
                })
            }
            _ => Err(Error::InvalidCertificatePolicies(
                "expected Sequence for UserNotice".to_string(),
            )),
        }
    }
}

impl DecodableFrom<Element> for NoticeReference {}

impl Decoder<Element, NoticeReference> for Element {
    type Error = Error;

    fn decode(&self) -> Result<NoticeReference, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut iter = elements.iter();

                // First element: organization (DisplayText)
                let organization = match iter.next() {
                    Some(Element::IA5String(s) | Element::UTF8String(s)) => s.clone(),
                    Some(Element::PrintableString(s)) => s.clone(),
                    Some(_) => {
                        return Err(Error::InvalidCertificatePolicies(
                            "expected DisplayText for organization".to_string(),
                        ));
                    }
                    None => {
                        return Err(Error::InvalidCertificatePolicies(
                            "NoticeReference must have organization".to_string(),
                        ));
                    }
                };

                // Second element: noticeNumbers (SEQUENCE OF INTEGER)
                let notice_numbers = match iter.next() {
                    Some(Element::Sequence(nums)) => {
                        let mut result = Vec::new();
                        for num_elem in nums {
                            if let Element::Integer(n) = num_elem {
                                let num_value: i64 = n.try_into().map_err(|_| {
                                    Error::InvalidCertificatePolicies(
                                        "notice number out of i64 range".to_string(),
                                    )
                                })?;
                                result.push(num_value);
                            } else {
                                return Err(Error::InvalidCertificatePolicies(
                                    "expected INTEGER in noticeNumbers".to_string(),
                                ));
                            }
                        }
                        result
                    }
                    Some(_) => {
                        return Err(Error::InvalidCertificatePolicies(
                            "expected Sequence for noticeNumbers".to_string(),
                        ));
                    }
                    None => {
                        return Err(Error::InvalidCertificatePolicies(
                            "NoticeReference must have noticeNumbers".to_string(),
                        ));
                    }
                };

                Ok(NoticeReference {
                    organization,
                    notice_numbers,
                })
            }
            _ => Err(Error::InvalidCertificatePolicies(
                "expected Sequence for NoticeReference".to_string(),
            )),
        }
    }
}

impl StandardExtension for CertificatePolicies {
    const OID: &'static str = "2.5.29.32";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::Element;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest(
        input,
        expected,
        // Test case: Single policy without qualifiers
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap()),
                ]),
            ]),
            CertificatePolicies {
                policies: vec![
                    PolicyInformation {
                        policy_identifier: ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap(),
                        policy_qualifiers: None,
                    },
                ],
            }
        ),
        // Test case: Policy with CPS URI qualifier
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
                    Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.3.6.1.5.5.7.2.1").unwrap()),
                            Element::IA5String("https://example.com/cps".to_string()),
                        ]),
                    ]),
                ]),
            ]),
            CertificatePolicies {
                policies: vec![
                    PolicyInformation {
                        policy_identifier: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                        policy_qualifiers: Some(vec![
                            PolicyQualifierInfo {
                                policy_qualifier_id: ObjectIdentifier::from_str("1.3.6.1.5.5.7.2.1").unwrap(),
                                qualifier: Qualifier::CpsUri("https://example.com/cps".to_string()),
                            },
                        ]),
                    },
                ],
            }
        ),
        // Test case: Multiple policies
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.5").unwrap()),
                ]),
            ]),
            CertificatePolicies {
                policies: vec![
                    PolicyInformation {
                        policy_identifier: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                        policy_qualifiers: None,
                    },
                    PolicyInformation {
                        policy_identifier: ObjectIdentifier::from_str("1.2.3.5").unwrap(),
                        policy_qualifiers: None,
                    },
                ],
            }
        ),
        // Test case: Policy with User Notice (explicit text only)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
                    Element::Sequence(vec![
                        Element::Sequence(vec![
                            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.3.6.1.5.5.7.2.2").unwrap()),
                            Element::Sequence(vec![
                                Element::UTF8String("This is a notice".to_string()),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
            CertificatePolicies {
                policies: vec![
                    PolicyInformation {
                        policy_identifier: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                        policy_qualifiers: Some(vec![
                            PolicyQualifierInfo {
                                policy_qualifier_id: ObjectIdentifier::from_str("1.3.6.1.5.5.7.2.2").unwrap(),
                                qualifier: Qualifier::UserNotice(UserNotice {
                                    notice_ref: None,
                                    explicit_text: Some("This is a notice".to_string()),
                                }),
                            },
                        ]),
                    },
                ],
            }
        ),
    )]
    fn test_certificate_policies_decode_success(input: Element, expected: CertificatePolicies) {
        let result: Result<CertificatePolicies, Error> = input.decode();
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
    fn test_certificate_policies_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<CertificatePolicies, Error> = input.decode();
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
    fn test_certificate_policies_with_any_policy() {
        // Test case: anyPolicy with CPS URI qualifier
        let input = Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(
                ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap(),
            ),
            Element::Sequence(vec![Element::Sequence(vec![
                Element::ObjectIdentifier(
                    ObjectIdentifier::from_str(PolicyQualifierInfo::ID_QT_CPS).unwrap(),
                ),
                Element::IA5String("https://example.com/anypolicy-cps".to_string()),
            ])]),
        ])]);

        let result: Result<CertificatePolicies, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode anyPolicy with qualifier");

        let cert_policies = result.unwrap();
        assert_eq!(cert_policies.policies.len(), 1);
        assert_eq!(
            cert_policies.policies[0].policy_identifier.to_string(),
            CertificatePolicies::ANY_POLICY
        );
        assert!(cert_policies.policies[0].policy_qualifiers.is_some());
    }

    #[test]
    fn test_certificate_policies_mixed_with_any_policy() {
        // Test case: Multiple policies including anyPolicy
        let input = Element::Sequence(vec![
            Element::Sequence(vec![Element::ObjectIdentifier(
                ObjectIdentifier::from_str("1.2.3.4.5").unwrap(),
            )]),
            Element::Sequence(vec![Element::ObjectIdentifier(
                ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap(),
            )]),
            Element::Sequence(vec![Element::ObjectIdentifier(
                ObjectIdentifier::from_str("1.2.3.4.6").unwrap(),
            )]),
        ]);

        let result: Result<CertificatePolicies, Error> = input.decode();
        assert!(
            result.is_ok(),
            "Failed to decode mixed policies with anyPolicy"
        );

        let cert_policies = result.unwrap();
        assert_eq!(cert_policies.policies.len(), 3);
        assert_eq!(
            cert_policies.policies[0].policy_identifier,
            "1.2.3.4.5"
        );
        assert_eq!(
            cert_policies.policies[1].policy_identifier,
            CertificatePolicies::ANY_POLICY
        );
        assert_eq!(
            cert_policies.policies[2].policy_identifier,
            "1.2.3.4.6"
        );
    }
}
