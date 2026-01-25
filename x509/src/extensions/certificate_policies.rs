use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, Integer, ObjectIdentifier, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;

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

        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::CertificatePolicies).into()),
        }
    }
}

impl DecodableFrom<Element> for CertificatePolicies {}

impl Decoder<Element, CertificatePolicies> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificatePolicies, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::CertificatePoliciesEmpty.into());
                }

                let policies = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<PolicyInformation>, _>>()?;

                Ok(CertificatePolicies { policies })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::CertificatePolicies).into()),
        }
    }
}

impl EncodableTo<CertificatePolicies> for Element {}

impl Encoder<CertificatePolicies, Element> for CertificatePolicies {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.policies.is_empty() {
            return Err(error::Error::CertificatePoliciesEmpty.into());
        }

        let policy_elements = self
            .policies
            .iter()
            .map(|p| p.encode())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Element::Sequence(policy_elements))
    }
}

impl DecodableFrom<Element> for PolicyInformation {}

impl Decoder<Element, PolicyInformation> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyInformation, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (policy_identifier, policy_qualifiers) = match elements.as_slice() {
                    // Only policyIdentifier
                    [Element::ObjectIdentifier(oid)] => (oid.clone(), None),
                    // policyIdentifier + policyQualifiers
                    [
                        Element::ObjectIdentifier(oid),
                        Element::Sequence(qualifiers),
                    ] => {
                        let result = qualifiers
                            .iter()
                            .map(|elem| elem.decode())
                            .collect::<Result<Vec<PolicyQualifierInfo>, _>>()?;
                        (oid.clone(), Some(result))
                    }
                    // policyIdentifier + wrong type for policyQualifiers
                    [Element::ObjectIdentifier(_), _] => {
                        return Err(error::Error::PolicyQualifiersExpectedSequence.into());
                    }
                    // Wrong type for policyIdentifier
                    [_, ..] => {
                        return Err(error::Error::PolicyInformationExpectedOid.into());
                    }
                    // Empty
                    [] => {
                        return Err(error::Error::PolicyInformationMissingIdentifier.into());
                    }
                };

                Ok(PolicyInformation {
                    policy_identifier,
                    policy_qualifiers,
                })
            }
            _ => Err(error::Error::PolicyInformationExpectedSequence.into()),
        }
    }
}

impl EncodableTo<PolicyInformation> for Element {}

impl Encoder<PolicyInformation, Element> for PolicyInformation {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let policy_id = Element::ObjectIdentifier(self.policy_identifier.clone());

        let qualifiers_elem = self
            .policy_qualifiers
            .as_ref()
            .map(|qualifiers| {
                qualifiers
                    .iter()
                    .map(|q| q.encode())
                    .collect::<Result<Vec<_>, _>>()
                    .map(Element::Sequence)
            })
            .transpose()?;

        let elements: Vec<_> = std::iter::once(policy_id).chain(qualifiers_elem).collect();

        Ok(Element::Sequence(elements))
    }
}

impl DecodableFrom<Element> for PolicyQualifierInfo {}

impl Decoder<Element, PolicyQualifierInfo> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyQualifierInfo, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (policy_qualifier_id, qualifier_elem) = match elements.as_slice() {
                    [Element::ObjectIdentifier(oid), qualifier] => (oid.clone(), qualifier),
                    [Element::ObjectIdentifier(_)] => {
                        return Err(error::Error::PolicyQualifierInfoInvalidElementCount.into());
                    }
                    [_, ..] => {
                        return Err(error::Error::PolicyQualifierIdExpectedOid.into());
                    }
                    [] => {
                        return Err(error::Error::PolicyQualifierInfoInvalidElementCount.into());
                    }
                };

                let qualifier = match policy_qualifier_id.to_string().as_str() {
                    PolicyQualifierInfo::ID_QT_CPS => {
                        // CPS URI is an IA5String
                        if let Element::IA5String(s) = qualifier_elem {
                            Qualifier::CpsUri(s.clone())
                        } else {
                            return Err(error::Error::PolicyQualifierIdExpectedOid.into());
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
            _ => Err(error::Error::PolicyQualifierInfoExpectedSequence.into()),
        }
    }
}

impl EncodableTo<PolicyQualifierInfo> for Element {}

impl Encoder<PolicyQualifierInfo, Element> for PolicyQualifierInfo {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let qualifier_elem = match &self.qualifier {
            Qualifier::CpsUri(uri) => Element::IA5String(uri.clone()),
            Qualifier::UserNotice(notice) => notice.encode()?,
            Qualifier::Other(bytes) => Element::OctetString(bytes.clone().into()),
        };

        Ok(Element::Sequence(vec![
            Element::ObjectIdentifier(self.policy_qualifier_id.clone()),
            qualifier_elem,
        ]))
    }
}

impl DecodableFrom<Element> for UserNotice {}

impl Decoder<Element, UserNotice> for Element {
    type Error = Error;

    fn decode(&self) -> Result<UserNotice, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (notice_ref, explicit_text) = elements.iter().try_fold(
                    (None, None),
                    |(notice, text), elem| -> Result<_, Error> {
                        match elem {
                            Element::Sequence(_) => Ok((Some(elem.decode()?), text)),
                            Element::IA5String(s) | Element::UTF8String(s) => {
                                Ok((notice, Some(s.clone())))
                            }
                            Element::PrintableString(s) => Ok((notice, Some(s.clone()))),
                            _ => Err(error::Error::UnexpectedElementType(
                                error::Kind::CertificatePolicies,
                            )
                            .into()),
                        }
                    },
                )?;

                Ok(UserNotice {
                    notice_ref,
                    explicit_text,
                })
            }
            _ => Err(error::Error::UserNoticeExpectedSequence.into()),
        }
    }
}

impl EncodableTo<UserNotice> for Element {}

impl Encoder<UserNotice, Element> for UserNotice {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let notice_ref_elem = if let Some(nr) = &self.notice_ref {
            Some(nr.encode()?)
        } else {
            None
        };
        let text_elem = self
            .explicit_text
            .as_ref()
            .map(|text| Element::UTF8String(text.clone()));

        let elements = notice_ref_elem.into_iter().chain(text_elem).collect();

        Ok(Element::Sequence(elements))
    }
}

impl DecodableFrom<Element> for NoticeReference {}

impl Decoder<Element, NoticeReference> for Element {
    type Error = Error;

    fn decode(&self) -> Result<NoticeReference, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (organization, notice_numbers) = match elements.as_slice() {
                    [
                        Element::IA5String(s) | Element::UTF8String(s),
                        Element::Sequence(nums),
                    ]
                    | [Element::PrintableString(s), Element::Sequence(nums)] => {
                        let numbers = nums
                            .iter()
                            .map(|num_elem| -> Result<i64, Error> {
                                match num_elem {
                                    Element::Integer(n) => n.try_into().map_err(|_| {
                                        error::Error::ValueOutOfRangeU32(
                                            error::Kind::CertificatePolicies,
                                        )
                                        .into()
                                    }),
                                    _ => Err(error::Error::NoticeNumbersExpectedIntegers.into()),
                                }
                            })
                            .collect::<Result<Vec<i64>, Error>>()?;
                        (s.clone(), numbers)
                    }
                    [
                        Element::IA5String(_)
                        | Element::UTF8String(_)
                        | Element::PrintableString(_),
                        _,
                    ] => {
                        return Err(error::Error::NoticeNumbersExpectedSequence.into());
                    }
                    [
                        Element::IA5String(_)
                        | Element::UTF8String(_)
                        | Element::PrintableString(_),
                    ] => {
                        return Err(error::Error::NoticeReferenceInvalidStructure.into());
                    }
                    [_, ..] => {
                        return Err(error::Error::NoticeReferenceInvalidStructure.into());
                    }
                    [] => {
                        return Err(error::Error::NoticeReferenceInvalidStructure.into());
                    }
                };

                Ok(NoticeReference {
                    organization,
                    notice_numbers,
                })
            }
            _ => Err(error::Error::NoticeReferenceInvalidStructure.into()),
        }
    }
}

impl EncodableTo<NoticeReference> for Element {}

impl Encoder<NoticeReference, Element> for NoticeReference {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let org_elem = Element::UTF8String(self.organization.clone());
        let numbers = self
            .notice_numbers
            .iter()
            .map(|&num| {
                let bytes = num.to_be_bytes();
                let start = bytes
                    .iter()
                    .position(|&b| b != 0)
                    .unwrap_or(bytes.len() - 1);
                let slice = bytes.get(start..).unwrap_or(&bytes);
                Element::Integer(Integer::from(slice))
            })
            .collect();

        Ok(Element::Sequence(vec![
            org_elem,
            Element::Sequence(numbers),
        ]))
    }
}

impl Extension for CertificatePolicies {
    const OID: &'static str = "2.5.29.32";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for CertificatePolicies {
    fn oid_name(&self) -> Option<&'static str> {
        Some("certificatePolicies")
    }
}

impl fmt::Display for CertificatePolicies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("certificatePolicies");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for policy in &self.policies {
            writeln!(f, "                Policy: {}", policy.policy_identifier)?;
            if let Some(ref qualifiers) = policy.policy_qualifiers {
                for qualifier in qualifiers {
                    writeln!(f, "                  {}", qualifier.policy_qualifier_id)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::Element;

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

    #[rstest]
    // Test case: Empty sequence
    #[case(
        Element::Sequence(vec![]),
        "at least one PolicyInformation required"
    )]
    // Test case: Not a Sequence
    #[case(Element::Boolean(true), "expected SEQUENCE")]
    fn test_certificate_policies_decode_failure(
        #[case] input: Element,
        #[case] expected_error_msg: &str,
    ) {
        let result: Result<CertificatePolicies, _> = input.decode();
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
        assert_eq!(cert_policies.policies[0].policy_identifier, "1.2.3.4.5");
        assert_eq!(
            cert_policies.policies[1].policy_identifier,
            CertificatePolicies::ANY_POLICY
        );
        assert_eq!(cert_policies.policies[2].policy_identifier, "1.2.3.4.6");
    }

    #[rstest]
    #[case(CertificatePolicies {
        policies: vec![
            PolicyInformation {
                policy_identifier: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                policy_qualifiers: None,
            },
        ],
    })]
    #[case(CertificatePolicies {
        policies: vec![
            PolicyInformation {
                policy_identifier: ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap(),
                policy_qualifiers: None,
            },
        ],
    })]
    #[case(CertificatePolicies {
        policies: vec![
            PolicyInformation {
                policy_identifier: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                policy_qualifiers: Some(vec![
                    PolicyQualifierInfo {
                        policy_qualifier_id: ObjectIdentifier::from_str(PolicyQualifierInfo::ID_QT_CPS).unwrap(),
                        qualifier: Qualifier::CpsUri("http://example.com/cps".to_string()),
                    },
                ]),
            },
        ],
    })]
    fn test_certificate_policies_encode_decode(#[case] original: CertificatePolicies) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<CertificatePolicies, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original.policies.len(), roundtrip.policies.len());
        for (orig, rt) in original.policies.iter().zip(roundtrip.policies.iter()) {
            assert_eq!(orig.policy_identifier, rt.policy_identifier);
        }
    }
}
