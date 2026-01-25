use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::certificate_policies::{CertPolicyId, CertificatePolicies};

/*
RFC 5280 Section 4.2.1.5

id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }

PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
     issuerDomainPolicy      CertPolicyId,
     subjectDomainPolicy     CertPolicyId }

CertPolicyId ::= OBJECT IDENTIFIER

The policy mappings extension can be used in CA certificates.  It lists
one or more pairs of OIDs; each pair includes an issuerDomainPolicy and
a subjectDomainPolicy.  The pairing indicates that the issuing CA considers
its issuerDomainPolicy equivalent to the subject CA's subjectDomainPolicy.

The issuing CA's users might accept an issuerDomainPolicy for certain
applications.  The policy mapping tells the issuing CA's users that they
can also accept the subject CA's subjectDomainPolicy for those applications.

Policy mapping is used to allow a CA in one domain (or "policy space")
to recognize the policies of a CA in another domain.

Constraints:
- This extension SHOULD only appear in CA certificates.
- The value of issuerDomainPolicy or subjectDomainPolicy MUST NOT be anyPolicy (2.5.29.32.0).
- Policy mappings are typically marked as critical.
*/

/// PolicyMappings extension defines policy equivalences between CAs
/// OID: 2.5.29.33
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMappings {
    /// List of policy mappings
    pub mappings: Vec<PolicyMapping>,
}

/// A single policy mapping from issuer domain policy to subject domain policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMapping {
    /// The policy OID in the issuer's domain
    pub issuer_domain_policy: CertPolicyId,
    /// The equivalent policy OID in the subject's domain
    pub subject_domain_policy: CertPolicyId,
}

impl Extension for PolicyMappings {
    /// OID for PolicyMappings extension (2.5.29.33)
    const OID: &'static str = "2.5.29.33";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;

        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::PolicyMappingsEmpty.into()),
        }
    }
}

impl DecodableFrom<Element> for PolicyMappings {}

impl Decoder<Element, PolicyMappings> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyMappings, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::PolicyMappingsEmpty.into());
                }

                let mappings: Vec<PolicyMapping> = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(PolicyMappings { mappings })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::PolicyMappings).into()),
        }
    }
}

impl EncodableTo<PolicyMappings> for Element {}

impl Encoder<PolicyMappings, Element> for PolicyMappings {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.mappings.is_empty() {
            return Err(error::Error::PolicyMappingsEmpty.into());
        }

        let mapping_elements = self
            .mappings
            .iter()
            .map(|m| m.encode())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Element::Sequence(mapping_elements))
    }
}

impl DecodableFrom<Element> for PolicyMapping {}

impl Decoder<Element, PolicyMapping> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyMapping, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (issuer_domain_policy, subject_domain_policy) = match elements.as_slice() {
                    [
                        Element::ObjectIdentifier(issuer),
                        Element::ObjectIdentifier(subject),
                    ] => (issuer.clone(), subject.clone()),
                    [_, Element::ObjectIdentifier(_)] => {
                        return Err(error::Error::PolicyMappingIssuerExpectedOid.into());
                    }
                    [Element::ObjectIdentifier(_), _] => {
                        return Err(error::Error::PolicyMappingSubjectExpectedOid.into());
                    }
                    _ => {
                        return Err(error::Error::PolicyMappingInvalidStructure.into());
                    }
                };

                // RFC 5280: anyPolicy (2.5.29.32.0) MUST NOT be used in policy mappings
                if issuer_domain_policy == CertificatePolicies::ANY_POLICY {
                    return Err(error::Error::PolicyMappingIssuerExpectedOid.into());
                }
                if subject_domain_policy == CertificatePolicies::ANY_POLICY {
                    return Err(error::Error::PolicyMappingSubjectExpectedOid.into());
                }

                Ok(PolicyMapping {
                    issuer_domain_policy,
                    subject_domain_policy,
                })
            }
            _ => Err(error::Error::PolicyMappingInvalidStructure.into()),
        }
    }
}

impl EncodableTo<PolicyMapping> for Element {}

impl Encoder<PolicyMapping, Element> for PolicyMapping {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.issuer_domain_policy == CertificatePolicies::ANY_POLICY {
            return Err(error::Error::PolicyMappingIssuerExpectedOid.into());
        }
        if self.subject_domain_policy == CertificatePolicies::ANY_POLICY {
            return Err(error::Error::PolicyMappingSubjectExpectedOid.into());
        }

        Ok(Element::Sequence(vec![
            Element::ObjectIdentifier(self.issuer_domain_policy.clone()),
            Element::ObjectIdentifier(self.subject_domain_policy.clone()),
        ]))
    }
}

impl OidName for PolicyMappings {
    fn oid_name(&self) -> Option<&'static str> {
        Some("policyMappings")
    }
}

impl fmt::Display for PolicyMappings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("policyMappings");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for mapping in &self.mappings {
            writeln!(
                f,
                "                {}: {}",
                mapping.issuer_domain_policy, mapping.subject_domain_policy
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::ObjectIdentifier;

    /// Test successful parsing with single mapping
    #[rstest]
    #[case::single_mapping(
        Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
            Element::ObjectIdentifier(ObjectIdentifier::from_str("5.6.7.8").unwrap()),
        ])]),
        true,
        Some(1)
    )]
    #[case::empty_sequence(
        Element::Sequence(vec![]),
        false,
        None
    )]
    #[case::wrong_type(
        Element::Integer(tsumiki_asn1::Integer::from(vec![42])),
        false,
        None
    )]
    #[case::non_oid_issuer(
        Element::Sequence(vec![Element::Sequence(vec![
            Element::Integer(tsumiki_asn1::Integer::from(vec![1])),
            Element::ObjectIdentifier(ObjectIdentifier::from_str("5.6.7.8").unwrap()),
        ])]),
        false,
        None
    )]
    #[case::non_oid_subject(
        Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
            Element::Integer(tsumiki_asn1::Integer::from(vec![1])),
        ])]),
        false,
        None
    )]
    fn test_policy_mappings_decode(
        #[case] elem: Element,
        #[case] should_succeed: bool,
        #[case] expected_count: Option<usize>,
    ) {
        let result: Result<PolicyMappings, _> = elem.decode();

        if should_succeed {
            assert!(
                result.is_ok(),
                "Expected success but got error: {:?}",
                result
            );
            if let Some(count) = expected_count {
                let mappings = result.unwrap();
                assert_eq!(mappings.mappings.len(), count);
            }
        } else {
            assert!(result.is_err(), "Expected error but got success");
        }
    }

    /// Test parsing failure with anyPolicy OID (2.5.29.32.0)
    #[rstest]
    #[case::any_policy_issuer(
        Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap()),
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
        ])])
    )]
    #[case::any_policy_subject(
        Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
            Element::ObjectIdentifier(ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap()),
        ])])
    )]
    fn test_policy_mappings_any_policy_rejected(#[case] elem: Element) {
        let result: Result<PolicyMappings, _> = elem.decode();
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("PolicyMapping") && err_msg.contains("ExpectedOid"));
    }

    /// Test full parse through Extension::parse
    #[rstest]
    fn test_policy_mappings_parse() {
        // Test parsing through Extension::parse
        // DER: OCTET STRING containing SEQUENCE { SEQUENCE { OID, OID } }
        let oid1_bytes = vec![0x06, 0x03, 0x2A, 0x03, 0x04]; // 1.2.3.4
        let oid2_bytes = vec![0x06, 0x03, 0x55, 0x04, 0x06]; // 2.5.4.6

        let inner_seq = vec![0x30, 0x0A]; // SEQUENCE, length 10
        let mut content = inner_seq;
        content.extend_from_slice(&oid1_bytes);
        content.extend_from_slice(&oid2_bytes);

        let outer_seq = vec![0x30, content.len() as u8];
        let mut der_bytes = outer_seq;
        der_bytes.extend(content);

        let octet_string = OctetString::from(der_bytes);
        let result = PolicyMappings::parse(&octet_string);
        assert!(result.is_ok());

        let mappings = result.unwrap();
        assert_eq!(mappings.mappings.len(), 1);
    }

    #[rstest]
    #[case(PolicyMappings {
        mappings: vec![
            PolicyMapping {
                issuer_domain_policy: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                subject_domain_policy: ObjectIdentifier::from_str("5.6.7.8").unwrap(),
            },
        ],
    })]
    #[case(PolicyMappings {
        mappings: vec![
            PolicyMapping {
                issuer_domain_policy: ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                subject_domain_policy: ObjectIdentifier::from_str("5.6.7.8").unwrap(),
            },
            PolicyMapping {
                issuer_domain_policy: ObjectIdentifier::from_str("9.10.11.12").unwrap(),
                subject_domain_policy: ObjectIdentifier::from_str("13.14.15.16").unwrap(),
            },
        ],
    })]
    fn test_policy_mappings_encode_decode(#[case] original: PolicyMappings) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<PolicyMappings, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
