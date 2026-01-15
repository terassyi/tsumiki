use asn1::{ASN1Object, Element, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

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
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidPolicyMappings("empty content".to_string()));
        }

        elements[0].decode()
    }
}

impl DecodableFrom<Element> for PolicyMappings {}

impl Decoder<Element, PolicyMappings> for Element {
    type Error = Error;

    fn decode(&self) -> Result<PolicyMappings, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidPolicyMappings(
                        "empty sequence - at least one mapping required".to_string(),
                    ));
                }

                let mappings: Vec<PolicyMapping> = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(PolicyMappings { mappings })
            }
            _ => Err(Error::InvalidPolicyMappings(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl EncodableTo<PolicyMappings> for Element {}

impl Encoder<PolicyMappings, Element> for PolicyMappings {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.mappings.is_empty() {
            return Err(Error::InvalidPolicyMappings(
                "at least one mapping required".to_string(),
            ));
        }

        let mapping_elements = self.mappings
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
                if elements.len() != 2 {
                    return Err(Error::InvalidPolicyMappings(format!(
                        "expected 2 elements in mapping, got {}",
                        elements.len()
                    )));
                }

                let mut iter = elements.iter();

                let issuer_domain_policy = match iter.next() {
                    Some(Element::ObjectIdentifier(oid)) => oid.clone(),
                    _ => {
                        return Err(Error::InvalidPolicyMappings(
                            "issuerDomainPolicy must be ObjectIdentifier".to_string(),
                        ));
                    }
                };

                let subject_domain_policy = match iter.next() {
                    Some(Element::ObjectIdentifier(oid)) => oid.clone(),
                    _ => {
                        return Err(Error::InvalidPolicyMappings(
                            "subjectDomainPolicy must be ObjectIdentifier".to_string(),
                        ));
                    }
                };

                // RFC 5280: anyPolicy (2.5.29.32.0) MUST NOT be used in policy mappings
                if issuer_domain_policy == CertificatePolicies::ANY_POLICY {
                    return Err(Error::InvalidPolicyMappings(
                        "issuerDomainPolicy must not be anyPolicy (2.5.29.32.0)".to_string(),
                    ));
                }
                if subject_domain_policy == CertificatePolicies::ANY_POLICY {
                    return Err(Error::InvalidPolicyMappings(
                        "subjectDomainPolicy must not be anyPolicy (2.5.29.32.0)".to_string(),
                    ));
                }

                Ok(PolicyMapping {
                    issuer_domain_policy,
                    subject_domain_policy,
                })
            }
            _ => Err(Error::InvalidPolicyMappings(
                "expected Sequence for PolicyMapping".to_string(),
            )),
        }
    }
}

impl EncodableTo<PolicyMapping> for Element {}

impl Encoder<PolicyMapping, Element> for PolicyMapping {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.issuer_domain_policy == CertificatePolicies::ANY_POLICY {
            return Err(Error::InvalidPolicyMappings(
                "issuerDomainPolicy must not be anyPolicy".to_string(),
            ));
        }
        if self.subject_domain_policy == CertificatePolicies::ANY_POLICY {
            return Err(Error::InvalidPolicyMappings(
                "subjectDomainPolicy must not be anyPolicy".to_string(),
            ));
        }

        Ok(Element::Sequence(vec![
            Element::ObjectIdentifier(self.issuer_domain_policy.clone()),
            Element::ObjectIdentifier(self.subject_domain_policy.clone()),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ObjectIdentifier;
    use std::str::FromStr;

    /// Test successful parsing with single mapping
    #[test]
    fn test_policy_mappings_single_mapping() {
        // SEQUENCE { SEQUENCE { OID "1.2.3.4", OID "5.6.7.8" } }
        let oid1 = ObjectIdentifier::from_str("1.2.3.4").unwrap();
        let oid2 = ObjectIdentifier::from_str("5.6.7.8").unwrap();

        let elem = Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(oid1.clone()),
            Element::ObjectIdentifier(oid2.clone()),
        ])]);

        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_ok());

        let mappings = result.unwrap();
        assert_eq!(mappings.mappings.len(), 1);
        assert_eq!(mappings.mappings[0].issuer_domain_policy, oid1);
        assert_eq!(mappings.mappings[0].subject_domain_policy, oid2);
    }

    /// Test parsing failure with empty sequence
    #[test]
    fn test_policy_mappings_empty_sequence() {
        let elem = Element::Sequence(vec![]);
        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_err());
    }

    /// Test parsing failure with wrong type
    #[test]
    fn test_policy_mappings_wrong_type() {
        let elem = Element::Integer(asn1::Integer::from(vec![42]));
        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_err());
    }

    /// Test parsing failure with non-OID elements
    #[test]
    fn test_policy_mappings_non_oid_issuer() {
        let elem = Element::Sequence(vec![Element::Sequence(vec![
            Element::Integer(asn1::Integer::from(vec![1])),
            Element::ObjectIdentifier(ObjectIdentifier::from_str("5.6.7.8").unwrap()),
        ])]);
        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_mappings_non_oid_subject() {
        let elem = Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
            Element::Integer(asn1::Integer::from(vec![1])),
        ])]);
        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_err());
    }

    /// Test parsing failure with anyPolicy OID (2.5.29.32.0)
    #[test]
    fn test_policy_mappings_any_policy_issuer() {
        let any_policy = ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap();
        let normal_policy = ObjectIdentifier::from_str("1.2.3.4").unwrap();

        let elem = Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(any_policy),
            Element::ObjectIdentifier(normal_policy),
        ])]);

        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("anyPolicy"));
    }

    #[test]
    fn test_policy_mappings_any_policy_subject() {
        let normal_policy = ObjectIdentifier::from_str("1.2.3.4").unwrap();
        let any_policy = ObjectIdentifier::from_str(CertificatePolicies::ANY_POLICY).unwrap();

        let elem = Element::Sequence(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(normal_policy),
            Element::ObjectIdentifier(any_policy),
        ])]);

        let result: Result<PolicyMappings, Error> = elem.decode();
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("anyPolicy"));
    }

    /// Test full parse through StandardExtension::parse
    #[test]
    fn test_policy_mappings_parse() {
        // Test parsing through StandardExtension::parse
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
}
