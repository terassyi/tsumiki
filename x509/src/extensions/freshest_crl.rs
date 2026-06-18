//! Freshest CRL extension (RFC 5280 §4.2.1.15).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, OctetString};
use tsumiki_pkix_types::OidName;

use crate::error::Error;
use crate::extensions::{DistributionPoint, DistributionPoints, Extension};

/*
RFC 5280 Section 4.2.1.15

id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }

FreshestCRL ::= CRLDistributionPoints

The freshest CRL extension identifies how delta CRL information is obtained. It
uses the exact same syntax as the CRL distribution points extension (§4.2.1.13),
but the identified CRLs are delta CRLs rather than base CRLs. MUST be marked
non-critical.
*/

/// Freshest CRL extension ([RFC 5280 §4.2.1.15](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.15)).
///
/// Identifies the location of delta CRL distribution points. Structurally
/// identical to `CRLDistributionPoints` (`FreshestCRL ::= CRLDistributionPoints`),
/// so it is a thin wrapper over the shared [`DistributionPoints`] collection.
/// OID: 2.5.29.46
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FreshestCRL(DistributionPoints);

impl FreshestCRL {
    /// The delta-CRL distribution points carried by this extension.
    pub fn distribution_points(&self) -> &[DistributionPoint] {
        &self.0.distribution_points
    }
}

impl Extension for FreshestCRL {
    /// OID for FreshestCRL extension (2.5.29.46)
    const OID: &'static str = "2.5.29.46";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        Ok(FreshestCRL(value.decode()?))
    }
}

impl EncodableTo<FreshestCRL> for Element {}

impl Encoder<FreshestCRL, Element> for FreshestCRL {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.0.encode()
    }
}

impl OidName for FreshestCRL {
    fn oid_name(&self) -> Option<&'static str> {
        Some("freshestCRL")
    }
}

impl fmt::Display for FreshestCRL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 Freshest CRL:")?;
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::general_name::GeneralName;
    use crate::extensions::{DistributionPoint, DistributionPointName};
    use rstest::rstest;

    fn points(uris: &[&str]) -> DistributionPoints {
        DistributionPoints {
            distribution_points: vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(
                    uris.iter()
                        .map(|u| GeneralName::Uri(u.to_string()))
                        .collect(),
                )),
                reasons: None,
                crl_issuer: None,
            }],
        }
    }

    #[test]
    fn parse_rejects_wrong_type() {
        let octet_string = OctetString::from(vec![0x02, 0x01, 0x2A]); // INTEGER 42
        assert!(FreshestCRL::parse(&octet_string).is_err());
    }

    #[rstest]
    #[case(FreshestCRL(points(&["http://delta-crl.example.com/delta.pem"])))]
    #[case(FreshestCRL(points(&[
        "http://delta1.example.com/delta.pem",
        "http://delta2.example.com/delta.pem",
    ])))]
    fn encode_decode(#[case] original: FreshestCRL) {
        let element = original.encode().unwrap();
        let tlv = element.encode().unwrap();
        let bytes = tlv.encode().unwrap();
        let octet_string = OctetString::from(bytes);
        let roundtrip = FreshestCRL::parse(&octet_string).unwrap();
        assert_eq!(original, roundtrip);
    }

    #[test]
    fn display_no_duplicate_header() {
        let ext = FreshestCRL(points(&["http://delta.example.com/delta.crl"]));
        let output = ext.to_string();
        assert!(output.starts_with("            X509v3 Freshest CRL:\n"));
        assert!(output.contains("URI:http://delta.example.com/delta.crl"));
        assert!(!output.contains("CRLDistributionPoints"));
        assert!(!output.contains("CRL Distribution Points"));
        assert!(!output.contains("freshestCRL"));
    }
}
