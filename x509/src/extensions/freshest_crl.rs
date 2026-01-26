use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, OctetString};
use tsumiki_pkix_types::OidName;

use crate::error::Error;
use crate::extensions::{CRLDistributionPoints, Extension};

/*
RFC 5280 Section 4.2.1.15

id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }

FreshestCRL ::= CRLDistributionPoints

The freshest CRL extension identifies how delta CRL information is obtained.
The extension MUST be marked as non-critical by conforming CAs.

A delta CRL is a CRL that only contains entries for certificates that have
been revoked since the issuance of a referenced base CRL. This extension
identifies the location of the delta CRL. The use of delta CRLs can
significantly reduce download time and processing time for CRL validation
in environments where the base CRL is large.

The freshest CRL extension uses the exact same syntax as the CRL distribution
points extension (4.2.1.13), but the identified CRLs are delta CRLs rather
than base CRLs.

Delta CRLs contain:
- A delta CRL indicator extension identifying the version of the base CRL
- Only certificates revoked since the base CRL was issued
- Optionally, certificates whose revocation was removed (in practice rare)

Clients process delta CRLs as follows:
1. Download and process the base CRL (via CRL Distribution Points extension)
2. Download the delta CRL (via Freshest CRL extension)
3. Apply the delta CRL updates to the base CRL
4. Use the combined revocation list for validation

Benefits:
- Reduced bandwidth: Only delta needs to be downloaded for updates
- Faster processing: Smaller CRLs are faster to parse
- More frequent updates: Delta CRLs can be issued more frequently than base CRLs

Example scenario:
- Base CRL: 10 MB, issued daily, contains 100,000 revoked certificates
- Delta CRL: 100 KB, issued hourly, contains ~100 newly revoked certificates
- Bandwidth savings: 99% reduction for hourly updates
*/

/// Freshest CRL extension ([RFC 5280 Section 4.2.1.15](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.15)).
///
/// Identifies the location of delta CRL distribution points.
/// The syntax is identical to CRLDistributionPoints, but the referenced CRLs
/// are delta CRLs containing only certificates revoked since the base CRL.
/// OID: 2.5.29.46
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshestCRL {
    /// Distribution points for delta CRLs
    /// Uses the same structure as CRLDistributionPoints
    pub distribution_points: CRLDistributionPoints,
}

impl Extension for FreshestCRL {
    /// OID for FreshestCRL extension (2.5.29.46)
    const OID: &'static str = "2.5.29.46";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // Parse using the CRLDistributionPoints parser since the syntax is identical
        let distribution_points = CRLDistributionPoints::parse(value)?;
        Ok(Self {
            distribution_points,
        })
    }
}

impl EncodableTo<FreshestCRL> for Element {}

impl Encoder<FreshestCRL, Element> for FreshestCRL {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.distribution_points.encode()
    }
}

impl OidName for FreshestCRL {
    fn oid_name(&self) -> Option<&'static str> {
        Some("freshestCRL")
    }
}

impl fmt::Display for FreshestCRL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("freshestCRL");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        write!(f, "                {}", self.distribution_points)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::general_name::GeneralName;
    use crate::extensions::{DistributionPoint, DistributionPointName};
    use rstest::rstest;

    /// Test parsing failure with wrong type
    #[test]
    fn test_freshest_crl_decode_failure_wrong_type() {
        let der_bytes = vec![0x02, 0x01, 0x2A]; // INTEGER 42
        let octet_string = OctetString::from(der_bytes);
        let result = FreshestCRL::parse(&octet_string);
        assert!(result.is_err());
    }

    #[rstest]
    #[case(FreshestCRL {
        distribution_points: CRLDistributionPoints {
            distribution_points: vec![
                DistributionPoint {
                    distribution_point: Some(DistributionPointName::FullName(vec![
                        GeneralName::Uri("http://delta-crl.example.com/delta.pem".to_string()),
                    ])),
                    reasons: None,
                    crl_issuer: None,
                },
            ],
        },
    })]
    #[case(FreshestCRL {
        distribution_points: CRLDistributionPoints {
            distribution_points: vec![
                DistributionPoint {
                    distribution_point: Some(DistributionPointName::FullName(vec![
                        GeneralName::Uri("http://delta1.example.com/delta.pem".to_string()),
                        GeneralName::Uri("http://delta2.example.com/delta.pem".to_string()),
                    ])),
                    reasons: None,
                    crl_issuer: None,
                },
            ],
        },
    })]
    fn test_freshest_crl_encode_decode(#[case] original: FreshestCRL) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        // Element -> Tlv -> Vec<u8>
        let tlv = element.encode().unwrap();
        let bytes = tlv.encode().unwrap();
        let octet_string = OctetString::from(bytes);

        let result = FreshestCRL::parse(&octet_string);
        assert!(result.is_ok(), "Failed to decode: {:?}", result);

        let roundtrip = result.unwrap();
        assert_eq!(original, roundtrip);
    }
}
