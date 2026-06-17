//! CRL Distribution Points extension (RFC 5280 §4.2.1.13).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, OctetString};
use tsumiki_pkix_types::OidName;

use crate::error::Error;
use crate::extensions::{DistributionPoint, DistributionPoints, Extension};

/// CRL Distribution Points extension ([RFC 5280 §4.2.1.13](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13)).
///
/// Identifies how CRL information is obtained. A thin wrapper over the shared
/// [`DistributionPoints`] collection (`CRLDistributionPoints ::= SEQUENCE OF
/// DistributionPoint`).
/// OID: 2.5.29.31
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CRLDistributionPoints(DistributionPoints);

impl CRLDistributionPoints {
    /// The distribution points carried by this extension.
    pub fn distribution_points(&self) -> &[DistributionPoint] {
        &self.0.distribution_points
    }
}

impl Extension for CRLDistributionPoints {
    /// OID for CRLDistributionPoints extension (2.5.29.31)
    const OID: &'static str = "2.5.29.31";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        Ok(CRLDistributionPoints(value.decode()?))
    }
}

impl EncodableTo<CRLDistributionPoints> for Element {}

impl Encoder<CRLDistributionPoints, Element> for CRLDistributionPoints {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.0.encode()
    }
}

impl OidName for CRLDistributionPoints {
    fn oid_name(&self) -> Option<&'static str> {
        Some("CRLDistributionPoints")
    }
}

impl fmt::Display for CRLDistributionPoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 CRL Distribution Points:")?;
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::general_name::GeneralName;
    use crate::extensions::{DistributionPoint, DistributionPointName};

    fn dp(uri: &str) -> DistributionPoint {
        DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![GeneralName::Uri(
                uri.to_string(),
            )])),
            reasons: None,
            crl_issuer: None,
        }
    }

    #[test]
    fn display_header() {
        let ext = CRLDistributionPoints(DistributionPoints {
            distribution_points: vec![dp("http://crl.example.com/ca.crl")],
        });
        let output = ext.to_string();
        assert!(output.starts_with("            X509v3 CRL Distribution Points:\n"));
        assert!(output.contains("URI:http://crl.example.com/ca.crl"));
        // Camel-case form must not appear anywhere
        assert!(!output.contains("CRLDistributionPoints"));
    }

    #[test]
    fn display_blank_line_between_dps() {
        let ext = CRLDistributionPoints(DistributionPoints {
            distribution_points: vec![
                dp("http://crl1.example.com/a.crl"),
                dp("http://crl2.example.com/b.crl"),
            ],
        });
        let output = ext.to_string();
        let pos_header = output.find("X509v3 CRL Distribution Points:").unwrap();
        let pos_first = output.find("URI:http://crl1").unwrap();
        let pos_second = output.find("URI:http://crl2").unwrap();
        assert!(
            output[pos_header..pos_first].contains("\n\n"),
            "expected blank line after header"
        );
        assert!(
            output[pos_first..pos_second].contains("\n\n"),
            "expected blank line between DPs"
        );
    }
}
