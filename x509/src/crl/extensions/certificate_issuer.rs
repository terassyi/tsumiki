//! Certificate Issuer entry extension (RFC 5280 §5.3.3).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::Extension;
use crate::error::Error;
use crate::extensions::general_name::{GeneralName, GeneralNames};

/*
RFC 5280 Section 5.3.3

id-ce-certificateIssuer OBJECT IDENTIFIER ::= { id-ce 29 }

CertificateIssuer ::= GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

The certificate issuer is a CRL entry extension used with indirect CRLs. It
identifies the certificate issuer associated with an entry when that issuer
differs from the CRL issuer. This extension MUST be marked critical.
*/

/// Certificate Issuer entry extension ([RFC 5280 §5.3.3](https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.3)).
///
/// Identifies the issuer of a certificate referenced by an indirect CRL entry
/// when it differs from the CRL issuer. A thin wrapper over the shared
/// [`GeneralNames`] building block. Appears in a revoked certificate's
/// `crlEntryExtensions`.
/// OID: 2.5.29.29
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertificateIssuer(GeneralNames);

impl CertificateIssuer {
    /// The certificate issuer names.
    pub fn names(&self) -> &[GeneralName] {
        &self.0.names
    }
}

impl Extension for CertificateIssuer {
    /// OID for certificateIssuer entry extension (2.5.29.29)
    const OID: &'static str = "2.5.29.29";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        Ok(CertificateIssuer(value.decode()?))
    }
}

impl EncodableTo<CertificateIssuer> for Element {}

impl Encoder<CertificateIssuer, Element> for CertificateIssuer {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.0.encode()
    }
}

impl OidName for CertificateIssuer {
    fn oid_name(&self) -> Option<&'static str> {
        Some("certificateIssuer")
    }
}

impl fmt::Display for CertificateIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 Certificate Issuer:")?;
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_issuer(names: Vec<GeneralName>) -> CertificateIssuer {
        CertificateIssuer(GeneralNames { names })
    }

    #[test]
    fn parse_round_trip() {
        let original = certificate_issuer(vec![
            GeneralName::Uri("http://ca.example.com/".to_string()),
            GeneralName::Uri("http://ca2.example.com/".to_string()),
        ]);
        // CertificateIssuer -> Element -> Tlv -> DER bytes -> OctetString -> parse
        let tlv = original.encode().unwrap().encode().unwrap();
        let value = OctetString::from(tlv.encode().unwrap());
        let parsed = CertificateIssuer::parse(&value).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.names().len(), 2);
    }

    #[test]
    fn display_header() {
        let ext = certificate_issuer(vec![GeneralName::Uri(
            "http://indirect-ca.example.com/".to_string(),
        )]);
        let output = ext.to_string();
        assert!(output.starts_with("            X509v3 Certificate Issuer:\n"));
        assert!(output.contains("http://indirect-ca.example.com/"));
    }
}
