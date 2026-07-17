use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, OctetString};
use tsumiki_pkix_types::OidName;

use crate::error::Error;
use crate::extensions::Extension;
use crate::extensions::general_name::{GeneralName, GeneralNames};

/*
RFC 5280 Section 4.2.1.7

IssuerAltName ::= GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

The issuer alternative name extension allows additional identities to be bound
to the issuer of the certificate. This extension MUST be non-critical.
*/

/// Issuer Alternative Name extension ([RFC 5280 Section 4.2.1.7](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7)).
///
/// Allows additional identities to be bound to the issuer of the certificate.
/// A thin wrapper over the shared [`GeneralNames`] building block.
/// OID: 2.5.29.18
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssuerAltName(GeneralNames);

impl IssuerAltName {
    /// The issuer alternative names.
    pub fn names(&self) -> &[GeneralName] {
        &self.0.names
    }
}

impl Extension for IssuerAltName {
    const OID: &'static str = "2.5.29.18";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        Ok(IssuerAltName(value.decode()?))
    }
}

impl EncodableTo<IssuerAltName> for Element {}

impl Encoder<IssuerAltName, Element> for IssuerAltName {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.0.encode()
    }
}

impl OidName for IssuerAltName {
    fn oid_name(&self) -> Option<&'static str> {
        Some("issuerAltName")
    }
}

impl fmt::Display for IssuerAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 issuerAltName:")?;
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_alt_name(names: Vec<GeneralName>) -> IssuerAltName {
        IssuerAltName(GeneralNames { names })
    }

    #[test]
    fn parse_round_trip() {
        let original = issuer_alt_name(vec![
            GeneralName::DnsName("ca.example.com".to_string()),
            GeneralName::Rfc822Name("ca@example.com".to_string()),
            GeneralName::Uri("https://ca.example.com".to_string()),
        ]);
        // IssuerAltName -> Element -> Tlv -> DER bytes -> OctetString -> parse
        let tlv = original.encode().unwrap().encode().unwrap();
        let value = OctetString::from(tlv.encode().unwrap());
        let parsed = IssuerAltName::parse(&value).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.names().len(), 3);
    }

    #[test]
    fn display_header() {
        let ext = issuer_alt_name(vec![GeneralName::DnsName("ca.example.com".to_string())]);
        let output = ext.to_string();
        assert!(output.starts_with("            X509v3 issuerAltName:\n"));
        assert!(output.contains("ca.example.com"));
    }
}
