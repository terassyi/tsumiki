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
RFC 5280 Section 4.2.1.6
SubjectAltName ::= GeneralNames
GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
*/

/// Subject Alternative Name extension ([RFC 5280 Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)).
///
/// Allows additional identities to be bound to the subject of the certificate.
/// This extension is widely used for TLS certificates to specify hostnames,
/// email addresses, and IP addresses. A thin wrapper over the shared
/// [`GeneralNames`] building block.
///
/// # Common Uses
/// - DNS names for TLS/SSL certificates (e.g., "www.example.com", "*.example.com")
/// - Email addresses for S/MIME certificates
/// - IP addresses for host certificates
/// - URIs for web services
///
/// # Example
/// ```no_run
/// use std::str::FromStr;
/// use tsumiki_x509::cert::Certificate;
/// use tsumiki_x509::cert::extensions::SubjectAltName;
/// use tsumiki_x509::extensions::GeneralName;
///
/// let cert = Certificate::from_str("-----BEGIN CERTIFICATE-----...").unwrap();
/// if let Some(san) = cert.extension::<SubjectAltName>().unwrap() {
///     for name in san.names() {
///         match name {
///             GeneralName::DnsName(dns) => println!("DNS: {}", dns),
///             GeneralName::IpAddress(ip) => println!("IP: {:?}", ip),
///             _ => {}
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubjectAltName(GeneralNames);

impl SubjectAltName {
    /// The subject alternative names.
    pub fn names(&self) -> &[GeneralName] {
        &self.0.names
    }
}

impl Extension for SubjectAltName {
    /// OID for SubjectAltName extension (2.5.29.17)
    const OID: &'static str = "2.5.29.17";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        Ok(SubjectAltName(value.decode()?))
    }
}

impl EncodableTo<SubjectAltName> for Element {}

impl Encoder<SubjectAltName, Element> for SubjectAltName {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.0.encode()
    }
}

impl OidName for SubjectAltName {
    fn oid_name(&self) -> Option<&'static str> {
        Some("subjectAltName")
    }
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 subjectAltName:")?;
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject_alt_name(names: Vec<GeneralName>) -> SubjectAltName {
        SubjectAltName(GeneralNames { names })
    }

    #[test]
    fn parse_round_trip() {
        let original = subject_alt_name(vec![
            GeneralName::DnsName("www.example.com".to_string()),
            GeneralName::DnsName("*.example.com".to_string()),
            GeneralName::Rfc822Name("admin@example.com".to_string()),
        ]);
        // SubjectAltName -> Element -> Tlv -> DER bytes -> OctetString -> parse
        let tlv = original.encode().unwrap().encode().unwrap();
        let value = OctetString::from(tlv.encode().unwrap());
        let parsed = SubjectAltName::parse(&value).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.names().len(), 3);
    }

    #[test]
    fn display_header() {
        let ext = subject_alt_name(vec![GeneralName::DnsName("www.example.com".to_string())]);
        let output = ext.to_string();
        assert!(output.starts_with("            X509v3 subjectAltName:\n"));
        assert!(output.contains("www.example.com"));
    }
}
