//! Certificate Issuer entry extension (RFC 5280 §5.3.3).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::Extension;
use super::error::{self, Kind};
use crate::error::Error;
use crate::extensions::general_name::GeneralName;

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
/// when it differs from the CRL issuer. Appears in a revoked certificate's
/// `crlEntryExtensions`.
/// OID: 2.5.29.29
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateIssuer {
    pub names: Vec<GeneralName>,
}

impl DecodableFrom<Element> for CertificateIssuer {}

impl Decoder<Element, CertificateIssuer> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificateIssuer, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::AtLeastOneGeneralNameRequired(
                        Kind::CertificateIssuer,
                    )
                    .into());
                }
                let names = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CertificateIssuer { names })
            }
            _ => Err(error::Error::ExpectedSequence(Kind::CertificateIssuer).into()),
        }
    }
}

impl EncodableTo<CertificateIssuer> for Element {}

impl Encoder<CertificateIssuer, Element> for CertificateIssuer {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.names.is_empty() {
            return Err(
                error::Error::AtLeastOneGeneralNameRequired(Kind::CertificateIssuer).into(),
            );
        }
        let elements = self
            .names
            .iter()
            .map(|name| name.encode())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Element::Sequence(elements))
    }
}

impl Extension for CertificateIssuer {
    /// OID for certificateIssuer entry extension (2.5.29.29)
    const OID: &'static str = "2.5.29.29";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(error::Error::InvalidAsn1)?;
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(Kind::CertificateIssuer).into()),
        }
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
        for name in &self.names {
            writeln!(f, "                {}", name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(u: &str) -> GeneralName {
        GeneralName::Uri(u.to_string())
    }

    #[test]
    fn decode_encode_round_trip() {
        let original = CertificateIssuer {
            names: vec![
                uri("http://ca.example.com/"),
                uri("http://ca2.example.com/"),
            ],
        };
        let element = original.encode().unwrap();
        let decoded: CertificateIssuer = element.decode().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn parse_from_octet_string_round_trip() {
        // Element -> Tlv -> DER bytes -> OctetString -> parse
        let original = CertificateIssuer {
            names: vec![uri("http://indirect-ca.example.com/")],
        };
        let tlv = original.encode().unwrap().encode().unwrap();
        let value = OctetString::from(tlv.encode().unwrap());
        let parsed = CertificateIssuer::parse(&value).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn decode_rejects_empty_sequence() {
        let decoded: Result<CertificateIssuer, _> = Element::Sequence(vec![]).decode();
        assert!(decoded.is_err());
    }

    #[test]
    fn decode_rejects_non_sequence() {
        let decoded: Result<CertificateIssuer, _> = Element::Null.decode();
        assert!(decoded.is_err());
    }

    #[test]
    fn encode_rejects_empty() {
        let empty = CertificateIssuer { names: vec![] };
        assert!(empty.encode().is_err());
    }
}
