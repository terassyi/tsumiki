//! Delta CRL Indicator extension (RFC 5280 §5.2.4).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, Integer, OctetString};
use tsumiki_pkix_types::OidName;

use super::Extension;
use super::error;
use crate::error::Error;

/*
RFC 5280 Section 5.2.4

id-ce-deltaCRLIndicator OBJECT IDENTIFIER ::= { id-ce 27 }

BaseCRLNumber ::= CRLNumber
CRLNumber ::= INTEGER (0..MAX)

The delta CRL indicator is a critical CRL extension that identifies a CRL as
being a delta CRL. Its value, BaseCRLNumber, is the CRL number of the base CRL
that this delta CRL builds upon.
*/

/// Delta CRL Indicator extension ([RFC 5280 §5.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.4)).
///
/// Marks a CRL as a delta CRL and carries the `BaseCRLNumber` (the CRL number
/// of the base CRL it builds upon). MUST be marked critical.
/// OID: 2.5.29.27
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeltaCrlIndicator(Integer);

impl DeltaCrlIndicator {
    /// The base CRL number this delta CRL builds upon.
    pub fn base_crl_number(&self) -> &Integer {
        &self.0
    }
}

impl Extension for DeltaCrlIndicator {
    /// OID for deltaCRLIndicator extension (2.5.29.27)
    const OID: &'static str = "2.5.29.27";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(error::Error::InvalidAsn1)?;
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(error::Kind::DeltaCrlIndicator).into()),
        }
    }
}

impl DecodableFrom<Element> for DeltaCrlIndicator {}

impl Decoder<Element, DeltaCrlIndicator> for Element {
    type Error = Error;

    fn decode(&self) -> Result<DeltaCrlIndicator, Self::Error> {
        match self {
            Element::Integer(integer) => Ok(DeltaCrlIndicator(integer.clone())),
            _ => Err(error::Error::ExpectedInteger(error::Kind::DeltaCrlIndicator).into()),
        }
    }
}

impl EncodableTo<DeltaCrlIndicator> for Element {}

impl Encoder<DeltaCrlIndicator, Element> for DeltaCrlIndicator {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::Integer(self.0.clone()))
    }
}

impl OidName for DeltaCrlIndicator {
    fn oid_name(&self) -> Option<&'static str> {
        Some("deltaCRLIndicator")
    }
}

impl fmt::Display for DeltaCrlIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 Delta CRL Indicator:")?;
        writeln!(f, "                {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(bytes: Vec<u8>) -> Integer {
        Integer::from(bytes)
    }

    #[test]
    fn decode_encode_round_trip() {
        let elem = Element::Integer(base(vec![0x0c]));
        let decoded: DeltaCrlIndicator = elem.decode().unwrap();
        assert_eq!(decoded.base_crl_number(), &base(vec![0x0c]));
        assert_eq!(decoded.encode().unwrap(), elem);
    }

    #[test]
    fn parse_from_octet_string() {
        // OCTET STRING content = DER INTEGER 12 (0x02 0x01 0x0c)
        let value = OctetString::from(vec![0x02, 0x01, 0x0c]);
        let decoded = DeltaCrlIndicator::parse(&value).unwrap();
        assert_eq!(decoded.base_crl_number(), &base(vec![0x0c]));
    }

    #[test]
    fn decode_rejects_non_integer() {
        let decoded: Result<DeltaCrlIndicator, _> = Element::Null.decode();
        assert!(decoded.is_err());
    }
}
