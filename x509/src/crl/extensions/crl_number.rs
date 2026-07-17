//! CRL Number extension (RFC 5280 §5.2.3).

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
RFC 5280 Section 5.2.3

id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }

CRLNumber ::= INTEGER (0..MAX)

The CRL number is a non-critical CRL extension that conveys a monotonically
increasing sequence number for a given CRL scope and CRL issuer. Conforming
CRL issuers MUST NOT use CRLNumber values longer than 20 octets.
*/

/// CRL Number extension ([RFC 5280 §5.2.3](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3)).
///
/// A monotonically increasing sequence number for a given CRL scope and issuer.
/// OID: 2.5.29.20
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CRLNumber(Integer);

impl CRLNumber {
    /// The CRL number value.
    pub fn number(&self) -> &Integer {
        &self.0
    }
}

impl Extension for CRLNumber {
    /// OID for cRLNumber extension (2.5.29.20)
    const OID: &'static str = "2.5.29.20";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(error::Error::InvalidAsn1)?;
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(error::Kind::CRLNumber).into()),
        }
    }
}

impl DecodableFrom<Element> for CRLNumber {}

impl Decoder<Element, CRLNumber> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CRLNumber, Self::Error> {
        match self {
            Element::Integer(integer) => Ok(CRLNumber(integer.clone())),
            _ => Err(error::Error::ExpectedInteger(error::Kind::CRLNumber).into()),
        }
    }
}

impl EncodableTo<CRLNumber> for Element {}

impl Encoder<CRLNumber, Element> for CRLNumber {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::Integer(self.0.clone()))
    }
}

impl OidName for CRLNumber {
    fn oid_name(&self) -> Option<&'static str> {
        Some("cRLNumber")
    }
}

impl fmt::Display for CRLNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 CRL Number:")?;
        writeln!(f, "                {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crl_number(bytes: Vec<u8>) -> Integer {
        Integer::from(bytes)
    }

    #[test]
    fn decode_encode_round_trip() {
        let elem = Element::Integer(crl_number(vec![0x2a]));
        let decoded: CRLNumber = elem.decode().unwrap();
        assert_eq!(decoded.number(), &crl_number(vec![0x2a]));
        let encoded = decoded.encode().unwrap();
        assert_eq!(encoded, elem);
    }

    #[test]
    fn parse_from_octet_string() {
        // OCTET STRING content = DER INTEGER 42 (0x02 0x01 0x2a)
        let value = OctetString::from(vec![0x02, 0x01, 0x2a]);
        let decoded = CRLNumber::parse(&value).unwrap();
        assert_eq!(decoded.number(), &crl_number(vec![0x2a]));
    }

    #[test]
    fn decode_rejects_non_integer() {
        let decoded: Result<CRLNumber, _> = Element::Null.decode();
        assert!(decoded.is_err());
    }

    #[test]
    fn handles_large_value() {
        // CRLNumber may be up to 20 octets; ensure a wide value round-trips.
        let wide = vec![0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let elem = Element::Integer(crl_number(wide));
        let decoded: CRLNumber = elem.decode().unwrap();
        assert_eq!(decoded.encode().unwrap(), elem);
    }
}
