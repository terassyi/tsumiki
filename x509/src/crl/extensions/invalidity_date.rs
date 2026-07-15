//! Invalidity Date entry extension (RFC 5280 §5.3.2).

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::Extension;
use super::error::{self, Kind};
use crate::error::Error;

/*
RFC 5280 Section 5.3.2

id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }

InvalidityDate ::= GeneralizedTime

The invalidity date is a non-critical CRL entry extension that provides the date
on which it is known or suspected that the private key was compromised or that
the certificate otherwise became invalid. Unlike `Time`, this value is always a
GeneralizedTime.
*/

/// Invalidity Date entry extension ([RFC 5280 §5.3.2](https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.2)).
///
/// The date on which the private key is known or suspected to have been
/// compromised. Appears in a revoked certificate's `crlEntryExtensions`.
/// OID: 2.5.29.24
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvalidityDate(NaiveDateTime);

impl InvalidityDate {
    /// The date on which the certificate became invalid.
    pub fn date(&self) -> &NaiveDateTime {
        &self.0
    }
}

impl Extension for InvalidityDate {
    /// OID for invalidityDate entry extension (2.5.29.24)
    const OID: &'static str = "2.5.29.24";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(error::Error::InvalidAsn1)?;
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(Kind::InvalidityDate).into()),
        }
    }
}

impl DecodableFrom<Element> for InvalidityDate {}

impl Decoder<Element, InvalidityDate> for Element {
    type Error = Error;

    fn decode(&self) -> Result<InvalidityDate, Self::Error> {
        match self {
            Element::GeneralizedTime(datetime) => Ok(InvalidityDate(*datetime)),
            _ => Err(error::Error::ExpectedGeneralizedTime(Kind::InvalidityDate).into()),
        }
    }
}

impl EncodableTo<InvalidityDate> for Element {}

impl Encoder<InvalidityDate, Element> for InvalidityDate {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::GeneralizedTime(self.0))
    }
}

impl OidName for InvalidityDate {
    fn oid_name(&self) -> Option<&'static str> {
        Some("invalidityDate")
    }
}

impl fmt::Display for InvalidityDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 Invalidity Date:")?;
        writeln!(f, "                {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn datetime() -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2024, 1, 2)
            .unwrap()
            .and_hms_opt(3, 4, 5)
            .unwrap()
    }

    #[test]
    fn decode_encode_round_trip() {
        let elem = Element::GeneralizedTime(datetime());
        let decoded: InvalidityDate = elem.decode().unwrap();
        assert_eq!(decoded.date(), &datetime());
        assert_eq!(decoded.encode().unwrap(), elem);
    }

    #[test]
    fn parse_from_octet_string_round_trip() {
        // Element -> Tlv -> DER bytes -> OctetString -> parse
        let date = InvalidityDate(datetime());
        let tlv = date.encode().unwrap().encode().unwrap();
        let value = OctetString::from(tlv.encode().unwrap());
        let parsed = InvalidityDate::parse(&value).unwrap();
        assert_eq!(date, parsed);
    }

    #[test]
    fn decode_rejects_non_generalized_time() {
        let decoded: Result<InvalidityDate, _> = Element::Null.decode();
        assert!(decoded.is_err());
        // RFC requires GeneralizedTime specifically; UTCTime must not be accepted.
        let utc: Result<InvalidityDate, _> = Element::UTCTime(datetime()).decode();
        assert!(utc.is_err());
    }
}
