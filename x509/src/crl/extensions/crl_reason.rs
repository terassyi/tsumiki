//! CRL Reason Code entry extension (RFC 5280 §5.3.1).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, Integer, OctetString};
use tsumiki_pkix_types::OidName;

use super::Extension;
use super::error::{self, Kind};
use crate::error::Error;

/*
RFC 5280 Section 5.3.1

id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }

CRLReason ::= ENUMERATED {
    unspecified             (0),
    keyCompromise           (1),
    cACompromise            (2),
    affiliationChanged      (3),
    superseded              (4),
    cessationOfOperation    (5),
    certificateHold         (6),
    -- value 7 is not used
    removeFromCRL           (8),
    privilegeWithdrawn      (9),
    aACompromise           (10) }

The reasonCode is a non-critical CRL entry extension that identifies the reason
for the certificate revocation.
*/

/// CRL Reason Code entry extension ([RFC 5280 §5.3.1](https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1)).
///
/// Identifies the reason a certificate was revoked. Appears in a revoked
/// certificate's `crlEntryExtensions`.
/// OID: 2.5.29.21
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CRLReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCRL,
    PrivilegeWithdrawn,
    AACompromise,
}

impl TryFrom<&Integer> for CRLReason {
    type Error = error::Error;

    fn try_from(value: &Integer) -> Result<Self, Self::Error> {
        match value.to_i64() {
            Some(0) => Ok(CRLReason::Unspecified),
            Some(1) => Ok(CRLReason::KeyCompromise),
            Some(2) => Ok(CRLReason::CACompromise),
            Some(3) => Ok(CRLReason::AffiliationChanged),
            Some(4) => Ok(CRLReason::Superseded),
            Some(5) => Ok(CRLReason::CessationOfOperation),
            Some(6) => Ok(CRLReason::CertificateHold),
            Some(8) => Ok(CRLReason::RemoveFromCRL),
            Some(9) => Ok(CRLReason::PrivilegeWithdrawn),
            Some(10) => Ok(CRLReason::AACompromise),
            _ => Err(error::Error::UnknownReasonCode),
        }
    }
}

impl From<CRLReason> for u8 {
    fn from(reason: CRLReason) -> u8 {
        match reason {
            CRLReason::Unspecified => 0,
            CRLReason::KeyCompromise => 1,
            CRLReason::CACompromise => 2,
            CRLReason::AffiliationChanged => 3,
            CRLReason::Superseded => 4,
            CRLReason::CessationOfOperation => 5,
            CRLReason::CertificateHold => 6,
            CRLReason::RemoveFromCRL => 8,
            CRLReason::PrivilegeWithdrawn => 9,
            CRLReason::AACompromise => 10,
        }
    }
}

impl CRLReason {
    fn description(&self) -> &'static str {
        match self {
            CRLReason::Unspecified => "Unspecified",
            CRLReason::KeyCompromise => "Key Compromise",
            CRLReason::CACompromise => "CA Compromise",
            CRLReason::AffiliationChanged => "Affiliation Changed",
            CRLReason::Superseded => "Superseded",
            CRLReason::CessationOfOperation => "Cessation Of Operation",
            CRLReason::CertificateHold => "Certificate Hold",
            CRLReason::RemoveFromCRL => "Remove From CRL",
            CRLReason::PrivilegeWithdrawn => "Privilege Withdrawn",
            CRLReason::AACompromise => "AA Compromise",
        }
    }
}

impl Extension for CRLReason {
    /// OID for cRLReason entry extension (2.5.29.21)
    const OID: &'static str = "2.5.29.21";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(error::Error::InvalidAsn1)?;
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(Kind::CRLReason).into()),
        }
    }
}

impl DecodableFrom<Element> for CRLReason {}

impl Decoder<Element, CRLReason> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CRLReason, Self::Error> {
        match self {
            Element::Enumerated(value) => Ok(CRLReason::try_from(value)?),
            _ => Err(error::Error::ExpectedEnumerated(Kind::CRLReason).into()),
        }
    }
}

impl EncodableTo<CRLReason> for Element {}

impl Encoder<CRLReason, Element> for CRLReason {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::Enumerated(Integer::from(vec![u8::from(*self)])))
    }
}

impl OidName for CRLReason {
    fn oid_name(&self) -> Option<&'static str> {
        Some("cRLReason")
    }
}

impl fmt::Display for CRLReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 CRL Reason Code:")?;
        writeln!(f, "                {}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(CRLReason::Unspecified, 0)]
    #[case(CRLReason::KeyCompromise, 1)]
    #[case(CRLReason::CACompromise, 2)]
    #[case(CRLReason::CertificateHold, 6)]
    #[case(CRLReason::RemoveFromCRL, 8)]
    #[case(CRLReason::AACompromise, 10)]
    fn encode_decode_round_trip(#[case] reason: CRLReason, #[case] value: u8) {
        assert_eq!(u8::from(reason), value);
        let element = reason.encode().unwrap();
        let decoded: CRLReason = element.decode().unwrap();
        assert_eq!(reason, decoded);
    }

    #[test]
    fn parse_from_octet_string() {
        // OCTET STRING content = DER ENUMERATED 1 (0x0a 0x01 0x01) = keyCompromise
        let value = OctetString::from(vec![0x0a, 0x01, 0x01]);
        let decoded = CRLReason::parse(&value).unwrap();
        assert_eq!(decoded, CRLReason::KeyCompromise);
    }

    #[test]
    fn decode_rejects_unused_and_unknown_values() {
        // value 7 is explicitly unused; 11 is out of range.
        for v in [7u8, 11] {
            let decoded: Result<CRLReason, _> =
                Element::Enumerated(Integer::from(vec![v])).decode();
            assert!(decoded.is_err());
        }
    }

    #[test]
    fn decode_rejects_non_enumerated() {
        let decoded: Result<CRLReason, _> = Element::Null.decode();
        assert!(decoded.is_err());
    }
}
