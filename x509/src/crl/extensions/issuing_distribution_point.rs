//! Issuing Distribution Point extension (RFC 5280 §5.2.5).

use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::Extension;
use super::error::{self, Kind};
use crate::error::Error;
use crate::extensions::{DistributionPointName, ReasonFlags};

/*
RFC 5280 Section 5.2.5

id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }

IssuingDistributionPoint ::= SEQUENCE {
    distributionPoint          [0] DistributionPointName OPTIONAL,
    onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    onlySomeReasons            [3] ReasonFlags OPTIONAL,
    indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }

The issuing distribution point is a critical CRL extension that identifies the
CRL distribution point and scope for a particular CRL, and indicates whether
the CRL covers revocation for end-entity certificates only, CA certificates
only, attribute certificates only, or a limited set of reason codes.
*/

/// Issuing Distribution Point extension ([RFC 5280 §5.2.5](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5)).
///
/// Identifies the CRL distribution point and scope for a particular CRL. MUST
/// be marked critical. Reuses the shared [`DistributionPointName`] and
/// [`ReasonFlags`] building blocks.
/// OID: 2.5.29.28
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuingDistributionPoint {
    /// Distribution point name for this CRL (`[0]`).
    pub distribution_point: Option<DistributionPointName>,
    /// CRL covers only end-entity certificates (`[1]`, DEFAULT FALSE).
    pub only_contains_user_certs: bool,
    /// CRL covers only CA certificates (`[2]`, DEFAULT FALSE).
    pub only_contains_ca_certs: bool,
    /// CRL is limited to the given revocation reasons (`[3]`).
    pub only_some_reasons: Option<ReasonFlags>,
    /// CRL is an indirect CRL (`[4]`, DEFAULT FALSE).
    pub indirect_crl: bool,
    /// CRL covers only attribute certificates (`[5]`, DEFAULT FALSE).
    pub only_contains_attribute_certs: bool,
}

impl Extension for IssuingDistributionPoint {
    /// OID for issuingDistributionPoint extension (2.5.29.28)
    const OID: &'static str = "2.5.29.28";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        let asn1_obj = ASN1Object::try_from(value).map_err(error::Error::InvalidAsn1)?;
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptyContent(Kind::IssuingDistributionPoint).into()),
        }
    }
}

impl DecodableFrom<Element> for IssuingDistributionPoint {}

impl Decoder<Element, IssuingDistributionPoint> for Element {
    type Error = Error;

    fn decode(&self) -> Result<IssuingDistributionPoint, Self::Error> {
        let elements = match self {
            Element::Sequence(elements) => elements,
            _ => return Err(error::Error::ExpectedSequence(Kind::IssuingDistributionPoint).into()),
        };

        // IMPLICIT `[n] BOOLEAN` content the parser exposes as a raw OctetString
        // (DER: `0xFF` = true, `0x00` = false).
        let decode_bool = |elem: &Element| -> Result<bool, Error> {
            match elem {
                Element::OctetString(octets) => {
                    Ok(octets.as_bytes().first().is_some_and(|&b| b != 0))
                }
                _ => Err(error::Error::ExpectedBoolean(Kind::IssuingDistributionPoint).into()),
            }
        };

        let (
            distribution_point,
            only_contains_user_certs,
            only_contains_ca_certs,
            only_some_reasons,
            indirect_crl,
            only_contains_attribute_certs,
        ) = elements.iter().try_fold(
            (None, false, false, None, false, false),
            |(dp, user, ca, reasons, indirect, attr), elem| -> Result<_, Error> {
                match elem {
                    Element::ContextSpecific { slot, element, .. } => match slot {
                        0 => Ok((
                            Some(element.as_ref().decode()?),
                            user,
                            ca,
                            reasons,
                            indirect,
                            attr,
                        )),
                        1 => Ok((dp, decode_bool(element)?, ca, reasons, indirect, attr)),
                        2 => Ok((dp, user, decode_bool(element)?, reasons, indirect, attr)),
                        3 => Ok((
                            dp,
                            user,
                            ca,
                            Some(element.as_ref().decode()?),
                            indirect,
                            attr,
                        )),
                        4 => Ok((dp, user, ca, reasons, decode_bool(element)?, attr)),
                        5 => Ok((dp, user, ca, reasons, indirect, decode_bool(element)?)),
                        slot => Err(error::Error::UnknownContextTag {
                            kind: Kind::IssuingDistributionPoint,
                            slot: *slot,
                        }
                        .into()),
                    },
                    _ => Err(
                        error::Error::UnexpectedElementType(Kind::IssuingDistributionPoint).into(),
                    ),
                }
            },
        )?;

        Ok(IssuingDistributionPoint {
            distribution_point,
            only_contains_user_certs,
            only_contains_ca_certs,
            only_some_reasons,
            indirect_crl,
            only_contains_attribute_certs,
        })
    }
}

impl EncodableTo<IssuingDistributionPoint> for Element {}

impl Encoder<IssuingDistributionPoint, Element> for IssuingDistributionPoint {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let distribution_point = self
            .distribution_point
            .as_ref()
            .map(|dp| -> Result<_, Self::Error> {
                Ok(Element::ContextSpecific {
                    constructed: true,
                    slot: 0,
                    element: Box::new(dp.encode()?),
                })
            })
            .transpose()?;

        // Wraps content `octets` as an IMPLICIT primitive `[slot]` element.
        let implicit_primitive = |slot: u8, octets: Vec<u8>| Element::ContextSpecific {
            constructed: false,
            slot,
            element: Box::new(Element::OctetString(OctetString::from(octets))),
        };

        // BOOLEAN DEFAULT FALSE fields are omitted when false (DER).
        let bool_field = |set: bool, slot: u8| set.then(|| implicit_primitive(slot, vec![0xff]));

        let reasons = self
            .only_some_reasons
            .as_ref()
            .map(|reasons| -> Result<_, Self::Error> {
                match reasons.encode()? {
                    Element::BitString(bits) => {
                        let octets = std::iter::once(bits.unused_bits())
                            .chain(bits.as_bytes().iter().copied())
                            .collect();
                        Ok(implicit_primitive(3, octets))
                    }
                    _ => {
                        Err(error::Error::ExpectedBitString(Kind::IssuingDistributionPoint).into())
                    }
                }
            })
            .transpose()?;

        let elements = distribution_point
            .into_iter()
            .chain(bool_field(self.only_contains_user_certs, 1))
            .chain(bool_field(self.only_contains_ca_certs, 2))
            .chain(reasons)
            .chain(bool_field(self.indirect_crl, 4))
            .chain(bool_field(self.only_contains_attribute_certs, 5))
            .collect();

        Ok(Element::Sequence(elements))
    }
}

impl OidName for IssuingDistributionPoint {
    fn oid_name(&self) -> Option<&'static str> {
        Some("issuingDistributionPoint")
    }
}

impl fmt::Display for IssuingDistributionPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "            X509v3 Issuing Distribution Point:")?;
        if let Some(dp) = &self.distribution_point {
            write!(f, "                {}", dp)?;
        }
        if self.only_contains_user_certs {
            writeln!(f, "                Only User Certificates")?;
        }
        if self.only_contains_ca_certs {
            writeln!(f, "                Only CA Certificates")?;
        }
        if let Some(reasons) = &self.only_some_reasons {
            writeln!(f, "                Only Some Reasons: {}", reasons)?;
        }
        if self.indirect_crl {
            writeln!(f, "                Indirect CRL")?;
        }
        if self.only_contains_attribute_certs {
            writeln!(f, "                Only Attribute Certificates")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::GeneralName;
    use rstest::rstest;

    fn full_name(uri: &str) -> DistributionPointName {
        DistributionPointName::FullName(vec![GeneralName::Uri(uri.to_string())])
    }

    fn reasons_key_compromise() -> ReasonFlags {
        ReasonFlags {
            key_compromise: true,
            ca_compromise: false,
            affiliation_changed: false,
            superseded: false,
            cessation_of_operation: false,
            certificate_hold: false,
            privilege_withdrawn: false,
            aa_compromise: false,
        }
    }

    #[rstest]
    #[case(IssuingDistributionPoint {
        distribution_point: Some(full_name("http://crl.example.com/idp.crl")),
        only_contains_user_certs: false,
        only_contains_ca_certs: false,
        only_some_reasons: None,
        indirect_crl: false,
        only_contains_attribute_certs: false,
    })]
    #[case(IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: true,
        only_contains_ca_certs: false,
        only_some_reasons: None,
        indirect_crl: false,
        only_contains_attribute_certs: false,
    })]
    #[case(IssuingDistributionPoint {
        distribution_point: Some(full_name("http://crl.example.com/ca.crl")),
        only_contains_user_certs: false,
        only_contains_ca_certs: true,
        only_some_reasons: Some(reasons_key_compromise()),
        indirect_crl: true,
        only_contains_attribute_certs: false,
    })]
    fn encode_decode_round_trip(#[case] original: IssuingDistributionPoint) {
        let element = original.encode().unwrap();
        let decoded: IssuingDistributionPoint = element.decode().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn absent_booleans_default_false() {
        // SEQUENCE with only distributionPoint [0]; all booleans absent.
        let idp = IssuingDistributionPoint {
            distribution_point: Some(full_name("http://crl.example.com/idp.crl")),
            only_contains_user_certs: false,
            only_contains_ca_certs: false,
            only_some_reasons: None,
            indirect_crl: false,
            only_contains_attribute_certs: false,
        };
        let element = idp.encode().unwrap();
        // Only the [0] field is emitted (no DEFAULT-FALSE booleans).
        match &element {
            Element::Sequence(elems) => assert_eq!(elems.len(), 1),
            _ => panic!("expected SEQUENCE"),
        }
        let decoded: IssuingDistributionPoint = element.decode().unwrap();
        assert!(!decoded.only_contains_user_certs);
        assert!(!decoded.indirect_crl);
    }

    #[test]
    fn parse_from_octet_string_round_trip() {
        // Exercises the REAL DER path (bytes -> parse), where IMPLICIT primitive
        // tags arrive as raw OctetString: [1] BOOLEAN and [3] ReasonFlags both go
        // through the shared decoders rather than Element-level construction.
        let idp = IssuingDistributionPoint {
            distribution_point: Some(full_name("http://crl.example.com/idp.crl")),
            only_contains_user_certs: true,
            only_contains_ca_certs: false,
            only_some_reasons: Some(reasons_key_compromise()),
            indirect_crl: true,
            only_contains_attribute_certs: false,
        };
        // Element -> Tlv -> DER bytes -> OctetString -> parse
        let tlv = idp.encode().unwrap().encode().unwrap();
        let value = OctetString::from(tlv.encode().unwrap());
        let parsed = IssuingDistributionPoint::parse(&value).unwrap();
        assert_eq!(idp, parsed);
    }

    #[test]
    fn decode_rejects_non_sequence() {
        let decoded: Result<IssuingDistributionPoint, _> = Element::Null.decode();
        assert!(decoded.is_err());
    }
}
