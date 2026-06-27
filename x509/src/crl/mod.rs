//! Certificate Revocation List (CRL) types and DER codec (RFC 5280 §5.1).
//!
//! This module parses and encodes the X.509 CRL structures `CertificateList`,
//! `TBSCertList`, and `RevokedCertificate`, reusing the shared PKIX types from
//! `tsumiki-pkix-types` and the extension machinery from [`crate::extensions`].

use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, BitString, Element, Integer};
use tsumiki_pkix_types::{AlgorithmIdentifier, CertificateSerialNumber, Name, Time};

use crate::crl::error::{CRLField, Error};
use crate::extensions::Extensions;

pub mod error;
pub mod extensions;

/*
https://datatracker.ietf.org/doc/html/rfc5280#section-5.1

CertificateList  ::=  SEQUENCE  {
    tbsCertList          TBSCertList,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}

TBSCertList  ::=  SEQUENCE  {
    version                 Version OPTIONAL,  -- if present, MUST be v2
    signature               AlgorithmIdentifier,
    issuer                  Name,
    thisUpdate              Time,
    nextUpdate              Time OPTIONAL,
    revokedCertificates     SEQUENCE OF SEQUENCE  {
        userCertificate         CertificateSerialNumber,
        revocationDate          Time,
        crlEntryExtensions      Extensions OPTIONAL  -- if present, version MUST be v2
    } OPTIONAL,
    crlExtensions           [0]  EXPLICIT Extensions OPTIONAL  -- if present, version MUST be v2
}

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

Time ::= CHOICE {
    utcTime        UTCTime,
    generalTime    GeneralizedTime
}
*/

/// CRL version (RFC 5280 §5.1.2.1).
///
/// Defined as `Version ::= INTEGER { v1(0), v2(1), v3(2) }`. For CRLs only v1
/// and v2 are meaningful: the version field is OPTIONAL and, when present, MUST
/// be v2. Unlike the certificate version, the CRL version appears as a bare
/// INTEGER directly in `TBSCertList` (no `[0] EXPLICIT` wrapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    /// Version 1 (the implied default when the version field is absent).
    V1 = 0,
    /// Version 2 (required when the version field is present).
    V2 = 1,
}

impl DecodableFrom<Element> for Version {}

impl Decoder<Element, Version> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Version, Self::Error> {
        let Element::Integer(integer) = self else {
            return Err(Error::InvalidVersion("expected INTEGER".to_string()));
        };
        match integer.to_u64() {
            Some(0) => Ok(Version::V1),
            Some(1) => Ok(Version::V2),
            Some(v) => Err(Error::InvalidVersion(v.to_string())),
            None => Err(Error::InvalidVersion("value out of range".to_string())),
        }
    }
}

impl EncodableTo<Version> for Element {}

impl Encoder<Version, Element> for Version {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::Integer(Integer::from(vec![*self as u8])))
    }
}

/// A single revoked certificate entry within a CRL (RFC 5280 §5.1).
///
/// ```text
/// RevokedCertificate ::= SEQUENCE {
///     userCertificate     CertificateSerialNumber,
///     revocationDate      Time,
///     crlEntryExtensions  Extensions OPTIONAL
/// }
/// ```
///
/// `crlEntryExtensions` is an untagged (bare) SEQUENCE, so the contained
/// [`Extensions`] carries `tag: None`.
#[derive(Debug, Clone, PartialEq)]
pub struct RevokedCertificate {
    user_certificate: CertificateSerialNumber,
    revocation_date: Time,
    crl_entry_extensions: Option<Extensions>,
}

impl RevokedCertificate {
    /// The serial number of the revoked certificate.
    pub fn user_certificate(&self) -> &CertificateSerialNumber {
        &self.user_certificate
    }

    /// The date on which the certificate was revoked.
    pub fn revocation_date(&self) -> &Time {
        &self.revocation_date
    }

    /// The per-entry CRL extensions, if present.
    pub fn crl_entry_extensions(&self) -> Option<&Extensions> {
        self.crl_entry_extensions.as_ref()
    }
}

impl DecodableFrom<Element> for RevokedCertificate {}

impl Decoder<Element, RevokedCertificate> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RevokedCertificate, Self::Error> {
        let Element::Sequence(elements) = self else {
            return Err(Error::ExpectedSequence(CRLField::RevokedCertificate));
        };
        if elements.len() < 2 || elements.len() > 3 {
            return Err(Error::InvalidElementCount {
                context: CRLField::RevokedCertificate,
                expected: "2-3",
                actual: elements.len(),
            });
        }

        let mut iter = elements.iter();

        let user_certificate = iter
            .next()
            .ok_or(Error::MissingField(CRLField::UserCertificate))?
            .decode()?;

        let revocation_date = iter
            .next()
            .ok_or(Error::MissingField(CRLField::RevocationDate))?
            .decode()
            .map_err(|_| Error::InvalidTime(CRLField::RevocationDate))?;

        let crl_entry_extensions = iter.next().map(|elem| elem.decode()).transpose()?;

        Ok(RevokedCertificate {
            user_certificate,
            revocation_date,
            crl_entry_extensions,
        })
    }
}

impl EncodableTo<RevokedCertificate> for Element {}

impl Encoder<RevokedCertificate, Element> for RevokedCertificate {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let crl_entry_extensions = self
            .crl_entry_extensions
            .as_ref()
            .map(|exts| exts.encode())
            .transpose()?;

        let elements = std::iter::once(self.user_certificate.encode()?)
            .chain(std::iter::once(self.revocation_date.encode()?))
            .chain(crl_entry_extensions)
            .collect();

        Ok(Element::Sequence(elements))
    }
}

/// The to-be-signed portion of a CRL (RFC 5280 §5.1).
#[derive(Debug, Clone, PartialEq)]
pub struct TBSCertList {
    version: Option<Version>,
    signature: AlgorithmIdentifier,
    issuer: Name,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certificates: Vec<RevokedCertificate>,
    crl_extensions: Option<Extensions>,
}

impl TBSCertList {
    /// The CRL version, if explicitly encoded (absent implies v1).
    pub fn version(&self) -> Option<Version> {
        self.version
    }

    /// The algorithm used to sign the CRL.
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    /// The CRL issuer.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// The issue date of this CRL.
    pub fn this_update(&self) -> &Time {
        &self.this_update
    }

    /// The date by which the next CRL will be issued, if present.
    pub fn next_update(&self) -> Option<&Time> {
        self.next_update.as_ref()
    }

    /// The list of revoked certificates (empty if the field is absent).
    pub fn revoked_certificates(&self) -> &[RevokedCertificate] {
        &self.revoked_certificates
    }

    /// The CRL-global extensions (`crlExtensions [0]`), if present.
    pub fn crl_extensions(&self) -> Option<&Extensions> {
        self.crl_extensions.as_ref()
    }
}

impl DecodableFrom<Element> for TBSCertList {}

impl Decoder<Element, TBSCertList> for Element {
    type Error = Error;

    fn decode(&self) -> Result<TBSCertList, Self::Error> {
        let Element::Sequence(elements) = self else {
            return Err(Error::ExpectedSequence(CRLField::TBSCertList));
        };
        // Required: signature, issuer, thisUpdate (3). Optional: version,
        // nextUpdate, revokedCertificates, crlExtensions (up to 7 total).
        if elements.len() < 3 || elements.len() > 7 {
            return Err(Error::InvalidElementCount {
                context: CRLField::TBSCertList,
                expected: "3-7",
                actual: elements.len(),
            });
        }

        let mut iter = elements.iter().peekable();

        // version OPTIONAL -- present iff the first element is a bare INTEGER.
        let version = match iter.peek() {
            Some(Element::Integer(_)) => Some(
                iter.next()
                    .ok_or(Error::MissingField(CRLField::Version))?
                    .decode()?,
            ),
            _ => None,
        };

        let signature = iter
            .next()
            .ok_or(Error::MissingField(CRLField::Signature))?
            .decode()?;

        let issuer = iter
            .next()
            .ok_or(Error::MissingField(CRLField::Issuer))?
            .decode()?;

        let this_update = iter
            .next()
            .ok_or(Error::MissingField(CRLField::ThisUpdate))?
            .decode()
            .map_err(|_| Error::InvalidTime(CRLField::ThisUpdate))?;

        // Remaining optional fields appear in a fixed DER order: nextUpdate
        // (Time), revokedCertificates (SEQUENCE OF), crlExtensions ([0]).
        let (next_update, revoked_certificates, crl_extensions) = iter.try_fold(
            (None, Vec::new(), None),
            |(next_update, revoked, crl_exts), elem| match elem {
                Element::UTCTime(_) | Element::GeneralizedTime(_)
                    if next_update.is_none() && revoked.is_empty() && crl_exts.is_none() =>
                {
                    let time = elem
                        .decode()
                        .map_err(|_| Error::InvalidTime(CRLField::NextUpdate))?;
                    Ok((Some(time), revoked, crl_exts))
                }
                Element::Sequence(items) if revoked.is_empty() && crl_exts.is_none() => {
                    let parsed = items
                        .iter()
                        .map(|item| item.decode())
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((next_update, parsed, crl_exts))
                }
                Element::ContextSpecific { slot: 0, .. } if crl_exts.is_none() => {
                    Ok((next_update, revoked, Some(elem.decode()?)))
                }
                _ => Err(Error::UnexpectedElement(CRLField::TBSCertList)),
            },
        )?;

        Ok(TBSCertList {
            version,
            signature,
            issuer,
            this_update,
            next_update,
            revoked_certificates,
            crl_extensions,
        })
    }
}

impl EncodableTo<TBSCertList> for Element {}

impl Encoder<TBSCertList, Element> for TBSCertList {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let version = self.version.map(|v| v.encode()).transpose()?;
        let next_update = self.next_update.map(|t| t.encode()).transpose()?;
        let revoked = if self.revoked_certificates.is_empty() {
            None
        } else {
            let items = self
                .revoked_certificates
                .iter()
                .map(|rc| rc.encode())
                .collect::<Result<Vec<_>, _>>()?;
            Some(Element::Sequence(items))
        };
        let crl_extensions = self
            .crl_extensions
            .as_ref()
            .map(|e| e.encode())
            .transpose()?;

        let elements = version
            .into_iter()
            .chain(std::iter::once(self.signature.encode()?))
            .chain(std::iter::once(self.issuer.encode()?))
            .chain(std::iter::once(self.this_update.encode()?))
            .chain(next_update)
            .chain(revoked)
            .chain(crl_extensions)
            .collect();

        Ok(Element::Sequence(elements))
    }
}

/// A complete, signed X.509 Certificate Revocation List (RFC 5280 §5.1).
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateList {
    tbs_cert_list: TBSCertList,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString,
}

impl CertificateList {
    /// The to-be-signed CRL contents.
    pub fn tbs_cert_list(&self) -> &TBSCertList {
        &self.tbs_cert_list
    }

    /// The algorithm used to produce `signature_value`.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// The CRL issuer's signature over the encoded `tbs_cert_list`.
    pub fn signature_value(&self) -> &BitString {
        &self.signature_value
    }
}

impl DecodableFrom<Element> for CertificateList {}

impl Decoder<Element, CertificateList> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificateList, Self::Error> {
        let Element::Sequence(elements) = self else {
            return Err(Error::ExpectedSequence(CRLField::CertificateList));
        };
        let (tbs_elem, sig_alg_elem, sig_val_elem) = match elements.as_slice() {
            [tbs, sig_alg, sig_val] => (tbs, sig_alg, sig_val),
            _ => {
                return Err(Error::InvalidElementCount {
                    context: CRLField::CertificateList,
                    expected: "3",
                    actual: elements.len(),
                });
            }
        };

        let tbs_cert_list = tbs_elem.decode()?;
        let signature_algorithm = sig_alg_elem.decode()?;
        let signature_value = match sig_val_elem {
            Element::BitString(bs) => bs.clone(),
            _ => return Err(Error::ExpectedBitString(CRLField::SignatureValue)),
        };

        Ok(CertificateList {
            tbs_cert_list,
            signature_algorithm,
            signature_value,
        })
    }
}

impl EncodableTo<CertificateList> for Element {}

impl Encoder<CertificateList, Element> for CertificateList {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::Sequence(vec![
            self.tbs_cert_list.encode()?,
            self.signature_algorithm.encode()?,
            Element::BitString(self.signature_value.clone()),
        ]))
    }
}

impl DecodableFrom<ASN1Object> for CertificateList {}

impl Decoder<ASN1Object, CertificateList> for ASN1Object {
    type Error = Error;

    fn decode(&self) -> Result<CertificateList, Self::Error> {
        let elements = self.elements();
        if elements.len() != 1 {
            return Err(Error::InvalidElementCount {
                context: CRLField::CertificateList,
                expected: "1",
                actual: elements.len(),
            });
        }
        elements
            .first()
            .ok_or(Error::EmptyCertificateList)?
            .decode()
    }
}

impl EncodableTo<CertificateList> for ASN1Object {}

impl Encoder<CertificateList, ASN1Object> for CertificateList {
    type Error = Error;

    fn encode(&self) -> Result<ASN1Object, Self::Error> {
        Ok(ASN1Object::new(vec![self.encode()?]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveDateTime};
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki_asn1::ObjectIdentifier;

    fn dt(year: i32, month: u32, day: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
    }

    // AlgorithmIdentifier element: SEQUENCE { OID, NULL }.
    fn alg_elem() -> Element {
        Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()),
            Element::Null,
        ])
    }

    // Empty Name element: SEQUENCE OF RDN with no components.
    fn name_elem() -> Element {
        Element::Sequence(vec![])
    }

    fn revoked_elem(serial: u8, date: NaiveDateTime) -> Element {
        Element::Sequence(vec![
            Element::Integer(Integer::from(vec![serial])),
            Element::UTCTime(date),
        ])
    }

    #[rstest]
    #[case(0, Version::V1)]
    #[case(1, Version::V2)]
    fn version_round_trip(#[case] raw: u8, #[case] expected: Version) {
        let elem = Element::Integer(Integer::from(vec![raw]));
        let decoded: Version = elem.decode().unwrap();
        assert_eq!(decoded, expected);
        let encoded = decoded.encode().unwrap();
        assert_eq!(encoded, elem);
    }

    #[test]
    fn version_rejects_unknown_value() {
        let elem = Element::Integer(Integer::from(vec![5]));
        let decoded: Result<Version, _> = elem.decode();
        assert!(decoded.is_err());
    }

    #[test]
    fn revoked_certificate_rejects_non_time_revocation_date() {
        // revocationDate is not a Time element.
        let elem = Element::Sequence(vec![
            Element::Integer(Integer::from(vec![0x01])),
            Element::Null,
        ]);
        let decoded: Result<RevokedCertificate, _> = elem.decode();
        assert!(matches!(
            decoded,
            Err(Error::InvalidTime(CRLField::RevocationDate))
        ));
    }

    #[test]
    fn revoked_certificate_round_trip() {
        let elem = revoked_elem(0x42, dt(2024, 3, 1));
        let decoded: RevokedCertificate = elem.decode().unwrap();
        assert_eq!(decoded.revocation_date(), &Time::from(dt(2024, 3, 1)));
        assert!(decoded.crl_entry_extensions().is_none());
        let encoded = decoded.encode().unwrap();
        assert_eq!(encoded, elem);
    }

    #[test]
    fn tbs_cert_list_round_trip_full() {
        let elem = Element::Sequence(vec![
            Element::Integer(Integer::from(vec![1])), // version v2
            alg_elem(),
            name_elem(),
            Element::UTCTime(dt(2024, 1, 1)), // thisUpdate
            Element::UTCTime(dt(2024, 2, 1)), // nextUpdate
            Element::Sequence(vec![
                revoked_elem(0x01, dt(2024, 1, 10)),
                revoked_elem(0x02, dt(2024, 1, 20)),
            ]),
        ]);
        let decoded: TBSCertList = elem.decode().unwrap();
        assert_eq!(decoded.version(), Some(Version::V2));
        assert_eq!(decoded.next_update(), Some(&Time::from(dt(2024, 2, 1))));
        assert_eq!(decoded.revoked_certificates().len(), 2);
        let encoded = decoded.encode().unwrap();
        assert_eq!(encoded, elem);
    }

    #[test]
    fn tbs_cert_list_round_trip_minimal() {
        // Required fields only: signature, issuer, thisUpdate.
        let elem = Element::Sequence(vec![
            alg_elem(),
            name_elem(),
            Element::UTCTime(dt(2024, 1, 1)),
        ]);
        let decoded: TBSCertList = elem.decode().unwrap();
        assert_eq!(decoded.version(), None);
        assert_eq!(decoded.next_update(), None);
        assert!(decoded.revoked_certificates().is_empty());
        let encoded = decoded.encode().unwrap();
        assert_eq!(encoded, elem);
    }

    #[test]
    fn certificate_list_round_trip() {
        let tbs = Element::Sequence(vec![
            alg_elem(),
            name_elem(),
            Element::UTCTime(dt(2024, 1, 1)),
        ]);
        let elem = Element::Sequence(vec![
            tbs,
            alg_elem(),
            Element::BitString(BitString::new(0, vec![0xde, 0xad, 0xbe, 0xef])),
        ]);
        let decoded: CertificateList = elem.decode().unwrap();
        let encoded: Element = decoded.encode().unwrap();
        assert_eq!(encoded, elem);
    }

    #[test]
    fn certificate_list_rejects_wrong_element_count() {
        let elem = Element::Sequence(vec![alg_elem(), name_elem()]);
        let decoded: Result<CertificateList, _> = elem.decode();
        assert!(decoded.is_err());
    }
}
