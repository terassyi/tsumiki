//! Time
//!
//! Defined in RFC 5280 Section 4.1.2.5 (and reused by the CRL profile, §5.1).
//!
//! ```asn1
//! Time ::= CHOICE {
//!     utcTime        UTCTime,
//!     generalTime    GeneralizedTime
//! }
//! ```

use chrono::{Datelike, NaiveDateTime};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::Element;

use crate::error::{Error, Result};

/// An X.509 `Time`, a point in time encoded as either `UTCTime` or
/// `GeneralizedTime`.
///
/// Per RFC 5280, `UTCTime` is used for years 1950 through 2049 and
/// `GeneralizedTime` for any year outside that range; [`Time::encode`] applies
/// this rule automatically when re-encoding.
///
/// Construct one with `Time::from(datetime)` and recover the inner value with
/// `NaiveDateTime::from(time)` (or `time.into()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Time(NaiveDateTime);

impl From<NaiveDateTime> for Time {
    fn from(datetime: NaiveDateTime) -> Self {
        Time(datetime)
    }
}

impl From<Time> for NaiveDateTime {
    fn from(time: Time) -> Self {
        time.0
    }
}

impl AsRef<NaiveDateTime> for Time {
    fn as_ref(&self) -> &NaiveDateTime {
        &self.0
    }
}

impl DecodableFrom<Element> for Time {}

impl Decoder<Element, Time> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Time> {
        match self {
            Element::UTCTime(dt) | Element::GeneralizedTime(dt) => Ok(Time(*dt)),
            _ => Err(Error::InvalidTime),
        }
    }
}

impl EncodableTo<Time> for Element {}

impl Encoder<Time, Element> for Time {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        // RFC 5280: UTCTime for years 1950-2049, GeneralizedTime otherwise.
        let element = if (1950..2050).contains(&self.0.year()) {
            Element::UTCTime(self.0)
        } else {
            Element::GeneralizedTime(self.0)
        };
        Ok(element)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn dt(year: i32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(year, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
    }

    #[test]
    fn encode_uses_utctime_within_1950_2049() {
        let time = Time::from(dt(2024));
        assert_eq!(time.encode().unwrap(), Element::UTCTime(dt(2024)));
    }

    #[test]
    fn encode_uses_generalizedtime_outside_1950_2049() {
        assert_eq!(
            Time::from(dt(2060)).encode().unwrap(),
            Element::GeneralizedTime(dt(2060))
        );
        assert_eq!(
            Time::from(dt(1949)).encode().unwrap(),
            Element::GeneralizedTime(dt(1949))
        );
    }

    #[test]
    fn decode_accepts_both_time_kinds() {
        let utc: Time = Element::UTCTime(dt(2024)).decode().unwrap();
        assert_eq!(NaiveDateTime::from(utc), dt(2024));
        let general: Time = Element::GeneralizedTime(dt(2060)).decode().unwrap();
        assert_eq!(NaiveDateTime::from(general), dt(2060));
    }

    #[test]
    fn decode_rejects_non_time_element() {
        let decoded: Result<Time> = Element::Null.decode();
        assert!(decoded.is_err());
    }

    #[test]
    fn round_trip() {
        let elem = Element::UTCTime(dt(2024));
        let decoded: Time = elem.decode().unwrap();
        assert_eq!(decoded.encode().unwrap(), elem);
    }
}
