//! PKCS#9 signingTime attribute (OID: 1.2.840.113549.1.9.5)
//!
//! Defined in RFC 2985 Section 5.3.3
//!
//! ```asn1
//! signingTime ATTRIBUTE ::= {
//!     WITH SYNTAX SigningTime
//!     EQUALITY MATCHING RULE signingTimeMatch
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-signingTime
//! }
//!
//! SigningTime ::= Time -- imported from ISO/IEC 9594-8
//! ```
//!
//! The signingTime attribute type is intended for PKCS #7/CMS digitally
//! signed data. It specifies the time at which the signer (purportedly)
//! performed the signing process.
//!
//! ## Time Encoding Rules (from RFC 5652)
//!
//! - Dates between 1 January 1950 and 31 December 2049 (inclusive) MUST
//!   be encoded as UTCTime.
//! - Any dates with year values before 1950 or after 2049 MUST be encoded
//!   as GeneralizedTime.
//! - UTCTime values MUST be expressed in Greenwich Mean Time (Zulu) and MUST
//!   include seconds (i.e., times are YYMMDDHHMMSSZ), even where the number
//!   of seconds is zero.
//! - Midnight (GMT) must be represented as "YYMMDD000000Z".
//! - Century information is implicit:
//!   - Where YY is greater than or equal to 50, the year shall be interpreted as 19YY
//!   - Where YY is less than 50, the year shall be interpreted as 20YY
//! - GeneralizedTime values shall be expressed in Greenwich Mean Time (Zulu)
//!   and must include seconds (i.e., times are YYYYMMDDHHMMSSZ), even where
//!   the number of seconds is zero.
//! - GeneralizedTime values must not include fractional seconds.

use asn1::{ASN1Object, Element, OctetString};
use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};

use super::Attribute;
use crate::pkcs9::error::{Error, Result};

/// signingTime attribute
///
/// Contains the time at which the signer performed the signing process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningTime {
    /// The signing time
    time: DateTime<Utc>,
}

impl SigningTime {
    /// Create a new SigningTime
    pub fn new(time: DateTime<Utc>) -> Self {
        Self { time }
    }

    /// Get the signing time
    pub fn time(&self) -> &DateTime<Utc> {
        &self.time
    }

    /// Format as RFC 3339 string (for JSON serialization)
    pub fn to_rfc3339(&self) -> String {
        self.time.to_rfc3339()
    }

    /// Parse from RFC 3339 string
    pub fn from_rfc3339(s: &str) -> Result<Self> {
        let time = DateTime::parse_from_rfc3339(s)
            .map_err(|e| Error::InvalidSigningTime(format!("Invalid RFC3339: {}", e)))?
            .with_timezone(&Utc);
        Ok(Self { time })
    }
}

impl Serialize for SigningTime {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SigningTime", 1)?;
        state.serialize_field("signingTime", &self.to_rfc3339())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SigningTime {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            SigningTime,
        }

        struct SigningTimeVisitor;

        impl<'de> de::Visitor<'de> for SigningTimeVisitor {
            type Value = SigningTime;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct SigningTime")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SigningTime, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut time_string: Option<String> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::SigningTime => {
                            if time_string.is_some() {
                                return Err(de::Error::duplicate_field("signingTime"));
                            }
                            time_string = Some(map.next_value()?);
                        }
                    }
                }
                let time_string =
                    time_string.ok_or_else(|| de::Error::missing_field("signingTime"))?;

                SigningTime::from_rfc3339(&time_string).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["signingTime"];
        deserializer.deserialize_struct("SigningTime", FIELDS, SigningTimeVisitor)
    }
}

impl Attribute for SigningTime {
    const OID: &'static str = "1.2.840.113549.1.9.5";

    fn parse(values: &OctetString) -> Result<Self> {
        let asn1_obj = ASN1Object::try_from(values).map_err(Error::from)?;
        let elements = asn1_obj.elements();
        if elements.is_empty() {
            return Err(Error::InvalidSigningTime("Empty ASN1Object".into()));
        }

        // The first element should be a SET
        let Element::Set(set_contents) = &elements[0] else {
            return Err(Error::InvalidSigningTime(
                "Expected SET in signingTime values".into(),
            ));
        };

        // signingTime is SINGLE VALUE, so the SET should contain exactly one element
        if set_contents.len() != 1 {
            return Err(Error::InvalidSigningTime(format!(
                "signingTime must have exactly one value, got {}",
                set_contents.len()
            )));
        }

        // The value should be either UTCTime or GeneralizedTime
        let time = match &set_contents[0] {
            Element::UTCTime(naive_time) => {
                // Convert NaiveDateTime to DateTime<Utc>
                // Need to interpret the year based on RFC 5652 rules
                let year = naive_time.year();
                let adjusted_year = if year < 100 {
                    // Two-digit year: YY >= 50 => 19YY, YY < 50 => 20YY
                    if year >= 50 { 1900 + year } else { 2000 + year }
                } else {
                    year
                };
                Utc.with_ymd_and_hms(
                    adjusted_year,
                    naive_time.month(),
                    naive_time.day(),
                    naive_time.hour(),
                    naive_time.minute(),
                    naive_time.second(),
                )
                .single()
                .ok_or_else(|| Error::InvalidSigningTime("Invalid date/time from UTCTime".into()))?
            }
            Element::GeneralizedTime(naive_time) => {
                // Convert NaiveDateTime to DateTime<Utc>
                DateTime::from_naive_utc_and_offset(*naive_time, Utc)
            }
            _ => {
                return Err(Error::InvalidSigningTime(
                    "signingTime value must be UTCTime or GeneralizedTime".into(),
                ));
            }
        };

        Ok(Self { time })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ObjectIdentifier;
    use chrono::{Datelike, NaiveDateTime, Timelike};
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;

    use crate::pkcs9::attribute::RawAttribute;

    #[rstest]
    #[case("2024-01-15T10:30:45Z", 2024, 1, 15, 10, 30, 45)]
    #[case("2000-12-31T23:59:59Z", 2000, 12, 31, 23, 59, 59)]
    #[case("1999-06-15T12:00:00Z", 1999, 6, 15, 12, 0, 0)]
    fn test_signing_time_from_rfc3339(
        #[case] rfc3339: &str,
        #[case] year: i32,
        #[case] month: u32,
        #[case] day: u32,
        #[case] hour: u32,
        #[case] min: u32,
        #[case] sec: u32,
    ) {
        let signing_time = SigningTime::from_rfc3339(rfc3339).unwrap();
        let time = signing_time.time();
        assert_eq!(time.year(), year);
        assert_eq!(time.month(), month);
        assert_eq!(time.day(), day);
        assert_eq!(time.hour(), hour);
        assert_eq!(time.minute(), min);
        assert_eq!(time.second(), sec);
    }

    #[rstest]
    #[case("240115103045Z")] // UTCTime
    #[case("991231235959Z")] // UTCTime
    fn test_signing_time_parse_utc_time(#[case] time_str: &str) {
        // Parse using asn1's parse_utc_time to get NaiveDateTime
        let naive_time = NaiveDateTime::parse_from_str(time_str, "%y%m%d%H%M%SZ").unwrap();

        // Create a UTCTime element
        let utc_value = Element::UTCTime(naive_time);

        // Wrap in SET
        let set = Element::Set(vec![utc_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse as SigningTime
        let signing_time = SigningTime::parse(&octet_string).unwrap();
        assert!(signing_time.time().year() >= 1950);
    }

    #[rstest]
    #[case("20240115103045Z")] // GeneralizedTime
    #[case("19991231235959Z")] // GeneralizedTime
    fn test_signing_time_parse_generalized_time(#[case] time_str: &str) {
        // Parse using asn1's parse_generalized_time to get NaiveDateTime
        let naive_time = NaiveDateTime::parse_from_str(time_str, "%Y%m%d%H%M%SZ").unwrap();

        // Create a GeneralizedTime element
        let gen_value = Element::GeneralizedTime(naive_time);

        // Wrap in SET
        let set = Element::Set(vec![gen_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse as SigningTime
        let signing_time = SigningTime::parse(&octet_string).unwrap();
        assert!(signing_time.time().year() >= 1900);
    }

    #[rstest]
    #[case("240115103045Z")] // UTCTime
    #[case("20240115103045Z")] // GeneralizedTime
    fn test_signing_time_via_raw_attribute(#[case] time_str: &str) {
        // Create appropriate time element based on length
        let time_element = if time_str.len() == 13 {
            let naive_time = NaiveDateTime::parse_from_str(time_str, "%y%m%d%H%M%SZ").unwrap();
            Element::UTCTime(naive_time)
        } else {
            let naive_time = NaiveDateTime::parse_from_str(time_str, "%Y%m%d%H%M%SZ").unwrap();
            Element::GeneralizedTime(naive_time)
        };

        let set = Element::Set(vec![time_element]);
        let oid = ObjectIdentifier::from_str(SigningTime::OID).unwrap();

        let attr_seq = Element::Sequence(vec![Element::ObjectIdentifier(oid), set]);

        // Decode as RawAttribute
        let raw_attr: RawAttribute = attr_seq.decode().unwrap();

        // Parse as SigningTime
        let signing_time: SigningTime = raw_attr.parse().unwrap();
        assert!(signing_time.time().year() >= 1900);
    }

    #[test]
    fn test_signing_time_serde() {
        let time = Utc::now();
        let signing_time = SigningTime::new(time);

        // Serialize to JSON
        let json = serde_json::to_string(&signing_time).unwrap();
        assert!(json.contains("signingTime"));

        // Deserialize back
        let deserialized: SigningTime = serde_json::from_str(&json).unwrap();

        // Compare with tolerance (1 second) due to potential rounding
        let diff = (deserialized.time().timestamp() - time.timestamp()).abs();
        assert!(diff <= 1);
    }

    #[test]
    fn test_signing_time_rfc3339_roundtrip() {
        let time = Utc::now();
        let signing_time = SigningTime::new(time);

        let rfc3339 = signing_time.to_rfc3339();
        let parsed = SigningTime::from_rfc3339(&rfc3339).unwrap();

        // Compare with tolerance (1 second) due to potential rounding
        let diff = (parsed.time().timestamp() - time.timestamp()).abs();
        assert!(diff <= 1);
    }
}
