//! PKCS#9 challengePassword attribute (OID: 1.2.840.113549.1.9.7)
//!
//! Defined in RFC 2985 Section 5.4.1
//!
//! ```asn1
//! challengePassword ATTRIBUTE ::= {
//!     WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
//!     EQUALITY MATCHING RULE caseExactMatch
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-challengePassword
//! }
//!
//! DirectoryString ::= CHOICE {
//!     teletexString     TeletexString (SIZE (1..MAX)),
//!     printableString   PrintableString (SIZE (1..MAX)),
//!     universalString   UniversalString (SIZE (1..MAX)),
//!     utf8String        UTF8String (SIZE (1..MAX)),
//!     bmpString         BMPString (SIZE (1..MAX))
//! }
//! ```
//!
//! The challengePassword attribute type specifies a password by which
//! an entity may request certificate revocation. It is typically used
//! in PKCS#10 certificate signing requests (CSR) to provide password-based
//! authentication to the registration authority (RA) or certification authority (CA).
//!
//! Note: RFC 2985 marks this attribute as deprecated due to security concerns,
//! but it is still widely implemented and used in practice.

use asn1::OctetString;
use pkix_types::DirectoryString;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};
use std::fmt;

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, extract_single_value};

/// challengePassword attribute
///
/// Contains a DirectoryString (CHOICE of various string types) value
/// that provides a password for certificate revocation requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePassword {
    /// The challenge password as a DirectoryString
    password: DirectoryString,
}

impl ChallengePassword {
    /// Maximum length for challengePassword (pkcs-9-ub-challengePassword)
    const MAX_LENGTH: usize = 255;

    /// Create a new ChallengePassword
    pub fn new(password: String) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyValue("challengePassword".into()));
        }
        if password.len() > Self::MAX_LENGTH {
            return Err(Error::ValueTooLong {
                max: Self::MAX_LENGTH,
                actual: password.len(),
            });
        }
        Ok(Self {
            password: DirectoryString::new(password),
        })
    }

    /// Get the challenge password as a string
    pub fn password(&self) -> &str {
        self.password.as_str()
    }
}

impl fmt::Display for ChallengePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.password.as_str())
    }
}

impl Serialize for ChallengePassword {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ChallengePassword", 1)?;
        state.serialize_field("challengePassword", self.password.as_str())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ChallengePassword {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            ChallengePassword,
        }

        struct ChallengePasswordVisitor;

        impl<'de> de::Visitor<'de> for ChallengePasswordVisitor {
            type Value = ChallengePassword;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ChallengePassword")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ChallengePassword, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut password = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ChallengePassword => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("challengePassword"));
                            }
                            password = Some(map.next_value()?);
                        }
                    }
                }
                let password: String =
                    password.ok_or_else(|| de::Error::missing_field("challengePassword"))?;
                ChallengePassword::new(password).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["challengePassword"];
        deserializer.deserialize_struct("ChallengePassword", FIELDS, ChallengePasswordVisitor)
    }
}

impl Attribute for ChallengePassword {
    const OID: &'static str = "1.2.840.113549.1.9.7";

    fn parse(data: &OctetString) -> Result<Self> {
        let value = extract_single_value(data, "challengePassword")?;

        // Extract the DirectoryString value
        // DirectoryString is a CHOICE of various string types
        let dir_string = DirectoryString::try_from(&value)
            .map_err(|e| Error::ChallengePasswordInvalidEncoding(e.to_string()))?;

        // Validate length
        if dir_string.as_str().is_empty() {
            return Err(Error::EmptyValue("challengePassword".into()));
        }
        if dir_string.as_str().len() > Self::MAX_LENGTH {
            return Err(Error::ValueTooLong {
                max: Self::MAX_LENGTH,
                actual: dir_string.as_str().len(),
            });
        }

        Ok(Self {
            password: dir_string,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::{ASN1Object, Element, ObjectIdentifier};
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;

    use crate::pkcs9::attribute::RawAttribute;

    #[test]
    fn test_challenge_password_too_long() {
        let long_password = "a".repeat(256);
        let result = ChallengePassword::new(long_password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ValueTooLong { .. }));
    }

    #[rstest]
    #[case("password123", Element::PrintableString("password123".to_string()))]
    #[case("パスワード123", Element::UTF8String("パスワード123".to_string()))]
    fn test_challenge_password_parse_string_types(
        #[case] expected: &str,
        #[case] password_value: Element,
    ) {
        // Wrap in SET
        let set = Element::Set(vec![password_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse as ChallengePassword
        let password = ChallengePassword::parse(&octet_string).unwrap();
        assert_eq!(password.password(), expected);
    }

    #[test]
    fn test_challenge_password_parse_bmp_string() {
        // Create a BMPString element
        use asn1::BMPString;
        let bmp = BMPString::new("密码").unwrap();
        let password_value = Element::BMPString(bmp);

        // Wrap in SET
        let set = Element::Set(vec![password_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse as ChallengePassword
        let password = ChallengePassword::parse(&octet_string).unwrap();
        assert_eq!(password.password(), "密码");
    }

    #[rstest]
    #[case("mypassword")]
    #[case("test123")]
    #[case("securePassword")]
    fn test_challenge_password_via_raw_attribute(#[case] password_str: &str) {
        // Create a UTF8String element
        let password_value = Element::UTF8String(password_str.to_string());
        let set = Element::Set(vec![password_value]);
        let oid = ObjectIdentifier::from_str(ChallengePassword::OID).unwrap();

        let attr_seq = Element::Sequence(vec![Element::ObjectIdentifier(oid), set]);

        // Decode as RawAttribute
        let raw_attr: RawAttribute = attr_seq.decode().unwrap();

        // Parse as ChallengePassword
        let password: ChallengePassword = raw_attr.parse().unwrap();
        assert_eq!(password.password(), password_str);
    }

    #[test]
    fn test_challenge_password_multiple_values_error() {
        // Create multiple string elements (violates SINGLE VALUE)
        let password1 = Element::PrintableString("pass1".to_string());
        let password2 = Element::PrintableString("pass2".to_string());

        // Wrap in SET with multiple values
        let set = Element::Set(vec![password1, password2]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse should fail
        let result = ChallengePassword::parse(&octet_string);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_password_invalid_type_error() {
        // Create an invalid element (INTEGER instead of string)
        use asn1::Integer;
        use num_bigint::BigInt;
        let invalid_value = Element::Integer(Integer::from(BigInt::from(42)));

        // Wrap in SET
        let set = Element::Set(vec![invalid_value]);

        // Encode to DER
        let asn1_obj = ASN1Object::new(vec![set]);
        let der = asn1_obj.encode().unwrap();
        let der_bytes = der.encode().unwrap();
        let octet_string = OctetString::from(der_bytes);

        // Parse should fail
        let result = ChallengePassword::parse(&octet_string);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("serialize_test")]
    #[case("json_password")]
    #[case("Test123!")]
    fn test_challenge_password_serde(#[case] password_str: &str) {
        let password = ChallengePassword::new(password_str.to_string()).unwrap();

        // Serialize
        let json = serde_json::to_string(&password).unwrap();
        assert!(json.contains("challengePassword"));
        assert!(json.contains(password_str));

        // Deserialize
        let deserialized: ChallengePassword = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.password(), password_str);
    }

    #[test]
    fn test_challenge_password_max_length() {
        // Test at exactly max length
        let max_password = "a".repeat(ChallengePassword::MAX_LENGTH);
        let password = ChallengePassword::new(max_password.clone()).unwrap();
        assert_eq!(password.password().len(), ChallengePassword::MAX_LENGTH);

        // Test one over max length
        let over_max = "a".repeat(ChallengePassword::MAX_LENGTH + 1);
        let result = ChallengePassword::new(over_max);
        assert!(result.is_err());
    }
}
