//! SEC1 (RFC 5915) ECPrivateKey structure
//!
//! This module implements the ECPrivateKey structure as defined in
//! [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).

use asn1::{ASN1Object, BitString, Element, Integer, OctetString};
use der::Der;
use num_bigint::BigInt;
use pem::{Label, Pem, ToPem};
use pkix_types::OidName;
use pkix_types::algorithm::parameters::ec::NamedCurve;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::error::{Error, Result};

/*
RFC 5915 - Elliptic Curve Private Key Structure

ECPrivateKey ::= SEQUENCE {
    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    privateKey     OCTET STRING,
    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    publicKey  [1] BIT STRING OPTIONAL
}
*/

/// SEC1 ECPrivateKey version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// ecPrivkeyVer1 (value 1)
    V1 = 1,
}

impl From<Version> for i64 {
    fn from(v: Version) -> Self {
        v as i64
    }
}

impl From<Version> for Integer {
    fn from(v: Version) -> Self {
        Integer::from(BigInt::from(v as i64))
    }
}

impl TryFrom<i64> for Version {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Version::V1),
            _ => Err(Error::InvalidVersion(value)),
        }
    }
}

impl DecodableFrom<Element> for Version {}

impl Decoder<Element, Version> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Version> {
        match self {
            Element::Integer(int) => {
                let value: i64 = int.try_into().map_err(|_| Error::VersionOutOfRange)?;
                Version::try_from(value)
            }
            _ => Err(Error::ExpectedInteger("version")),
        }
    }
}

/// SEC1 EC Private Key structure (RFC 5915)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ECPrivateKey {
    /// Version (always V1)
    pub version: Version,
    /// Private key value as octet string
    pub private_key: OctetString,
    /// EC parameters (named curve) - OPTIONAL [0]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<NamedCurve>,
    /// Public key - OPTIONAL [1]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<BitString>,
}

impl ECPrivateKey {
    /// Creates a new ECPrivateKey with the given parameters.
    pub fn new(
        private_key: OctetString,
        parameters: Option<NamedCurve>,
        public_key: Option<BitString>,
    ) -> Self {
        Self {
            version: Version::V1,
            private_key,
            parameters,
            public_key,
        }
    }

    /// Returns the key size in bits based on the curve.
    #[must_use]
    pub fn key_size(&self) -> u32 {
        self.parameters.map_or_else(
            || (self.private_key.as_bytes().len() * 8) as u32,
            |curve| match curve {
                NamedCurve::Secp192r1 => 192,
                NamedCurve::Secp224r1 => 224,
                NamedCurve::Secp256r1 => 256,
                NamedCurve::Secp384r1 => 384,
                NamedCurve::Secp521r1 => 521,
                NamedCurve::Sect163k1 | NamedCurve::Sect163r2 => 163,
                NamedCurve::Sect233k1 | NamedCurve::Sect233r1 => 233,
                NamedCurve::Sect283k1 | NamedCurve::Sect283r1 => 283,
                NamedCurve::Sect409k1 | NamedCurve::Sect409r1 => 409,
                NamedCurve::Sect571k1 | NamedCurve::Sect571r1 => 571,
            },
        )
    }

    /// Returns the curve name if parameters are present.
    #[must_use]
    pub fn curve_name(&self) -> Option<&'static str> {
        self.parameters.as_ref().and_then(|c| c.oid_name())
    }
}

impl DecodableFrom<Element> for ECPrivateKey {}

impl Decoder<Element, ECPrivateKey> for Element {
    type Error = Error;

    fn decode(&self) -> Result<ECPrivateKey> {
        let elements = match self {
            Element::Sequence(elements) => elements,
            _ => return Err(Error::ExpectedSequence),
        };

        let mut iter = elements.iter();

        let version = iter
            .next()
            .ok_or_else(|| Error::InsufficientElements("missing version".into()))?
            .decode()?;

        let private_key = iter
            .next()
            .ok_or_else(|| Error::InsufficientElements("missing privateKey".into()))
            .and_then(|e| match e {
                Element::OctetString(octets) => Ok(octets.clone()),
                _ => Err(Error::ExpectedOctetString),
            })?;

        let parameters = iter
            .find_map(|e| match e {
                Element::ContextSpecific {
                    slot: 0,
                    element: inner,
                    ..
                } => Some(inner),
                _ => None,
            })
            .map(|inner| match inner.as_ref() {
                Element::ObjectIdentifier(oid) => {
                    NamedCurve::try_from(oid).map_err(|_| Error::UnknownCurve(oid.to_string()))
                }
                _ => Err(Error::UnknownCurve("invalid parameters".into())),
            })
            .transpose()?;

        let public_key = iter.find_map(|e| match e {
            Element::ContextSpecific {
                slot: 1,
                element: inner,
                ..
            } => match inner.as_ref() {
                Element::BitString(bits) => Some(bits.clone()),
                _ => None,
            },
            _ => None,
        });

        Ok(ECPrivateKey {
            version,
            private_key,
            parameters,
            public_key,
        })
    }
}

impl EncodableTo<ECPrivateKey> for Element {}

impl Encoder<ECPrivateKey, Element> for ECPrivateKey {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let base_elements = vec![
            Element::Integer(Integer::from(self.version)),
            Element::OctetString(self.private_key.clone()),
        ];

        let elements = [
            self.parameters.map(|curve| Element::ContextSpecific {
                slot: 0,
                constructed: true,
                element: Box::new(Element::ObjectIdentifier(curve.oid())),
            }),
            self.public_key
                .as_ref()
                .map(|pubkey| Element::ContextSpecific {
                    slot: 1,
                    constructed: true,
                    element: Box::new(Element::BitString(pubkey.clone())),
                }),
        ]
        .into_iter()
        .flatten()
        .fold(base_elements, |mut acc, elem| {
            acc.push(elem);
            acc
        });

        Ok(Element::Sequence(elements))
    }
}

impl DecodableFrom<Pem> for ECPrivateKey {}

impl Decoder<Pem, ECPrivateKey> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<ECPrivateKey> {
        let der: Der = self.decode()?;
        let asn1_obj: ASN1Object = der.decode()?;

        asn1_obj
            .elements()
            .first()
            .ok_or(Error::EmptyAsn1Object)?
            .decode()
    }
}

impl ToPem for ECPrivateKey {
    type Error = Error;

    fn pem_label(&self) -> Label {
        Label::ECPrivateKey
    }

    fn to_pem(&self) -> Result<Pem> {
        let element = self.encode()?;
        let asn1_obj = ASN1Object::new(vec![element]);
        let der: Der = asn1_obj.encode()?;
        let der_bytes: Vec<u8> = der.encode()?;

        Ok(Pem::from_bytes(self.pem_label(), &der_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    // Test EC private key (P-256) generated by OpenSSL
    // openssl ecparam -name prime256v1 -genkey -noout
    const EC_P256_PRIVATE_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIfdTjEBvN2/AupnhPeL8585jLgieLQmi4SfX/FVrTxZoAoGCCqGSM49
AwEHoUQDQgAEmvfw1VdwIlsJHfbHLhHXrO3Wq/0LBCduo6Nb96AiLGUxkn/OWt1I
9STYYNw8e/Xuzsy9j5joSxQDwmCWSGPGWw==
-----END EC PRIVATE KEY-----"#;

    // Test EC private key (P-384)
    // openssl ecparam -name secp384r1 -genkey -noout
    const EC_P384_PRIVATE_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCp+QQ1ic50MPNim8hemZ9853kE4ReucQLxVQnHLJ+B4Ejh552giISF
F8erNZqcuE+gBwYFK4EEACKhZANiAASms4UAIsjkkf567S2I5bvU2ELxXLFmcuBb
AgMjE74B7/b0jJEhqaszvV6jQsVKB2jevdyMED4KHm+rgRbRDfrtplf17rVHmesK
F4DFsVCxm1UW3yMaWOubErA/RlKdqsA=
-----END EC PRIVATE KEY-----"#;

    // Test EC private key (P-521)
    // openssl ecparam -name secp521r1 -genkey -noout
    const EC_P521_PRIVATE_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBG2F7/3uIELQgBKIBPJgI01TBxVxj5sc7ks1YwRHMX6HwthD5A8zz
6PpFSwpUudZPATNKKHAAme8+V8F7BSg0dqCgBwYFK4EEACOhgYkDgYYABAFMwaQy
3jgmaLl2RoOsag/fQXn60rxnGxt31gd7Tj2Dk3ABQgYBwOyxBpV/FXxD7CJXwvtV
dZ6bL/aGSmFX0iNUqwFqkkxrPTIF5lwmusiAUGR461IiqTodBQ9If3Wq5qE1UNPu
Qfy9psRxxxXzssiOv+KVS4Lh1VxPde57p20Rg7kH8g==
-----END EC PRIVATE KEY-----"#;

    #[test]
    fn test_version_conversion() {
        assert_eq!(i64::from(Version::V1), 1);
        assert_eq!(Version::try_from(1).unwrap(), Version::V1);
        assert!(Version::try_from(0).is_err());
        assert!(Version::try_from(2).is_err());
    }

    #[test]
    fn test_ec_private_key_encode_decode() {
        let private_key = OctetString::from(vec![0x01, 0x02, 0x03, 0x04]);
        let ec_key = ECPrivateKey::new(private_key.clone(), Some(NamedCurve::Secp256r1), None);

        let encoded = ec_key.encode().unwrap();
        let decoded: ECPrivateKey = encoded.decode().unwrap();

        assert_eq!(decoded.version, Version::V1);
        assert_eq!(decoded.private_key, private_key);
        assert_eq!(decoded.parameters, Some(NamedCurve::Secp256r1));
        assert!(decoded.public_key.is_none());
    }

    #[test]
    fn test_ec_private_key_with_public_key() {
        let private_key = OctetString::from(vec![0x01, 0x02, 0x03, 0x04]);
        let public_key = BitString::new(0, vec![0x04, 0x01, 0x02, 0x03, 0x04]);
        let ec_key = ECPrivateKey::new(
            private_key.clone(),
            Some(NamedCurve::Secp256r1),
            Some(public_key.clone()),
        );

        let encoded = ec_key.encode().unwrap();
        let decoded: ECPrivateKey = encoded.decode().unwrap();

        assert_eq!(decoded.version, Version::V1);
        assert_eq!(decoded.private_key, private_key);
        assert_eq!(decoded.parameters, Some(NamedCurve::Secp256r1));
        assert_eq!(decoded.public_key, Some(public_key));
    }

    #[rstest]
    #[case(EC_P256_PRIVATE_KEY)]
    #[case(EC_P384_PRIVATE_KEY)]
    #[case(EC_P521_PRIVATE_KEY)]
    fn test_ec_private_key_decode_from_pem(#[case] pem_str: &str) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        assert_eq!(pem.label(), Label::ECPrivateKey);

        let ec_key: ECPrivateKey = pem.decode().expect("Failed to decode ECPrivateKey");

        assert_eq!(ec_key.version, Version::V1);
        assert!(!ec_key.private_key.as_bytes().is_empty());
    }

    #[rstest]
    #[case(EC_P256_PRIVATE_KEY, 256)]
    #[case(EC_P384_PRIVATE_KEY, 384)]
    #[case(EC_P521_PRIVATE_KEY, 521)]
    fn test_ec_private_key_size(#[case] pem_str: &str, #[case] expected_bits: u32) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let ec_key: ECPrivateKey = pem.decode().expect("Failed to decode ECPrivateKey");
        assert_eq!(ec_key.key_size(), expected_bits);
    }

    #[rstest]
    #[case(EC_P256_PRIVATE_KEY)]
    #[case(EC_P384_PRIVATE_KEY)]
    #[case(EC_P521_PRIVATE_KEY)]
    fn test_ec_private_key_roundtrip(#[case] pem_str: &str) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let ec_key: ECPrivateKey = pem.decode().expect("Failed to decode ECPrivateKey");

        let encoded_element = ec_key.encode().expect("Failed to encode ECPrivateKey");
        let decoded: ECPrivateKey = encoded_element
            .decode()
            .expect("Failed to decode ECPrivateKey");

        assert_eq!(decoded.version, ec_key.version);
        assert_eq!(decoded.private_key, ec_key.private_key);
        assert_eq!(decoded.parameters, ec_key.parameters);
        assert_eq!(decoded.public_key.is_some(), ec_key.public_key.is_some());
    }

    #[rstest]
    #[case(EC_P256_PRIVATE_KEY)]
    #[case(EC_P384_PRIVATE_KEY)]
    #[case(EC_P521_PRIVATE_KEY)]
    fn test_ec_private_key_to_pem(#[case] pem_str: &str) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let ec_key: ECPrivateKey = pem.decode().expect("Failed to decode ECPrivateKey");

        let encoded_pem = ec_key.to_pem().expect("Failed to encode to PEM");

        assert_eq!(encoded_pem.label(), Label::ECPrivateKey);

        let decoded: ECPrivateKey = encoded_pem.decode().expect("Failed to decode PEM");
        assert_eq!(decoded.version, ec_key.version);
        assert_eq!(decoded.private_key, ec_key.private_key);
    }

    #[test]
    fn test_error_expected_sequence() {
        let element = Element::Integer(Integer::from(BigInt::from(1)));
        let result: Result<ECPrivateKey> = element.decode();
        assert!(matches!(result, Err(Error::ExpectedSequence)));
    }

    #[test]
    fn test_error_insufficient_elements() {
        let element = Element::Sequence(vec![Element::Integer(Integer::from(BigInt::from(1)))]);
        let result: Result<ECPrivateKey> = element.decode();
        assert!(matches!(result, Err(Error::InsufficientElements(_))));
    }

    #[test]
    fn test_error_invalid_version() {
        let element = Element::Sequence(vec![
            Element::Integer(Integer::from(BigInt::from(99))),
            Element::OctetString(OctetString::from(vec![0x01])),
        ]);
        let result: Result<ECPrivateKey> = element.decode();
        assert!(matches!(result, Err(Error::InvalidVersion(99))));
    }

    #[test]
    fn test_error_expected_octet_string() {
        let element = Element::Sequence(vec![
            Element::Integer(Integer::from(BigInt::from(1))),
            Element::Integer(Integer::from(BigInt::from(42))),
        ]);
        let result: Result<ECPrivateKey> = element.decode();
        assert!(matches!(result, Err(Error::ExpectedOctetString)));
    }
}
