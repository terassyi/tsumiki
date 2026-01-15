use asn1::{ASN1Object, BitString, Element, Integer, OctetString};
use der::Der;
use num_bigint::BigInt;
use pem::Pem;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::Result;
use super::error::Error;
use crate::pkcs9::Attributes;
use pkix_types::AlgorithmIdentifier;

/*
RFC 5958 - Asymmetric Key Packages

OneAsymmetricKey ::= SEQUENCE {
    version                   Version,
    privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    privateKey                PrivateKey,
    attributes            [0] Attributes OPTIONAL,
    ...,
    [[2: publicKey        [1] PublicKey OPTIONAL ]],
    ...
}

PrivateKeyInfo ::= OneAsymmetricKey

Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)

PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier

PrivateKey ::= OCTET STRING

PublicKey ::= BIT STRING

Attributes ::= SET OF Attribute
*/

/// PKCS#8 OneAsymmetricKey version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// Version 1 (no public key)
    V1 = 0,
    /// Version 2 (with public key)
    V2 = 1,
}

impl From<Version> for i64 {
    fn from(v: Version) -> Self {
        v as i64
    }
}

impl TryFrom<i64> for Version {
    type Error = Error;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            _ => Err(Error::InvalidVersion(value)),
        }
    }
}

impl From<Version> for Integer {
    fn from(v: Version) -> Self {
        Integer::from(BigInt::from(v as i64))
    }
}

/// OneAsymmetricKey Attributes wrapper
///
/// This structure wraps the Attributes type for use in OneAsymmetricKey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneAsymmetricKeyAttributes(Attributes);

impl OneAsymmetricKeyAttributes {
    /// Create a new OneAsymmetricKeyAttributes
    pub fn new(attributes: Attributes) -> Self {
        Self(attributes)
    }

    /// Get a reference to the inner Attributes
    pub fn attributes(&self) -> &Attributes {
        &self.0
    }

    /// Get a mutable reference to the inner Attributes
    pub fn attributes_mut(&mut self) -> &mut Attributes {
        &mut self.0
    }

    /// Convert to inner Attributes
    pub fn into_inner(self) -> Attributes {
        self.0
    }
}

impl AsRef<Attributes> for OneAsymmetricKeyAttributes {
    fn as_ref(&self) -> &Attributes {
        &self.0
    }
}

impl std::ops::Deref for OneAsymmetricKeyAttributes {
    type Target = Attributes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Attributes> for OneAsymmetricKeyAttributes {
    fn from(attributes: Attributes) -> Self {
        Self(attributes)
    }
}

impl From<OneAsymmetricKeyAttributes> for Attributes {
    fn from(attrs: OneAsymmetricKeyAttributes) -> Self {
        attrs.0
    }
}

impl DecodableFrom<Element> for OneAsymmetricKeyAttributes {}

// Decoder for OneAsymmetricKeyAttributes from Element (expecting SET)
impl Decoder<Element, OneAsymmetricKeyAttributes> for Element {
    type Error = Error;

    fn decode(&self) -> Result<OneAsymmetricKeyAttributes> {
        let attributes: Attributes = self.decode().map_err(Error::Pkcs9)?;
        Ok(OneAsymmetricKeyAttributes(attributes))
    }
}

impl EncodableTo<OneAsymmetricKeyAttributes> for Element {}

// Encoder for OneAsymmetricKeyAttributes to Element (SET)
impl Encoder<OneAsymmetricKeyAttributes, Element> for OneAsymmetricKeyAttributes {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        self.0.encode().map_err(Error::Pkcs9)
    }
}

/// OneAsymmetricKey (PKCS#8 v2)
///
/// This structure can contain both private and public keys.
/// When publicKey is present, version MUST be v2.
/// When publicKey is absent, version SHOULD be v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneAsymmetricKey {
    /// Version (v1 or v2)
    pub version: Version,
    /// Private key algorithm identifier
    pub private_key_algorithm: AlgorithmIdentifier,
    /// Private key bytes (algorithm-specific format)
    pub private_key: OctetString,
    /// Optional attributes [0]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<OneAsymmetricKeyAttributes>,
    /// Optional public key [1] (only in v2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<BitString>,
}

/// PrivateKeyInfo (PKCS#8 v1 compatibility)
///
/// This is an alias for OneAsymmetricKey for backward compatibility.
/// PrivateKeyInfo is the same as OneAsymmetricKey when version is v1.
pub type PrivateKeyInfo = OneAsymmetricKey;

impl DecodableFrom<Element> for OneAsymmetricKey {}

// Decoder implementation for OneAsymmetricKey
impl Decoder<Element, OneAsymmetricKey> for Element {
    type Error = Error;

    fn decode(&self) -> Result<OneAsymmetricKey> {
        // OneAsymmetricKey is a SEQUENCE
        match self {
            Element::Sequence(elements) => {
                if elements.len() < 3 {
                    return Err(Error::InvalidStructure(
                        "OneAsymmetricKey must have at least 3 elements".into(),
                    ));
                }

                // 1. version (INTEGER)
                let Element::Integer(int) = &elements[0] else {
                    return Err(Error::InvalidStructure("Invalid version".into()));
                };
                let version_int = int.to_i64().ok_or(Error::InvalidVersion(0))?;
                let version = Version::try_from(version_int)?;

                // 2. privateKeyAlgorithm (AlgorithmIdentifier)
                let private_key_algorithm = elements[1].decode()?;

                // 3. privateKey (OCTET STRING)
                let Element::OctetString(private_key) = &elements[2] else {
                    return Err(Error::InvalidStructure(
                        "privateKey must be OCTET STRING".into(),
                    ));
                };

                // Optional: attributes [0] and publicKey [1]
                let (attributes, public_key) =
                    elements[3..]
                        .iter()
                        .fold((None, None), |(attrs, pubkey), elem| match elem {
                            Element::ContextSpecific {
                                slot: 0, element, ..
                            } if matches!(element.as_ref(), Element::Set(_)) => {
                                (element.decode().ok(), pubkey)
                            }
                            Element::ContextSpecific {
                                slot: 1, element, ..
                            } => {
                                let new_pubkey = if let Element::BitString(bits) = element.as_ref()
                                {
                                    Some(bits.clone())
                                } else {
                                    pubkey
                                };
                                (attrs, new_pubkey)
                            }
                            _ => (attrs, pubkey),
                        });

                Ok(OneAsymmetricKey {
                    version,
                    private_key_algorithm,
                    private_key: private_key.clone(),
                    attributes,
                    public_key,
                })
            }
            _ => Err(Error::InvalidStructure(
                "OneAsymmetricKey must be a SEQUENCE".into(),
            )),
        }
    }
}

impl EncodableTo<OneAsymmetricKey> for Element {}

// Encoder implementation for OneAsymmetricKey
impl Encoder<OneAsymmetricKey, Element> for OneAsymmetricKey {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let version_int = Integer::from(BigInt::from(self.version as i64));
        let base_elements = vec![
            Element::Integer(version_int),
            self.private_key_algorithm.encode()?,
            Element::OctetString(self.private_key.clone()),
        ];

        let optional_elements = [
            self.attributes
                .as_ref()
                .map(|attrs| {
                    attrs.encode().map(|encoded| Element::ContextSpecific {
                        slot: 0,
                        constructed: true,
                        element: Box::new(encoded),
                    })
                })
                .transpose()?,
            self.public_key
                .as_ref()
                .map(|pubkey| Element::ContextSpecific {
                    slot: 1,
                    constructed: false,
                    element: Box::new(Element::BitString(pubkey.clone())),
                }),
        ];

        let elements = base_elements
            .into_iter()
            .chain(optional_elements.into_iter().flatten())
            .collect();

        Ok(Element::Sequence(elements))
    }
}

impl DecodableFrom<ASN1Object> for OneAsymmetricKey {}

// Decoder implementation for OneAsymmetricKey from ASN1Object
impl Decoder<ASN1Object, OneAsymmetricKey> for ASN1Object {
    type Error = Error;

    fn decode(&self) -> Result<OneAsymmetricKey> {
        if self.elements().is_empty() {
            return Err(Error::InvalidStructure("ASN1Object has no elements".into()));
        }
        // Decode from the first element
        self.elements()[0].decode()
    }
}

// Decoder from Pem for convenient CLI usage
impl DecodableFrom<Pem> for OneAsymmetricKey {}

impl Decoder<Pem, OneAsymmetricKey> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<OneAsymmetricKey> {
        let der: Der = Decoder::<Pem, Der>::decode(self)?;
        let asn1_obj: ASN1Object = der.decode()?;
        Decoder::<ASN1Object, OneAsymmetricKey>::decode(&asn1_obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs8::AlgorithmParameters;
    use rstest::rstest;

    // Test constants for OIDs (dot notation strings)
    const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
    const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
    const ED25519_OID: &str = "1.3.101.112";
    const PRIME256V1_OID: &str = "1.2.840.10045.3.1.7";

    // PEM test data - actual PKCS#8 keys
    const RSA_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDmv7EEQO9B/tSS
jlFB5L79XppctPwwSfjTb5QzvemWzHkG4PZG79WkNMj8UPcrixTIkZpf32y5WEGX
QXArkFRUmboasfRQaleLEPeOPCBibIrZkGXokhidm4A8ZeqU92rkwMYC5C8+4Pdd
4Kpzm/R7+IYXXXu9u1BVSg95z5RPSzcPTx0BDhgPZC7fIwkZwJmicv8zaIXKBddI
Jm8YLrmjAwxft21NxcrSbCT8DWVHX+75xye6IGAsTt2fBn05BiYnjkK6ZwBwccdo
30fmtmfcFsC8xOIXPNxOQPcLnFWZZcMkQLCHUybd2+mOFEWsghHYlQ6LyAo/66FV
He+lH4mjAgMBAAECggEADLiSrLZbulqvI2k/J4/Ry6wUfHnp0UuysQ1csUGOCCc7
oNp0GVMNhyD115srFTZ0rd4BEboCh3FLJGiSI4SwcX2MGf6nhmtmah9EVo4QBv0O
5pGkXJ75Rm8VMb84oH/HX9cU04H67M+AM6e4HemCH/eChPU9ZidWdW1AzylXdsuG
6gySsjkd47zDeNDVhK5fBfH7kzogNlh9RdzDmkrpYm5F4hkgus8xWKpPUBpdquSh
/dBF5OW8gEuA6kYASzIcAYZK2TZuQHHGRpJkBkwbte61BwWZEGodYiXYESWNHfPA
1UkwQdf0zzMO0BHynmkGsoBElvtWbmT6sqwLr/vH0QKBgQD9iXwBBdN0z+1T3Jy2
UlYwET/yPZzmkFnHxkpZi5/jBxK5nCJO6wNXcEJfYtlDDO8mleJkAPfy06AEL1YQ
T5Df/4PnSmLNUYz4QO6qLxj9pvuOfAyPqSxKmjrvqyJGHw79N50DPh80Pap5bJ1v
XmB8iwS/jVbwphxKm3h4cNywqwKBgQDo/YkVaAFOzH2kjU72NJyHKYmrcs4kQg3e
KsanJw6K1zKxQjM1fTGuswiK1IhBUL0aICMjS4AL/TVjemTspmaFmQiPMmxlFR0o
sUfwNwDS/91Fi22QSSLvWvFAxTBsVVyZNkGlRuuhD3H8fGNx4MF+8jvXuhJWV75l
15DAHLQ66QKBgQCPqSqhrbpu0y7IORZ3XNpHbE7OpUjVgG/O+jXA3ZPgYW6jy6vJ
CfOfxRVm1S0EiDyuoXlhbwcQCgf+tw/OODeAJVmJYiXv70iwlqJlvkAr4kViLDo1
4Qce0puYmGDYWNr2cl++qaGmyVZibUAcDd8gUumC3MSpoYYgZE3z+Qej9wKBgEuo
2XVMGvCd00c2ZCfrmdECmiRE2dBIavx0Y6IwOra3f0y0tLBwAUw781AyCDU9pMrx
GLgDcodyKH4vZsq6lpxXv8HQnAaPPrLSLwxAsFHUqORGjMPIHEIiBCoGXt0vMyzF
w7eKOkZJH7jgI+L9G5i/zNMXJ5FGWRv1Tpo0OArRAoGBAOlRIE7hsCpEUtpbRMIl
B26vMthQdq8njgnpL9bubV82MXcTqzxe6mwHezLMEB0BYmb+lX5ktZOonqOgQWsj
rLdkb1HDq7D30YEoDvwfuTAoewGO/QBf+jXMHWx5TRUopcU/61bCI4D1zp/urrXo
JAOJrxibNzk6iWT9+VFcxO3m
-----END PRIVATE KEY-----";

    const EC_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB
AAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA
///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV
AMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg
9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A
AAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQgYI0ddgrJC35H
ZW0Nu0qm01vrDR8fPF0qnfMi2RdjmDahRANCAAT5GBhOCq01zvZhrnbaJ6T/hFTN
4QdED/mxYwPGfvOaoea8yxi7iXp8fM29MtiTHu/KdyWATVdPufYQvMw1M2OG
-----END PRIVATE KEY-----";

    // PKCS#8 key with attributes (friendlyName + localKeyId)
    const PKCS8_WITH_ATTRIBUTES_PEM: &str = "-----BEGIN PRIVATE KEY-----
MGECAQAwDQYJKoZIhvcNAQEBBQAEBDACAQCgRzFFMC0GCSqGSIb3DQEJFDEgHh4A
TQB5ACAAVABlAHMAdAAgAFIAUwBBACAASwBlAHkwFAYJKoZIhvcNAQkVMQcEBQEC
AwQF
-----END PRIVATE KEY-----";

    #[test]
    fn test_algorithm_identifier_rsa_with_null() {
        // RSA algorithm with NULL parameters
        let oid = RSA_ENCRYPTION_OID.parse().unwrap();
        let alg_id = AlgorithmIdentifier::new_with_params(oid, AlgorithmParameters::Null);

        // Test encoding
        let encoded = alg_id.encode().unwrap();
        if let Element::Sequence(elements) = &encoded {
            assert_eq!(elements.len(), 2);
            assert!(matches!(elements[0], Element::ObjectIdentifier(_)));
            assert!(matches!(elements[1], Element::Null));
        } else {
            panic!("Expected SEQUENCE");
        }

        // Test round-trip
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();
        assert_eq!(decoded.algorithm, alg_id.algorithm);
        assert!(matches!(
            decoded.parameters,
            Some(AlgorithmParameters::Null)
        ));
    }

    #[test]
    fn test_algorithm_identifier_without_params() {
        // EdDSA algorithm without parameters
        let oid = ED25519_OID.parse().unwrap();
        let alg_id = AlgorithmIdentifier::new(oid);

        // Test encoding
        let encoded = alg_id.encode().unwrap();
        if let Element::Sequence(elements) = &encoded {
            assert_eq!(elements.len(), 1); // Only OID, no parameters
            assert!(matches!(elements[0], Element::ObjectIdentifier(_)));
        } else {
            panic!("Expected SEQUENCE");
        }

        // Test round-trip
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();
        assert_eq!(decoded.algorithm, alg_id.algorithm);
        assert!(decoded.parameters.is_none());
    }

    #[test]
    fn test_algorithm_identifier_with_sequence_params() {
        // EC algorithm with SEQUENCE parameters
        let oid = EC_PUBLIC_KEY_OID.parse().unwrap();
        let curve_oid = PRIME256V1_OID.parse().unwrap();
        let params = AlgorithmParameters::Elm(Element::ObjectIdentifier(curve_oid));
        let alg_id = AlgorithmIdentifier::new_with_params(oid, params);

        // Test encoding
        let encoded = alg_id.encode().unwrap();
        if let Element::Sequence(elements) = &encoded {
            assert_eq!(elements.len(), 2);
            assert!(matches!(elements[0], Element::ObjectIdentifier(_)));
            assert!(matches!(elements[1], Element::ObjectIdentifier(_)));
        } else {
            panic!("Expected SEQUENCE");
        }

        // Test round-trip
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();
        assert_eq!(decoded.algorithm, alg_id.algorithm);
        assert!(matches!(
            decoded.parameters,
            Some(AlgorithmParameters::Elm(Element::ObjectIdentifier(_)))
        ));
    }

    #[rstest]
    #[case(RSA_PKCS8_PEM, "1.2.840.113549.1.1.1", true, false)]
    #[case(EC_PKCS8_PEM, "1.2.840.10045.2.1", false, true)]
    fn test_one_asymmetric_key_decode_from_pem(
        #[case] pem_data: &str,
        #[case] expected_oid: &str,
        #[case] has_null_params: bool,
        #[case] has_oid_params: bool,
    ) {
        // Decode PEM -> DER -> ASN1Object -> Element
        let pem = pem_data.decode().expect("Failed to decode PEM");
        let der: der::Der = pem.decode().expect("Failed to decode DER from PEM");
        let asn1_obj = der.decode().expect("Failed to decode ASN1Object");
        let der_element = asn1_obj
            .elements()
            .first()
            .expect("ASN1Object should have at least one element");

        // Decode OneAsymmetricKey
        let key: OneAsymmetricKey = der_element
            .decode()
            .expect("Failed to decode OneAsymmetricKey");

        // Verify structure
        assert_eq!(key.version, Version::V1);
        assert_eq!(
            key.private_key_algorithm.algorithm.to_string(),
            expected_oid
        );

        // Check parameters type
        if has_null_params {
            assert!(
                matches!(
                    key.private_key_algorithm.parameters,
                    Some(AlgorithmParameters::Null)
                ),
                "Expected NULL parameters"
            );
        }
        if has_oid_params {
            assert!(
                matches!(
                    key.private_key_algorithm.parameters,
                    Some(AlgorithmParameters::Elm(Element::Sequence(_)))
                ),
                "Expected SEQUENCE parameters"
            );
        }

        assert!(!key.private_key.as_bytes().is_empty());
    }

    #[test]
    fn test_one_asymmetric_key_round_trip() {
        // Create a simple key structure (Ed25519)
        let oid = ED25519_OID.parse().unwrap();
        let alg_id = AlgorithmIdentifier::new(oid);
        let private_key = OctetString::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let key = OneAsymmetricKey {
            version: Version::V1,
            private_key_algorithm: alg_id,
            private_key,
            attributes: None,
            public_key: None,
        };

        // Encode
        let encoded = key.encode().expect("Failed to encode");

        // Decode
        let decoded: OneAsymmetricKey = encoded.decode().expect("Failed to decode");

        // Verify
        assert_eq!(decoded.version, key.version);
        assert_eq!(
            decoded.private_key_algorithm.algorithm,
            key.private_key_algorithm.algorithm
        );
        assert_eq!(decoded.private_key, key.private_key);
    }

    #[test]
    fn test_one_asymmetric_key_with_attributes() {
        // Decode from PEM constant
        let key = decode_key_from_pem(PKCS8_WITH_ATTRIBUTES_PEM);

        // Verify basic structure
        assert_eq!(key.version, Version::V1);
        assert_eq!(
            key.private_key_algorithm.algorithm.to_string(),
            RSA_ENCRYPTION_OID
        );
        assert!(
            key.attributes.is_some(),
            "Expected attributes to be present"
        );

        // Parse and verify attributes
        let attrs = key.attributes.unwrap();
        assert_eq!(attrs.len(), 2, "Expected 2 attributes");

        let parsed = crate::pkcs9::ParsedAttributes::from(attrs.as_ref().as_ref());

        // Verify friendlyName
        let friendly_name = parsed
            .friendly_name
            .as_ref()
            .expect("Expected friendlyName attribute");
        assert_eq!(friendly_name.name(), "My Test RSA Key");

        // Verify localKeyId
        let local_key_id = parsed
            .local_key_id
            .as_ref()
            .expect("Expected localKeyId attribute");
        assert_eq!(
            local_key_id.key_id().as_ref(),
            &[0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn test_one_asymmetric_key_with_attributes_encode() {
        // Create key with attributes
        let key = create_test_key_with_attributes();

        // Encode to PEM
        let pem = encode_key_to_pem(&key);
        let pem_string = pem.to_string();

        // Verify generated PEM matches the expected constant
        let expected = normalize_pem(PKCS8_WITH_ATTRIBUTES_PEM);
        let actual = normalize_pem(&pem_string);
        assert_eq!(
            actual, expected,
            "Generated PEM does not match expected constant"
        );

        // Verify round-trip: decode the generated PEM
        let decoded = decode_key_from_pem(&pem_string);
        assert!(decoded.attributes.is_some());
        assert_eq!(decoded.attributes.unwrap().len(), 2);
    }

    // Helper functions for test_one_asymmetric_key_with_attributes tests

    /// Decode a OneAsymmetricKey from PEM string
    fn decode_key_from_pem(pem_str: &str) -> OneAsymmetricKey {
        let pem = pem_str.decode().expect("Failed to decode PEM");
        let der: der::Der = pem.decode().expect("Failed to decode DER from PEM");
        let asn1_obj = der.decode().expect("Failed to decode ASN1Object");
        let element = asn1_obj
            .elements()
            .first()
            .expect("ASN1Object should have at least one element");
        element.decode().expect("Failed to decode OneAsymmetricKey")
    }

    /// Create a test OneAsymmetricKey with friendlyName and localKeyId attributes
    fn create_test_key_with_attributes() -> OneAsymmetricKey {
        use crate::pkcs9::Attributes;

        // Algorithm identifier
        let oid = RSA_ENCRYPTION_OID.parse().unwrap();
        let alg_id = AlgorithmIdentifier::new_with_params(oid, AlgorithmParameters::Null);

        // Minimal private key (fake for testing)
        let private_key = OctetString::from(vec![0x30, 0x02, 0x01, 0x00]);

        // Create friendlyName attribute
        let fn_attr = create_friendly_name_attribute("My Test RSA Key");

        // Create localKeyId attribute
        let lk_attr = create_local_key_id_attribute(&[0x01, 0x02, 0x03, 0x04, 0x05]);

        let attrs = Attributes::new(vec![fn_attr, lk_attr]);
        let key_attrs = OneAsymmetricKeyAttributes::new(attrs);

        OneAsymmetricKey {
            version: Version::V1,
            private_key_algorithm: alg_id,
            private_key,
            attributes: Some(key_attrs),
            public_key: None,
        }
    }

    /// Create a friendlyName RawAttribute
    fn create_friendly_name_attribute(name: &str) -> crate::pkcs9::RawAttribute {
        use asn1::BMPString;

        let oid: asn1::ObjectIdentifier = "1.2.840.113549.1.9.20".parse().unwrap();
        let bmp = BMPString::new(name).unwrap();
        let values = Element::Set(vec![Element::BMPString(bmp)]);
        let attr_elem = Element::Sequence(vec![Element::ObjectIdentifier(oid), values]);
        attr_elem.decode().unwrap()
    }

    /// Create a localKeyId RawAttribute
    fn create_local_key_id_attribute(key_id: &[u8]) -> crate::pkcs9::RawAttribute {
        let oid: asn1::ObjectIdentifier = "1.2.840.113549.1.9.21".parse().unwrap();
        let octets = OctetString::from(key_id.to_vec());
        let values = Element::Set(vec![Element::OctetString(octets)]);
        let attr_elem = Element::Sequence(vec![Element::ObjectIdentifier(oid), values]);
        attr_elem.decode().unwrap()
    }

    /// Encode a OneAsymmetricKey to PEM
    fn encode_key_to_pem(key: &OneAsymmetricKey) -> pem::Pem {
        use asn1::ASN1Object;

        let element: Element = key.encode().expect("Failed to encode");
        let asn1_obj = ASN1Object::new(vec![element]);
        let der: der::Der = asn1_obj.encode().expect("Failed to encode to DER");
        let der_bytes: Vec<u8> = der.encode().expect("Failed to encode DER to bytes");
        pem::Pem::from_bytes(pem::Label::PrivateKey, &der_bytes)
    }

    /// Normalize PEM string for comparison (trim whitespace)
    fn normalize_pem(pem_str: &str) -> String {
        pem_str
            .lines()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join("\n")
    }
}
