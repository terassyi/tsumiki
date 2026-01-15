//! RFC 5958 EncryptedPrivateKeyInfo
//!
//! Encrypted private key container. The actual encryption/decryption
//! implementation requires RFC 8018 PBKDF2/PBES2 (not yet implemented).

use asn1::{ASN1Object, Element, OctetString};
use der::Der;
use pem::Pem;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::Result;
use super::error::Error;
use pkix_types::AlgorithmIdentifier;

/// EncryptedPrivateKeyInfo
///
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///     encryptionAlgorithm  EncryptionAlgorithmIdentifier,
///     encryptedData        EncryptedData
/// }
///
/// EncryptedData ::= OCTET STRING
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPrivateKeyInfo {
    /// Encryption algorithm identifier
    pub encryption_algorithm: AlgorithmIdentifier,
    /// Encrypted private key data
    pub encrypted_data: OctetString,
}

impl DecodableFrom<Element> for EncryptedPrivateKeyInfo {}

// Decoder implementation for EncryptedPrivateKeyInfo
impl Decoder<Element, EncryptedPrivateKeyInfo> for Element {
    type Error = Error;

    fn decode(&self) -> Result<EncryptedPrivateKeyInfo> {
        // EncryptedPrivateKeyInfo is a SEQUENCE with 2 elements
        match self {
            Element::Sequence(elements) => {
                if elements.len() != 2 {
                    return Err(Error::InvalidStructure(
                        "EncryptedPrivateKeyInfo must have 2 elements".into(),
                    ));
                }

                // 1. encryptionAlgorithm (AlgorithmIdentifier)
                let encryption_algorithm: AlgorithmIdentifier = elements[0].decode()?;

                // 2. encryptedData (OCTET STRING)
                let encrypted_data = match &elements[1] {
                    Element::OctetString(data) => data.clone(),
                    _ => {
                        return Err(Error::InvalidStructure(
                            "encryptedData must be OCTET STRING".into(),
                        ));
                    }
                };

                Ok(EncryptedPrivateKeyInfo {
                    encryption_algorithm,
                    encrypted_data,
                })
            }
            _ => Err(Error::InvalidStructure(
                "EncryptedPrivateKeyInfo must be a SEQUENCE".into(),
            )),
        }
    }
}

impl DecodableFrom<ASN1Object> for EncryptedPrivateKeyInfo {}

// Decoder implementation for EncryptedPrivateKeyInfo from ASN1Object
impl Decoder<ASN1Object, EncryptedPrivateKeyInfo> for ASN1Object {
    type Error = Error;

    fn decode(&self) -> Result<EncryptedPrivateKeyInfo> {
        if self.elements().is_empty() {
            return Err(Error::InvalidStructure("ASN1Object has no elements".into()));
        }
        // Decode from the first element
        self.elements()[0].decode()
    }
}

impl EncodableTo<EncryptedPrivateKeyInfo> for Element {}

// Encoder implementation for EncryptedPrivateKeyInfo
impl Encoder<EncryptedPrivateKeyInfo, Element> for EncryptedPrivateKeyInfo {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        Ok(Element::Sequence(vec![
            self.encryption_algorithm.encode()?,
            Element::OctetString(self.encrypted_data.clone()),
        ]))
    }
}

impl EncodableTo<EncryptedPrivateKeyInfo> for ASN1Object {}

// Encoder implementation for EncryptedPrivateKeyInfo to ASN1Object
impl Encoder<EncryptedPrivateKeyInfo, ASN1Object> for EncryptedPrivateKeyInfo {
    type Error = Error;

    fn encode(&self) -> Result<ASN1Object> {
        let element: Element = Encoder::<EncryptedPrivateKeyInfo, Element>::encode(self)?;
        Ok(ASN1Object::new(vec![element]))
    }
}

// Decoder from Pem for convenient CLI usage
impl DecodableFrom<Pem> for EncryptedPrivateKeyInfo {}

impl Decoder<Pem, EncryptedPrivateKeyInfo> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<EncryptedPrivateKeyInfo> {
        let der: Der = Decoder::<Pem, Der>::decode(self)?;
        let asn1_obj: ASN1Object = der.decode()?;
        Decoder::<ASN1Object, EncryptedPrivateKeyInfo>::decode(&asn1_obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Der;
    use pem::{Label, Pem};
    use rstest::rstest;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;

    // Encrypted PKCS#8 RSA key (encrypted with AES-256-CBC, password: "test")
    const ENCRYPTED_RSA_PKCS8_PEM: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI8OCo2tL7Ae0CAggA
MB0GCWCGSAFlAwQBKgQQ+Vi6w+TQCYpgM/vVRhhStASCBNAMpQbLZeo01DWSsTMm
jeAjZFbbkGIU9+MXYNtvXJE0i4SDtPliWLlB3rWrZG9pb3mAz6OhcWEYRMJh7dCO
uQNAVboZPVI0DcbwUPQC1bhLSlneMISeZXsRRiBSOmG7IScsu+6dl8DPPMSVzKtA
7R5Y7/IVulUKWeg8AWljYA/dkhCMYXPaCZGPDBSEmsitydBrE4VTMxyXM0QA7Gfz
yUvTQm1DR+U8ebTnZboMUge6GYfnXGjBABRMeITb9gaR2wN9W7vf6+oNmtfek3jp
DpeZn3lyH4glDPUE3aCIWGeARixSV4jYSvWRyXoWolG1rlNg170pnN4AnjnMMSKR
JPzATC52Xm/5e3g6AYfyoJucBKzavhTr9LNCp9gsHyKYk9GYOzI7zoTMcC21YhwA
ftLlza9BQhkte3I9D0vVGXJLk84GPuGPj4hiN7MAEA+1pmiMjX4LKydIl8/Zm/a+
639aIWHBhRKMRYGFlPgDU09n3PGmiipV54axbKQh2XDEjyQ458eIP1rPdDa2arCC
knggyG0NaMzgZgIEYulIdD7sgLyZBcmiKAXVgo8/xyGczc27LqabeseOZHqDnE/W
jxCU6ym6C0XEEjK3+BtFsqSgB2Car3HyCLfQzLUqHeraWkUhtqlQ0NERH8as/voD
mpIpP7KBaDNKh5Piz5TbBJeaqo6X8L+CpPa0S2ju0+K3z/Dbo2pJ4xrnVfVZYTCP
+mSIDNa+h8IhrpC3g8UMVrUCEjy6+JtgGrpb2TFA2wjJMdPmKw0MKJx+FrqqHOIm
j2v1GB4Mew32+1bXKZqCFZAXCtZbfPUHlvJdJCopFacRC+kDqbWkllbZuIteaIR7
HVjfSvVOIh0MdTE9XUOGEjC4ryN9GG1uKj4mzEshZ4Ko7f2mfDtckGwY7zfagJDZ
bEM6WWi4ApSa1pntrjSdyCFGhx/NtvqzbK+iA8oOhoULufXJqisP952fYhovxehH
ovK2UAczPYduyqu5qce8nLOjUynMmt03Ey9JaNMoLyYuhctkdSe6o2LCr6mNoWl6
tqInD8HvCtDxmhGPuUQ1XjDF/gKL3P0bSMnyo3rqgMosYWUxZ6FxZsQaT08Ymi81
oasp4JOHqPwmT8DVQEteapFlaX5WSmZHjrhzHt/sj/F2l4cV0ggBRoNb/g3Zpv8/
N1Eh8i5ved9TUUIvaqUzjX0czEOMRFboaSqXP8QfEGKB52InCJIRqZfin60TiYZh
ypgcQiYMPtqdNzzU5AKTIDszHFxFYBKXqe82WSPLZr6X41/bBgvFgicXBl2+/eS+
2pZHaHS3YQLiA27+E0L9JyHhkCtzN0BQgD+6OQTSc7Uad1f94pL6HwnUVDN/UDaQ
Smmi/EvuW0a1C8VIIQszBLklKzUJ+Ms/emhze2j53LiQO2L2/WVL/Q5n7YrSfVfV
3NQh9vNToeXwHIqa5BDTRhk2dNjFHBXJE5FABB/2A0vuLrmjnK40VqA3apD0YtaY
ItiSeHD+42tX5W1KmKhk1Keo8azt1DmoyFIK1t4NesYkaT5rn8CxKoSo32rhEcXu
2Ris6vTZQj3Z8G4+rrjbU1rMX6k3nosQzemapfG3hWOJDzKe0L5ZFvqiJYSe1hvM
xYIdqDrCRiXh0O4TNLlrGlbpDA==
-----END ENCRYPTED PRIVATE KEY-----";

    // Encrypted PKCS#8 EC key (encrypted with AES-256-CBC, password: "test")
    const ENCRYPTED_EC_PKCS8_PEM: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIVQtD8ou/A8ACAggA
MB0GCWCGSAFlAwQBKgQQsQCzKz/oG/Q7qxbgvY/aHQSCAYAXspO6Um6Hf2ltqtO3
6SKWK9TyfLCWViJMJ/8JwNELfnURDXcWMwVaSDHxZvaGf3EIHfMBjU904OGiPbyf
l2UjWhAKLo9wKN13qj5hBU+QBrxKPc8w4NRXyn8QXG/AcaUAtIP+idVLfZw0s1TZ
9f9CWoQCLwBFS5qxNhY4PM3j1jUScr3/wsWsrJgsW9gEPqs6OGAm2FTstQoysQ5S
Eh+xzuvC1rOqAjkEWY8SfTO+wicz1CwHxw3LiAX2jQnLWZcFVOi8GWY85mffPxU1
jqXTyyAY/XDIRnE9SOAjfiVd3GiqimAptVOEFCOSZDOcKoid4KHi5hxWH/cag9YV
1ALlhcsdFDenO18Kpa+1LPw8RKdkPlkq3vekhAvjqYfTEiz4Gkp29K1+7tyqHD7t
5FAzjutPEJQc+NkWa/IGL6Uuevh/EyoJu28FeFZRmfJo0zRziD2AY5qWTlmhokdL
t7pqbqBDtqOYW2v9TINhDGo+bosxOIjQuVAR6+6bA5LhBro=
-----END ENCRYPTED PRIVATE KEY-----";

    const PBES2_OID: &str = "1.2.840.113549.1.5.13"; // id-PBES2

    #[rstest]
    #[case(ENCRYPTED_RSA_PKCS8_PEM, "RSA")]
    #[case(ENCRYPTED_EC_PKCS8_PEM, "EC")]
    fn test_encrypted_private_key_info_decode_from_pem(
        #[case] pem_data: &str,
        #[case] key_type: &str,
    ) {
        // Decode PEM
        let pem: Pem = pem_data.parse().expect("Failed to parse PEM");
        assert_eq!(pem.label(), Label::EncryptedPrivateKey);

        // Decode DER to ASN1Object
        let der: Der = pem.decode().expect("Failed to decode DER from PEM");
        let asn1_obj: asn1::ASN1Object = der.decode().expect("Failed to decode ASN1Object");

        // Decode EncryptedPrivateKeyInfo directly from ASN1Object
        let encrypted_key: EncryptedPrivateKeyInfo = asn1_obj
            .decode()
            .expect("Failed to decode EncryptedPrivateKeyInfo");

        // Verify structure
        assert!(
            !encrypted_key.encrypted_data.as_bytes().is_empty(),
            "Encrypted data should not be empty"
        );

        // Verify encryption algorithm OID (should be PBES2)
        let alg_oid = encrypted_key.encryption_algorithm.algorithm.to_string();
        assert_eq!(
            alg_oid, PBES2_OID,
            "{} key should use PBES2 encryption",
            key_type
        );

        // Verify parameters are present (PBES2 requires parameters)
        assert!(
            encrypted_key.encryption_algorithm.parameters.is_some(),
            "PBES2 should have parameters"
        );

        println!(
            "Successfully decoded encrypted {} PKCS#8 key ({} bytes)",
            key_type,
            encrypted_key.encrypted_data.as_bytes().len()
        );
    }

    #[rstest]
    #[case(ENCRYPTED_RSA_PKCS8_PEM)]
    #[case(ENCRYPTED_EC_PKCS8_PEM)]
    fn test_encrypted_private_key_info_round_trip(#[case] pem_data: &str) {
        let pem: Pem = pem_data.parse().expect("Failed to parse PEM");
        let der: Der = pem.decode().expect("Failed to decode DER from PEM");
        let asn1_obj: asn1::ASN1Object = der.decode().expect("Failed to decode ASN1Object");

        // Decode directly from ASN1Object
        let original: EncryptedPrivateKeyInfo = asn1_obj.decode().expect("Failed to decode");

        // Encode to Element
        let encoded: Element = original.encode().expect("Failed to encode");

        // Decode again
        let decoded: EncryptedPrivateKeyInfo = encoded.decode().expect("Failed to decode again");

        // Verify
        assert_eq!(
            original.encryption_algorithm.algorithm, decoded.encryption_algorithm.algorithm,
            "Algorithm OID should match"
        );
        assert_eq!(
            original.encrypted_data.as_bytes(),
            decoded.encrypted_data.as_bytes(),
            "Encrypted data should match"
        );

        println!("Round-trip encoding/decoding successful");
    }

    #[rstest]
    #[case(ENCRYPTED_RSA_PKCS8_PEM)]
    #[case(ENCRYPTED_EC_PKCS8_PEM)]
    fn test_encrypted_private_key_info_structure(#[case] pem_data: &str) {
        let pem: Pem = pem_data.parse().expect("Failed to parse PEM");
        let der: Der = pem.decode().expect("Failed to decode DER from PEM");
        let asn1_obj: asn1::ASN1Object = der.decode().expect("Failed to decode ASN1Object");

        // Decode directly from ASN1Object
        let encrypted_key: EncryptedPrivateKeyInfo = asn1_obj.decode().expect("Failed to decode");

        // Verify it's a SEQUENCE with 2 elements when encoded
        let encoded = encrypted_key.encode().expect("Failed to encode");
        if let Element::Sequence(elements) = encoded {
            assert_eq!(elements.len(), 2, "Should have 2 elements");

            // First element should be AlgorithmIdentifier (SEQUENCE)
            assert!(
                matches!(elements[0], Element::Sequence(_)),
                "First element should be SEQUENCE (AlgorithmIdentifier)"
            );

            // Second element should be OCTET STRING
            assert!(
                matches!(elements[1], Element::OctetString(_)),
                "Second element should be OCTET STRING"
            );
        } else {
            panic!("Encoded EncryptedPrivateKeyInfo should be a SEQUENCE");
        }
    }

    #[rstest]
    #[case(ENCRYPTED_RSA_PKCS8_PEM)]
    #[case(ENCRYPTED_EC_PKCS8_PEM)]
    fn test_encrypted_private_key_info_asn1object_round_trip(#[case] pem_data: &str) {
        let pem: Pem = pem_data.parse().expect("Failed to parse PEM");
        let der: Der = pem.decode().expect("Failed to decode DER from PEM");
        let asn1_obj: asn1::ASN1Object = der.decode().expect("Failed to decode ASN1Object");

        // Decode from ASN1Object
        let original: EncryptedPrivateKeyInfo = asn1_obj.decode().expect("Failed to decode");

        // Encode to ASN1Object
        let encoded_obj: ASN1Object = original.encode().expect("Failed to encode to ASN1Object");

        // Decode again from ASN1Object
        let decoded: EncryptedPrivateKeyInfo = encoded_obj
            .decode()
            .expect("Failed to decode from encoded ASN1Object");

        // Verify
        assert_eq!(
            original.encryption_algorithm.algorithm, decoded.encryption_algorithm.algorithm,
            "Algorithm OID should match"
        );
        assert_eq!(
            original.encrypted_data.as_bytes(),
            decoded.encrypted_data.as_bytes(),
            "Encrypted data should match"
        );

        println!("ASN1Object round-trip encoding/decoding successful");
    }
}
