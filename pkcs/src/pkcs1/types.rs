use asn1::{ASN1Object, Element, Integer};
use der::Der;
use num_bigint::BigInt;
use pem::{Label, Pem, ToPem};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use super::error::{Error, Result};
use crate::PublicKey;
use crate::private_key::{KeyAlgorithm, PrivateKeyExt};
use crate::public_key::PublicKeyExt;

/*
RFC 8017 - PKCS #1: RSA Cryptography Specifications

RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}

Version ::= INTEGER { two-prime(0), multi(1) }
    (CONSTRAINED BY {-- version must be multi if otherPrimeInfos present --})
*/

/// PKCS#1 RSAPrivateKey version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    TwoPrime = 0,
    Multi = 1,
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
            0 => Ok(Version::TwoPrime),
            1 => Ok(Version::Multi),
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
                let value: i64 = int.try_into().map_err(|_| {
                    Error::InvalidInteger("Version integer value out of range for i64".to_string())
                })?;
                Version::try_from(value)
            }
            _ => Err(Error::InvalidStructure(
                "Version must be an INTEGER element".to_string(),
            )),
        }
    }
}

/// PKCS#1 RSA Private Key structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RSAPrivateKey {
    pub version: Version,
    pub modulus: Integer,          // n
    pub public_exponent: Integer,  // e
    pub private_exponent: Integer, // d
    pub prime1: Integer,           // p
    pub prime2: Integer,           // q
    pub exponent1: Integer,        // d mod (p-1)
    pub exponent2: Integer,        // d mod (q-1)
    pub coefficient: Integer,      // (inverse of q) mod p
                                   // otherPrimeInfos is rarely used, omitted for now
}

impl DecodableFrom<Element> for RSAPrivateKey {}

impl Decoder<Element, RSAPrivateKey> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RSAPrivateKey> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() < 9 {
                    return Err(Error::InvalidStructure(format!(
                        "expected at least 9 elements in RSAPrivateKey sequence, got {}",
                        elements.len()
                    )));
                }

                // Helper to extract INTEGER
                let get_integer = |idx: usize, field_name: &str| -> Result<Integer> {
                    if let Element::Integer(int) = &elements[idx] {
                        Ok(int.clone())
                    } else {
                        Err(Error::InvalidStructure(format!(
                            "expected Integer for {}",
                            field_name
                        )))
                    }
                };

                let version: Version = elements[0].decode()?;

                Ok(RSAPrivateKey {
                    version,
                    modulus: get_integer(1, "modulus")?,
                    public_exponent: get_integer(2, "publicExponent")?,
                    private_exponent: get_integer(3, "privateExponent")?,
                    prime1: get_integer(4, "prime1")?,
                    prime2: get_integer(5, "prime2")?,
                    exponent1: get_integer(6, "exponent1")?,
                    exponent2: get_integer(7, "exponent2")?,
                    coefficient: get_integer(8, "coefficient")?,
                })
            }
            _ => Err(Error::InvalidStructure(
                "expected Sequence for RSAPrivateKey".to_string(),
            )),
        }
    }
}

impl EncodableTo<RSAPrivateKey> for Element {}

impl Encoder<RSAPrivateKey, Element> for RSAPrivateKey {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        Ok(Element::Sequence(vec![
            Element::Integer(Integer::from(self.version)),
            Element::Integer(self.modulus.clone()),
            Element::Integer(self.public_exponent.clone()),
            Element::Integer(self.private_exponent.clone()),
            Element::Integer(self.prime1.clone()),
            Element::Integer(self.prime2.clone()),
            Element::Integer(self.exponent1.clone()),
            Element::Integer(self.exponent2.clone()),
            Element::Integer(self.coefficient.clone()),
        ]))
    }
}

impl PrivateKeyExt for RSAPrivateKey {
    fn key_size(&self) -> u32 {
        self.modulus.bits() as u32
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }

    fn public_key_bytes(&self) -> Option<&[u8]> {
        // RSA public key is derived from modulus and public_exponent,
        // not stored as raw bytes. Use public_key() method instead.
        None
    }

    fn public_key(&self) -> Option<PublicKey> {
        Some(PublicKey::Pkcs1(RSAPublicKey {
            modulus: self.modulus.clone(),
            public_exponent: self.public_exponent.clone(),
        }))
    }
}

/*
RFC 8017 - RSA Public Key

RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
*/

/// PKCS#1 RSA Public Key structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RSAPublicKey {
    pub modulus: Integer,         // n
    pub public_exponent: Integer, // e
}

impl DecodableFrom<Element> for RSAPublicKey {}

impl Decoder<Element, RSAPublicKey> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RSAPublicKey> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() != 2 {
                    return Err(Error::InvalidStructure(format!(
                        "expected 2 elements in RSAPublicKey sequence, got {}",
                        elements.len()
                    )));
                }

                let get_integer = |idx: usize, field_name: &str| -> Result<Integer> {
                    if let Element::Integer(int) = &elements[idx] {
                        Ok(int.clone())
                    } else {
                        Err(Error::InvalidStructure(format!(
                            "expected Integer for {}",
                            field_name
                        )))
                    }
                };

                Ok(RSAPublicKey {
                    modulus: get_integer(0, "modulus")?,
                    public_exponent: get_integer(1, "publicExponent")?,
                })
            }
            _ => Err(Error::InvalidStructure(
                "expected Sequence for RSAPublicKey".to_string(),
            )),
        }
    }
}

impl EncodableTo<RSAPublicKey> for Element {}

impl Encoder<RSAPublicKey, Element> for RSAPublicKey {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        Ok(Element::Sequence(vec![
            Element::Integer(self.modulus.clone()),
            Element::Integer(self.public_exponent.clone()),
        ]))
    }
}

// Pem -> RSAPrivateKey decoder
impl DecodableFrom<pem::Pem> for RSAPrivateKey {}

impl Decoder<pem::Pem, RSAPrivateKey> for pem::Pem {
    type Error = Error;

    fn decode(&self) -> Result<RSAPrivateKey> {
        // Decode PEM to DER
        let der: Der = self.decode()?;

        // Decode DER to ASN1Object
        let asn1_obj = der.decode()?;

        // Get first element
        if asn1_obj.elements().is_empty() {
            return Err(Error::InvalidStructure("No elements in ASN1Object".into()));
        }
        let element = &asn1_obj.elements()[0];

        // Decode to RSAPrivateKey
        element.decode()
    }
}

// Pem -> RSAPublicKey decoder
impl DecodableFrom<Pem> for RSAPublicKey {}

impl Decoder<Pem, RSAPublicKey> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<RSAPublicKey> {
        // Decode PEM to DER
        let der: Der = self.decode()?;

        // Decode DER to ASN1Object
        let asn1_obj = der.decode()?;

        // Get first element
        if asn1_obj.elements().is_empty() {
            return Err(Error::InvalidStructure("No elements in ASN1Object".into()));
        }
        let element = &asn1_obj.elements()[0];

        // Decode to RSAPublicKey
        element.decode()
    }
}

impl RSAPublicKey {
    /// Get the key size in bits (RSA modulus bit length)
    pub fn key_size(&self) -> u32 {
        self.modulus.bits() as u32
    }
}

impl PublicKeyExt for RSAPublicKey {
    fn key_size(&self) -> u32 {
        self.modulus.bits() as u32
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }

    fn public_key_bytes(&self) -> Option<&[u8]> {
        // RSA public key is structured (modulus + exponent),
        // not stored as raw bytes. Use the type directly.
        None
    }
}

// RSAPublicKey -> PEM encoder
impl ToPem for RSAPublicKey {
    type Error = Error;

    fn pem_label(&self) -> Label {
        Label::RSAPublicKey
    }

    fn to_pem(&self) -> Result<Pem> {
        // Encode RSAPublicKey to Element
        let element = self.encode()?;

        // Wrap Element in ASN1Object
        let asn1_obj = ASN1Object::new(vec![element]);

        // Encode ASN1Object to DER
        let der = asn1_obj.encode()?;

        // Get DER bytes
        let der_bytes = der.encode()?;

        // Create PEM from DER bytes
        Ok(Pem::from_bytes(self.pem_label(), &der_bytes))
    }
}

// RSAPrivateKey -> PEM encoder
impl ToPem for RSAPrivateKey {
    type Error = Error;

    fn pem_label(&self) -> Label {
        Label::RSAPrivateKey
    }

    fn to_pem(&self) -> Result<Pem> {
        let element = self.encode()?;
        let asn1_obj = ASN1Object::new(vec![element]);
        let der = asn1_obj.encode()?;
        let der_bytes = der.encode()?;
        Ok(Pem::from_bytes(self.pem_label(), &der_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_key::PrivateKeyExt;
    use rstest::rstest;
    use std::str::FromStr;

    // Real RSA keys generated by OpenSSL
    const RSA_2048_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvf4anqhlMYhVhpOv8XK/ygPFUxkNa8Rh9NNTVlqiWuPgD4Lj
7YCsa31kQwYgOKADsG5ROApHSjKsWrKQ70DSpxZmPiO8j7jFQdUJLbe/hfiFskoM
Ur+V5imxrkJB5cnBgIw49ykn0mVtyLRG9RS8Xv+XqNEHFnugS7z2cFQqKYI8oq2L
yLxSbMzDlzkB1p64u5p6Gy0W3KQZt42/sompo+swMslw+XN2rSNFfUWfJWGdEFJc
Sl+9oOz7y9ZGv56uC3VdGnU9u6MmC3iMZ/Vf9qQIHOr6KE6IaJNvHPSAET7qnBWJ
q+x0UrsMJmGdkjGvE3MgIjgaLxjgn/sfO1++vwIDAQABAoIBAEp5BUQ1q9zbnPKw
h2H0Yds02S82fb1FcERAZcVOp59K/XP3EZLyQiOsNhXTm+O2TVvmEi4OUV1zOX4f
ypIN7cSTEia/aVVIzwF8GSnzgb5o6Tc2sVfqQz7CDyTIUf5ZtGDIFjhDyJk/KuZm
S/4bT69JLtB8hvO4J+AoRM1JIHG+Lpe1p+Vsudk3+/AKiyx4tU1Z/zR3Rm9GxUd0
XHZAUhnYumrczJeq9XS9ufvgJUZ0q+qdAuG4PL4+0KAblS+biad0mv32ibkGsiXt
CvcZwIMlzQvt+Ai6Oa9GK6lfgrpYYKwZry6pnzI4/j6db4fnWXcNnkHDir7YjsZK
8QTlfOkCgYEA8cilQsTcF2GRC4CMwGpz/7rZAgjLn7ucscqVhzQIFrZNpMtq2LEL
/QNMa7dayDryr2b4RAcA2ns5WCRRCSslpVcXwrPDyxzhKdmnCTbu8nLTwtuRYzMU
s/Oeex7o37aKwpiNQzfqqGTZy0xMulma//M6mX5D14bN4oVt43zx25UCgYEAySnk
afMoZaLoW3rzDqiq8G3+M8tnFjhs7/r8Bz1BUuOfMjfK8ZFYWLseC8DaiOGLdJl8
4P98R81xZp4KlYMqbLeIM1f/uo3um7a8AiD2ueuW8qe2xB+5vbiNpJU/fruOU+Bk
FAZmaIGk8DdUom7SPktKTREYwiZ4o0BF/On2fAMCgYEAietymcvB4HR/UJhbsccH
tHDZKRfrT4qtr51n/l/n3UzQrZh7snAL7p/bD/bfiihWF0gdhnCYRAjWhTjyINDE
ALTVkPMKVOp8ZmsJpW/4jcSClzy4imWxAZWOaZ0QKczvCmIK8rUK3lPpCNbVTdef
WzFb1AL6oA79kqGaNZIoRKECgYA2HVzi25S8cqyLH3IPOXRypURC7q7WnWtAy4XM
9L+D6tPCkJu5jF310LBufPzM4c/AGCIt7MykDDI7Zrx2KAjboiuzlDKpHtFXdjrx
X6i/rw62TEOwUtCGpwUDh1rDXvUUv0Js2KPn7ShPrrLH14QbWems/bJpWCwPzpSF
SvMRvQKBgQDUNNVtpsS/4GwAmKwmLaHrbCn8oBlWBjpSS8NGbyQfA9ErllMLz3OO
s2qerzz5oOlJm54dGAWRm1e7wTqUdeVOmCCceEvztVUsPfjPUgk7x4pfiFVUaltS
t1uLx7BFNLk8mjqiaognIGpAlEtRJi+LPZQmIOzmPd0eZKAHNozgwQ==
-----END RSA PRIVATE KEY-----"#;

    const RSA_2048_PUBLIC_KEY: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvf4anqhlMYhVhpOv8XK/ygPFUxkNa8Rh9NNTVlqiWuPgD4Lj7YCs
a31kQwYgOKADsG5ROApHSjKsWrKQ70DSpxZmPiO8j7jFQdUJLbe/hfiFskoMUr+V
5imxrkJB5cnBgIw49ykn0mVtyLRG9RS8Xv+XqNEHFnugS7z2cFQqKYI8oq2LyLxS
bMzDlzkB1p64u5p6Gy0W3KQZt42/sompo+swMslw+XN2rSNFfUWfJWGdEFJcSl+9
oOz7y9ZGv56uC3VdGnU9u6MmC3iMZ/Vf9qQIHOr6KE6IaJNvHPSAET7qnBWJq+x0
UrsMJmGdkjGvE3MgIjgaLxjgn/sfO1++vwIDAQAB
-----END RSA PUBLIC KEY-----"#;

    const RSA_1024_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDgvbJ4YpD0/itPGaGVNcXlhi1QuKy58c27sZqCHXZ/eAI7bvuM
hcVKpims2ClJMpg2DKHHmTCXsKg9+ZEjzA0BDuU2Kc9ot762+urWUAHYpqhJgtJx
eIvoYU/Lud82YmJIkIGHxmuisglJfVXR4lGzFwdGH8ga5jFRosGUVtSEcwIDAQAB
AoGBAKKGTKRmk3G4xVUksgeXpY+A4xB3HOIzjZZor9XcvK8d+G9GqT9MFgsP8x9+
Cw1WO2EK7YvMqqloJaL78gwzKkr4gsU4kNN0yUCWxQWKJCw4gx6EmdP9ouGFeKDL
iE0ZSv4qDVMgxIfDdCfXEUlTd+IoODB8fqbsdQjFXBrCKiVhAkEA96Upe9G29s9s
ZNQMF3nCEJHAA0MBLCzAI/XZ1uyzj7RydpzAn66EAvOdCX9fSJ478z50xbULTHYe
k2Rzk6cpywJBAOhSt/n6u/QuO7tiHjKPHnrIDuKXDTcxaSoDWJylWimW0WVrq1gA
pZp2SgexaaP9ZIlPR5OoziOJBf+TZuIy2vkCQGqb0mj4VhCYKOybEH2GsBGb/RIq
ZTXUKf8RFm9cxMwnfWMshgv3/+KZZ1AwYh+L5vkHORPnpW6MJwuCofK9ctMCQQCW
M5y0ptHLvfRqYrZJU9SN5zgQcT5fF7f5LK6moBUZ3GNHIgRmYgyvP5j/Pkmhd5r/
V11cbv/PY7CYGzGiPuTpAkEA3SrmIxFKivp/KGT5rcCdQGq5Fcf5WXfY5wvjMc26
Nr0MSJxgFbkccWwrk0bsm/o788pOUbw8tzDl4xeCZgF0qw==
-----END RSA PRIVATE KEY-----"#;

    const RSA_1024_PUBLIC_KEY: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOC9snhikPT+K08ZoZU1xeWGLVC4rLnxzbuxmoIddn94Ajtu+4yFxUqm
KazYKUkymDYMoceZMJewqD35kSPMDQEO5TYpz2i3vrb66tZQAdimqEmC0nF4i+hh
T8u53zZiYkiQgYfGa6KyCUl9VdHiUbMXB0YfyBrmMVGiwZRW1IRzAgMBAAE=
-----END RSA PUBLIC KEY-----"#;

    const RSA_4096_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"#;

    const RSA_4096_PUBLIC_KEY: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEApkQrXFcqnh7JdPwcZ/EPHymiZxQ3je6SQO4OuUSt/bKPNlb/lRD8
b7N4smmMupe9FQ2/NgzyRzAYU5dzukVMkTtsS/8oiEc7IoLGcVQKOCyXjlcjs1TX
4vFqITPWY9KeU3AWd3E8kcBuoCsvnNRIkPWhjSoHurtmkG6wIVXmcTJC0PjXnmjs
MJ5JF8ZaEjJu38Fx43jrbhrFCWy6CiT+DoZqJqzz3CRfNY7cmKiL07Ku58zXAf3k
8iv6M+YUZQyN2DneXMiEZqx2s6DMILStPOcfRCozpZUKLGX06531FsCT6/iA72Ro
L2ymgSbRL7a6PqHRXxDlgFu6tYabt5ZdjJOcTE5Tb6OC9zTizwDFKAXCyByGA3Ar
GoKqUqcQSWcCGLGIcS/AlhHpXHyPsvlt++i0IWgOD4YamzXa92AbQM5Aclc9uGIm
/HqBCMpHp7SUImXhv4b1zuNj4ks8CZAg09tDMcMxli5tjra1JbkE1STuDvUwqz23
QfdqtekFIjbM2fpRL8xkrSioe2gnXm06dtwJtET4v7O3QUh/F4Fms3cA94cpIfhN
sADszaz5jQs/AywCa9KXWmQddH0r3nt4/DilQN4FapQLDVqdUu6YSPEfaQzWyaSM
EB7VTM4mzawmSqcOq3/aYDSYqcRBlk5lfWc43qcPVNoKZ9x993MFIgkCAwEAAQ==
-----END RSA PUBLIC KEY-----"#;

    #[test]
    fn test_version_conversion() {
        assert_eq!(i64::from(Version::TwoPrime), 0);
        assert_eq!(i64::from(Version::Multi), 1);

        assert_eq!(Version::try_from(0).unwrap(), Version::TwoPrime);
        assert_eq!(Version::try_from(1).unwrap(), Version::Multi);
        assert!(Version::try_from(2).is_err());
    }

    #[test]
    fn test_rsa_public_key_encode_decode() {
        let pubkey = RSAPublicKey {
            modulus: Integer::from(vec![0x00, 0xff, 0xaa]),
            public_exponent: Integer::from(vec![0x01, 0x00, 0x01]), // 65537
        };

        let encoded: Element = pubkey.encode().unwrap();
        let decoded: RSAPublicKey = encoded.decode().unwrap();

        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn test_rsa_private_key_encode_decode() {
        // Minimal test RSA private key (not a real key, just for structure testing)
        let privkey = RSAPrivateKey {
            version: Version::TwoPrime,
            modulus: Integer::from(vec![0x00, 0xff]),
            public_exponent: Integer::from(vec![0x01, 0x00, 0x01]),
            private_exponent: Integer::from(vec![0x00, 0xaa]),
            prime1: Integer::from(vec![0x00, 0x0b]),
            prime2: Integer::from(vec![0x00, 0x0d]),
            exponent1: Integer::from(vec![0x00, 0x05]),
            exponent2: Integer::from(vec![0x00, 0x07]),
            coefficient: Integer::from(vec![0x00, 0x03]),
        };

        let encoded = privkey.encode().unwrap();
        let decoded: RSAPrivateKey = encoded.decode().unwrap();

        assert_eq!(decoded.version, privkey.version);
        assert_eq!(decoded.modulus, privkey.modulus);
        assert_eq!(decoded.public_exponent, privkey.public_exponent);
    }

    #[rstest]
    #[case(RSA_1024_PUBLIC_KEY)]
    #[case(RSA_2048_PUBLIC_KEY)]
    #[case(RSA_4096_PUBLIC_KEY)]
    fn test_real_rsa_public_key_decode_encode(#[case] pem_str: &str) {
        // Decode PEM
        let pem = pem::Pem::from_str(pem_str).expect("Failed to parse PEM");
        assert_eq!(pem.label(), pem::Label::RSAPublicKey);

        // Decode PEM to DER
        let der: der::Der = pem.decode().expect("Failed to decode PEM to DER");

        // Decode DER to ASN1Object
        let asn1_obj: asn1::ASN1Object = der.decode().expect("Failed to decode DER to ASN1Object");

        // Get Element from ASN1Object (first element)
        assert!(
            !asn1_obj.elements().is_empty(),
            "ASN1Object should have at least one element"
        );
        let element = &asn1_obj.elements()[0];

        // Decode Element to RSAPublicKey
        let pubkey: RSAPublicKey = element.decode().expect("Failed to decode RSAPublicKey");

        // Verify it has expected structure
        assert!(pubkey.modulus.to_u64().is_none()); // Should be too large for u64
        assert!(pubkey.public_exponent.to_u64().is_some()); // Should fit in u64 (typically 65537)

        // Encode back to Element
        let encoded_element = pubkey.encode().expect("Failed to encode RSAPublicKey");

        // Decode again and compare
        let decoded_again: RSAPublicKey = encoded_element
            .decode()
            .expect("Failed to decode encoded RSAPublicKey");
        assert_eq!(decoded_again, pubkey);
    }

    #[rstest]
    #[case(RSA_1024_PRIVATE_KEY, 1024)]
    #[case(RSA_2048_PRIVATE_KEY, 2048)]
    #[case(RSA_4096_PRIVATE_KEY, 4096)]
    fn test_rsa_private_key_size(#[case] pem_str: &str, #[case] expected_bits: u32) {
        let pem = pem::Pem::from_str(pem_str).expect("Failed to parse PEM");
        let privkey: RSAPrivateKey = pem.decode().expect("Failed to decode RSAPrivateKey");
        assert_eq!(privkey.key_size(), expected_bits);
    }

    #[rstest]
    #[case(RSA_1024_PRIVATE_KEY, 1024)]
    #[case(RSA_2048_PRIVATE_KEY, 2048)]
    #[case(RSA_4096_PRIVATE_KEY, 4096)]
    fn test_rsa_public_key_size(#[case] pem_str: &str, #[case] expected_bits: u32) {
        let pem = pem::Pem::from_str(pem_str).expect("Failed to parse PEM");
        let privkey: RSAPrivateKey = pem.decode().expect("Failed to decode RSAPrivateKey");
        let pubkey = privkey.public_key().expect("Failed to get public key");
        assert_eq!(pubkey.key_size(), expected_bits);
    }

    #[rstest]
    #[case(RSA_1024_PRIVATE_KEY)]
    #[case(RSA_2048_PRIVATE_KEY)]
    #[case(RSA_4096_PRIVATE_KEY)]
    fn test_real_rsa_private_key_decode_encode(#[case] pem_str: &str) {
        // Decode PEM
        let pem = pem::Pem::from_str(pem_str).expect("Failed to parse PEM");
        assert_eq!(pem.label(), pem::Label::RSAPrivateKey);

        // Decode PEM to DER
        let der: der::Der = pem.decode().expect("Failed to decode PEM to DER");

        // Decode DER to ASN1Object
        let asn1_obj: asn1::ASN1Object = der.decode().expect("Failed to decode DER to ASN1Object");

        // Get Element from ASN1Object (first element)
        assert!(
            !asn1_obj.elements().is_empty(),
            "ASN1Object should have at least one element"
        );
        let element = &asn1_obj.elements()[0];

        // Decode Element to RSAPrivateKey
        let privkey: RSAPrivateKey = element.decode().expect("Failed to decode RSAPrivateKey");

        // Verify it has expected structure
        assert_eq!(privkey.version, Version::TwoPrime);
        assert!(privkey.modulus.to_u64().is_none()); // Should be too large for u64
        assert!(privkey.public_exponent.to_u64().is_some()); // Typically 65537

        // Encode back to Element
        let encoded_element = privkey.encode().expect("Failed to encode RSAPrivateKey");

        // Encode Element to ASN1Object and then to DER
        let encoded_asn1 = asn1::ASN1Object::new(vec![encoded_element]);
        let encoded_der: der::Der = encoded_asn1
            .encode()
            .expect("Failed to encode ASN1Object to Der");

        // Decode back and compare
        let decoded_asn1: asn1::ASN1Object = encoded_der
            .decode()
            .expect("Failed to decode Der to ASN1Object");
        assert!(
            !decoded_asn1.elements().is_empty(),
            "Decoded ASN1Object should have at least one element"
        );
        let decoded_element = &decoded_asn1.elements()[0];
        let reencoded_privkey: RSAPrivateKey = decoded_element
            .decode()
            .expect("Failed to decode RSAPrivateKey");

        assert_eq!(privkey.version, reencoded_privkey.version);
        assert_eq!(privkey.modulus, reencoded_privkey.modulus);
        assert_eq!(privkey.public_exponent, reencoded_privkey.public_exponent);
        assert_eq!(privkey.private_exponent, reencoded_privkey.private_exponent);
        assert_eq!(privkey.prime1, reencoded_privkey.prime1);
        assert_eq!(privkey.prime2, reencoded_privkey.prime2);
        assert_eq!(privkey.exponent1, reencoded_privkey.exponent1);
        assert_eq!(privkey.exponent2, reencoded_privkey.exponent2);
        assert_eq!(privkey.coefficient, reencoded_privkey.coefficient);
    }
}
