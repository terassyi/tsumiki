//! Unified private key type supporting multiple formats.
//!
//! This module provides [`PrivateKey`], an enum that can represent private keys
//! in any of the common formats:
//! - PKCS#1 (RSA keys only)
//! - SEC1 (EC keys only)
//! - PKCS#8 (generic format for any key type)
//!
//! The primary use case is automatic format detection when loading keys from
//! DER or PEM data.

use asn1::{ASN1Object, Element};
use der::Der;
use pem::{Label, Pem};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::{Error, Result};
use crate::pkcs1::RSAPrivateKey;
use crate::pkcs8::OneAsymmetricKey;
use crate::sec1::ECPrivateKey;

/// A private key in one of the supported formats.
///
/// This enum allows handling private keys without knowing their exact format
/// ahead of time. Use [`PrivateKey::from_der`] or the `Decoder` implementation
/// for `Pem` to automatically detect the format.
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// PKCS#1 RSA private key (RSA keys only)
    Pkcs1(RSAPrivateKey),
    /// SEC1 EC private key (elliptic curve keys only)
    Sec1(ECPrivateKey),
    /// PKCS#8 private key (generic format)
    Pkcs8(OneAsymmetricKey),
}

impl PrivateKey {
    /// Attempt to parse a private key from DER-encoded bytes.
    ///
    /// This method tries each format in order:
    /// 1. PKCS#8 (most common for modern keys)
    /// 2. SEC1 (EC keys)
    /// 3. PKCS#1 (RSA keys)
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be parsed as any known format.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let der: Der = bytes.to_vec().decode()?;
        let asn1_obj: ASN1Object = der.decode()?;

        let element = asn1_obj.elements().first().ok_or(Error::EmptyAsn1Object)?;

        element.decode()
    }

    /// Get the key size in bits.
    pub fn key_size(&self) -> u32 {
        match self {
            PrivateKey::Pkcs1(key) => key.key_size(),
            PrivateKey::Sec1(key) => key.key_size(),
            PrivateKey::Pkcs8(key) => key.key_size(),
        }
    }

    /// Returns `true` if this is a PKCS#1 RSA key.
    pub fn is_pkcs1(&self) -> bool {
        matches!(self, PrivateKey::Pkcs1(_))
    }

    /// Returns `true` if this is a SEC1 EC key.
    pub fn is_sec1(&self) -> bool {
        matches!(self, PrivateKey::Sec1(_))
    }

    /// Returns `true` if this is a PKCS#8 key.
    pub fn is_pkcs8(&self) -> bool {
        matches!(self, PrivateKey::Pkcs8(_))
    }

    /// Try to get the inner PKCS#1 RSA key.
    pub fn as_pkcs1(&self) -> Option<&RSAPrivateKey> {
        match self {
            PrivateKey::Pkcs1(key) => Some(key),
            _ => None,
        }
    }

    /// Try to get the inner SEC1 EC key.
    pub fn as_sec1(&self) -> Option<&ECPrivateKey> {
        match self {
            PrivateKey::Sec1(key) => Some(key),
            _ => None,
        }
    }

    /// Try to get the inner PKCS#8 key.
    pub fn as_pkcs8(&self) -> Option<&OneAsymmetricKey> {
        match self {
            PrivateKey::Pkcs8(key) => Some(key),
            _ => None,
        }
    }

    /// Consume and return the inner PKCS#1 RSA key.
    pub fn into_pkcs1(self) -> Option<RSAPrivateKey> {
        match self {
            PrivateKey::Pkcs1(key) => Some(key),
            _ => None,
        }
    }

    /// Consume and return the inner SEC1 EC key.
    pub fn into_sec1(self) -> Option<ECPrivateKey> {
        match self {
            PrivateKey::Sec1(key) => Some(key),
            _ => None,
        }
    }

    /// Consume and return the inner PKCS#8 key.
    pub fn into_pkcs8(self) -> Option<OneAsymmetricKey> {
        match self {
            PrivateKey::Pkcs8(key) => Some(key),
            _ => None,
        }
    }
}

// Element -> PrivateKey decoder
impl DecodableFrom<Element> for PrivateKey {}

impl Decoder<Element, PrivateKey> for Element {
    type Error = Error;

    /// Attempt to parse a private key from an ASN.1 element.
    ///
    /// This method tries each format in order:
    /// 1. PKCS#8 (most common for modern keys)
    /// 2. SEC1 (EC keys)
    /// 3. PKCS#1 (RSA keys)
    fn decode(&self) -> Result<PrivateKey> {
        // Try PKCS#8 first (most common modern format)
        let pkcs8_err = match self.decode() {
            Ok(key) => return Ok(PrivateKey::Pkcs8(key)),
            Err(e) => e,
        };

        // Try SEC1 (EC private key)
        let sec1_err = match self.decode() {
            Ok(key) => return Ok(PrivateKey::Sec1(key)),
            Err(e) => e,
        };

        // Try PKCS#1 (RSA private key)
        let pkcs1_err = match self.decode() {
            Ok(key) => return Ok(PrivateKey::Pkcs1(key)),
            Err(e) => e,
        };

        Err(Error::UnrecognizedPrivateKeyFormat {
            pkcs8: Box::new(pkcs8_err),
            sec1: Box::new(sec1_err),
            pkcs1: Box::new(pkcs1_err),
        })
    }
}

// Pem -> PrivateKey decoder
impl DecodableFrom<Pem> for PrivateKey {}

impl Decoder<Pem, PrivateKey> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<PrivateKey> {
        // Use label to determine format when available
        match self.label() {
            Label::RSAPrivateKey => Ok(PrivateKey::Pkcs1(self.decode()?)),
            Label::ECPrivateKey => Ok(PrivateKey::Sec1(self.decode()?)),
            Label::PrivateKey => Ok(PrivateKey::Pkcs8(self.decode()?)),
            _ => {
                // Try to auto-detect from content
                let der: Der = self.decode()?;
                let asn1_obj: ASN1Object = der.decode()?;

                let element = asn1_obj.elements().first().ok_or(Error::EmptyAsn1Object)?;

                element.decode()
            }
        }
    }
}

impl From<RSAPrivateKey> for PrivateKey {
    fn from(key: RSAPrivateKey) -> Self {
        PrivateKey::Pkcs1(key)
    }
}

impl From<ECPrivateKey> for PrivateKey {
    fn from(key: ECPrivateKey) -> Self {
        PrivateKey::Sec1(key)
    }
}

impl From<OneAsymmetricKey> for PrivateKey {
    fn from(key: OneAsymmetricKey) -> Self {
        PrivateKey::Pkcs8(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    const RSA_2048_PKCS1: &str = r#"-----BEGIN RSA PRIVATE KEY-----
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

    // P-256 (prime256v1) EC private key
    const EC_P256_SEC1: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIfdTjEBvN2/AupnhPeL8585jLgieLQmi4SfX/FVrTxZoAoGCCqGSM49
AwEHoUQDQgAEmvfw1VdwIlsJHfbHLhHXrO3Wq/0LBCduo6Nb96AiLGUxkn/OWt1I
9STYYNw8e/Xuzsy9j5joSxQDwmCWSGPGWw==
-----END EC PRIVATE KEY-----"#;

    const RSA_2048_PKCS8: &str = r#"-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----"#;

    #[rstest]
    #[case(RSA_2048_PKCS1, true, false, false, Some(2048))]
    #[case(EC_P256_SEC1, false, true, false, Some(256))]
    // PKCS#8 v1 keys don't have public key, so key_size returns 0
    #[case(RSA_2048_PKCS8, false, false, true, None)]
    fn test_private_key_from_pem(
        #[case] pem_str: &str,
        #[case] is_pkcs1: bool,
        #[case] is_sec1: bool,
        #[case] is_pkcs8: bool,
        #[case] expected_bits: Option<u32>,
    ) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let key: PrivateKey = pem.decode().expect("Failed to decode PrivateKey");

        assert_eq!(key.is_pkcs1(), is_pkcs1);
        assert_eq!(key.is_sec1(), is_sec1);
        assert_eq!(key.is_pkcs8(), is_pkcs8);
        if let Some(expected) = expected_bits {
            assert_eq!(key.key_size(), expected);
        }
    }

    #[test]
    fn test_private_key_accessors() {
        let pem = Pem::from_str(RSA_2048_PKCS1).expect("Failed to parse PEM");
        let key: PrivateKey = pem.decode().expect("Failed to decode PrivateKey");

        assert!(key.as_pkcs1().is_some());
        assert!(key.as_sec1().is_none());
        assert!(key.as_pkcs8().is_none());

        let inner = key.into_pkcs1();
        assert!(inner.is_some());
    }

    #[derive(Debug, Clone, Copy)]
    enum KeyFormat {
        Pkcs1,
        Sec1,
        Pkcs8,
    }

    #[rstest]
    #[case::pkcs1(RSA_2048_PKCS1, KeyFormat::Pkcs1)]
    #[case::sec1(EC_P256_SEC1, KeyFormat::Sec1)]
    #[case::pkcs8(RSA_2048_PKCS8, KeyFormat::Pkcs8)]
    fn test_from_conversions(#[case] pem_str: &str, #[case] format: KeyFormat) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");

        let key = match format {
            KeyFormat::Pkcs1 => {
                let rsa_key: RSAPrivateKey = pem.decode().expect("Failed to decode RSAPrivateKey");
                PrivateKey::from(rsa_key)
            }
            KeyFormat::Sec1 => {
                let ec_key: ECPrivateKey = pem.decode().expect("Failed to decode ECPrivateKey");
                PrivateKey::from(ec_key)
            }
            KeyFormat::Pkcs8 => {
                let pkcs8_key: OneAsymmetricKey =
                    pem.decode().expect("Failed to decode OneAsymmetricKey");
                PrivateKey::from(pkcs8_key)
            }
        };

        match format {
            KeyFormat::Pkcs1 => assert!(key.is_pkcs1()),
            KeyFormat::Sec1 => assert!(key.is_sec1()),
            KeyFormat::Pkcs8 => assert!(key.is_pkcs8()),
        }
    }
}
