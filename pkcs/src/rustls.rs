//! Conversion between rustls-pki-types and tsumiki pkcs types.
//!
//! This module is only compiled when the `rustls` feature is enabled.

use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;
use tsumiki_asn1::{ASN1Object, Element};

use crate::error::{Error, Result};
use crate::pkcs1::{self, RSAPrivateKey};
use crate::pkcs8::{self, OneAsymmetricKey};
use crate::private_key::PrivateKey;
use crate::sec1::{self, ECPrivateKey};

// ============================================================================
// Helper functions for common conversion patterns
// ============================================================================

/// Decodes DER bytes into an ASN.1 element.
fn decode_der_to_element(der_bytes: &[u8]) -> Result<Element> {
    let der = der_bytes.decode()?;
    let asn1_obj = der.decode()?;
    asn1_obj
        .elements()
        .first()
        .cloned()
        .ok_or(Error::Sec1(sec1::Error::EmptyAsn1Object))
}

/// Encodes an ASN.1 element into DER bytes.
fn encode_element_to_der(element: Element) -> Result<Vec<u8>> {
    let asn1_obj = ASN1Object::new(vec![element]);
    let der = asn1_obj.encode()?;
    Ok(der.encode()?)
}

// ============================================================================
// PKCS#1 RSAPrivateKey <-> PrivatePkcs1KeyDer
// ============================================================================

/// Converts a `PrivatePkcs1KeyDer` to an `RSAPrivateKey`.
impl TryFrom<PrivatePkcs1KeyDer<'_>> for RSAPrivateKey {
    type Error = Error;

    fn try_from(key_der: PrivatePkcs1KeyDer<'_>) -> Result<Self> {
        let element = decode_der_to_element(key_der.secret_pkcs1_der())?;
        element.decode().map_err(Error::Pkcs1)
    }
}

/// Converts an `RSAPrivateKey` to a `PrivatePkcs1KeyDer<'static>`.
impl TryFrom<&RSAPrivateKey> for PrivatePkcs1KeyDer<'static> {
    type Error = Error;

    fn try_from(key: &RSAPrivateKey) -> Result<Self> {
        let element = key.encode().map_err(Error::Pkcs1)?;
        let bytes = encode_element_to_der(element)?;
        Ok(PrivatePkcs1KeyDer::from(bytes))
    }
}

/// Converts an `RSAPrivateKey` to a `PrivatePkcs1KeyDer<'static>`.
impl TryFrom<RSAPrivateKey> for PrivatePkcs1KeyDer<'static> {
    type Error = Error;

    fn try_from(key: RSAPrivateKey) -> Result<Self> {
        PrivatePkcs1KeyDer::try_from(&key)
    }
}

// ============================================================================
// SEC1 ECPrivateKey <-> PrivateSec1KeyDer
// ============================================================================

/// Converts a `PrivateSec1KeyDer` to an `ECPrivateKey`.
impl TryFrom<PrivateSec1KeyDer<'_>> for ECPrivateKey {
    type Error = Error;

    fn try_from(key_der: PrivateSec1KeyDer<'_>) -> Result<Self> {
        let element = decode_der_to_element(key_der.secret_sec1_der())?;
        element.decode().map_err(Error::Sec1)
    }
}

/// Converts an `ECPrivateKey` to a `PrivateSec1KeyDer<'static>`.
impl TryFrom<&ECPrivateKey> for PrivateSec1KeyDer<'static> {
    type Error = Error;

    fn try_from(key: &ECPrivateKey) -> Result<Self> {
        let element = key.encode().map_err(Error::Sec1)?;
        let bytes = encode_element_to_der(element)?;
        Ok(PrivateSec1KeyDer::from(bytes))
    }
}

/// Converts an `ECPrivateKey` to a `PrivateSec1KeyDer<'static>`.
impl TryFrom<ECPrivateKey> for PrivateSec1KeyDer<'static> {
    type Error = Error;

    fn try_from(key: ECPrivateKey) -> Result<Self> {
        PrivateSec1KeyDer::try_from(&key)
    }
}

// ============================================================================
// PKCS#8 OneAsymmetricKey <-> PrivatePkcs8KeyDer
// ============================================================================

/// Converts a `PrivatePkcs8KeyDer` to an `OneAsymmetricKey`.
impl TryFrom<PrivatePkcs8KeyDer<'_>> for OneAsymmetricKey {
    type Error = Error;

    fn try_from(key_der: PrivatePkcs8KeyDer<'_>) -> Result<Self> {
        let element = decode_der_to_element(key_der.secret_pkcs8_der())?;
        element.decode().map_err(Error::Pkcs8)
    }
}

/// Converts an `OneAsymmetricKey` to a `PrivatePkcs8KeyDer<'static>`.
impl TryFrom<&OneAsymmetricKey> for PrivatePkcs8KeyDer<'static> {
    type Error = Error;

    fn try_from(key: &OneAsymmetricKey) -> Result<Self> {
        let element = key.encode().map_err(Error::Pkcs8)?;
        let bytes = encode_element_to_der(element)?;
        Ok(PrivatePkcs8KeyDer::from(bytes))
    }
}

/// Converts an `OneAsymmetricKey` to a `PrivatePkcs8KeyDer<'static>`.
impl TryFrom<OneAsymmetricKey> for PrivatePkcs8KeyDer<'static> {
    type Error = Error;

    fn try_from(key: OneAsymmetricKey) -> Result<Self> {
        PrivatePkcs8KeyDer::try_from(&key)
    }
}

// ============================================================================
// PrivateKeyDer enum conversions
// ============================================================================

/// Converts a `PrivateKeyDer` to an `RSAPrivateKey`.
/// Only succeeds if the inner key is PKCS#1 format.
impl TryFrom<PrivateKeyDer<'_>> for RSAPrivateKey {
    type Error = Error;

    fn try_from(key_der: PrivateKeyDer<'_>) -> Result<Self> {
        match key_der {
            PrivateKeyDer::Pkcs1(pkcs1) => RSAPrivateKey::try_from(pkcs1),
            _ => Err(Error::Pkcs1(pkcs1::Error::UnexpectedKeyFormat {
                expected: "PKCS#1",
            })),
        }
    }
}

/// Converts a `PrivateKeyDer` to an `ECPrivateKey`.
/// Only succeeds if the inner key is SEC1 format.
impl TryFrom<PrivateKeyDer<'_>> for ECPrivateKey {
    type Error = Error;

    fn try_from(key_der: PrivateKeyDer<'_>) -> Result<Self> {
        match key_der {
            PrivateKeyDer::Sec1(sec1) => ECPrivateKey::try_from(sec1),
            _ => Err(Error::Sec1(sec1::Error::ExpectedSequence)),
        }
    }
}

/// Converts a `PrivateKeyDer` to an `OneAsymmetricKey`.
/// Only succeeds if the inner key is PKCS#8 format.
impl TryFrom<PrivateKeyDer<'_>> for OneAsymmetricKey {
    type Error = Error;

    fn try_from(key_der: PrivateKeyDer<'_>) -> Result<Self> {
        match key_der {
            PrivateKeyDer::Pkcs8(pkcs8) => OneAsymmetricKey::try_from(pkcs8),
            _ => Err(Error::Pkcs8(pkcs8::Error::UnexpectedKeyFormat {
                expected: "PKCS#8",
            })),
        }
    }
}

// ============================================================================
// PrivateKey <-> PrivateKeyDer
// ============================================================================

/// Converts a `PrivateKeyDer` to a `PrivateKey`.
/// Automatically detects the format from the enum variant.
impl TryFrom<PrivateKeyDer<'_>> for PrivateKey {
    type Error = Error;

    fn try_from(key_der: PrivateKeyDer<'_>) -> Result<Self> {
        match key_der {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                let key = RSAPrivateKey::try_from(pkcs1)?;
                Ok(PrivateKey::Pkcs1(key))
            }
            PrivateKeyDer::Sec1(sec1) => {
                let key = ECPrivateKey::try_from(sec1)?;
                Ok(PrivateKey::Sec1(key))
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                let key = OneAsymmetricKey::try_from(pkcs8)?;
                Ok(PrivateKey::Pkcs8(key))
            }
            _ => Err(Error::Pkcs8(pkcs8::Error::UnexpectedKeyFormat {
                expected: "PKCS#1, SEC1, or PKCS#8",
            })),
        }
    }
}

/// Converts a `PrivateKey` to a `PrivateKeyDer<'static>`.
/// The output format matches the input format.
impl TryFrom<&PrivateKey> for PrivateKeyDer<'static> {
    type Error = Error;

    fn try_from(key: &PrivateKey) -> Result<Self> {
        match key {
            PrivateKey::Pkcs1(rsa) => {
                let der = PrivatePkcs1KeyDer::try_from(rsa)?;
                Ok(PrivateKeyDer::Pkcs1(der))
            }
            PrivateKey::Sec1(ec) => {
                let der = PrivateSec1KeyDer::try_from(ec)?;
                Ok(PrivateKeyDer::Sec1(der))
            }
            PrivateKey::Pkcs8(pkcs8) => {
                let der = PrivatePkcs8KeyDer::try_from(pkcs8)?;
                Ok(PrivateKeyDer::Pkcs8(der))
            }
        }
    }
}

/// Converts a `PrivateKey` to a `PrivateKeyDer<'static>`.
impl TryFrom<PrivateKey> for PrivateKeyDer<'static> {
    type Error = Error;

    fn try_from(key: PrivateKey) -> Result<Self> {
        PrivateKeyDer::try_from(&key)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;
    use tsumiki::decoder::Decoder;
    use tsumiki_pem::Pem;

    use super::*;
    use crate::private_key::PrivateKeyExt;

    #[derive(Debug, Clone, Copy)]
    enum KeyType {
        Pkcs1,
        Sec1,
        Pkcs8,
    }

    #[derive(Debug, Clone, Copy)]
    enum TargetType {
        Rsa,
        Ec,
        Pkcs8,
    }

    // PKCS#1 RSA private keys
    const RSA_1024_PKCS1_PEM: &str = r"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

    const RSA_2048_PKCS1_PEM: &str = r"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

    // SEC1 EC private keys
    const EC_P256_SEC1_PEM: &str = r"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIfdTjEBvN2/AupnhPeL8585jLgieLQmi4SfX/FVrTxZoAoGCCqGSM49
AwEHoUQDQgAEmvfw1VdwIlsJHfbHLhHXrO3Wq/0LBCduo6Nb96AiLGUxkn/OWt1I
9STYYNw8e/Xuzsy9j5joSxQDwmCWSGPGWw==
-----END EC PRIVATE KEY-----";

    const EC_P384_SEC1_PEM: &str = r"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCp+QQ1ic50MPNim8hemZ9853kE4ReucQLxVQnHLJ+B4Ejh552giISF
F8erNZqcuE+gBwYFK4EEACKhZANiAASms4UAIsjkkf567S2I5bvU2ELxXLFmcuBb
AgMjE74B7/b0jJEhqaszvV6jQsVKB2jevdyMED4KHm+rgRbRDfrtplf17rVHmesK
F4DFsVCxm1UW3yMaWOubErA/RlKdqsA=
-----END EC PRIVATE KEY-----";

    // PKCS#8 private keys
    const RSA_PKCS8_PEM: &str = r"-----BEGIN PRIVATE KEY-----
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

    const EC_PKCS8_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh91OMQG83b8C6meE
94vznzmMuCJ4tCaLhJ9f8VWtPFmhRANCAAT5GBhOCq01zvZhrnbaJ6T/hFTN4QdE
D/mxYwPGfvOaoea8yxi7iXp8fM29MtiTHu/KdyWATVdPufYQvMw1M2OG
-----END PRIVATE KEY-----";

    /// Test RSAPrivateKey -> PrivatePkcs1KeyDer -> RSAPrivateKey roundtrip
    /// Verifies that RSA key fields are preserved after encoding and decoding
    #[rstest]
    #[case::rsa_1024(RSA_1024_PKCS1_PEM, 1024)]
    #[case::rsa_2048(RSA_2048_PKCS1_PEM, 2048)]
    fn test_rsa_private_key_to_pkcs1_der_to_rsa_private_key(
        #[case] pem_str: &str,
        #[case] expected_key_size: u32,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let rsa_key: RSAPrivateKey = pem.decode().unwrap();
        assert_eq!(rsa_key.key_size(), expected_key_size);

        // RSAPrivateKey -> PrivatePkcs1KeyDer
        let pkcs1_der = PrivatePkcs1KeyDer::try_from(&rsa_key).unwrap();
        assert!(!pkcs1_der.secret_pkcs1_der().is_empty());

        // PrivatePkcs1KeyDer -> RSAPrivateKey
        let rsa_key_back = RSAPrivateKey::try_from(pkcs1_der).unwrap();
        assert_eq!(rsa_key.version, rsa_key_back.version);
        assert_eq!(rsa_key.modulus, rsa_key_back.modulus);
        assert_eq!(rsa_key.public_exponent, rsa_key_back.public_exponent);
    }

    /// Test PrivatePkcs1KeyDer -> RSAPrivateKey -> PrivatePkcs1KeyDer roundtrip
    /// Verifies that DER bytes are preserved after decoding and re-encoding
    #[rstest]
    #[case::rsa_1024(RSA_1024_PKCS1_PEM)]
    #[case::rsa_2048(RSA_2048_PKCS1_PEM)]
    fn test_pkcs1_der_to_rsa_private_key_to_pkcs1_der(#[case] pem_str: &str) {
        let pem = Pem::from_str(pem_str).unwrap();
        let original_der_bytes: Vec<u8> = pem.decode().unwrap();
        let pkcs1_der = PrivatePkcs1KeyDer::from(original_der_bytes.clone());

        // PrivatePkcs1KeyDer -> RSAPrivateKey -> PrivatePkcs1KeyDer
        let rsa_key = RSAPrivateKey::try_from(pkcs1_der).unwrap();
        let roundtrip_der = PrivatePkcs1KeyDer::try_from(&rsa_key).unwrap();

        assert_eq!(original_der_bytes, roundtrip_der.secret_pkcs1_der());
    }

    /// Test ECPrivateKey -> PrivateSec1KeyDer -> ECPrivateKey roundtrip
    /// Verifies that EC key fields are preserved after encoding and decoding
    #[rstest]
    #[case::ec_p256(EC_P256_SEC1_PEM, 256)]
    #[case::ec_p384(EC_P384_SEC1_PEM, 384)]
    fn test_ec_private_key_to_sec1_der_to_ec_private_key(
        #[case] pem_str: &str,
        #[case] expected_key_size: u32,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let ec_key: ECPrivateKey = pem.decode().unwrap();
        assert_eq!(ec_key.key_size(), expected_key_size);

        // ECPrivateKey -> PrivateSec1KeyDer
        let sec1_der = PrivateSec1KeyDer::try_from(&ec_key).unwrap();
        assert!(!sec1_der.secret_sec1_der().is_empty());

        // PrivateSec1KeyDer -> ECPrivateKey
        let ec_key_back = ECPrivateKey::try_from(sec1_der).unwrap();
        assert_eq!(ec_key.version, ec_key_back.version);
        assert_eq!(ec_key.private_key, ec_key_back.private_key);
        assert_eq!(ec_key.parameters, ec_key_back.parameters);
    }

    /// Test PrivateSec1KeyDer -> ECPrivateKey -> PrivateSec1KeyDer roundtrip
    /// Verifies that DER bytes are preserved after decoding and re-encoding
    #[rstest]
    #[case::ec_p256(EC_P256_SEC1_PEM)]
    #[case::ec_p384(EC_P384_SEC1_PEM)]
    fn test_sec1_der_to_ec_private_key_to_sec1_der(#[case] pem_str: &str) {
        let pem = Pem::from_str(pem_str).unwrap();
        let original_der_bytes: Vec<u8> = pem.decode().unwrap();
        let sec1_der = PrivateSec1KeyDer::from(original_der_bytes.clone());

        // PrivateSec1KeyDer -> ECPrivateKey -> PrivateSec1KeyDer
        let ec_key = ECPrivateKey::try_from(sec1_der).unwrap();
        let roundtrip_der = PrivateSec1KeyDer::try_from(&ec_key).unwrap();

        assert_eq!(original_der_bytes, roundtrip_der.secret_sec1_der());
    }

    /// Test OneAsymmetricKey -> PrivatePkcs8KeyDer -> OneAsymmetricKey roundtrip
    /// Verifies that PKCS#8 key fields are preserved after encoding and decoding
    #[rstest]
    #[case::rsa(RSA_PKCS8_PEM, "1.2.840.113549.1.1.1")]
    #[case::ec(EC_PKCS8_PEM, "1.2.840.10045.2.1")]
    fn test_one_asymmetric_key_to_pkcs8_der_to_one_asymmetric_key(
        #[case] pem_str: &str,
        #[case] expected_algorithm_oid: &str,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let key: OneAsymmetricKey = pem.decode().unwrap();
        assert_eq!(
            key.private_key_algorithm.algorithm.to_string(),
            expected_algorithm_oid
        );

        // OneAsymmetricKey -> PrivatePkcs8KeyDer
        let pkcs8_der = PrivatePkcs8KeyDer::try_from(&key).unwrap();
        assert!(!pkcs8_der.secret_pkcs8_der().is_empty());

        // PrivatePkcs8KeyDer -> OneAsymmetricKey
        let key_back = OneAsymmetricKey::try_from(pkcs8_der).unwrap();
        assert_eq!(key.version, key_back.version);
        assert_eq!(
            key.private_key_algorithm.algorithm,
            key_back.private_key_algorithm.algorithm
        );
        assert_eq!(key.private_key, key_back.private_key);
    }

    /// Test PrivatePkcs8KeyDer -> OneAsymmetricKey -> PrivatePkcs8KeyDer roundtrip
    /// Verifies that DER bytes are preserved after decoding and re-encoding
    #[rstest]
    #[case::rsa(RSA_PKCS8_PEM)]
    #[case::ec(EC_PKCS8_PEM)]
    fn test_pkcs8_der_to_one_asymmetric_key_to_pkcs8_der(#[case] pem_str: &str) {
        let pem = Pem::from_str(pem_str).unwrap();
        let original_der_bytes: Vec<u8> = pem.decode().unwrap();
        let pkcs8_der = PrivatePkcs8KeyDer::from(original_der_bytes.clone());

        // PrivatePkcs8KeyDer -> OneAsymmetricKey -> PrivatePkcs8KeyDer
        let key = OneAsymmetricKey::try_from(pkcs8_der).unwrap();
        let roundtrip_der = PrivatePkcs8KeyDer::try_from(&key).unwrap();

        assert_eq!(original_der_bytes, roundtrip_der.secret_pkcs8_der());
    }

    /// Test PrivateKeyDer enum conversion to specific key types
    /// Verifies that PrivateKeyDer can be correctly converted to the corresponding key type
    #[rstest]
    #[case::pkcs1_to_rsa(RSA_2048_PKCS1_PEM, KeyType::Pkcs1, 2048)]
    #[case::sec1_to_ec(EC_P256_SEC1_PEM, KeyType::Sec1, 256)]
    #[case::pkcs8_rsa(RSA_PKCS8_PEM, KeyType::Pkcs8, 0)]
    fn test_private_key_der_to_specific_type(
        #[case] pem_str: &str,
        #[case] key_type: KeyType,
        #[case] expected_key_size: u32,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let der_bytes: Vec<u8> = pem.decode().unwrap();

        match key_type {
            KeyType::Pkcs1 => {
                let private_key_der = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der_bytes));
                let rsa_key = RSAPrivateKey::try_from(private_key_der).unwrap();
                assert_eq!(rsa_key.key_size(), expected_key_size);
            }
            KeyType::Sec1 => {
                let private_key_der = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der_bytes));
                let ec_key = ECPrivateKey::try_from(private_key_der).unwrap();
                assert_eq!(ec_key.key_size(), expected_key_size);
            }
            KeyType::Pkcs8 => {
                let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_bytes));
                let key = OneAsymmetricKey::try_from(private_key_der).unwrap();
                assert_eq!(
                    key.private_key_algorithm.algorithm.to_string(),
                    "1.2.840.113549.1.1.1"
                );
            }
        }
    }

    /// Test error case: wrong PrivateKeyDer variant cannot convert to target type
    /// Verifies that type mismatch errors are properly returned
    #[rstest]
    #[case::sec1_to_rsa(EC_P256_SEC1_PEM, KeyType::Sec1, TargetType::Rsa)]
    #[case::pkcs1_to_ec(RSA_2048_PKCS1_PEM, KeyType::Pkcs1, TargetType::Ec)]
    #[case::pkcs1_to_pkcs8(RSA_2048_PKCS1_PEM, KeyType::Pkcs1, TargetType::Pkcs8)]
    fn test_private_key_der_type_mismatch_error(
        #[case] pem_str: &str,
        #[case] source_type: KeyType,
        #[case] target_type: TargetType,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let der_bytes: Vec<u8> = pem.decode().unwrap();

        let private_key_der = match source_type {
            KeyType::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der_bytes)),
            KeyType::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der_bytes)),
            KeyType::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_bytes)),
        };

        match target_type {
            TargetType::Rsa => {
                assert!(RSAPrivateKey::try_from(private_key_der).is_err());
            }
            TargetType::Ec => {
                assert!(ECPrivateKey::try_from(private_key_der).is_err());
            }
            TargetType::Pkcs8 => {
                assert!(OneAsymmetricKey::try_from(private_key_der).is_err());
            }
        }
    }

    // ========================================================================
    // PrivateKey <-> PrivateKeyDer tests
    // ========================================================================

    /// Test PrivateKeyDer -> PrivateKey conversion for all formats
    #[rstest]
    #[case::pkcs1(RSA_2048_PKCS1_PEM, KeyType::Pkcs1, Some(2048))]
    #[case::sec1(EC_P256_SEC1_PEM, KeyType::Sec1, Some(256))]
    // PKCS#8 v1 keys don't have public key, so key_size returns 0
    #[case::pkcs8_rsa(RSA_PKCS8_PEM, KeyType::Pkcs8, None)]
    #[case::pkcs8_ec(EC_PKCS8_PEM, KeyType::Pkcs8, None)]
    fn test_private_key_der_to_private_key(
        #[case] pem_str: &str,
        #[case] key_type: KeyType,
        #[case] expected_key_size: Option<u32>,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let der_bytes: Vec<u8> = pem.decode().unwrap();

        let private_key_der = match key_type {
            KeyType::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der_bytes)),
            KeyType::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der_bytes)),
            KeyType::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_bytes)),
        };

        let private_key = PrivateKey::try_from(private_key_der).unwrap();
        if let Some(expected) = expected_key_size {
            assert_eq!(private_key.key_size(), expected);
        }

        match key_type {
            KeyType::Pkcs1 => assert!(private_key.is_pkcs1()),
            KeyType::Sec1 => assert!(private_key.is_sec1()),
            KeyType::Pkcs8 => assert!(private_key.is_pkcs8()),
        }
    }

    /// Test PrivateKey -> PrivateKeyDer roundtrip
    #[rstest]
    #[case::pkcs1(RSA_2048_PKCS1_PEM, KeyType::Pkcs1)]
    #[case::sec1(EC_P256_SEC1_PEM, KeyType::Sec1)]
    #[case::pkcs8_rsa(RSA_PKCS8_PEM, KeyType::Pkcs8)]
    #[case::pkcs8_ec(EC_PKCS8_PEM, KeyType::Pkcs8)]
    fn test_private_key_to_private_key_der_roundtrip(
        #[case] pem_str: &str,
        #[case] key_type: KeyType,
    ) {
        let pem = Pem::from_str(pem_str).unwrap();
        let der_bytes: Vec<u8> = pem.decode().unwrap();

        let private_key_der = match key_type {
            KeyType::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der_bytes)),
            KeyType::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der_bytes)),
            KeyType::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_bytes)),
        };

        // PrivateKeyDer -> PrivateKey -> PrivateKeyDer
        let private_key = PrivateKey::try_from(private_key_der).unwrap();
        let roundtrip_der = PrivateKeyDer::try_from(&private_key).unwrap();

        // Verify format is preserved
        match key_type {
            KeyType::Pkcs1 => assert!(matches!(roundtrip_der, PrivateKeyDer::Pkcs1(_))),
            KeyType::Sec1 => assert!(matches!(roundtrip_der, PrivateKeyDer::Sec1(_))),
            KeyType::Pkcs8 => assert!(matches!(roundtrip_der, PrivateKeyDer::Pkcs8(_))),
        }
    }
}
