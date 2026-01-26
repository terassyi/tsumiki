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
//!
//! # PrivateKeyExt Trait
//!
//! The [`PrivateKeyExt`] trait provides a unified interface for accessing
//! common private key properties across different formats:
//!
//! ```no_run
//! use tsumiki::decoder::Decoder;
//! use tsumiki_pem::Pem;
//! use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};
//!
//! let pem: Pem = "-----BEGIN PRIVATE KEY-----...".parse().unwrap();
//! let key: PrivateKey = pem.decode().unwrap();
//! println!("Algorithm: {:?}", key.algorithm());
//! println!("Key size: {} bits", key.key_size());
//! if let Some(pubkey) = key.public_key_bytes() {
//!     println!("Public key available");
//! }
//! ```

use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki_asn1::{ASN1Object, Element};
use tsumiki_der::Der;
use tsumiki_pem::{Label, Pem, ToPem};
use tsumiki_pkix_types::algorithm::AlgorithmIdentifier;

use crate::error::{Error, Result};
use crate::pkcs1::RSAPrivateKey;
use crate::pkcs8::{OID_ED448, OID_ED25519, OneAsymmetricKey};
use crate::sec1::ECPrivateKey;

/// Key algorithm type.
///
/// Represents the cryptographic algorithm used by a private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// RSA encryption
    Rsa,
    /// Elliptic Curve (ECDSA/ECDH)
    Ec,
    /// Ed25519 (EdDSA)
    Ed25519,
    /// Ed448 (EdDSA)
    Ed448,
    /// Unknown or unsupported algorithm
    Unknown,
}

impl KeyAlgorithm {
    /// Returns the OID string for this algorithm, if known.
    #[must_use]
    pub fn oid(&self) -> Option<&'static str> {
        match self {
            KeyAlgorithm::Rsa => Some(AlgorithmIdentifier::OID_RSA_ENCRYPTION),
            KeyAlgorithm::Ec => Some(AlgorithmIdentifier::OID_EC_PUBLIC_KEY),
            KeyAlgorithm::Ed25519 => Some(OID_ED25519),
            KeyAlgorithm::Ed448 => Some(OID_ED448),
            KeyAlgorithm::Unknown => None,
        }
    }

    /// Returns a human-readable name for this algorithm.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa => "RSA",
            KeyAlgorithm::Ec => "EC",
            KeyAlgorithm::Ed25519 => "Ed25519",
            KeyAlgorithm::Ed448 => "Ed448",
            KeyAlgorithm::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Trait for common private key operations.
///
/// This trait provides a unified interface for accessing properties
/// common to all private key formats (PKCS#1, SEC1, PKCS#8).
///
/// # Implementors
///
/// - [`RSAPrivateKey`](crate::pkcs1::RSAPrivateKey) - PKCS#1 RSA private keys
/// - [`ECPrivateKey`](crate::sec1::ECPrivateKey) - SEC1 EC private keys
/// - [`OneAsymmetricKey`](crate::pkcs8::OneAsymmetricKey) - PKCS#8 generic private keys
/// - [`PrivateKey`] - Unified enum for all formats
///
/// # Examples
///
/// ```no_run
/// use tsumiki::decoder::Decoder;
/// use tsumiki_pem::Pem;
/// use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};
///
/// let pem: Pem = "-----BEGIN RSA PRIVATE KEY-----...".parse().unwrap();
/// let key: PrivateKey = pem.decode().unwrap();
///
/// println!("Algorithm: {}", key.algorithm());
/// println!("Key size: {} bits", key.key_size());
///
/// if let Some(pubkey) = key.public_key() {
///     println!("Public key extracted successfully");
/// }
/// ```
pub trait PrivateKeyExt {
    /// Returns the key size in bits.
    ///
    /// For RSA keys, this is the modulus bit length.
    /// For EC keys, this is determined by the curve (e.g., 256 for P-256).
    /// For Ed25519, this returns 256 bits.
    /// For Ed448, this returns 448 bits.
    ///
    /// Returns 0 if the key size cannot be determined (e.g., PKCS#8 v1 keys
    /// without embedded public key information).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tsumiki::decoder::Decoder;
    /// use tsumiki_pem::Pem;
    /// use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};
    ///
    /// let pem: Pem = "-----BEGIN PRIVATE KEY-----...".parse().unwrap();
    /// let key: PrivateKey = pem.decode().unwrap();
    /// match key.key_size() {
    ///     0 => println!("Key size unknown"),
    ///     bits => println!("Key size: {} bits", bits),
    /// }
    /// ```
    fn key_size(&self) -> u32;

    /// Returns the algorithm type of this key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tsumiki::decoder::Decoder;
    /// use tsumiki_pem::Pem;
    /// use tsumiki_pkcs::{PrivateKey, PrivateKeyExt, KeyAlgorithm};
    ///
    /// let pem: Pem = "-----BEGIN PRIVATE KEY-----...".parse().unwrap();
    /// let key: PrivateKey = pem.decode().unwrap();
    /// match key.algorithm() {
    ///     KeyAlgorithm::Rsa => println!("RSA key"),
    ///     KeyAlgorithm::Ec => println!("Elliptic curve key"),
    ///     KeyAlgorithm::Ed25519 => println!("Ed25519 key"),
    ///     KeyAlgorithm::Ed448 => println!("Ed448 key"),
    ///     KeyAlgorithm::Unknown => println!("Unknown algorithm"),
    ///     _ => println!("Other algorithm"),
    /// }
    /// ```
    fn algorithm(&self) -> KeyAlgorithm;

    /// Returns the raw public key bytes, if available.
    ///
    /// This method returns the public key as raw bytes when available in the
    /// key structure. For structured access to the public key, use [`public_key()`](Self::public_key)
    /// instead.
    ///
    /// # Availability
    ///
    /// - **PKCS#1 RSA keys**: Returns `None` (use [`public_key()`](Self::public_key) for structured access)
    /// - **SEC1 EC keys**: Returns the uncompressed point bytes if present
    /// - **PKCS#8 v2 keys**: Returns the public key bytes if present
    /// - **PKCS#8 v1 keys**: Returns `None` (no public key embedded)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tsumiki::decoder::Decoder;
    /// use tsumiki_pem::Pem;
    /// use tsumiki_pkcs::{PrivateKey, PrivateKeyExt};
    ///
    /// let pem: Pem = "-----BEGIN PRIVATE KEY-----...".parse().unwrap();
    /// let key: PrivateKey = pem.decode().unwrap();
    /// if let Some(bytes) = key.public_key_bytes() {
    ///     println!("Public key: {} bytes", bytes.len());
    /// }
    /// ```
    fn public_key_bytes(&self) -> Option<&[u8]>;

    /// Extracts the public key from this private key, if available.
    ///
    /// Returns a [`PublicKey`](crate::PublicKey) enum that can represent the public key
    /// in either PKCS#1 or X.509/SPKI format.
    ///
    /// # Return Format
    ///
    /// The format of the returned public key depends on the input format:
    ///
    /// | Input Format | Output Format | Condition |
    /// |--------------|---------------|-----------|
    /// | PKCS#1 RSA   | `PublicKey::Pkcs1` | Always available |
    /// | SEC1 EC      | `PublicKey::Spki` | If public key present |
    /// | PKCS#8 v1    | `None` | No public key embedded |
    /// | PKCS#8 v2    | `PublicKey::Spki` | If public key present |
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tsumiki::decoder::Decoder;
    /// use tsumiki_pem::Pem;
    /// use tsumiki_pkcs::{PrivateKey, PrivateKeyExt, PublicKey};
    /// use tsumiki_pem::ToPem;
    ///
    /// let pem: Pem = "-----BEGIN PRIVATE KEY-----...".parse().unwrap();
    /// let key: PrivateKey = pem.decode().unwrap();
    /// if let Some(pubkey) = key.public_key() {
    ///     // Export to PEM format
    ///     let pem = pubkey.to_pem().unwrap();
    ///     println!("{}", pem);
    ///
    ///     // Check the format
    ///     match pubkey {
    ///         PublicKey::Pkcs1(_) => println!("PKCS#1 RSA public key"),
    ///         PublicKey::Spki(_) => println!("X.509/SPKI public key"),
    ///     }
    /// }
    /// ```
    fn public_key(&self) -> Option<crate::PublicKey>;
}

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
    ///
    /// This is a convenience method that delegates to [`PrivateKeyExt::key_size`].
    pub fn key_size(&self) -> u32 {
        <Self as PrivateKeyExt>::key_size(self)
    }

    /// Get the algorithm type of this key.
    ///
    /// This is a convenience method that delegates to [`PrivateKeyExt::algorithm`].
    pub fn algorithm(&self) -> KeyAlgorithm {
        <Self as PrivateKeyExt>::algorithm(self)
    }

    /// Get the public key bytes, if available.
    ///
    /// This is a convenience method that delegates to [`PrivateKeyExt::public_key_bytes`].
    pub fn public_key_bytes(&self) -> Option<&[u8]> {
        <Self as PrivateKeyExt>::public_key_bytes(self)
    }

    /// Extract the public key from this private key, if available.
    ///
    /// This is a convenience method that delegates to [`PrivateKeyExt::public_key`].
    pub fn public_key(&self) -> Option<crate::PublicKey> {
        <Self as PrivateKeyExt>::public_key(self)
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

impl ToPem for PrivateKey {
    type Error = Error;

    fn pem_label(&self) -> Label {
        match self {
            PrivateKey::Pkcs1(_) => Label::RSAPrivateKey,
            PrivateKey::Sec1(_) => Label::ECPrivateKey,
            PrivateKey::Pkcs8(_) => Label::PrivateKey,
        }
    }

    fn to_pem(&self) -> Result<Pem> {
        match self {
            PrivateKey::Pkcs1(key) => key.to_pem().map_err(Error::from),
            PrivateKey::Sec1(key) => key.to_pem().map_err(Error::from),
            PrivateKey::Pkcs8(key) => key.to_pem().map_err(Error::from),
        }
    }
}

impl PrivateKeyExt for PrivateKey {
    fn key_size(&self) -> u32 {
        match self {
            PrivateKey::Pkcs1(key) => key.key_size(),
            PrivateKey::Sec1(key) => key.key_size(),
            PrivateKey::Pkcs8(key) => key.key_size(),
        }
    }

    fn algorithm(&self) -> KeyAlgorithm {
        match self {
            PrivateKey::Pkcs1(key) => key.algorithm(),
            PrivateKey::Sec1(key) => key.algorithm(),
            PrivateKey::Pkcs8(key) => key.algorithm(),
        }
    }

    fn public_key_bytes(&self) -> Option<&[u8]> {
        match self {
            PrivateKey::Pkcs1(key) => key.public_key_bytes(),
            PrivateKey::Sec1(key) => key.public_key_bytes(),
            PrivateKey::Pkcs8(key) => key.public_key_bytes(),
        }
    }

    fn public_key(&self) -> Option<crate::PublicKey> {
        match self {
            PrivateKey::Pkcs1(key) => PrivateKeyExt::public_key(key),
            PrivateKey::Sec1(key) => PrivateKeyExt::public_key(key),
            PrivateKey::Pkcs8(key) => PrivateKeyExt::public_key(key),
        }
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

    #[rstest]
    #[case::pkcs1_rsa(RSA_2048_PKCS1, true, KeyAlgorithm::Rsa, 2048, 2048)]
    #[case::sec1_ec(EC_P256_SEC1, true, KeyAlgorithm::Ec, 256, 520)]
    #[case::pkcs8_rsa_v1(RSA_2048_PKCS8, false, KeyAlgorithm::Rsa, 0, 0)]
    fn test_public_key_extraction(
        #[case] pem_str: &str,
        #[case] has_public_key: bool,
        #[case] expected_algorithm: KeyAlgorithm,
        #[case] expected_private_key_size: u32,
        #[case] expected_public_key_size: u32,
    ) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let key: PrivateKey = pem.decode().expect("Failed to decode PrivateKey");

        // Verify algorithm
        assert_eq!(key.algorithm(), expected_algorithm);

        // Verify key size
        assert_eq!(key.key_size(), expected_private_key_size);

        // Verify public key extraction
        let pub_key = key.public_key();
        assert_eq!(pub_key.is_some(), has_public_key);

        if let Some(pub_key) = pub_key {
            // Public key should have the same algorithm
            assert_eq!(pub_key.algorithm(), expected_algorithm);

            // Verify public key size
            assert_eq!(pub_key.key_size(), expected_public_key_size);
        }
    }

    #[test]
    fn test_public_key_extraction_pkcs1_returns_pkcs1_format() {
        let pem = Pem::from_str(RSA_2048_PKCS1).expect("Failed to parse PEM");
        let key: PrivateKey = pem.decode().expect("Failed to decode PrivateKey");

        let pub_key = key.public_key().expect("Should have public key");
        assert!(pub_key.is_pkcs1());
        assert!(!pub_key.is_spki());
    }

    #[test]
    fn test_public_key_extraction_sec1_returns_spki_format() {
        let pem = Pem::from_str(EC_P256_SEC1).expect("Failed to parse PEM");
        let key: PrivateKey = pem.decode().expect("Failed to decode PrivateKey");

        let pub_key = key.public_key().expect("Should have public key");
        assert!(!pub_key.is_pkcs1());
        assert!(pub_key.is_spki());
    }

    #[rstest]
    #[case::pkcs1_rsa(RSA_2048_PKCS1, Label::RSAPrivateKey)]
    #[case::sec1_ec(EC_P256_SEC1, Label::ECPrivateKey)]
    #[case::pkcs8_rsa(RSA_2048_PKCS8, Label::PrivateKey)]
    fn test_to_pem_roundtrip(#[case] pem_str: &str, #[case] expected_label: Label) {
        let original_pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let key: PrivateKey = original_pem.decode().expect("Failed to decode PrivateKey");

        // Verify PEM label
        assert_eq!(key.pem_label(), expected_label);

        // Convert to PEM
        let exported_pem = key.to_pem().expect("Failed to export to PEM");
        assert_eq!(exported_pem.label(), expected_label);

        // Decode back and verify
        let decoded_key: PrivateKey = exported_pem
            .decode()
            .expect("Failed to decode exported PEM");
        assert_eq!(decoded_key.algorithm(), key.algorithm());
        assert_eq!(decoded_key.key_size(), key.key_size());
    }
}
