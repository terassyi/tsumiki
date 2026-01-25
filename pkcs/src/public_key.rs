//! Unified public key type supporting multiple formats.
//!
//! This module provides [`PublicKey`], an enum that can represent public keys
//! in any of the common formats:
//! - PKCS#1 (RSA keys only)
//! - X.509/PKCS#8 SubjectPublicKeyInfo (generic format for any key type)
//!
//! The primary use case is automatic format detection when loading keys from
//! DER or PEM data.
//!
//! # PublicKeyExt Trait
//!
//! The [`PublicKeyExt`] trait provides a unified interface for accessing
//! common public key properties across different formats:
//!
//! ```ignore
//! use pkcs::{PublicKey, PublicKeyExt};
//!
//! let key: PublicKey = /* ... */;
//! println!("Algorithm: {:?}", key.algorithm());
//! println!("Key size: {} bits", key.key_size());
//! ```

use tsumiki_asn1::{ASN1Object, Element};
use tsumiki_der::Der;
use tsumiki_pem::{Label, Pem, ToPem};

use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::{Error, Result};
use crate::pkcs1::RSAPublicKey;
use crate::pkcs8::PublicKey as Pkcs8PublicKey;
use crate::private_key::KeyAlgorithm;

/// Trait for common public key operations.
///
/// This trait provides a unified interface for accessing properties
/// common to all public key formats (PKCS#1, X.509/PKCS#8).
///
/// # Implementors
///
/// - [`RSAPublicKey`](crate::pkcs1::RSAPublicKey) - PKCS#1 RSA public keys
/// - [`PublicKey`](crate::pkcs8::PublicKey) (PKCS#8) - X.509/SPKI public keys
/// - [`PublicKey`] - Unified enum for all formats
///
/// # Examples
///
/// ```ignore
/// use pkcs::{PublicKey, PublicKeyExt};
/// use tsumiki::decoder::Decoder;
/// use tsumiki_pem::Pem;
///
/// let pem: Pem = "-----BEGIN PUBLIC KEY-----...".parse()?;
/// let key: PublicKey = pem.decode()?;
///
/// println!("Algorithm: {}", key.algorithm());
/// println!("Key size: {} bits", key.key_size());
/// ```
pub trait PublicKeyExt {
    /// Returns the key size in bits.
    ///
    /// For RSA keys, this is the modulus bit length.
    /// For EC keys, this is the uncompressed point bit length (e.g., 520 for P-256).
    /// For Ed25519, this returns 256 bits.
    /// For Ed448, this returns 448 bits.
    ///
    /// Returns 0 if the key size cannot be determined.
    ///
    /// # Note on EC Key Sizes
    ///
    /// For EC public keys, the returned size represents the uncompressed point format,
    /// which is `1 + 2 * curve_bits / 8` bytes, or `8 + 2 * curve_bits` bits.
    /// For example, a P-256 curve produces a 520-bit public key (65 bytes).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use pkcs::{PublicKey, PublicKeyExt};
    ///
    /// let key: PublicKey = /* ... */;
    /// println!("Key size: {} bits", key.key_size());
    /// ```
    fn key_size(&self) -> u32;

    /// Returns the algorithm type of this key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use pkcs::{PublicKey, PublicKeyExt, KeyAlgorithm};
    ///
    /// let key: PublicKey = /* ... */;
    /// match key.algorithm() {
    ///     KeyAlgorithm::Rsa => println!("RSA key"),
    ///     KeyAlgorithm::Ec => println!("Elliptic curve key"),
    ///     KeyAlgorithm::Ed25519 => println!("Ed25519 key"),
    ///     KeyAlgorithm::Ed448 => println!("Ed448 key"),
    ///     KeyAlgorithm::Unknown => println!("Unknown algorithm"),
    /// }
    /// ```
    fn algorithm(&self) -> KeyAlgorithm;

    /// Returns the raw public key bytes, if available.
    ///
    /// # Availability
    ///
    /// - **PKCS#1 RSA keys**: Returns `None` (the key is structured as modulus + exponent;
    ///   use [`RSAPublicKey`](crate::pkcs1::RSAPublicKey) directly for access)
    /// - **X.509/SPKI keys**: Returns the subject public key bytes
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use pkcs::{PublicKey, PublicKeyExt};
    ///
    /// let key: PublicKey = /* ... */;
    /// if let Some(bytes) = key.public_key_bytes() {
    ///     println!("Public key: {} bytes", bytes.len());
    /// }
    /// ```
    fn public_key_bytes(&self) -> Option<&[u8]>;
}

/// A public key in one of the supported formats.
///
/// This enum allows handling public keys without knowing their exact format
/// ahead of time. Use [`PublicKey::from_der`] or the `Decoder` implementation
/// for `Pem` to automatically detect the format.
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// PKCS#1 RSA public key (RSA keys only)
    Pkcs1(RSAPublicKey),
    /// X.509/PKCS#8 SubjectPublicKeyInfo (generic format)
    Spki(Pkcs8PublicKey),
}

impl PublicKey {
    /// Attempt to parse a public key from DER-encoded bytes.
    ///
    /// This method tries each format in order:
    /// 1. X.509/PKCS#8 SubjectPublicKeyInfo (most common)
    /// 2. PKCS#1 RSA public key
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
    /// This is a convenience method that delegates to [`PublicKeyExt::key_size`].
    pub fn key_size(&self) -> u32 {
        <Self as PublicKeyExt>::key_size(self)
    }

    /// Get the algorithm type of this key.
    ///
    /// This is a convenience method that delegates to [`PublicKeyExt::algorithm`].
    pub fn algorithm(&self) -> KeyAlgorithm {
        <Self as PublicKeyExt>::algorithm(self)
    }

    /// Get the public key bytes, if available.
    ///
    /// This is a convenience method that delegates to [`PublicKeyExt::public_key_bytes`].
    pub fn public_key_bytes(&self) -> Option<&[u8]> {
        <Self as PublicKeyExt>::public_key_bytes(self)
    }

    /// Returns `true` if this is a PKCS#1 RSA key.
    pub fn is_pkcs1(&self) -> bool {
        matches!(self, PublicKey::Pkcs1(_))
    }

    /// Returns `true` if this is an X.509/PKCS#8 SubjectPublicKeyInfo key.
    pub fn is_spki(&self) -> bool {
        matches!(self, PublicKey::Spki(_))
    }

    /// Try to get the inner PKCS#1 RSA key.
    pub fn as_pkcs1(&self) -> Option<&RSAPublicKey> {
        match self {
            PublicKey::Pkcs1(key) => Some(key),
            _ => None,
        }
    }

    /// Try to get the inner X.509/PKCS#8 key.
    pub fn as_spki(&self) -> Option<&Pkcs8PublicKey> {
        match self {
            PublicKey::Spki(key) => Some(key),
            _ => None,
        }
    }

    /// Consume and return the inner PKCS#1 RSA key.
    pub fn into_pkcs1(self) -> Option<RSAPublicKey> {
        match self {
            PublicKey::Pkcs1(key) => Some(key),
            _ => None,
        }
    }

    /// Consume and return the inner X.509/PKCS#8 key.
    pub fn into_spki(self) -> Option<Pkcs8PublicKey> {
        match self {
            PublicKey::Spki(key) => Some(key),
            _ => None,
        }
    }
}

// Element -> PublicKey decoder
impl DecodableFrom<Element> for PublicKey {}

impl Decoder<Element, PublicKey> for Element {
    type Error = Error;

    /// Attempt to parse a public key from an ASN.1 element.
    ///
    /// This method tries each format in order:
    /// 1. X.509/PKCS#8 SubjectPublicKeyInfo (most common)
    /// 2. PKCS#1 RSA public key
    fn decode(&self) -> Result<PublicKey> {
        // Try X.509/PKCS#8 first (most common modern format)
        let spki_err = match self.decode() {
            Ok(key) => return Ok(PublicKey::Spki(key)),
            Err(e) => e,
        };

        // Try PKCS#1 (RSA public key)
        let pkcs1_err = match self.decode() {
            Ok(key) => return Ok(PublicKey::Pkcs1(key)),
            Err(e) => e,
        };

        Err(Error::UnrecognizedPublicKeyFormat {
            spki: Box::new(spki_err),
            pkcs1: Box::new(pkcs1_err),
        })
    }
}

// Pem -> PublicKey decoder
impl DecodableFrom<Pem> for PublicKey {}

impl Decoder<Pem, PublicKey> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<PublicKey> {
        // Use label to determine format when available
        match self.label() {
            Label::RSAPublicKey => Ok(PublicKey::Pkcs1(self.decode()?)),
            Label::PublicKey => Ok(PublicKey::Spki(self.decode()?)),
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

impl From<RSAPublicKey> for PublicKey {
    fn from(key: RSAPublicKey) -> Self {
        PublicKey::Pkcs1(key)
    }
}

impl From<Pkcs8PublicKey> for PublicKey {
    fn from(key: Pkcs8PublicKey) -> Self {
        PublicKey::Spki(key)
    }
}

impl ToPem for PublicKey {
    type Error = Error;

    fn pem_label(&self) -> Label {
        match self {
            PublicKey::Pkcs1(_) => Label::RSAPublicKey,
            PublicKey::Spki(_) => Label::PublicKey,
        }
    }

    fn to_pem(&self) -> Result<Pem> {
        match self {
            PublicKey::Pkcs1(key) => key.to_pem().map_err(Error::from),
            PublicKey::Spki(key) => key.to_pem().map_err(Error::from),
        }
    }
}

impl PublicKeyExt for PublicKey {
    fn key_size(&self) -> u32 {
        match self {
            PublicKey::Pkcs1(key) => key.key_size(),
            PublicKey::Spki(key) => key.key_size(),
        }
    }

    fn algorithm(&self) -> KeyAlgorithm {
        match self {
            PublicKey::Pkcs1(key) => key.algorithm(),
            PublicKey::Spki(key) => key.algorithm(),
        }
    }

    fn public_key_bytes(&self) -> Option<&[u8]> {
        match self {
            PublicKey::Pkcs1(key) => key.public_key_bytes(),
            PublicKey::Spki(key) => key.public_key_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    // RSA 2048-bit public key in PKCS#1 format
    const RSA_2048_PKCS1_PUB: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvf4anqhlMYhVhpOv8XK/ygPFUxkNa8Rh9NNTVlqiWuPgD4Lj7YCs
a31kQwYgOKADsG5ROApHSjKsWrKQ70DSpxZmPiO8j7jFQdUJLbe/hfiFskoMUr+V
5imxrkJB5cnBgIw49ykn0mVtyLRG9RS8Xv+XqNEHFnugS7z2cFQqKYI8oq2LyLxS
bMzDlzkB1p64u5p6Gy0W3KQZt42/sompo+swMslw+XN2rSNFfUWfJWGdEFJcSl+9
oOz7y9ZGv56uC3VdGnU9u6MmC3iMZ/Vf9qQIHOr6KE6IaJNvHPSAET7qnBWJq+x0
UrsMJmGdkjGvE3MgIjgaLxjgn/sfO1++vwIDAQAB
-----END RSA PUBLIC KEY-----"#;

    // EC P-256 public key in X.509/SPKI format
    const EC_P256_SPKI_PUB: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmvfw1VdwIlsJHfbHLhHXrO3Wq/0L
BCduo6Nb96AiLGUxkn/OWt1I9STYYNw8e/Xuzsy9j5joSxQDwmCWSGPGWw==
-----END PUBLIC KEY-----"#;

    #[rstest]
    #[case(RSA_2048_PKCS1_PUB, true, false, 2048, KeyAlgorithm::Rsa)]
    #[case(EC_P256_SPKI_PUB, false, true, 520, KeyAlgorithm::Ec)]
    fn test_public_key_from_pem(
        #[case] pem_str: &str,
        #[case] is_pkcs1: bool,
        #[case] is_spki: bool,
        #[case] expected_bits: u32,
        #[case] expected_alg: KeyAlgorithm,
    ) {
        let pem = Pem::from_str(pem_str).expect("Failed to parse PEM");
        let key: PublicKey = pem.decode().expect("Failed to decode PublicKey");

        assert_eq!(key.is_pkcs1(), is_pkcs1);
        assert_eq!(key.is_spki(), is_spki);
        assert_eq!(key.key_size(), expected_bits);
        assert_eq!(key.algorithm(), expected_alg);
    }

    #[test]
    fn test_public_key_accessors() {
        let pem = Pem::from_str(RSA_2048_PKCS1_PUB).expect("Failed to parse PEM");
        let key: PublicKey = pem.decode().expect("Failed to decode PublicKey");

        assert!(key.as_pkcs1().is_some());
        assert!(key.as_spki().is_none());

        let inner = key.into_pkcs1();
        assert!(inner.is_some());
    }

    #[test]
    fn test_from_conversions() {
        let pem = Pem::from_str(RSA_2048_PKCS1_PUB).expect("Failed to parse PEM");
        let rsa_key: RSAPublicKey = pem.decode().expect("Failed to decode RSAPublicKey");
        let key = PublicKey::from(rsa_key);
        assert!(key.is_pkcs1());

        let pem = Pem::from_str(EC_P256_SPKI_PUB).expect("Failed to parse PEM");
        let spki_key: Pkcs8PublicKey = pem.decode().expect("Failed to decode Pkcs8PublicKey");
        let key = PublicKey::from(spki_key);
        assert!(key.is_spki());
    }
}
