use pem::Pem;
use tsumiki::decoder::Decoder;

use crate::error::Result;

/// Decode PEM to a specific type
///
/// This is a generic function that can decode PEM to any type that implements
/// `Decoder<Pem, T>`. This includes Certificate, RSAPrivateKey, RSAPublicKey, etc.
///
/// # Arguments
/// * `pem` - PEM object to decode
///
/// # Returns
/// The decoded object of type T
///
/// # Example
/// ```ignore
/// let pem = Pem::from_str(pem_string)?;
/// let cert: Certificate = decode(pem)?;
/// let key: RSAPrivateKey = decode(pem)?;
/// ```
pub(crate) fn decode<T>(pem: Pem) -> Result<T>
where
    T: tsumiki::decoder::DecodableFrom<Pem>,
    Pem: Decoder<Pem, T>,
    <Pem as Decoder<Pem, T>>::Error: Into<crate::error::Error>,
{
    // Decode to target type
    pem.decode().map_err(Into::into)
}
