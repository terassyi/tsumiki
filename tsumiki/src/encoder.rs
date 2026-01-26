//! Encoder trait for type-safe conversions.
//!
//! The `Encoder` trait enables converting from a source type `T` to an
//! encoded type `E` in a type-safe manner. It is the inverse of the
//! `Decoder` trait and is used to convert PKI data structures back into
//! their encoded representations.
//!
//! # Design Pattern
//!
//! The encoder uses a two-trait pattern for type safety:
//!
//! 1. `Encoder<T, E>` - Performs the actual conversion
//! 2. `EncodableTo<T>` - Marker trait constraining valid conversions
//!
//! This ensures that only valid type conversions are possible at compile time.
//!
//! # Implementation Guide
//!
//! To add a new encodable type, implement both traits:
//!
//! ```no_run
//! use tsumiki::encoder::{Encoder, EncodableTo};
//!
//! struct SourceType { data: Vec<u8> }
//! struct EncodedType(Vec<u8>);
//!
//! #[derive(Debug)]
//! struct MyError;
//!
//! // 1. Mark the destination type as encodable from the source type
//! impl EncodableTo<SourceType> for EncodedType {}
//!
//! // 2. Implement the encoder on the source type
//! impl Encoder<SourceType, EncodedType> for SourceType {
//!     type Error = MyError;
//!
//!     fn encode(&self) -> Result<EncodedType, Self::Error> {
//!         // Encoding logic here
//!         Ok(EncodedType(self.data.clone()))
//!     }
//! }
//! ```
//!
//! # Example
//!
//! The `der` crate implements encoding from DER structures to bytes:
//!
//! ```ignore
//! use tsumiki::encoder::Encoder;
//! use tsumiki_der::Der;
//!
//! let der = Der::new(vec![0x30, 0x00]);
//! let bytes: Vec<u8> = der.encode().unwrap();
//! ```

/// Encoder trait for converting from type `T` to type `E`.
///
/// This trait is implemented by the source type `T` to enable conversion
/// to the encoded type `E`. The destination type must implement
/// `EncodableTo<T>` to ensure type safety.
///
/// # Type Parameters
///
/// * `T` - The source type (usually `Self`)
/// * `E` - The encoded type that `T` can be encoded to
///
/// # Examples
///
/// Implementing an encoder:
///
/// ```no_run
/// use tsumiki::encoder::{Encoder, EncodableTo};
///
/// struct MyType { value: u32 }
///
/// #[derive(Debug)]
/// struct MyError;
///
/// impl EncodableTo<MyType> for Vec<u8> {}
///
/// impl Encoder<MyType, Vec<u8>> for MyType {
///     type Error = MyError;
///
///     fn encode(&self) -> Result<Vec<u8>, Self::Error> {
///         // Serialize self (MyType) to bytes
///         Ok(self.value.to_be_bytes().to_vec())
///     }
/// }
/// ```
///
/// Using an encoder:
///
/// ```ignore
/// use tsumiki::encoder::Encoder;
/// use tsumiki_der::Der;
///
/// let der = Der::new(vec![0x30, 0x00]);
/// let bytes: Vec<u8> = der.encode().unwrap();
/// ```
pub trait Encoder<T, E: EncodableTo<T>> {
    /// The error type returned when encoding fails.
    type Error;

    /// Encodes `self` into type `E`.
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion fails. The specific error
    /// conditions depend on the implementing type.
    fn encode(&self) -> Result<E, Self::Error>;
}

/// Marker trait indicating that type `E` can be encoded from type `T`.
///
/// This trait is used to constrain the `Encoder` trait and ensure
/// type safety at compile time. It prevents invalid conversions by
/// requiring explicit implementation for each valid type pair.
///
/// # Purpose
///
/// This trait serves as a compile-time guard. Without it, any type
/// could attempt to encode into any other type, leading to potential
/// runtime errors. By requiring `EncodableTo<T>` to be implemented,
/// the compiler can verify that a conversion is valid before allowing
/// the `Encoder` implementation.
///
/// # Implementation
///
/// This trait has no methods and serves only as a marker. Implement it
/// for destination types that can be encoded from a source type:
///
/// ```no_run
/// use tsumiki::encoder::EncodableTo;
///
/// struct MySourceType;
/// struct MyEncodedType;
///
/// // Allow MySourceType to be encoded to MyEncodedType
/// impl EncodableTo<MySourceType> for MyEncodedType {}
/// ```
pub trait EncodableTo<T> {}
