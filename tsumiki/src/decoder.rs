//! Decoder trait for type-safe conversions.
//!
//! The `Decoder` trait enables converting from a source type `T` to a
//! destination type `D` in a type-safe manner. It is used throughout
//! tsumiki to convert between different representations of PKI data.
//!
//! # Design Pattern
//!
//! The decoder uses a two-trait pattern for type safety:
//!
//! 1. `Decoder<T, D>` - Performs the actual conversion
//! 2. `DecodableFrom<T>` - Marker trait constraining valid conversions
//!
//! This ensures that only valid type conversions are possible at compile time.
//!
//! # Implementation Guide
//!
//! To add a new decodable type, implement both traits:
//!
//! ```no_run
//! use tsumiki::decoder::{Decoder, DecodableFrom};
//!
//! struct SourceType(Vec<u8>);
//! struct DestType(String);
//!
//! #[derive(Debug)]
//! struct MyError;
//!
//! // 1. Mark the destination type as decodable from the source type
//! impl DecodableFrom<SourceType> for DestType {}
//!
//! // 2. Implement the decoder on the source type
//! impl Decoder<SourceType, DestType> for SourceType {
//!     type Error = MyError;
//!
//!     fn decode(&self) -> Result<DestType, Self::Error> {
//!         // Conversion logic here
//!         Ok(DestType(String::from_utf8_lossy(&self.0).to_string()))
//!     }
//! }
//! ```
//!
//! # Example
//!
//! The `der` crate implements decoding from byte slices to DER structures:
//!
//! ```ignore
//! use tsumiki::decoder::Decoder;
//! use tsumiki_der::Der;
//!
//! let bytes = vec![0x30, 0x00]; // SEQUENCE with length 0
//! let der: Der = bytes.decode().unwrap();
//! ```

/// Decoder trait for converting from type `T` to type `D`.
///
/// This trait is implemented by the source type `T` to enable conversion
/// to the destination type `D`. The destination type must implement
/// `DecodableFrom<T>` to ensure type safety.
///
/// # Type Parameters
///
/// * `T` - The source type (usually `Self`)
/// * `D` - The destination type that can be decoded from `T`
///
/// # Examples
///
/// Implementing a decoder:
///
/// ```no_run
/// use tsumiki::decoder::{Decoder, DecodableFrom};
///
/// struct MyType(String);
///
/// #[derive(Debug)]
/// struct MyError;
///
/// impl DecodableFrom<Vec<u8>> for MyType {}
///
/// impl Decoder<Vec<u8>, MyType> for Vec<u8> {
///     type Error = MyError;
///
///     fn decode(&self) -> Result<MyType, Self::Error> {
///         // Parse self (Vec<u8>) and construct MyType
///         Ok(MyType(String::from_utf8_lossy(self).to_string()))
///     }
/// }
/// ```
///
/// Using a decoder:
///
/// ```ignore
/// use tsumiki::decoder::Decoder;
/// use tsumiki_der::Der;
///
/// let bytes = vec![0x30, 0x00];
/// let result: Der = bytes.decode().unwrap();
/// ```
pub trait Decoder<T, D: DecodableFrom<T>> {
    /// The error type returned when decoding fails.
    type Error;

    /// Decodes `self` into type `D`.
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion fails. The specific error
    /// conditions depend on the implementing type.
    fn decode(&self) -> Result<D, Self::Error>;
}

/// Marker trait indicating that type `D` can be decoded from type `T`.
///
/// This trait is used to constrain the `Decoder` trait and ensure
/// type safety at compile time. It prevents invalid conversions by
/// requiring explicit implementation for each valid type pair.
///
/// # Purpose
///
/// This trait serves as a compile-time guard. Without it, any type
/// could attempt to decode into any other type, leading to potential
/// runtime errors. By requiring `DecodableFrom<T>` to be implemented,
/// the compiler can verify that a conversion is valid before allowing
/// the `Decoder` implementation.
///
/// # Implementation
///
/// This trait has no methods and serves only as a marker. Implement it
/// for destination types that can be decoded from a source type:
///
/// ```no_run
/// use tsumiki::decoder::DecodableFrom;
///
/// struct MySourceType;
/// struct MyDestType;
///
/// // Allow MyDestType to be decoded from MySourceType
/// impl DecodableFrom<MySourceType> for MyDestType {}
/// ```
pub trait DecodableFrom<T> {}
