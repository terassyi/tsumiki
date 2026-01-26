//! # tsumiki
//!
//! Core traits for encoding and decoding in the tsumiki PKI toolkit.
//!
//! This crate defines the fundamental `Decoder` and `Encoder` traits that
//! establish a type-safe conversion pattern used throughout tsumiki.
//!
//! ## Overview
//!
//! The conversion pattern flows like this:
//! ```text
//! PEM → Vec<u8> → DER → ASN1Object → Certificate
//! ```
//!
//! Each step uses the `Decoder` trait to convert from one type to the next,
//! and the `Encoder` trait to convert in the reverse direction.
//!
//! ## Type Safety
//!
//! The traits use marker traits (`DecodableFrom` and `EncodableTo`) to ensure
//! type safety at compile time. This prevents invalid conversions and catches
//! errors early in the development process.
//!
//! ## Example
//!
//! The following example demonstrates the decoding pattern. Note that specific
//! implementations are provided by the `der`, `asn1`, and `x509` crates:
//!
//! ```ignore
//! use tsumiki::decoder::Decoder;
//! use tsumiki_der::Der;
//! use tsumiki_asn1::ASN1Object;
//!
//! // Decode raw bytes to DER
//! let bytes = vec![0x30, 0x00];
//! let der: Der = bytes.decode().unwrap();
//!
//! // Decode DER to ASN.1
//! let asn1: ASN1Object = der.decode().unwrap();
//! ```
//!
//! Encoding works in the reverse direction:
//!
//! ```ignore
//! use tsumiki::encoder::Encoder;
//! use tsumiki_der::Der;
//! use tsumiki_asn1::ASN1Object;
//!
//! // Encode ASN.1 to DER
//! let asn1 = ASN1Object::new(vec![]);
//! let der: Der = asn1.encode().unwrap();
//!
//! // Encode DER to bytes
//! let bytes: Vec<u8> = der.encode().unwrap();
//! ```

#![forbid(unsafe_code)]

pub mod decoder;
pub mod encoder;
