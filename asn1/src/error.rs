//! Error types for ASN.1 parsing and encoding.

use std::num::ParseIntError;

use thiserror::Error;

/// Errors that can occur during ASN.1 parsing and encoding operations.
#[derive(Debug, Error)]
pub enum Error {
    // Boolean errors
    #[error("invalid boolean")]
    InvalidBoolean,

    // Integer errors
    #[error("INTEGER: no data")]
    IntegerNoData,
    #[error("INTEGER: value out of range for i64")]
    IntegerOutOfRangeI64,
    #[error("INTEGER: value out of range for u64")]
    IntegerOutOfRangeU64,
    #[error("parse int error: {0}")]
    ParseInt(ParseIntError),

    // ObjectIdentifier errors
    #[error("OBJECT IDENTIFIER: no data")]
    ObjectIdentifierNoData,
    #[error("OBJECT IDENTIFIER: incomplete encoding")]
    ObjectIdentifierIncompleteEncoding,
    #[error("OBJECT IDENTIFIER: too few components (need at least 2)")]
    ObjectIdentifierTooFewComponents,
    #[error("OBJECT IDENTIFIER: empty string")]
    ObjectIdentifierEmptyString,
    #[error("OBJECT IDENTIFIER: invalid component '{0}'")]
    ObjectIdentifierInvalidComponent(String),

    // BitString errors
    #[error("BIT STRING: no data")]
    BitStringNoData,
    #[error("BIT STRING: unused bits {0} out of range (must be 0-7)")]
    BitStringUnusedBitsOutOfRange(u8),

    // String type errors
    #[error("UTF8String: invalid UTF-8")]
    Utf8StringInvalidUtf8,
    #[error("PrintableString: invalid encoding")]
    PrintableStringInvalidEncoding,
    #[error("IA5String: invalid encoding")]
    Ia5StringInvalidEncoding,

    // Time errors
    #[error("UTCTime: no data")]
    UtcTimeNoData,
    #[error("UTCTime: invalid format")]
    UtcTimeInvalidFormat,
    #[error("GeneralizedTime: no data")]
    GeneralizedTimeNoData,
    #[error("GeneralizedTime: invalid format")]
    GeneralizedTimeInvalidFormat,

    // BMPString errors
    #[error("BMPString: odd byte length {0}")]
    BmpStringOddLength(usize),
    #[error("BMPString: invalid code point at position {position}: 0x{code_point:04X}")]
    BmpStringInvalidCodePoint { position: usize, code_point: u16 },
    #[error("BMPString: contains character outside BMP (requires surrogate pair)")]
    BmpStringRequiresSurrogatePair,
    #[error("BMPString: conversion to String failed")]
    BmpStringConversionFailed,

    // Context-specific errors
    #[error("invalid context-specific value: {slot}, {msg}")]
    InvalidContextSpecific { slot: u8, msg: String },

    // DER errors
    #[error("invalid DER encoding: {0}")]
    FailedToDecodeDer(#[source] tsumiki_der::error::Error),

    // Element errors
    #[error("element: cannot encode {0}")]
    ElementCannotEncode(&'static str),
    #[error("element: unimplemented type")]
    ElementUnimplemented,
}
