use std::num::ParseIntError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid boolean")]
    InvalidBoolean,
    #[error("invalid integer: {0}")]
    InvalidInteger(String),
    #[error("invalid object identifier: {0}")]
    InvalidObjectIdentifier(String),
    #[error("parse int error: {0}")]
    ParseInt(ParseIntError),
    #[error("invalid bit string: {0}")]
    InvalidBitString(String),
    #[error("invalid utf-8 string: {0}")]
    InvalidUTF8String(String),
    #[error("invalid printable string: {0}")]
    InvalidPrintableString(String),
    #[error("invalid IA5 string: {0}")]
    InvalidIA5String(String),
    #[error("invalid UTC time: {0}")]
    InvalidUTCTime(String),
    #[error("invalid generalized time: {0}")]
    InvalidGeneralizedTime(String),
    #[error("invalid context-specific value: {slot}, {msg}")]
    InvalidContextSpecific { slot: u8, msg: String },
    #[error("invalid DER encoding: {0}")]
    FailedToDecodeDer(#[source] der::error::Error),
    #[error("invalid element: {0}")]
    InvalidElement(String),
}
