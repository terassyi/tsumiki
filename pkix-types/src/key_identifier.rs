//! Key Identifier
//!
//! Defined in RFC 5280 Section 4.2.1.1 and 4.2.1.2
//!
//! ```asn1
//! KeyIdentifier ::= OCTET STRING
//! ```
//!
//! KeyIdentifier is used to identify a public key. It is typically
//! a SHA-1 hash (160 bits / 20 bytes) of the SubjectPublicKeyInfo.

use tsumiki_asn1::OctetString;

/// Key Identifier
///
/// An OCTET STRING used to identify a public key. Typically a SHA-1 hash
/// of the SubjectPublicKeyInfo (20 bytes), but can be any octet string.
///
/// Used in:
/// - SubjectKeyIdentifier extension (RFC 5280 4.2.1.2)
/// - AuthorityKeyIdentifier extension (RFC 5280 4.2.1.1)
/// - SignerIdentifier in CMS/PKCS#7 (RFC 5652)
pub type KeyIdentifier = OctetString;
