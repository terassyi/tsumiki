//! Trait for types that have OIDs with conventional names

/// Trait for types that have OIDs with conventional/standard names
///
/// This trait allows retrieving human-readable names for well-known OIDs.
/// For example, an EC parameter with OID `1.2.840.10045.3.1.7` has the conventional name `secp256r1`.
pub trait OidName {
    /// Returns the conventional name for this type's OID, if it has one
    fn oid_name(&self) -> Option<&'static str>;
}
