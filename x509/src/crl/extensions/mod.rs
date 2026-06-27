//! CRL extensions (RFC 5280 §5.2 global, §5.3 entry).
//!
//! CRL-specific extensions, plus the extensions shared with the certificate
//! profile (AuthorityKeyIdentifier, IssuerAltName, FreshestCRL) re-exported
//! here so the CRL profile presents its complete extension set, mirroring
//! [`crate::cert::extensions`].

use crate::extensions::Extension;

mod crl_number;
mod delta_crl_indicator;
pub mod error;
mod issuing_distribution_point;

pub use crl_number::CrlNumber;
pub use delta_crl_indicator::DeltaCrlIndicator;
pub use issuing_distribution_point::IssuingDistributionPoint;

// Extensions shared with the certificate profile (RFC 5280 §5.2.1/§5.2.2/§5.2.6).
pub use crate::extensions::authority_key_identifier::AuthorityKeyIdentifier;
pub use crate::extensions::freshest_crl::FreshestCRL;
pub use crate::extensions::issuer_alt_name::IssuerAltName;
