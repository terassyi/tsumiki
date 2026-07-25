//! X.509 certificate parsing and handling with full v3 extensions support.
//!
//! The crate is organized into:
//! - [`cert`]: the [`Certificate`](cert::Certificate) structure and its
//!   certificate-specific extensions ([`cert::extensions`]).
//! - [`crl`]: the [`CertificateList`](crl::CertificateList) (CRL) structure
//!   (RFC 5280 §5).
//! - [`extensions`]: the shared extension machinery (the
//!   [`Extension`](extensions::Extension) trait and `Extensions` container) and
//!   the types reused across X.509 documents (`GeneralName`,
//!   `AuthorityKeyIdentifier`, `DistributionPoint`, ...).
//! - [`error`]: error types shared across the crate.
//!
//! Types are accessed module-qualified, e.g. `tsumiki_x509::cert::Certificate`.

#![forbid(unsafe_code)]

use error::Error;
use tsumiki_der::tlv_spans;

pub mod cert;
pub mod crl;
pub mod error;
pub mod extensions;

/// Slices the exact DER of the signed portion (the tbs structure) out of the
/// original bytes of a `Certificate` / `CertificateList`.
///
/// The tbs is the first inner TLV of the outer SEQUENCE. This walks the tag and
/// length octets (via [`tlv_spans`]) to locate that TLV and returns a copy of
/// its exact bytes — no re-decoding or re-encoding, so the result is byte-for-byte
/// what was signed. Used to expose `tbs_der()` for signature verification.
pub(crate) fn capture_tbs_der(der_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let (outer_header, _outer_content) = tlv_spans(der_bytes)?;
    let region = der_bytes
        .get(outer_header..)
        .ok_or(Error::TbsCaptureFailed)?;
    let (tbs_header, tbs_content) = tlv_spans(region)?;
    let end = tbs_header
        .checked_add(tbs_content)
        .ok_or(Error::TbsCaptureFailed)?;
    region
        .get(..end)
        .map(<[u8]>::to_vec)
        .ok_or(Error::TbsCaptureFailed)
}
