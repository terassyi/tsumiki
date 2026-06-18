//! X.509 certificate parsing and handling with full v3 extensions support.
//!
//! The crate is organized into:
//! - [`cert`]: the [`Certificate`](cert::Certificate) structure and its
//!   certificate-specific extensions ([`cert::extensions`]).
//! - [`extensions`]: the shared extension machinery (the
//!   [`Extension`](extensions::Extension) trait and `Extensions` container) and
//!   the types reused across X.509 documents (`GeneralName`,
//!   `AuthorityKeyIdentifier`, `DistributionPoint`, ...).
//! - [`error`]: error types shared across the crate.
//!
//! Types are accessed module-qualified, e.g. `tsumiki_x509::cert::Certificate`.

#![forbid(unsafe_code)]

pub mod cert;
pub mod error;
pub mod extensions;
