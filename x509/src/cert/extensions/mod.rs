//! Certificate-specific X.509 v3 extensions.
//!
//! These extensions apply to certificates only. The extension machinery (the
//! [`crate::extensions::Extension`] trait, the `Extensions` container) and the
//! types reused by both certificates and CRLs live in the shared
//! [`crate::extensions`] module.

use serde::Serialize;
use tsumiki_pkix_types::OidName;

use crate::error::Error;
use crate::extensions::{Extension, Extensions, RawExtension};

// Extensions shared with the CRL profile are implemented in `crate::extensions`
// but re-exported here so the certificate profile exposes a complete extension
// set under `cert::extensions`.
pub use crate::extensions::authority_key_identifier::AuthorityKeyIdentifier;
pub use crate::extensions::freshest_crl::FreshestCRL;
pub use crate::extensions::issuer_alt_name::IssuerAltName;

mod authority_info_access;
mod basic_constraints;
mod certificate_policies;
mod crl_distribution_points;
pub mod error;
mod extended_key_usage;
mod inhibit_any_policy;
mod key_usage;
mod name_constraints;
mod policy_constraints;
mod policy_mappings;
mod subject_alt_name;
mod subject_directory_attributes;
mod subject_info_access;
mod subject_key_identifier;

pub use authority_info_access::{AccessDescription, AuthorityInfoAccess};
pub use basic_constraints::BasicConstraints;
pub use certificate_policies::{
    CertPolicyId, CertificatePolicies, NoticeReference, PolicyInformation, PolicyQualifierInfo,
    Qualifier, UserNotice,
};
pub use crl_distribution_points::CRLDistributionPoints;
pub use extended_key_usage::ExtendedKeyUsage;
pub use inhibit_any_policy::InhibitAnyPolicy;
pub use key_usage::KeyUsage;
pub use name_constraints::{GeneralSubtree, NameConstraints};
pub use policy_constraints::{PolicyConstraints, SkipCerts};
pub use policy_mappings::{PolicyMapping, PolicyMappings};
pub use subject_alt_name::SubjectAltName;
pub use subject_directory_attributes::{SubjectDirectoryAttribute, SubjectDirectoryAttributes};
pub use subject_info_access::SubjectInfoAccess;
pub use subject_key_identifier::SubjectKeyIdentifier;

/// ParsedExtensions holds all parsed extension types for JSON serialization
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ParsedExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) basic_constraints: Option<BasicConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_usage: Option<KeyUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extended_key_usage: Option<ExtendedKeyUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject_key_identifier: Option<SubjectKeyIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authority_key_identifier: Option<AuthorityKeyIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject_alt_name: Option<SubjectAltName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issuer_alt_name: Option<IssuerAltName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crl_distribution_points: Option<CRLDistributionPoints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) certificate_policies: Option<CertificatePolicies>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_mappings: Option<PolicyMappings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authority_info_access: Option<AuthorityInfoAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name_constraints: Option<NameConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_constraints: Option<PolicyConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) inhibit_any_policy: Option<InhibitAnyPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) freshest_crl: Option<FreshestCRL>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject_info_access: Option<SubjectInfoAccess>,
    // SubjectDirectoryAttributes currently has no Serialize impl because
    // AttributeValue is held as raw asn1 Element; skip it in JSON output.
    #[serde(skip)]
    pub(crate) subject_directory_attributes: Option<SubjectDirectoryAttributes>,
}

impl ParsedExtensions {
    pub(crate) fn from_extensions(extensions: &Extensions) -> Result<Self, Error> {
        let mut raw = ParsedExtensions {
            basic_constraints: None,
            key_usage: None,
            extended_key_usage: None,
            subject_key_identifier: None,
            authority_key_identifier: None,
            subject_alt_name: None,
            issuer_alt_name: None,
            crl_distribution_points: None,
            certificate_policies: None,
            policy_mappings: None,
            authority_info_access: None,
            name_constraints: None,
            policy_constraints: None,
            inhibit_any_policy: None,
            freshest_crl: None,
            subject_info_access: None,
            subject_directory_attributes: None,
        };

        for ext in extensions.extensions() {
            match ext.oid().to_string().as_str() {
                BasicConstraints::OID => {
                    raw.basic_constraints = Some(ext.parse::<BasicConstraints>()?);
                }
                KeyUsage::OID => {
                    raw.key_usage = Some(ext.parse::<KeyUsage>()?);
                }
                ExtendedKeyUsage::OID => {
                    raw.extended_key_usage = Some(ext.parse::<ExtendedKeyUsage>()?);
                }
                SubjectKeyIdentifier::OID => {
                    raw.subject_key_identifier = Some(ext.parse::<SubjectKeyIdentifier>()?);
                }
                AuthorityKeyIdentifier::OID => {
                    raw.authority_key_identifier = Some(ext.parse::<AuthorityKeyIdentifier>()?);
                }
                SubjectAltName::OID => {
                    raw.subject_alt_name = Some(ext.parse::<SubjectAltName>()?);
                }
                IssuerAltName::OID => {
                    raw.issuer_alt_name = Some(ext.parse::<IssuerAltName>()?);
                }
                CRLDistributionPoints::OID => {
                    raw.crl_distribution_points = Some(ext.parse::<CRLDistributionPoints>()?);
                }
                CertificatePolicies::OID => {
                    raw.certificate_policies = Some(ext.parse::<CertificatePolicies>()?);
                }
                PolicyMappings::OID => {
                    raw.policy_mappings = Some(ext.parse::<PolicyMappings>()?);
                }
                AuthorityInfoAccess::OID => {
                    raw.authority_info_access = Some(ext.parse::<AuthorityInfoAccess>()?);
                }
                NameConstraints::OID => {
                    raw.name_constraints = Some(ext.parse::<NameConstraints>()?);
                }
                PolicyConstraints::OID => {
                    raw.policy_constraints = Some(ext.parse::<PolicyConstraints>()?);
                }
                InhibitAnyPolicy::OID => {
                    raw.inhibit_any_policy = Some(ext.parse::<InhibitAnyPolicy>()?);
                }
                FreshestCRL::OID => {
                    raw.freshest_crl = Some(ext.parse::<FreshestCRL>()?);
                }
                SubjectInfoAccess::OID => {
                    raw.subject_info_access = Some(ext.parse::<SubjectInfoAccess>()?);
                }
                SubjectDirectoryAttributes::OID => {
                    raw.subject_directory_attributes =
                        Some(ext.parse::<SubjectDirectoryAttributes>()?);
                }
                _ => {
                    // Unknown extension, skip
                }
            }
        }

        Ok(raw)
    }
}

/// Maps an extension OID to its short name (used in openssl-style output).
impl OidName for RawExtension {
    fn oid_name(&self) -> Option<&'static str> {
        match self.oid().to_string().as_str() {
            SubjectKeyIdentifier::OID => Some("subjectKeyIdentifier"),
            KeyUsage::OID => Some("keyUsage"),
            SubjectAltName::OID => Some("subjectAltName"),
            IssuerAltName::OID => Some("issuerAltName"),
            BasicConstraints::OID => Some("basicConstraints"),
            NameConstraints::OID => Some("nameConstraints"),
            CRLDistributionPoints::OID => Some("cRLDistributionPoints"),
            CertificatePolicies::OID => Some("certificatePolicies"),
            PolicyMappings::OID => Some("policyMappings"),
            AuthorityKeyIdentifier::OID => Some("authorityKeyIdentifier"),
            PolicyConstraints::OID => Some("policyConstraints"),
            ExtendedKeyUsage::OID => Some("extKeyUsage"),
            FreshestCRL::OID => Some("freshestCRL"),
            InhibitAnyPolicy::OID => Some("inhibitAnyPolicy"),
            AuthorityInfoAccess::OID => Some("authorityInfoAccess"),
            SubjectInfoAccess::OID => Some("subjectInfoAccess"),
            SubjectDirectoryAttributes::OID => Some("subjectDirectoryAttributes"),
            _ => None,
        }
    }
}
