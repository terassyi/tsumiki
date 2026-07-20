use std::str::FromStr;

use chrono::{NaiveDateTime, Utc};
use clap::Args;
use tsumiki::decoder::Decoder;
use tsumiki_asn1::ASN1Object;
use tsumiki_der::Der;
use tsumiki_x509::crl::extensions::{
    AuthorityKeyIdentifier, CRLNumber, DeltaCRLIndicator, FreshestCRL, IssuerAltName,
    IssuingDistributionPoint,
};
use tsumiki_x509::crl::{CertificateList, TBSCertList};

use crate::error::Result;
use crate::output::OutputFormat;
use crate::utils::read_input;

#[derive(Args)]
pub(crate) struct Config {
    /// Path to the CRL file (PEM or DER format). If not specified, reads from stdin
    file: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    output: OutputFormat,

    /// Show only issuer
    #[arg(long)]
    show_issuer: bool,

    /// Show only update dates (thisUpdate / nextUpdate)
    #[arg(long)]
    show_dates: bool,

    /// Show only the CRL number
    #[arg(long)]
    show_number: bool,

    /// List revoked certificate entries
    #[arg(long)]
    list_revoked: bool,

    /// List CRL extensions
    #[arg(long)]
    list_extensions: bool,

    /// Check whether the CRL is expired (nextUpdate has passed)
    #[arg(long)]
    check_expiry: bool,

    /// Limit the number of revoked entries shown by --list-revoked
    #[arg(long, requires = "list_revoked")]
    max_entries: Option<usize>,
}

impl Config {
    fn should_show_specific_fields(&self) -> bool {
        [
            self.show_issuer,
            self.show_dates,
            self.show_number,
            self.list_revoked,
            self.list_extensions,
            self.check_expiry,
        ]
        .iter()
        .any(|&flag| flag)
    }
}

pub(crate) fn execute(config: Config) -> Result<()> {
    let input_bytes = read_input(config.file.as_deref())?;

    // Parse as PEM first (via `FromStr`), falling back to DER
    // (`Vec<u8>` -> `Der` -> `ASN1Object` -> `CertificateList` via `Decoder`).
    let crl = match String::from_utf8(input_bytes.clone())
        .ok()
        .and_then(|contents| CertificateList::from_str(&contents).ok())
    {
        Some(crl) => crl,
        None => {
            let der: Der = input_bytes.decode()?;
            let asn1_obj: ASN1Object = der.decode()?;
            asn1_obj.decode()?
        }
    };

    // Show only the requested fields if any selector flag is set.
    if config.should_show_specific_fields() {
        return show_specific_fields(&crl, &config);
    }

    match config.output {
        OutputFormat::Text => println!("{}", crl),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&crl)?),
        OutputFormat::Yaml => {
            let value = serde_json::to_value(&crl)?;
            println!("{}", serde_yml::to_string(&value)?);
        }
        OutputFormat::Brief => {
            let tbs = crl.tbs_cert_list();
            println!(
                "Issuer: {} | Revoked: {}",
                tbs.issuer(),
                tbs.revoked_certificates().len()
            );
        }
    }

    Ok(())
}

fn show_specific_fields(crl: &CertificateList, config: &Config) -> Result<()> {
    let tbs = crl.tbs_cert_list();

    let parts = [
        config.show_issuer.then(|| format_issuer(tbs)),
        config.show_dates.then(|| format_dates(tbs)),
        config.show_number.then(|| format_number(tbs)),
        config
            .list_revoked
            .then(|| format_revoked(tbs, config.max_entries)),
        config.list_extensions.then(|| format_extensions(tbs)),
        config.check_expiry.then(|| format_expiry(tbs)),
    ];

    let output = parts
        .into_iter()
        .flatten()
        .collect::<Result<Vec<_>>>()?
        .join("");

    print!("{}", output);

    Ok(())
}

fn format_issuer(tbs: &TBSCertList) -> Result<String> {
    Ok(format!("Issuer: {}\n", tbs.issuer()))
}

fn format_dates(tbs: &TBSCertList) -> Result<String> {
    let next_update = match tbs.next_update() {
        Some(t) => t.as_ref().to_string(),
        None => "NONE".to_string(),
    };
    Ok(format!(
        "Last Update: {}\nNext Update: {}\n",
        tbs.this_update().as_ref(),
        next_update
    ))
}

fn format_number(tbs: &TBSCertList) -> Result<String> {
    let number = tbs
        .crl_extensions()
        .and_then(|exts| exts.extension::<CRLNumber>().ok().flatten());
    Ok(number.map_or_else(
        || "CRL Number: NONE\n".to_string(),
        |n| format!("CRL Number: {}\n", n.number()),
    ))
}

fn format_revoked(tbs: &TBSCertList, max_entries: Option<usize>) -> Result<String> {
    let revoked = tbs.revoked_certificates();
    if revoked.is_empty() {
        return Ok("No Revoked Certificates.\n".to_string());
    }

    let limit = max_entries.unwrap_or(revoked.len());
    let entries: String = revoked
        .iter()
        .take(limit)
        .map(|entry| {
            format!(
                "    Serial Number: {}\n        Revocation Date: {}\n",
                entry.user_certificate(),
                entry.revocation_date().as_ref()
            )
        })
        .collect();

    let omitted = revoked.len().saturating_sub(limit);
    let tail = if omitted > 0 {
        format!("    ... ({} more omitted)\n", omitted)
    } else {
        String::new()
    };

    Ok(format!("Revoked Certificates:\n{}{}", entries, tail))
}

fn format_extensions(tbs: &TBSCertList) -> Result<String> {
    let Some(exts) = tbs.crl_extensions() else {
        return Ok("No CRL extensions.\n".to_string());
    };

    // Mirror the CRL extensions block of `Display for CertificateList`.
    let body: String = [
        exts.extension::<AuthorityKeyIdentifier>()
            .ok()
            .flatten()
            .map(|x| x.to_string()),
        exts.extension::<IssuerAltName>()
            .ok()
            .flatten()
            .map(|x| x.to_string()),
        exts.extension::<CRLNumber>()
            .ok()
            .flatten()
            .map(|x| x.to_string()),
        exts.extension::<DeltaCRLIndicator>()
            .ok()
            .flatten()
            .map(|x| x.to_string()),
        exts.extension::<IssuingDistributionPoint>()
            .ok()
            .flatten()
            .map(|x| x.to_string()),
        exts.extension::<FreshestCRL>()
            .ok()
            .flatten()
            .map(|x| x.to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();

    Ok(format!("CRL extensions:\n{}", body))
}

fn format_expiry(tbs: &TBSCertList) -> Result<String> {
    // Mirror `cert inspect --check-expiry`: exit non-zero when expired so the
    // flag is usable as a scripting/CI predicate. A CRL without nextUpdate has
    // no defined expiry, so it is reported as valid.
    let Some(next_update) = tbs.next_update() else {
        return Ok("CRL is VALID (nextUpdate: NONE)\n".to_string());
    };
    let next: NaiveDateTime = *next_update.as_ref();
    let now = Utc::now().naive_utc();
    if now > next {
        let output = format!(
            "CRL is EXPIRED (nextUpdate was {})\n",
            next.format("%Y-%m-%d %H:%M:%S UTC")
        );
        print!("{}", output);
        std::process::exit(1);
    } else {
        Ok(format!(
            "CRL is VALID (nextUpdate {})\n",
            next.format("%Y-%m-%d %H:%M:%S UTC")
        ))
    }
}
