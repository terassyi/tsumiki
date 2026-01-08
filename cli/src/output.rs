#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    /// Human-readable text format (OpenSSL-like)
    Text,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
}
