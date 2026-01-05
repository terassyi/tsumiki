#[derive(Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text format (OpenSSL-like)
    Text,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
}
