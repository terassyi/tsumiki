use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("parser error {0:?}")]
    Parser(nom::error::ErrorKind),
    #[error("parser incomplete: {0:?}")]
    ParserIncomplete(nom::Needed),
    #[error("pem: {0}")]
    Pem(pem::error::Error),
}
