use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("dummy")]
    Dummy,
    #[error("parser error {0:?}")]
    Parser(nom::error::ErrorKind),
}
