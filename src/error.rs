use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no private keys found in file")]
    NoPrivateKeys,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
