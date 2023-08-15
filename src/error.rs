use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("can't find cmdline (/cmdline.txt) on boot partition")]
    NoCmdline,
    #[error("can't find disk device")]
    NoDiskDev,
    #[error("no private keys found in file")]
    NoPrivateKeys,
    #[error("no rootfs set in active cmdline")]
    RootdevUnset,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("actix_web: {0}")]
    ActixWeb(#[from] actix_web::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
