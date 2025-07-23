use std::net::SocketAddr;

pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod net;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}

#[derive(thiserror::Error, Debug)]
pub enum IpouError {
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parsing error: {0}")]
    SerdeYml(#[from] serde_yml::Error),
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    #[error("TUN device creation failed: {0}")]
    TunDevice(#[from] tun::Error),
}

pub type Result<T> = std::result::Result<T, IpouError>;
