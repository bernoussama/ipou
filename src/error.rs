use std::io;
use std::net::AddrParseError;

#[derive(thiserror::Error, Debug)]
pub enum IpouError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("CLI error: {0}")]
    Cli(String),

    #[error("Packet parsing error: {0}")]
    Packet(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("TUN device error: {0}")]
    Tun(#[from] tun::Error),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] AddrParseError),

    #[error("Channel send error")]
    ChannelSend,

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, IpouError>;