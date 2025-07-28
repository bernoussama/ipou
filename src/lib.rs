use std::net::SocketAddr;

// modules
pub mod cli;
pub mod config;
pub mod crypto;
pub mod net;
pub mod proto;
pub mod tasks;

// Constants
pub const MTU: usize = 1420;
const MAX_UDP_SIZE: usize = (1 << 16) - 1;
pub const CHANNEL_BUFFER_SIZE: usize = MTU + 512; // Buffered channels
pub const ENCRYPTION_OVERHEAD: usize = 28; // 12 nonce + 16 auth tag
pub const KEEPALIVE_INTERVAL: u64 = 26;

// types
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}

pub type DecryptedPacket = Vec<u8>;
#[derive(Debug, Clone)]
pub enum TunMessage {
    DecryptedPacket,
    Shutdown,
}

pub type EncryptedPacket = (Vec<u8>, SocketAddr);
#[derive(Debug, Clone)]
pub enum UdpMessage {
    EncryptedPacket,
    Shutdown,
}

// errors
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

    #[error(" bincode decoding error: {0}")]
    DecodeError(#[from] bincode::error::DecodeError),
    #[error(" bincode encoding error: {0}")]
    EncodeError(#[from] bincode::error::EncodeError),

    #[error(" invalid packet type error: {0}")]
    InvalidPacketType(u8),
}

pub type Result<T> = std::result::Result<T, IpouError>;
