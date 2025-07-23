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
