use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use chacha20poly1305::ChaCha20Poly1305;

pub mod error;
pub mod net;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub secret: String,
    pub pubkey: String,
    pub peers: HashMap<IpAddr, Peer>,
}

pub struct RuntimeConfig {
    pub shared_secrets: HashMap<IpAddr, [u8; 32]>,
    pub ciphers: HashMap<IpAddr, ChaCha20Poly1305>,
    pub ips: HashMap<SocketAddr, IpAddr>,
}
