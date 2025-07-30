use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};

use crate::{crypto::PublicKeyBytes, proto::state::PeerState};

use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy)]
pub enum ConfigUpdateEvent {
    PeerConnected {
        pubkey: PublicKeyBytes,
        endpoint: SocketAddr,
    },
    PeerDisconnected {
        pubkey: PublicKeyBytes,
    },
    PeerStateChanged {
        pubkey: PublicKeyBytes,
        state: PeerState,
    },
}

pub type ConfigUpdateSender = mpsc::UnboundedSender<ConfigUpdateEvent>;
pub type ConfigUpdateReceiver = mpsc::UnboundedReceiver<ConfigUpdateEvent>;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct PeerConfig {
    pub pub_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<String>,
    // New fields for protocol
    pub is_anchor: bool,  // Can this peer act as an anchor?
    pub persistent: bool, // Should we maintain connection?
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub name: String, // Name of the TUN interface
    pub pubkey: String,
    pub address: String, // Local IP address for the TUN interface
    pub endpoint: Option<SocketAddr>,
    pub secret: String,
    pub peers: Vec<PeerConfig>,
    pub role: PeerRole,
    pub keepalive_interval: u64,
    pub peer_timeout: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum PeerRole {
    Anchor,  // Can accept incoming connections
    Dynamic, // Connects to anchors
}

pub struct RuntimeConfig {
    pub shared_secrets: HashMap<PublicKeyBytes, [u8; 32]>,
    pub ciphers: HashMap<SocketAddr, ChaCha20Poly1305>,
    pub ips: HashMap<SocketAddr, IpAddr>,
    pub ip_to_pubkey: HashMap<IpAddr, PublicKeyBytes>,
}

pub fn load_config(config_path: &str) -> Config {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found! using defaults.");
            let (private_key, public_key) = crate::crypto::generate_keypair();

            let peers: Vec<PeerConfig> = vec![PeerConfig {
                pub_key: base64::encode(public_key),
                endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1194)),
                is_anchor: true,
                persistent: true,
                allowed_ips: vec!["10.0.0.5".to_string()],
            }];

            let conf = Config {
                name: "utun0".to_string(),
                endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1194)),
                address: "10.0.0.1".to_string(),
                secret: base64::encode(private_key),
                pubkey: base64::encode(public_key),
                peers,
                role: PeerRole::Dynamic,
                keepalive_interval: 30, // seconds
                peer_timeout: 300,      // seconds
            };
            std::fs::write(config_path, serde_yml::to_string(&conf).unwrap())
                .expect("Failed to write default config file");
            conf
        }
    }
}
