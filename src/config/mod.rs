use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::crypto::PublicKeyBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    Anchor,
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub pub_key: String,
    pub role: PeerRole,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub pubkey: String,
    pub secret: String,
    pub role: PeerRole,
    pub listen_port: u16,
    pub address: String,
    pub peers: Vec<PeerConfig>,
}

pub struct RuntimeConfig {
    pub ciphers: HashMap<PublicKeyBytes, ChaCha20Poly1305>,
    pub shared_secrets: HashMap<PublicKeyBytes, [u8; 32]>,
    pub current_endpoints: HashMap<PublicKeyBytes, SocketAddr>,
    pub ips: HashMap<SocketAddr, IpAddr>,
    pub ip_to_pubkey: HashMap<IpAddr, PublicKeyBytes>,
}

impl Debug for RuntimeConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("RuntimeConfig")
            .field("shared_secrets", &self.shared_secrets)
            .field("current_endpoints", &self.current_endpoints)
            .field("ips", &self.ips)
            .field("ip_to_pubkey", &self.ip_to_pubkey)
            .finish()
    }
}

impl RuntimeConfig {
    pub fn new() -> Self {
        Self {
            ciphers: HashMap::new(),
            shared_secrets: HashMap::new(),
            current_endpoints: HashMap::new(),
            ips: HashMap::new(),
            ip_to_pubkey: HashMap::new(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connected,
    Disconnected,
}

#[derive(Debug)]
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

#[derive(Debug, Clone)]
pub struct ConfigUpdateSender(pub Sender<ConfigUpdateEvent>);

impl ConfigUpdateSender {
    pub async fn send(&self, event: ConfigUpdateEvent) {
        if let Err(e) = self.0.send(event).await {
            eprintln!("Failed to send config update event: {e}");
        }
    }
}

pub type ConfigUpdateReceiver = Receiver<ConfigUpdateEvent>;

pub fn config_update_channel() -> (Arc<ConfigUpdateSender>, ConfigUpdateReceiver) {
    let (tx, rx) = mpsc::channel(100);
    (Arc::new(ConfigUpdateSender(tx)), rx)
}
