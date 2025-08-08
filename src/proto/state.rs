use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use chacha20poly1305::ChaCha20Poly1305;
use tokio::sync::RwLock;

use crate::{
    config::{ConfigUpdateEvent, ConfigUpdateSender},
    crypto::PublicKeyBytes,
    proto::{self, Timestamp},
};

#[derive(Debug, Clone, Copy)]
pub enum PeerState {
    Unknown,
    Connecting,
    Connected,
    Stale,  // havent heard from peer in a while
    Failed, // Connection attemps failed
}

#[derive(Debug)]
pub struct Peer {
    pub pubkey: PublicKeyBytes,
    pub state: PeerState,
    pub last_endpoint: Option<SocketAddr>,
    pub private_ip: Option<IpAddr>, // Added from RuntimeConfig
    pub last_seen: Timestamp,
    pub failed_attempts: u16,
    config_update_tx: Option<ConfigUpdateSender>, // Add this field
}

impl Peer {
    pub fn new(pubkey: PublicKeyBytes) -> Self {
        Self {
            pubkey,
            state: PeerState::Unknown,
            last_endpoint: None,
            private_ip: None,
            last_seen: 0,
            failed_attempts: 0,
            config_update_tx: None,
        }
    }
    pub fn with_update_sender(pubkey: PublicKeyBytes, tx: ConfigUpdateSender) -> Self {
        Self {
            pubkey,
            state: PeerState::Unknown,
            last_endpoint: None,
            private_ip: None,
            last_seen: 0,
            failed_attempts: 0,
            config_update_tx: Some(tx),
        }
    }

    pub fn mark_connecting(&mut self) {
        self.state = PeerState::Connecting;

        #[cfg(debug_assertions)]
        println!("Peer {} is now connecting", base64::encode(self.pubkey));
    }

    pub fn mark_connected(&mut self, endpoint: SocketAddr, private_ip: IpAddr) {
        self.state = PeerState::Connected;
        self.last_endpoint = Some(endpoint);
        self.private_ip = Some(private_ip);
        self.last_seen = proto::now();
        self.failed_attempts = 0;

        // Emit config update event
        if let Some(tx) = &self.config_update_tx {
            let _ = tx.send(ConfigUpdateEvent::PeerConnected {
                pubkey: self.pubkey,
                endpoint,
            });
        }

        #[cfg(debug_assertions)]
        println!(
            "Peer {} is now connected at {endpoint:?}",
            base64::encode(self.pubkey)
        );
    }

    pub fn mark_stale(&mut self) {
        self.state = PeerState::Stale;

        // Emit config update event
        if let Some(tx) = &self.config_update_tx {
            let _ = tx.send(ConfigUpdateEvent::PeerStateChanged {
                pubkey: self.pubkey,
                state: PeerState::Stale,
            });
        }
        #[cfg(debug_assertions)]
        println!("Peer {} is now stale", base64::encode(self.pubkey));
    }
    pub fn mark_failed(&mut self) {
        self.state = PeerState::Failed;
        self.failed_attempts += 1;

        if let Some(tx) = &self.config_update_tx {
            let _ = tx.send(ConfigUpdateEvent::PeerStateChanged {
                pubkey: self.pubkey,
                state: PeerState::Failed,
            });
        }
        #[cfg(debug_assertions)]
        println!(
            "Peer {} connection failed, attempts: {}",
            base64::encode(self.pubkey),
            self.failed_attempts
        );
    }
    pub fn seen(&mut self) {
        self.last_seen = proto::now();
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, PeerState::Connected)
    }

    pub fn is_stale(&self) -> bool {
        matches!(self.state, PeerState::Stale)
    }
}

pub struct VpnState {
    // This holds all peers, keyed by their public key.
    pub peers: RwLock<HashMap<PublicKeyBytes, Peer>>,

    // This maps private IPs to ciphers.
    pub ciphers: RwLock<HashMap<IpAddr, ChaCha20Poly1305>>,

    // This maps private IPs to public keys for quick lookup.
    pub ip_to_pubkey: RwLock<HashMap<IpAddr, PublicKeyBytes>>,

    // This maps public endpoints to public keys for incoming packets.
    pub endpoint_to_pubkey: RwLock<HashMap<SocketAddr, PublicKeyBytes>>,

    // Shared secrets are still needed to generate ciphers.
    // They are derived from the config, so they can be pre-calculated.
    pub shared_secrets: HashMap<PublicKeyBytes, [u8; 32]>,
}
