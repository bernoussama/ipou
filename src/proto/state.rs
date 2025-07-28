use std::net::SocketAddr;

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
pub struct PeerConnection {
    pub pubkey: PublicKeyBytes,
    pub state: PeerState,
    pub last_endpoint: Option<SocketAddr>,
    pub last_seen: Timestamp,
    pub failed_attempts: u16,
    config_update_tx: Option<ConfigUpdateSender>, // Add this field
}

impl PeerConnection {
    pub fn new(pubkey: PublicKeyBytes) -> Self {
        Self {
            pubkey,
            state: PeerState::Unknown,
            last_endpoint: None,
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

    pub fn mark_connected(&mut self, endpoint: SocketAddr) {
        self.state = PeerState::Connected;
        self.last_endpoint = Some(endpoint);
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
