use std::{net::SocketAddr, sync::Arc};

use crate::{
    config::{ConfigUpdateEvent, ConfigUpdateSender, PeerState},
    crypto::PublicKeyBytes,
};

#[derive(Debug, Clone)]
pub struct PeerConnection {
    pub pubkey: PublicKeyBytes,
    pub last_endpoint: Option<SocketAddr>,
    pub last_seen: u64,
    pub state: PeerState,
    config_update_tx: Arc<ConfigUpdateSender>,
}

impl PeerConnection {
    pub fn new(pubkey: PublicKeyBytes) -> Self {
        let (tx, _) = crate::config::config_update_channel();
        Self {
            pubkey,
            last_endpoint: None,
            last_seen: 0,
            state: PeerState::Disconnected,
            config_update_tx: tx,
        }
    }

    pub fn with_update_sender(
        pubkey: PublicKeyBytes,
        config_update_tx: Arc<ConfigUpdateSender>,
    ) -> Self {
        Self {
            pubkey,
            last_endpoint: None,
            last_seen: 0,
            state: PeerState::Disconnected,
            config_update_tx,
        }
    }

    pub fn mark_connected(&mut self, endpoint: SocketAddr) {
        self.last_endpoint = Some(endpoint);
        self.state = PeerState::Connected;
        let tx = self.config_update_tx.clone();
        let pubkey = self.pubkey;
        tokio::spawn(async move {
            tx.send(ConfigUpdateEvent::PeerConnected {
                pubkey,
                endpoint,
            })
            .await;
        });
    }

    pub fn mark_disconnected(&mut self) {
        self.state = PeerState::Disconnected;
        let tx = self.config_update_tx.clone();
        let pubkey = self.pubkey;
        tokio::spawn(async move {
            tx.send(ConfigUpdateEvent::PeerDisconnected { pubkey })
                .await;
        });
    }

    pub fn is_connected(&self) -> bool {
        self.state == PeerState::Connected
    }
}
