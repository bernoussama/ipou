use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use std::sync::Arc;
use uuid::Uuid;

/// Connection states for peer connections
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// No connection established
    Disconnected,
    /// Currently attempting to establish connection
    Connecting,
    /// Successfully connected and active
    Connected,
    /// Connection is stale (missed keep-alives) but not yet disconnected
    Stale,
}

/// Tracks the state of a connection with a peer
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Current connection state
    pub state: ConnectionState,
    /// Last known endpoint for this peer
    pub last_endpoint: Option<SocketAddr>,
    /// Session ID for this connection
    pub session_id: Option<[u8; 16]>,
    /// Last time we received a packet from this peer
    pub last_seen: SystemTime,
    /// Last time we sent a keep-alive
    pub last_keepalive_sent: SystemTime,
    /// Number of consecutive missed keep-alives
    pub missed_keepalives: u32,
    /// Current sequence number for outgoing packets
    pub sequence: u64,
    /// Highest sequence number seen from this peer (for replay protection)
    pub last_sequence_received: u64,
}

impl ConnectionInfo {
    pub fn new() -> Self {
        let now = SystemTime::now();
        Self {
            state: ConnectionState::Disconnected,
            last_endpoint: None,
            session_id: None,
            last_seen: now,
            last_keepalive_sent: now,
            missed_keepalives: 0,
            sequence: 0,
            last_sequence_received: 0,
        }
    }

    /// Update the connection state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Mark that we received a packet from this peer
    pub fn mark_packet_received(&mut self, sequence: u64) {
        self.last_seen = SystemTime::now();
        self.missed_keepalives = 0;
        if sequence > self.last_sequence_received {
            self.last_sequence_received = sequence;
        }
    }

    /// Get the next sequence number for outgoing packets
    pub fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Check if this connection is stale (hasn't received packets recently)
    pub fn is_stale(&self, timeout_seconds: u64) -> bool {
        if let Ok(duration) = self.last_seen.duration_since(UNIX_EPOCH) {
            let now_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now_seconds.saturating_sub(duration.as_secs()) > timeout_seconds
        } else {
            true
        }
    }

    /// Check if we need to send a keep-alive
    pub fn needs_keepalive(&self, interval_seconds: u64) -> bool {
        if let Ok(duration) = self.last_keepalive_sent.duration_since(UNIX_EPOCH) {
            let now_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now_seconds.saturating_sub(duration.as_secs()) >= interval_seconds
        } else {
            true
        }
    }

    /// Mark that we sent a keep-alive
    pub fn mark_keepalive_sent(&mut self) {
        self.last_keepalive_sent = SystemTime::now();
    }

    /// Increment missed keep-alive counter
    pub fn increment_missed_keepalives(&mut self) {
        self.missed_keepalives += 1;
    }
}

/// Manages connection state for all peers
#[derive(Debug, Clone)]
pub struct StateManager {
    /// Map from peer public key to connection info
    connections: Arc<RwLock<HashMap<[u8; 32], ConnectionInfo>>>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get connection info for a peer
    pub async fn get_connection(&self, peer_key: &[u8; 32]) -> Option<ConnectionInfo> {
        let connections = self.connections.read().await;
        connections.get(peer_key).cloned()
    }

    /// Update connection info for a peer
    pub async fn update_connection(&self, peer_key: [u8; 32], info: ConnectionInfo) {
        let mut connections = self.connections.write().await;
        connections.insert(peer_key, info);
    }

    /// Set the state for a peer connection
    pub async fn set_peer_state(&self, peer_key: [u8; 32], state: ConnectionState) {
        let mut connections = self.connections.write().await;
        let info = connections.entry(peer_key).or_insert_with(ConnectionInfo::new);
        info.set_state(state);
    }

    /// Mark that we received a packet from a peer
    pub async fn mark_packet_received(&self, peer_key: [u8; 32], sequence: u64, endpoint: SocketAddr) {
        let mut connections = self.connections.write().await;
        let info = connections.entry(peer_key).or_insert_with(ConnectionInfo::new);
        info.mark_packet_received(sequence);
        info.last_endpoint = Some(endpoint);
    }

    /// Get the next sequence number for a peer
    pub async fn next_sequence(&self, peer_key: [u8; 32]) -> u64 {
        let mut connections = self.connections.write().await;
        let info = connections.entry(peer_key).or_insert_with(ConnectionInfo::new);
        info.next_sequence()
    }

    /// Get all peers that need keep-alive packets
    pub async fn peers_needing_keepalive(&self, interval_seconds: u64) -> Vec<([u8; 32], SocketAddr)> {
        let connections = self.connections.read().await;
        let mut result = Vec::new();
        
        for (peer_key, info) in connections.iter() {
            if info.state == ConnectionState::Connected && info.needs_keepalive(interval_seconds) {
                if let Some(endpoint) = info.last_endpoint {
                    result.push((*peer_key, endpoint));
                }
            }
        }
        
        result
    }

    /// Get all stale connections
    pub async fn stale_connections(&self, timeout_seconds: u64) -> Vec<[u8; 32]> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .filter(|(_, info)| info.state == ConnectionState::Connected && info.is_stale(timeout_seconds))
            .map(|(key, _)| *key)
            .collect()
    }

    /// Generate a new session ID
    pub fn generate_session_id() -> [u8; 16] {
        let uuid = Uuid::new_v4();
        *uuid.as_bytes()
    }

    /// Set session ID for a peer
    pub async fn set_session_id(&self, peer_key: [u8; 32], session_id: [u8; 16]) {
        let mut connections = self.connections.write().await;
        let info = connections.entry(peer_key).or_insert_with(ConnectionInfo::new);
        info.session_id = Some(session_id);
    }

    /// Get session ID for a peer
    pub async fn get_session_id(&self, peer_key: &[u8; 32]) -> Option<[u8; 16]> {
        let connections = self.connections.read().await;
        connections.get(peer_key)?.session_id
    }
}