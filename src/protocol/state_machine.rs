use crate::config::{Config, PeerRole};
use crate::protocol::discovery::DiscoveryManager;
use crate::protocol::handshake::HandshakeManager;
use crate::protocol::keepalive::KeepaliveManager;
use crate::protocol::punch::PunchManager;
use crate::protocol::{PacketType, ProtocolPacket};
use crate::state::{ConnectionState, StateManager};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval};

/// Main protocol state machine that coordinates all protocol components
pub struct ProtocolStateMachine {
    config: Config,
    our_public_key: [u8; 32],
    state_manager: StateManager,
    handshake_manager: HandshakeManager,
    discovery_manager: DiscoveryManager,
    punch_manager: PunchManager,
    keepalive_manager: KeepaliveManager,
    send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl ProtocolStateMachine {
    pub fn new(
        config: Config,
        our_public_key: [u8; 32],
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> Self {
        let state_manager = StateManager::new();

        let handshake_manager = HandshakeManager::new(state_manager.clone(), our_public_key);
        let discovery_manager = DiscoveryManager::new(state_manager.clone(), our_public_key);
        let punch_manager = PunchManager::new(state_manager.clone(), our_public_key);
        let keepalive_manager = KeepaliveManager::new(state_manager.clone(), our_public_key);

        Self {
            config,
            our_public_key,
            state_manager,
            handshake_manager,
            discovery_manager,
            punch_manager,
            keepalive_manager,
            send_channel,
        }
    }

    /// Start the protocol state machine
    pub async fn start(&self, our_endpoint: SocketAddr) -> crate::Result<()> {
        println!("Starting protocol state machine for endpoint: {}", our_endpoint);

        // Start background tasks
        self.start_keepalive_task(our_endpoint).await;
        self.start_connection_monitor().await;
        self.start_initial_connections().await?;

        Ok(())
    }

    /// Handle incoming protocol packets
    pub async fn handle_protocol_packet(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
    ) -> crate::Result<()> {
        // Update discovery manager with this peer's endpoint
        self.discovery_manager
            .mark_peer_seen(packet.sender_id, sender_endpoint)
            .await;

        match packet.packet_type {
            PacketType::HandshakeInit => {
                self.handshake_manager
                    .handle_handshake_init(packet, sender_endpoint, self.send_channel.clone())
                    .await?;
            }
            PacketType::HandshakeResponse => {
                self.handshake_manager
                    .handle_handshake_response(packet, sender_endpoint)
                    .await?;
            }
            PacketType::RequestEndpoint => {
                self.discovery_manager
                    .handle_endpoint_request(packet, sender_endpoint, self.send_channel.clone())
                    .await?;
            }
            PacketType::EndpointInfo => {
                let sender_id = packet.sender_id; // Extract before moving
                if let Some(target_endpoint) = self
                    .discovery_manager
                    .handle_endpoint_info(packet, sender_endpoint)
                    .await?
                {
                    // Got endpoint info for a peer - try to establish connection
                    self.initiate_connection_to_peer(sender_id, target_endpoint)
                        .await?;
                }
            }
            PacketType::InitiatePunch => {
                self.punch_manager
                    .handle_initiate_punch(
                        packet,
                        sender_endpoint,
                        self.send_channel.clone(),
                        self.config.protocol.max_punch_attempts,
                        self.config.protocol.punch_timeout,
                    )
                    .await?;
            }
            PacketType::Keepalive => {
                self.keepalive_manager
                    .handle_keepalive(packet, sender_endpoint)
                    .await?;
            }
            PacketType::VpnData => {
                // This should be handled by the main VPN packet processing
                // For now, just mark that we received a packet from this peer
                self.state_manager
                    .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
                    .await;
            }
        }

        Ok(())
    }

    /// Start initial connections to configured peers
    async fn start_initial_connections(&self) -> crate::Result<()> {
        for peer_config in &self.config.peers {
            let peer_key = self.parse_peer_key(&peer_config.public_key)?;

            match peer_config.role {
                PeerRole::Anchor => {
                    if let Some(endpoint) = peer_config.endpoint {
                        // Directly connect to anchor peers
                        self.handshake_manager
                            .initiate_handshake(peer_key, endpoint, self.send_channel.clone())
                            .await?;
                    }
                }
                PeerRole::Dynamic => {
                    // For dynamic peers, we need to discover them through anchors
                    self.discover_dynamic_peer(peer_key, &peer_config.anchors)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Discover a dynamic peer through its configured anchors
    async fn discover_dynamic_peer(
        &self,
        target_peer: [u8; 32],
        anchor_keys: &[String],
    ) -> crate::Result<()> {
        for anchor_key_str in anchor_keys {
            let anchor_key = self.parse_peer_key(anchor_key_str)?;
            
            // Check if we know this anchor's endpoint
            if let Some(anchor_endpoint) = self.discovery_manager.get_peer_endpoint(&anchor_key).await {
                // Our endpoint - this should come from the socket binding
                let our_endpoint = SocketAddr::from(([0, 0, 0, 0], self.config.port.unwrap_or(51820)));
                
                self.discovery_manager
                    .request_peer_endpoint(
                        target_peer,
                        anchor_key,
                        anchor_endpoint,
                        our_endpoint,
                        self.send_channel.clone(),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Initiate connection to a discovered peer
    async fn initiate_connection_to_peer(
        &self,
        target_peer: [u8; 32],
        target_endpoint: SocketAddr,
    ) -> crate::Result<()> {
        // Check if we're already connected
        if let Some(connection) = self.state_manager.get_connection(&target_peer).await {
            if connection.state == ConnectionState::Connected {
                return Ok(());
            }
        }

        // Initiate handshake
        self.handshake_manager
            .initiate_handshake(target_peer, target_endpoint, self.send_channel.clone())
            .await?;

        Ok(())
    }

    /// Start keep-alive background task
    async fn start_keepalive_task(&self, our_endpoint: SocketAddr) {
        let keepalive_manager = self.keepalive_manager.clone();
        let send_channel = self.send_channel.clone();
        let interval_seconds = self.config.protocol.keepalive_interval;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_seconds));

            loop {
                ticker.tick().await;

                if let Err(e) = keepalive_manager
                    .send_keepalives(our_endpoint, interval_seconds, send_channel.clone())
                    .await
                {
                    eprintln!("Error sending keepalives: {}", e);
                }
            }
        });
    }

    /// Start connection monitoring background task
    async fn start_connection_monitor(&self) {
        let keepalive_manager = self.keepalive_manager.clone();
        let timeout_seconds = self.config.protocol.connection_timeout;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30)); // Check every 30 seconds

            loop {
                ticker.tick().await;

                if let Err(e) = keepalive_manager.check_stale_connections(timeout_seconds).await {
                    eprintln!("Error checking stale connections: {}", e);
                }
            }
        });
    }

    /// Parse a peer key from base64 string
    fn parse_peer_key(&self, key_str: &str) -> crate::Result<[u8; 32]> {
        let key_bytes = base64::decode(key_str)?;
        if key_bytes.len() != 32 {
            return Err(crate::IpouError::InvalidKeyLength(key_bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Get the state manager (for integration with existing code)
    pub fn state_manager(&self) -> &StateManager {
        &self.state_manager
    }

    /// Get connection statistics
    pub async fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        stats.insert("active_punch_sessions".to_string(), 
                    self.punch_manager.active_sessions_count().await as u64);
        // Add more stats as needed
        stats
    }
}