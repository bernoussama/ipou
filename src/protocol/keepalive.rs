use crate::protocol::{Keepalive, PacketType, ProtocolPacket};
use crate::state::{ConnectionState, StateManager};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Manages keep-alive packets for connection maintenance
#[derive(Clone)]
pub struct KeepaliveManager {
    state_manager: StateManager,
    our_public_key: [u8; 32],
}

impl KeepaliveManager {
    pub fn new(state_manager: StateManager, public_key: [u8; 32]) -> Self {
        Self {
            state_manager,
            our_public_key: public_key,
        }
    }

    /// Send keep-alive packets to all connected peers that need them
    pub async fn send_keepalives(
        &self,
        our_endpoint: SocketAddr,
        interval_seconds: u64,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        let peers_needing_keepalive = self
            .state_manager
            .peers_needing_keepalive(interval_seconds)
            .await;

        for (peer_key, peer_endpoint) in peers_needing_keepalive {
            if let Err(e) = self
                .send_keepalive_to_peer(peer_key, peer_endpoint, our_endpoint, &send_channel)
                .await
            {
                eprintln!("Failed to send keepalive to peer {:?}: {}", peer_key, e);
            }
        }

        Ok(())
    }

    /// Send a keep-alive packet to a specific peer
    async fn send_keepalive_to_peer(
        &self,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        our_endpoint: SocketAddr,
        send_channel: &mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let keepalive = Keepalive {
            timestamp,
            current_endpoint: our_endpoint,
        };

        // Serialize keepalive payload
        let payload = serde_yml::to_string(&keepalive)?.into_bytes();

        // Get session ID if we have one
        let session_id = self
            .state_manager
            .get_session_id(&peer_key)
            .await
            .unwrap_or_else(|| StateManager::generate_session_id());

        let sequence = self.state_manager.next_sequence(peer_key).await;

        // Create protocol packet
        let packet = ProtocolPacket::new(
            PacketType::Keepalive,
            self.our_public_key,
            session_id,
            sequence,
            payload,
        );

        // Send packet
        let packet_bytes = packet.to_bytes()?;
        if let Err(e) = send_channel.send((packet_bytes, peer_endpoint)).await {
            eprintln!("Failed to send keepalive packet: {}", e);
            return Err(crate::IpouError::Unknown(format!(
                "Channel send error: {}",
                e
            )));
        }

        // Mark that we sent a keepalive
        if let Some(mut connection) = self.state_manager.get_connection(&peer_key).await {
            connection.mark_keepalive_sent();
            self.state_manager
                .update_connection(peer_key, connection)
                .await;
        }

        println!("Sent keepalive to peer {:?}", peer_key);

        Ok(())
    }

    /// Handle incoming keep-alive packet
    pub async fn handle_keepalive(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
    ) -> crate::Result<()> {
        // Parse keepalive payload
        let payload_str = std::str::from_utf8(&packet.payload)?;
        let keepalive: Keepalive = serde_yml::from_str(payload_str)?;

        // Validate timestamp (simple check - within 5 minutes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(keepalive.timestamp) > 300 {
            eprintln!("Keepalive timestamp too old from peer {:?}", packet.sender_id);
            return Ok(());
        }

        // Mark packet received - this resets the missed keepalive counter
        self.state_manager
            .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
            .await;

        // Check if peer's endpoint has changed
        if keepalive.current_endpoint != sender_endpoint {
            println!(
                "Peer {:?} endpoint changed from {:?} to {:?}",
                packet.sender_id, sender_endpoint, keepalive.current_endpoint
            );
        }

        println!("Received keepalive from peer {:?}", packet.sender_id);

        Ok(())
    }

    /// Check for stale connections and mark them as stale
    pub async fn check_stale_connections(&self, timeout_seconds: u64) -> crate::Result<()> {
        let stale_peers = self.state_manager.stale_connections(timeout_seconds).await;

        for peer_key in stale_peers {
            println!("Marking peer {:?} as stale due to missed keepalives", peer_key);
            self.state_manager
                .set_peer_state(peer_key, ConnectionState::Stale)
                .await;
        }

        Ok(())
    }

    /// Attempt to reconnect stale connections
    pub async fn reconnect_stale_connections(
        &self,
        _known_anchors: &[(SocketAddr, [u8; 32])],
        _send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        // For now, this is a placeholder - we would need to integrate with
        // the handshake manager to actually attempt reconnections
        // This could involve:
        // 1. Reset peer state to Disconnected
        // 2. Initiate new handshake with known anchors
        // 3. Request endpoint information for stale peers

        println!("Reconnection logic would be triggered here for stale connections");

        // Reset stale connections to disconnected for now
        let stale_peers = self.state_manager.stale_connections(60).await; // 1 minute stale threshold
        for peer_key in stale_peers {
            self.state_manager
                .set_peer_state(peer_key, ConnectionState::Disconnected)
                .await;
        }

        Ok(())
    }

    /// Get connection health statistics
    pub async fn get_connection_stats(&self) -> ConnectionStats {
        // This would gather statistics about connection health
        // For now, return a simple placeholder
        ConnectionStats {
            total_peers: 0,
            connected_peers: 0,
            stale_peers: 0,
            disconnected_peers: 0,
        }
    }
}

/// Connection health statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub stale_peers: usize,
    pub disconnected_peers: usize,
}