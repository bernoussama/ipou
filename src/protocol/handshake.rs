use crate::protocol::{HandshakeInit, HandshakeResponse, PacketType, ProtocolPacket};
use crate::state::{ConnectionState, StateManager};
use rand::RngCore;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Manages handshake protocol for peer authentication
pub struct HandshakeManager {
    state_manager: StateManager,
    our_public_key: [u8; 32],
}

impl HandshakeManager {
    pub fn new(state_manager: StateManager, public_key: [u8; 32]) -> Self {
        Self {
            state_manager,
            our_public_key: public_key,
        }
    }

    /// Initiate handshake with a peer
    pub async fn initiate_handshake(
        &self,
        target_peer: [u8; 32],
        target_endpoint: SocketAddr,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        // Set peer state to connecting
        self.state_manager
            .set_peer_state(target_peer, ConnectionState::Connecting)
            .await;

        // Generate nonce and timestamp
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let handshake_init = HandshakeInit {
            public_key: self.our_public_key,
            timestamp,
            nonce,
        };

        // Serialize handshake payload
        let payload = serde_yml::to_string(&handshake_init)?.into_bytes();

        // Generate session ID for this handshake
        let session_id = StateManager::generate_session_id();
        let sequence = self.state_manager.next_sequence(target_peer).await;

        // Create protocol packet
        let packet = ProtocolPacket::new(
            PacketType::HandshakeInit,
            self.our_public_key,
            session_id,
            sequence,
            payload,
        );

        // Send packet
        let packet_bytes = packet.to_bytes()?;
        if let Err(e) = send_channel.send((packet_bytes, target_endpoint)).await {
            eprintln!("Failed to send handshake init: {}", e);
        }

        Ok(())
    }

    /// Handle incoming handshake init packet
    pub async fn handle_handshake_init(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        // Parse handshake init payload
        let payload_str = std::str::from_utf8(&packet.payload)?;
        let handshake_init: HandshakeInit = serde_yml::from_str(payload_str)?;

        // Validate timestamp (simple check - within 5 minutes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if now.saturating_sub(handshake_init.timestamp) > 300 {
            eprintln!("Handshake init timestamp too old");
            return Ok(());
        }

        // Mark packet received
        self.state_manager
            .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
            .await;

        // Generate response
        let mut response_nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut response_nonce);

        let handshake_response = HandshakeResponse {
            public_key: self.our_public_key,
            original_nonce: handshake_init.nonce,
            response_nonce,
            timestamp: now,
            session_id: packet.session_id,
        };

        // Serialize response payload
        let response_payload = serde_yml::to_string(&handshake_response)?.into_bytes();

        let sequence = self.state_manager.next_sequence(packet.sender_id).await;

        // Create response packet
        let response_packet = ProtocolPacket::new(
            PacketType::HandshakeResponse,
            self.our_public_key,
            packet.session_id,
            sequence,
            response_payload,
        );

        // Send response
        let response_bytes = response_packet.to_bytes()?;
        if let Err(e) = send_channel.send((response_bytes, sender_endpoint)).await {
            eprintln!("Failed to send handshake response: {}", e);
        }

        // Set session ID and state
        self.state_manager
            .set_session_id(packet.sender_id, packet.session_id)
            .await;
        self.state_manager
            .set_peer_state(packet.sender_id, ConnectionState::Connected)
            .await;

        println!("Handshake completed with peer: {:?}", packet.sender_id);

        Ok(())
    }

    /// Handle incoming handshake response packet
    pub async fn handle_handshake_response(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
    ) -> crate::Result<()> {
        // Parse handshake response payload
        let payload_str = std::str::from_utf8(&packet.payload)?;
        let handshake_response: HandshakeResponse = serde_yml::from_str(payload_str)?;

        // Mark packet received
        self.state_manager
            .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
            .await;

        // Validate timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if now.saturating_sub(handshake_response.timestamp) > 300 {
            eprintln!("Handshake response timestamp too old");
            return Ok(());
        }

        // TODO: Validate original_nonce matches what we sent

        // Set session ID and state
        self.state_manager
            .set_session_id(packet.sender_id, packet.session_id)
            .await;
        self.state_manager
            .set_peer_state(packet.sender_id, ConnectionState::Connected)
            .await;

        println!("Handshake response received from peer: {:?}", packet.sender_id);

        Ok(())
    }
}