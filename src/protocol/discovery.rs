use crate::protocol::{EndpointInfo, PacketType, ProtocolPacket, RequestEndpoint};
use crate::state::StateManager;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};

/// Tracks endpoint information for peers
#[derive(Debug, Clone)]
pub struct PeerEndpointInfo {
    pub endpoint: SocketAddr,
    pub last_seen: u64,
}

/// Manages peer discovery and endpoint tracking
pub struct DiscoveryManager {
    state_manager: StateManager,
    our_public_key: [u8; 32],
    /// Map from peer public key to their last known endpoint
    peer_endpoints: Arc<RwLock<HashMap<[u8; 32], PeerEndpointInfo>>>,
}

impl DiscoveryManager {
    pub fn new(state_manager: StateManager, public_key: [u8; 32]) -> Self {
        Self {
            state_manager,
            our_public_key: public_key,
            peer_endpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Request endpoint information for a target peer from an anchor
    pub async fn request_peer_endpoint(
        &self,
        target_peer: [u8; 32],
        anchor_peer: [u8; 32],
        anchor_endpoint: SocketAddr,
        our_endpoint: SocketAddr,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        let request = RequestEndpoint {
            target_peer,
            requester_endpoint: our_endpoint,
        };

        // Serialize request payload
        let payload = serde_yml::to_string(&request)?.into_bytes();

        // Get session ID if we have one
        let session_id = self
            .state_manager
            .get_session_id(&anchor_peer)
            .await
            .unwrap_or_else(|| StateManager::generate_session_id());

        let sequence = self.state_manager.next_sequence(anchor_peer).await;

        // Create protocol packet
        let packet = ProtocolPacket::new(
            PacketType::RequestEndpoint,
            self.our_public_key,
            session_id,
            sequence,
            payload,
        );

        // Send packet
        let packet_bytes = packet.to_bytes()?;
        if let Err(e) = send_channel.send((packet_bytes, anchor_endpoint)).await {
            eprintln!("Failed to send endpoint request: {}", e);
        }

        Ok(())
    }

    /// Handle incoming endpoint request (anchor peer functionality)
    pub async fn handle_endpoint_request(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
        send_channel: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> crate::Result<()> {
        // Parse request payload
        let payload_str = std::str::from_utf8(&packet.payload)?;
        let request: RequestEndpoint = serde_yml::from_str(payload_str)?;

        // Mark packet received
        self.state_manager
            .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
            .await;

        // Look up the target peer's endpoint
        let peer_endpoints = self.peer_endpoints.read().await;
        let endpoint_info = peer_endpoints.get(&request.target_peer);

        let response = EndpointInfo {
            peer_key: request.target_peer,
            endpoint: endpoint_info.map(|info| info.endpoint),
            last_seen: endpoint_info.map(|info| info.last_seen).unwrap_or(0),
        };

        // Serialize response payload
        let response_payload = serde_yml::to_string(&response)?.into_bytes();

        let sequence = self.state_manager.next_sequence(packet.sender_id).await;

        // Create response packet
        let response_packet = ProtocolPacket::new(
            PacketType::EndpointInfo,
            self.our_public_key,
            packet.session_id,
            sequence,
            response_payload,
        );

        // Send response to the requester
        let response_bytes = response_packet.to_bytes()?;
        if let Err(e) = send_channel
            .send((response_bytes, request.requester_endpoint))
            .await
        {
            eprintln!("Failed to send endpoint info response: {}", e);
        }

        Ok(())
    }

    /// Handle incoming endpoint info response
    pub async fn handle_endpoint_info(
        &self,
        packet: ProtocolPacket,
        sender_endpoint: SocketAddr,
    ) -> crate::Result<Option<SocketAddr>> {
        // Parse response payload
        let payload_str = std::str::from_utf8(&packet.payload)?;
        let endpoint_info: EndpointInfo = serde_yml::from_str(payload_str)?;

        // Mark packet received
        self.state_manager
            .mark_packet_received(packet.sender_id, packet.sequence, sender_endpoint)
            .await;

        println!(
            "Received endpoint info for peer {:?}: {:?}",
            endpoint_info.peer_key, endpoint_info.endpoint
        );

        // Store the endpoint info if we received one
        if let Some(endpoint) = endpoint_info.endpoint {
            self.update_peer_endpoint(endpoint_info.peer_key, endpoint, endpoint_info.last_seen)
                .await;
            return Ok(Some(endpoint));
        }

        Ok(None)
    }

    /// Update a peer's endpoint information
    pub async fn update_peer_endpoint(&self, peer_key: [u8; 32], endpoint: SocketAddr, last_seen: u64) {
        let mut peer_endpoints = self.peer_endpoints.write().await;
        peer_endpoints.insert(
            peer_key,
            PeerEndpointInfo {
                endpoint,
                last_seen,
            },
        );
    }

    /// Update a peer's endpoint when we receive a packet from them
    pub async fn mark_peer_seen(&self, peer_key: [u8; 32], endpoint: SocketAddr) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.update_peer_endpoint(peer_key, endpoint, timestamp).await;
    }

    /// Get last known endpoint for a peer
    pub async fn get_peer_endpoint(&self, peer_key: &[u8; 32]) -> Option<SocketAddr> {
        let peer_endpoints = self.peer_endpoints.read().await;
        peer_endpoints.get(peer_key).map(|info| info.endpoint)
    }

    /// Get all known peer endpoints
    pub async fn get_all_peer_endpoints(&self) -> HashMap<[u8; 32], SocketAddr> {
        let peer_endpoints = self.peer_endpoints.read().await;
        peer_endpoints
            .iter()
            .map(|(key, info)| (*key, info.endpoint))
            .collect()
    }
}