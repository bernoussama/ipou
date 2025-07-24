use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u8 = 1;

/// Protocol packet types for the anchor-based peer discovery system
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    /// Dynamic peer initiates handshake with anchor
    HandshakeInit = 1,
    /// Anchor responds to handshake
    HandshakeResponse = 2,
    /// Request endpoint information for a peer
    RequestEndpoint = 3,
    /// Response with peer endpoint information
    EndpointInfo = 4,
    /// Initiate hole punching procedure
    InitiatePunch = 5,
    /// Keep-alive packet to maintain connection
    Keepalive = 6,
    /// Actual VPN data packet
    VpnData = 7,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            1 => PacketType::HandshakeInit,
            2 => PacketType::HandshakeResponse,
            3 => PacketType::RequestEndpoint,
            4 => PacketType::EndpointInfo,
            5 => PacketType::InitiatePunch,
            6 => PacketType::Keepalive,
            7 => PacketType::VpnData,
            _ => PacketType::VpnData, // Default fallback
        }
    }
}

/// Main protocol packet wrapper
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtocolPacket {
    /// Protocol version for compatibility
    pub version: u8,
    /// Type of packet
    pub packet_type: PacketType,
    /// Sender's public key (32 bytes)
    pub sender_id: [u8; 32],
    /// Session identifier (16 bytes)
    pub session_id: [u8; 16],
    /// Sequence number for replay protection
    pub sequence: u64,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Ed25519 signature (64 bytes) - using Vec for serde compatibility
    pub signature: Vec<u8>,
}

impl ProtocolPacket {
    pub fn new(
        packet_type: PacketType,
        sender_id: [u8; 32],
        session_id: [u8; 16],
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            packet_type,
            sender_id,
            session_id,
            sequence,
            payload,
            signature: vec![0u8; 64], // TODO: Implement proper signing
        }
    }

    /// Serialize the packet to bytes
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        Ok(serde_yml::to_string(self)?.into_bytes())
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        let string_data = std::str::from_utf8(data)
            .map_err(|e| crate::IpouError::Unknown(format!("Invalid UTF-8: {}", e)))?;
        serde_yml::from_str(string_data).map_err(Into::into)
    }
}

/// Handshake initialization payload
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeInit {
    /// Public key of the initiating peer
    pub public_key: [u8; 32],
    /// Timestamp to prevent replay attacks
    pub timestamp: u64,
    /// Nonce for this handshake
    pub nonce: [u8; 32],
}

/// Handshake response payload
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResponse {
    /// Public key of the responding peer
    pub public_key: [u8; 32],
    /// Original nonce from the init packet
    pub original_nonce: [u8; 32],
    /// Response nonce
    pub response_nonce: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Session ID for future communications
    pub session_id: [u8; 16],
}

/// Request for endpoint information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestEndpoint {
    /// Public key of the target peer
    pub target_peer: [u8; 32],
    /// Requester's current endpoint (for response routing)
    pub requester_endpoint: SocketAddr,
}

/// Response with endpoint information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EndpointInfo {
    /// Public key of the requested peer
    pub peer_key: [u8; 32],
    /// Last known endpoint of the peer
    pub endpoint: Option<SocketAddr>,
    /// Timestamp when this endpoint was last seen
    pub last_seen: u64,
}

/// Initiate hole punching
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitiatePunch {
    /// Target peer to punch through to
    pub target_peer: [u8; 32],
    /// Target peer's endpoint
    pub target_endpoint: SocketAddr,
    /// Punch session ID for coordination
    pub punch_id: [u8; 16],
}

/// Keep-alive payload
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keepalive {
    /// Timestamp
    pub timestamp: u64,
    /// Current endpoint (for endpoint change detection)
    pub current_endpoint: SocketAddr,
}