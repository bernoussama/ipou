use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKeyBytes;

// Unix timestamp in seconds
pub type Timestamp = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Packet {
    HandshakeInit {
        sender_pubkey: PublicKeyBytes,
        timestamp: Timestamp,
    },
    HandshakeResponse {
        success: bool,
        message: String,
    },
    RequestPeer {
        target_pubkey: PublicKeyBytes,
    },
    PeerInfo {
        pubkey: PublicKeyBytes,
        endpoint: Option<SocketAddr>,
        last_seen: Timestamp,
    },
    KeepAlive {
        timestamp: Timestamp,
    },
    VpnData(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    RequestPeer = 0x03,
    PeerInfo = 0x04,
    KeepAlive = 0x05,
    VpnData = 0x10,
}

/// Wire format for Packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePacket {
    /// Quick discriminant
    pub packet_type: PacketType,
    /// encrypted Packet
    pub payload: Vec<u8>,
}
