use std::net::SocketAddr;

use bincode::{Decode, Encode, config::BigEndian};
use serde::{Deserialize, Serialize};

use crate::crypto::PublicKeyBytes;

pub mod state;

pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64KB limit

// Unix timestamp in seconds
pub type Timestamp = u64;

#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode)]
pub enum PacketType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    RequestPeer = 0x03,
    PeerInfo = 0x04,
    KeepAlive = 0x05,
    VpnData = 0x10,
}

/// Wire format for Packet
#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode)]
pub struct WirePacket {
    /// Quick discriminant
    pub packet_type: PacketType,
    /// encrypted Packet
    pub payload: Vec<u8>,
}

/// generate a timestamp for the current time
pub fn now() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
