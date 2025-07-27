use std::net::SocketAddr;

use bincode::{
    Decode, Encode,
    config::{self, BigEndian},
    error::DecodeError,
};
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

impl Packet {
    /// decodes a Packet from network bytes
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        match bincode::decode_from_slice::<Packet, _>(bytes, config::standard().with_big_endian()) {
            Ok((packet, _len)) => Ok(packet),
            Err(e) => Err(crate::IpouError::DecodeError(e)),
        }
    }
    /// encodes a Packet to network bytes
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        match bincode::encode_to_vec(self, config::standard().with_big_endian()) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(crate::IpouError::EncodeError(e)),
        }
    }
}

impl WirePacket {
    /// encodes a WirePacket to network bytes
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        match bincode::encode_to_vec(self, config::standard().with_big_endian()) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(crate::IpouError::EncodeError(e)),
        }
    }
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
    pub payload: Packet,
}

/// generate a timestamp for the current time
pub fn now() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
