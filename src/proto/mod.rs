use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKeyBytes;

pub mod state;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PacketType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    RequestPeer = 0x03,
    PeerInfo = 0x04,
    KeepAlive = 0x05,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Packet {
    HandshakeInit {
        sender_pubkey: PublicKeyBytes,
        sender_private_ip: IpAddr,
        timestamp: u64,
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
        last_seen: u64,
    },
    KeepAlive {
        timestamp: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WirePacket {
    pub packet_type: PacketType,
    pub payload: Packet,
}

impl WirePacket {
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut bytes = vec![self.packet_type as u8];
        bytes.extend(bincode::serialize(&self.payload)?);
        Ok(bytes)
    }
}

impl Packet {
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}