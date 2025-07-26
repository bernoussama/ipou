use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKeyBytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Packet {
    HandshakeInit {
        sender_pubkey: PublicKeyBytes,
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
    VpnData(Vec<u8>),
}

/// Wire format for Packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePacket {
    /// Quick discriminant
    pub packet_type: u8,
    /// encrypted Packet
    pub payload: Vec<u8>,
}
