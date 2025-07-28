use std::net::SocketAddr;

use bincode::{
    Decode, Encode,
    config::{self},
};
use serde::{Deserialize, Serialize};

use crate::{IpouError, crypto::PublicKeyBytes};

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
    /// decodes a Protocol Packet from network bytes
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        match bincode::decode_from_slice::<Packet, _>(bytes, config::standard()) {
            Ok((packet, _len)) => Ok(packet),
            Err(e) => Err(crate::IpouError::DecodeError(e)),
        }
    }
    /// encodes a Packet to network bytes
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        match bincode::encode_to_vec(self, config::standard()) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(crate::IpouError::EncodeError(e)),
        }
    }
}

impl WirePacket {
    /// encodes a WirePacket to network bytes
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        let mut encode_buf: Vec<u8> = Vec::new();
        encode_buf.push(self.packet_type as u8);
        match self.payload.encode() {
            Ok(bytes) => {
                encode_buf.extend_from_slice(&bytes);
                Ok(encode_buf)
            }
            Err(e) => Err(e),
        }
    }
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        // first byte to PacketType variant
        if bytes.len() < 2 {
            Err(IpouError::Unknown("WirePacket length < 2".to_string()))
        } else {
            let packet_type = PacketType::try_from(bytes[0])?;
            match Packet::decode(&bytes[1..]) {
                Ok(payload) => Ok(WirePacket {
                    packet_type,
                    payload,
                }),
                Err(e) => Err(e),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Decode, Encode)]
pub enum PacketType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    RequestPeer = 0x03,
    PeerInfo = 0x04,
    KeepAlive = 0x05,
    VpnData = 0x10,
}
impl TryFrom<u8> for PacketType {
    type Error = IpouError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::HandshakeInit),
            0x02 => Ok(PacketType::HandshakeResponse),
            0x03 => Ok(PacketType::RequestPeer),
            0x04 => Ok(PacketType::PeerInfo),
            0x05 => Ok(PacketType::KeepAlive),
            0x10 => Ok(PacketType::VpnData),
            _ => Err(IpouError::InvalidPacketType(value)),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_init_encode_decode() {
        let initial_sender_pubkey = [1u8; 32];
        let initial_timestamp = now();
        let packet = Packet::HandshakeInit {
            sender_pubkey: initial_sender_pubkey,
            timestamp: initial_timestamp,
        };
        let encoded = packet
            .encode()
            .expect("Failed to encode HandshakeInit packet");
        let decoded = Packet::decode(&encoded).expect("Failed to decode HandshakeInit packet");
        match decoded {
            Packet::HandshakeInit {
                sender_pubkey,
                timestamp,
            } => {
                assert_eq!(sender_pubkey, initial_sender_pubkey);
                assert_eq!(timestamp, initial_timestamp);
            }
            _ => panic!("Decoded packet type mismatch"),
        }
    }

    #[test]
    fn test_packet_encode_decode_vpn_data() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd];
        let packet = Packet::VpnData(data.clone());

        let encoded = packet.encode().expect("Failed to encode packet");
        let decoded = Packet::decode(&encoded).expect("Failed to decode packet");

        match decoded {
            Packet::VpnData(decoded_data) => {
                assert_eq!(decoded_data, data);
            }
            _ => panic!("Decoded packet type mismatch"),
        }
    }

    #[test]
    fn test_packet_decode_invalid_data() {
        let invalid_data = vec![0xff, 0xfe, 0xfd]; // Invalid bincode data
        let result = Packet::decode(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_encode_decode_keep_alive() {
        let packet = Packet::KeepAlive {
            timestamp: 1111111111,
        };

        let encoded = packet.encode().expect("Failed to encode packet");
        let decoded = Packet::decode(&encoded).expect("Failed to decode packet");

        match decoded {
            Packet::KeepAlive { timestamp } => {
                assert_eq!(timestamp, 1111111111);
            }
            _ => panic!("Decoded packet type mismatch"),
        }
    }

    #[test]
    fn test_wire_handshake_init() {
        let initial_sender_pubkey = [1u8; 32];
        let initial_timestamp = now();

        let payload = Packet::HandshakeInit {
            sender_pubkey: initial_sender_pubkey,
            timestamp: initial_timestamp,
        };

        let wire_packet = WirePacket {
            packet_type: PacketType::HandshakeInit,
            payload,
        };

        let encoded = wire_packet
            .encode()
            .expect("Failed to encode HandshakeInit wire packet");
        let decoded = WirePacket::decode(&encoded).expect("Failed to decode HandshakeInit packet");

        assert_eq!(decoded.packet_type as u8, PacketType::HandshakeInit as u8);
        match decoded.payload {
            Packet::HandshakeInit {
                sender_pubkey,
                timestamp,
            } => {
                assert_eq!(sender_pubkey, initial_sender_pubkey);
                assert_eq!(timestamp, initial_timestamp);
            }
            _ => panic!("Decoded packet type mismatch"),
        }
    }

    #[test]
    fn test_wirepacket_decode_invalid_packet_type() {
        let invalid_bytes = vec![0x99]; // Invalid packet type
        let result = WirePacket::decode(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_wirepacket_decode_empty_data() {
        let empty_data = vec![];
        let result = WirePacket::decode(&empty_data);
        println!("decoded empty data result: {result:#?}");
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_type_try_from() {
        assert_eq!(
            PacketType::try_from(0x01).unwrap() as u8,
            PacketType::HandshakeInit as u8
        );
        assert_eq!(
            PacketType::try_from(0x02).unwrap() as u8,
            PacketType::HandshakeResponse as u8
        );
        assert_eq!(
            PacketType::try_from(0x03).unwrap() as u8,
            PacketType::RequestPeer as u8
        );
        assert_eq!(
            PacketType::try_from(0x04).unwrap() as u8,
            PacketType::PeerInfo as u8
        );
        assert_eq!(
            PacketType::try_from(0x05).unwrap() as u8,
            PacketType::KeepAlive as u8
        );
        assert_eq!(
            PacketType::try_from(0x10).unwrap() as u8,
            PacketType::VpnData as u8
        );

        // Test invalid packet type
        assert!(PacketType::try_from(0x99).is_err());
    }

    #[test]
    fn test_now_timestamp() {
        let timestamp = now();
        assert!(timestamp > 0);

        // Check that it's reasonable (after year 2020)
        assert!(timestamp > 1577836800); // Jan 1, 2020
    }
}
