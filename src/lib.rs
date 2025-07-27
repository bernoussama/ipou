use std::net::SocketAddr;

// modules
pub mod cli;
pub mod config;
pub mod crypto;
pub mod net;
pub mod proto;
pub mod tasks;

// Constants
pub const MTU: usize = 1420;
const MAX_UDP_SIZE: usize = (1 << 16) - 1;
pub const CHANNEL_BUFFER_SIZE: usize = MTU + 512; // Buffered channels
pub const ENCRYPTION_OVERHEAD: usize = 28; // 12 nonce + 16 auth tag
pub const KEEPALIVE_INTERVAL: u64 = 26;

// types
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}

pub type DecryptedPacket = Vec<u8>;
#[derive(Debug, Clone)]
pub enum TunMessage {
    DecryptedPacket,
    Shutdown,
}

pub type EncryptedPacket = (Vec<u8>, SocketAddr);
#[derive(Debug, Clone)]
pub enum UdpMessage {
    EncryptedPacket,
    Shutdown,
}

// errors
#[derive(thiserror::Error, Debug)]
pub enum IpouError {
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parsing error: {0}")]
    SerdeYml(#[from] serde_yml::Error),
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    #[error("TUN device creation failed: {0}")]
    TunDevice(#[from] tun::Error),

    #[error(" bincode decoding error: {0}")]
    DecodeError(#[from] bincode::error::DecodeError),
    #[error(" bincode encoding error: {0}")]
    EncodeError(#[from] bincode::error::EncodeError),
}

pub type Result<T> = std::result::Result<T, IpouError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Tests for constants
    #[test]
    fn test_constants_are_valid() {
        assert_eq!(MTU, 1420);
        assert_eq!(CHANNEL_BUFFER_SIZE, MTU + 512);
        assert_eq!(CHANNEL_BUFFER_SIZE, 1932);
        assert_eq!(ENCRYPTION_OVERHEAD, 28);
        assert_eq!(KEEPALIVE_INTERVAL, 26);
    }

    #[test]
    fn test_max_udp_size_constant() {
        const EXPECTED_MAX_UDP_SIZE: usize = (1 << 16) - 1;
        assert_eq!(MAX_UDP_SIZE, EXPECTED_MAX_UDP_SIZE);
        assert_eq!(MAX_UDP_SIZE, 65535);
    }

    #[test]
    fn test_encryption_overhead_calculation() {
        // 12 bytes nonce + 16 bytes auth tag = 28 bytes
        assert_eq!(ENCRYPTION_OVERHEAD, 12 + 16);
    }

    #[test]
    fn test_constants_relationships() {
        // Test that CHANNEL_BUFFER_SIZE is larger than MTU
        assert!(CHANNEL_BUFFER_SIZE > MTU);
        
        // Test that ENCRYPTION_OVERHEAD is reasonable
        assert!(ENCRYPTION_OVERHEAD > 0);
        assert!(ENCRYPTION_OVERHEAD < 100); // Sanity check
        
        // Test that KEEPALIVE_INTERVAL is reasonable
        assert!(KEEPALIVE_INTERVAL > 0);
        assert!(KEEPALIVE_INTERVAL < 3600); // Less than an hour
    }

    #[test]
    fn test_mtu_size_validity() {
        // MTU should be reasonable for network packets
        assert!(MTU > 500);  // Minimum reasonable MTU
        assert!(MTU < 9000); // Less than jumbo frame size
    }

    // Tests for Peer struct
    #[test]
    fn test_peer_creation_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let peer = Peer {
            sock_addr: addr,
            pub_key: "test_key".to_string(),
        };
        
        assert_eq!(peer.sock_addr, addr);
        assert_eq!(peer.pub_key, "test_key");
    }

    #[test]
    fn test_peer_creation_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 9090);
        let peer = Peer {
            sock_addr: addr,
            pub_key: "ipv6_test_key".to_string(),
        };
        
        assert_eq!(peer.sock_addr, addr);
        assert_eq!(peer.pub_key, "ipv6_test_key");
    }

    #[test]
    fn test_peer_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let peer = Peer {
            sock_addr: addr,
            pub_key: "clone_test_key".to_string(),
        };
        
        let cloned_peer = peer.clone();
        assert_eq!(peer, cloned_peer);
        assert_eq!(peer.sock_addr, cloned_peer.sock_addr);
        assert_eq!(peer.pub_key, cloned_peer.pub_key);
    }

    #[test]
    fn test_peer_debug_format() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let peer = Peer {
            sock_addr: addr,
            pub_key: "debug_key".to_string(),
        };
        
        let debug_str = format!("{:?}", peer);
        assert!(debug_str.contains("127.0.0.1:8080"));
        assert!(debug_str.contains("debug_key"));
    }

    #[test]
    fn test_peer_partial_eq() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8080);
        
        let peer1 = Peer {
            sock_addr: addr1,
            pub_key: "same_key".to_string(),
        };
        
        let peer2 = Peer {
            sock_addr: addr1,
            pub_key: "same_key".to_string(),
        };
        
        let peer3 = Peer {
            sock_addr: addr2,
            pub_key: "same_key".to_string(),
        };
        
        let peer4 = Peer {
            sock_addr: addr1,
            pub_key: "different_key".to_string(),
        };
        
        assert_eq!(peer1, peer2);
        assert_ne!(peer1, peer3);
        assert_ne!(peer1, peer4);
    }

    #[test]
    fn test_peer_empty_key() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let peer = Peer {
            sock_addr: addr,
            pub_key: String::new(),
        };
        
        assert_eq!(peer.pub_key, "");
        assert!(peer.pub_key.is_empty());
    }

    #[test]
    fn test_peer_very_long_key() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1111);
        let long_key = "a".repeat(1000);
        let peer = Peer {
            sock_addr: addr,
            pub_key: long_key.clone(),
        };
        
        assert_eq!(peer.pub_key, long_key);
        assert_eq!(peer.pub_key.len(), 1000);
    }

    #[test]
    fn test_peer_with_special_characters_in_key() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let special_key = "key_with_!@#$%^&*()_+-={}[]|\\:;\"'<>?,./ characters".to_string();
        let peer = Peer {
            sock_addr: addr,
            pub_key: special_key.clone(),
        };
        
        assert_eq!(peer.pub_key, special_key);
    }

    #[test]
    fn test_peer_with_unicode_key() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let unicode_key = "🔑_密钥_κλειδί_مفتاح".to_string();
        let peer = Peer {
            sock_addr: addr,
            pub_key: unicode_key.clone(),
        };
        
        assert_eq!(peer.pub_key, unicode_key);
    }

    // Tests for TunMessage enum
    #[test]
    fn test_tun_message_variants() {
        let packet_msg = TunMessage::DecryptedPacket;
        let shutdown_msg = TunMessage::Shutdown;
        
        // Test Debug trait
        assert!(format!("{:?}", packet_msg).contains("DecryptedPacket"));
        assert!(format!("{:?}", shutdown_msg).contains("Shutdown"));
    }

    #[test]
    fn test_tun_message_clone() {
        let original = TunMessage::DecryptedPacket;
        let cloned = original.clone();
        
        // Since we can't directly compare enum variants without implementing PartialEq,
        // we test through debug formatting
        assert_eq!(format!("{:?}", original), format!("{:?}", cloned));
    }

    #[test]
    fn test_tun_message_shutdown() {
        let shutdown = TunMessage::Shutdown;
        let shutdown_clone = shutdown.clone();
        
        assert_eq!(format!("{:?}", shutdown), format!("{:?}", shutdown_clone));
        assert!(format!("{:?}", shutdown).contains("Shutdown"));
    }

    // Tests for UdpMessage enum
    #[test]
    fn test_udp_message_variants() {
        let packet_msg = UdpMessage::EncryptedPacket;
        let shutdown_msg = UdpMessage::Shutdown;
        
        // Test Debug trait
        assert!(format!("{:?}", packet_msg).contains("EncryptedPacket"));
        assert!(format!("{:?}", shutdown_msg).contains("Shutdown"));
    }

    #[test]
    fn test_udp_message_clone() {
        let original = UdpMessage::EncryptedPacket;
        let cloned = original.clone();
        
        assert_eq!(format!("{:?}", original), format!("{:?}", cloned));
    }

    // Tests for type aliases
    #[test]
    fn test_decrypted_packet_type() {
        let packet: DecryptedPacket = vec![1, 2, 3, 4, 5];
        assert_eq!(packet.len(), 5);
        assert_eq!(packet[0], 1);
        assert_eq!(packet[4], 5);
    }

    #[test]
    fn test_decrypted_packet_empty() {
        let packet: DecryptedPacket = Vec::new();
        assert!(packet.is_empty());
        assert_eq!(packet.len(), 0);
    }

    #[test]
    fn test_decrypted_packet_large() {
        let packet: DecryptedPacket = vec![0u8; MTU];
        assert_eq!(packet.len(), MTU);
        assert_eq!(packet.len(), 1420);
    }

    #[test]
    fn test_decrypted_packet_max_size() {
        let packet: DecryptedPacket = vec![0xFF; CHANNEL_BUFFER_SIZE];
        assert_eq!(packet.len(), CHANNEL_BUFFER_SIZE);
        assert!(packet.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_encrypted_packet_type() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let packet_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encrypted_packet: EncryptedPacket = (packet_data.clone(), addr);
        
        assert_eq!(encrypted_packet.0, packet_data);
        assert_eq!(encrypted_packet.1, addr);
    }

    #[test]
    fn test_encrypted_packet_empty_data() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9999);
        let encrypted_packet: EncryptedPacket = (Vec::new(), addr);
        
        assert!(encrypted_packet.0.is_empty());
        assert_eq!(encrypted_packet.1, addr);
    }

    #[test]
    fn test_encrypted_packet_with_encryption_overhead() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let data_with_overhead = vec![0u8; MTU + ENCRYPTION_OVERHEAD];
        let encrypted_packet: EncryptedPacket = (data_with_overhead.clone(), addr);
        
        assert_eq!(encrypted_packet.0.len(), MTU + ENCRYPTION_OVERHEAD);
        assert_eq!(encrypted_packet.0.len(), 1420 + 28);
        assert_eq!(encrypted_packet.1, addr);
    }

    // Tests for IpouError enum
    #[test]
    fn test_ipou_error_unknown() {
        let error = IpouError::Unknown("Test error message".to_string());
        let error_string = format!("{}", error);
        assert!(error_string.contains("An unknown error occurred: Test error message"));
    }

    #[test]
    fn test_ipou_error_invalid_key_length() {
        let error = IpouError::InvalidKeyLength(16);
        let error_string = format!("{}", error);
        assert!(error_string.contains("Invalid key length: expected 32, got 16"));
    }

    #[test]
    fn test_ipou_error_invalid_key_length_zero() {
        let error = IpouError::InvalidKeyLength(0);
        let error_string = format!("{}", error);
        assert!(error_string.contains("Invalid key length: expected 32, got 0"));
    }

    #[test]
    fn test_ipou_error_invalid_key_length_too_large() {
        let error = IpouError::InvalidKeyLength(64);
        let error_string = format!("{}", error);
        assert!(error_string.contains("Invalid key length: expected 32, got 64"));
    }

    #[test]
    fn test_ipou_error_debug() {
        let error = IpouError::Unknown("Debug test".to_string());
        let debug_string = format!("{:?}", error);
        assert!(debug_string.contains("Unknown"));
        assert!(debug_string.contains("Debug test"));
    }

    #[test]
    fn test_ipou_error_from_io_error() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let ipou_error = IpouError::from(io_error);
        
        match ipou_error {
            IpouError::Io(_) => {}, // Expected
            _ => panic!("Expected Io variant"),
        }
    }

    #[test]
    fn test_ipou_error_from_io_error_different_kinds() {
        let io_errors = vec![
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied"),
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused"),
            std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out"),
        ];
        
        for io_error in io_errors {
            let ipou_error = IpouError::from(io_error);
            match ipou_error {
                IpouError::Io(_) => {}, // Expected
                _ => panic!("Expected Io variant"),
            }
        }
    }

    // Tests for Result type alias
    #[test]
    fn test_result_type_ok() {
        let ok_result: Result<i32> = Ok(42);
        assert!(ok_result.is_ok());
        assert_eq!(ok_result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_err() {
        let err_result: Result<i32> = Err(IpouError::Unknown("Test".to_string()));
        assert!(err_result.is_err());
        
        match err_result {
            Err(IpouError::Unknown(msg)) => assert_eq!(msg, "Test"),
            _ => panic!("Expected Unknown error"),
        }
    }

    #[test]
    fn test_result_type_with_different_types() {
        let string_result: Result<String> = Ok("test".to_string());
        assert!(string_result.is_ok());
        assert_eq!(string_result.unwrap(), "test");
        
        let vec_result: Result<Vec<u8>> = Ok(vec![1, 2, 3]);
        assert!(vec_result.is_ok());
        assert_eq!(vec_result.unwrap(), vec![1, 2, 3]);
        
        let peer_result: Result<Peer> = Err(IpouError::InvalidKeyLength(10));
        assert!(peer_result.is_err());
    }

    // Test error message formatting and display
    #[test]
    fn test_all_error_variants_display() {
        let errors = vec![
            IpouError::Unknown("test".to_string()),
            IpouError::InvalidKeyLength(64),
        ];
        
        for error in errors {
            let display_str = format!("{}", error);
            assert!(!display_str.is_empty());
            let debug_str = format!("{:?}", error);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn test_error_source_chain() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "Original error");
        let ipou_error = IpouError::from(io_error);
        
        // Test that we can access the source error
        use std::error::Error;
        assert!(ipou_error.source().is_some());
    }

    // Comprehensive edge case tests
    #[test]
    fn test_peer_with_port_extremes() {
        // Test with port 0
        let addr_zero = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let peer_zero = Peer {
            sock_addr: addr_zero,
            pub_key: "port_zero".to_string(),
        };
        assert_eq!(peer_zero.sock_addr.port(), 0);
        
        // Test with max port
        let addr_max = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65535);
        let peer_max = Peer {
            sock_addr: addr_max,
            pub_key: "port_max".to_string(),
        };
        assert_eq!(peer_max.sock_addr.port(), 65535);
    }

    #[test]
    fn test_peer_with_ipv6_variants() {
        let ipv6_addresses = vec![
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), // Link-local
            Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0x8a2e, 0x370, 0x7334), // Documentation
        ];
        
        for (i, ipv6_addr) in ipv6_addresses.iter().enumerate() {
            let addr = SocketAddr::new(IpAddr::V6(*ipv6_addr), 8080 + i as u16);
            let peer = Peer {
                sock_addr: addr,
                pub_key: format!("ipv6_test_{}", i),
            };
            
            assert_eq!(peer.sock_addr.ip(), IpAddr::V6(*ipv6_addr));
            assert_eq!(peer.pub_key, format!("ipv6_test_{}", i));
        }
    }

    #[test]
    fn test_message_enums_match_exhaustively() {
        // Test that we handle all TunMessage variants
        let tun_messages = vec![TunMessage::DecryptedPacket, TunMessage::Shutdown];
        for msg in tun_messages {
            match msg {
                TunMessage::DecryptedPacket => assert!(format!("{:?}", msg).contains("DecryptedPacket")),
                TunMessage::Shutdown => assert!(format!("{:?}", msg).contains("Shutdown")),
            }
        }
        
        // Test that we handle all UdpMessage variants
        let udp_messages = vec![UdpMessage::EncryptedPacket, UdpMessage::Shutdown];
        for msg in udp_messages {
            match msg {
                UdpMessage::EncryptedPacket => assert!(format!("{:?}", msg).contains("EncryptedPacket")),
                UdpMessage::Shutdown => assert!(format!("{:?}", msg).contains("Shutdown")),
            }
        }
    }

    #[test]
    fn test_constants_are_compile_time() {
        // These should be compile-time constants
        const _: usize = MTU;
        const _: usize = CHANNEL_BUFFER_SIZE;
        const _: usize = ENCRYPTION_OVERHEAD;
        const _: u64 = KEEPALIVE_INTERVAL;
        const _: usize = MAX_UDP_SIZE;
    }

    #[test]
    fn test_packet_size_boundaries() {
        // Test packets at various size boundaries
        let sizes = vec![0, 1, MTU - 1, MTU, MTU + 1, CHANNEL_BUFFER_SIZE - 1, CHANNEL_BUFFER_SIZE];
        
        for size in sizes {
            let packet: DecryptedPacket = vec![0u8; size];
            assert_eq!(packet.len(), size);
            
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
            let encrypted: EncryptedPacket = (packet.clone(), addr);
            assert_eq!(encrypted.0.len(), size);
            assert_eq!(encrypted.1, addr);
        }
    }

    #[test]
    fn test_error_unknown_with_empty_string() {
        let error = IpouError::Unknown(String::new());
        let error_string = format!("{}", error);
        assert!(error_string.contains("An unknown error occurred:"));
    }

    #[test]
    fn test_error_unknown_with_very_long_message() {
        let long_message = "x".repeat(10000);
        let error = IpouError::Unknown(long_message.clone());
        let error_string = format!("{}", error);
        assert!(error_string.contains(&long_message));
        assert!(error_string.len() > 10000);
    }
}
