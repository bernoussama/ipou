use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};

use crate::{Peer, crypto::PublicKeyBytes};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct PeerConfig {
    pub pub_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<String>,
    // New fields for protocol
    pub is_anchor: bool,  // Can this peer act as an anchor?
    pub persistent: bool, // Should we maintain connection?
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub name: String, // Name of the TUN interface
    pub pubkey: String,
    pub address: String, // Local IP address for the TUN interface
    pub endpoint: Option<SocketAddr>,
    pub secret: String,
    pub peers: Vec<PeerConfig>,
    pub role: PeerRole,
    pub keepalive_interval: u64,
    pub peer_timeout: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum PeerRole {
    Anchor,  // Can accept incoming connections
    Dynamic, // Connects to anchors
}

pub struct RuntimeConfig {
    pub shared_secrets: HashMap<PublicKeyBytes, [u8; 32]>,
    pub ciphers: HashMap<SocketAddr, ChaCha20Poly1305>,
    pub ips: HashMap<SocketAddr, IpAddr>,
    pub ip_to_pubkey: HashMap<IpAddr, PublicKeyBytes>,
}

pub fn load_config(config_path: &str) -> Config {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found! using defaults.");
            let (private_key, public_key) = crate::crypto::generate_keypair();

            let peers: Vec<PeerConfig> = vec![];

            let conf = Config {
                name: "utun0".to_string(),
                endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1194)),
                address: "10.0.0.1".to_string(),
                secret: base64::encode(private_key),
                pubkey: base64::encode(public_key),
                peers,
                role: PeerRole::Dynamic,
                keepalive_interval: 30, // seconds
                peer_timeout: 300,      // seconds
            };
            std::fs::write(config_path, serde_yml::to_string(&conf).unwrap())
                .expect("Failed to write default config file");
            conf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_peer_config_serialization_roundtrip() {
        let peer_config = PeerConfig {
            pub_key: "test_public_key_12345".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080)),
            allowed_ips: vec!["10.0.0.0/24".to_string(), "192.168.1.0/24".to_string()],
            is_anchor: true,
            persistent: false,
        };

        let serialized = serde_yml::to_string(&peer_config).unwrap();
        let deserialized: PeerConfig = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(peer_config, deserialized);
        assert_eq!(peer_config.pub_key, deserialized.pub_key);
        assert_eq!(peer_config.endpoint, deserialized.endpoint);
        assert_eq!(peer_config.allowed_ips, deserialized.allowed_ips);
        assert_eq!(peer_config.is_anchor, deserialized.is_anchor);
        assert_eq!(peer_config.persistent, deserialized.persistent);
    }

    #[test]
    fn test_peer_config_with_none_endpoint() {
        let peer_config = PeerConfig {
            pub_key: "test_key_none_endpoint".to_string(),
            endpoint: None,
            allowed_ips: vec!["10.0.0.1/32".to_string()],
            is_anchor: false,
            persistent: true,
        };

        let serialized = serde_yml::to_string(&peer_config).unwrap();
        let deserialized: PeerConfig = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(peer_config, deserialized);
        assert!(deserialized.endpoint.is_none());
        assert_eq!(deserialized.is_anchor, false);
        assert_eq!(deserialized.persistent, true);
    }

    #[test]
    fn test_peer_config_empty_allowed_ips() {
        let peer_config = PeerConfig {
            pub_key: "empty_ips_key".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090)),
            allowed_ips: vec![],
            is_anchor: true,
            persistent: true,
        };

        let serialized = serde_yml::to_string(&peer_config).unwrap();
        let deserialized: PeerConfig = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(peer_config, deserialized);
        assert!(deserialized.allowed_ips.is_empty());
    }

    #[test]
    fn test_peer_config_with_ipv6_endpoint() {
        let peer_config = PeerConfig {
            pub_key: "ipv6_peer_key".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 51820)),
            allowed_ips: vec!["2001:db8::/32".to_string()],
            is_anchor: false,
            persistent: true,
        };

        let serialized = serde_yml::to_string(&peer_config).unwrap();
        let deserialized: PeerConfig = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(peer_config, deserialized);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config {
            name: "test_interface".to_string(),
            pubkey: "test_public_key_base64".to_string(),
            address: "10.0.0.5".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 51820)),
            secret: "test_secret_base64".to_string(),
            peers: vec![
                PeerConfig {
                    pub_key: "peer1_key".to_string(),
                    endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 51821)),
                    allowed_ips: vec!["10.0.0.2/32".to_string()],
                    is_anchor: false,
                    persistent: true,
                }
            ],
            role: PeerRole::Anchor,
            keepalive_interval: 25,
            peer_timeout: 180,
        };

        let serialized = serde_yml::to_string(&config).unwrap();
        let deserialized: Config = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(config, deserialized);
        assert_eq!(config.peers.len(), deserialized.peers.len());
        assert_eq!(config.role, deserialized.role);
    }

    #[test]
    fn test_config_with_dynamic_role() {
        let config = Config {
            name: "dynamic_interface".to_string(),
            pubkey: "dynamic_public_key".to_string(),
            address: "10.0.0.10".to_string(),
            endpoint: None,
            secret: "dynamic_secret".to_string(),
            peers: vec![],
            role: PeerRole::Dynamic,
            keepalive_interval: 60,
            peer_timeout: 600,
        };

        let serialized = serde_yml::to_string(&config).unwrap();
        let deserialized: Config = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(config, deserialized);
        assert_eq!(deserialized.role, PeerRole::Dynamic);
        assert!(deserialized.endpoint.is_none());
        assert!(deserialized.peers.is_empty());
    }

    #[test]
    fn test_peer_role_serialization() {
        let anchor_role = PeerRole::Anchor;
        let dynamic_role = PeerRole::Dynamic;

        let anchor_serialized = serde_yml::to_string(&anchor_role).unwrap();
        let dynamic_serialized = serde_yml::to_string(&dynamic_role).unwrap();

        let anchor_deserialized: PeerRole = serde_yml::from_str(&anchor_serialized).unwrap();
        let dynamic_deserialized: PeerRole = serde_yml::from_str(&dynamic_serialized).unwrap();

        assert_eq!(anchor_role, anchor_deserialized);
        assert_eq!(dynamic_role, dynamic_deserialized);
        
        // Test that the serialized forms are as expected
        assert!(anchor_serialized.contains("Anchor"));
        assert!(dynamic_serialized.contains("Dynamic"));
    }

    #[test]
    fn test_runtime_config_creation() {
        let runtime_config = RuntimeConfig {
            shared_secrets: HashMap::new(),
            ciphers: HashMap::new(),
            ips: HashMap::new(),
            ip_to_pubkey: HashMap::new(),
        };

        // Test that empty HashMaps are created properly
        assert_eq!(runtime_config.shared_secrets.len(), 0);
        assert_eq!(runtime_config.ciphers.len(), 0);
        assert_eq!(runtime_config.ips.len(), 0);
        assert_eq!(runtime_config.ip_to_pubkey.len(), 0);
    }

    #[test]
    fn test_runtime_config_with_data() {
        let mut runtime_config = RuntimeConfig {
            shared_secrets: HashMap::new(),
            ciphers: HashMap::new(),
            ips: HashMap::new(),
            ip_to_pubkey: HashMap::new(),
        };

        // Add some test data
        let test_pubkey = [1u8; 32];
        let test_secret = [2u8; 32];
        let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        runtime_config.shared_secrets.insert(test_pubkey, test_secret);
        runtime_config.ips.insert(test_addr, test_ip);
        runtime_config.ip_to_pubkey.insert(test_ip, test_pubkey);

        assert_eq!(runtime_config.shared_secrets.len(), 1);
        assert_eq!(runtime_config.ips.len(), 1);
        assert_eq!(runtime_config.ip_to_pubkey.len(), 1);
        assert_eq!(runtime_config.shared_secrets.get(&test_pubkey), Some(&test_secret));
        assert_eq!(runtime_config.ips.get(&test_addr), Some(&test_ip));
        assert_eq!(runtime_config.ip_to_pubkey.get(&test_ip), Some(&test_pubkey));
    }

    #[test]
    fn test_load_config_from_valid_file() {
        let config_content = r#"
name: "test_tun"
pubkey: "test_pubkey_base64"
address: "10.0.0.2"
endpoint: "192.168.1.100:51820"
secret: "test_secret_base64"
peers:
  - pub_key: "peer_pubkey"
    endpoint: "192.168.1.101:51821"
    allowed_ips: ["10.0.0.3/32"]
    is_anchor: true
    persistent: false
role: Anchor
keepalive_interval: 30
peer_timeout: 300
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = load_config(temp_file.path().to_str().unwrap());

        assert_eq!(config.name, "test_tun");
        assert_eq!(config.pubkey, "test_pubkey_base64");
        assert_eq!(config.address, "10.0.0.2");
        assert_eq!(config.endpoint, Some("192.168.1.100:51820".parse().unwrap()));
        assert_eq!(config.secret, "test_secret_base64");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].pub_key, "peer_pubkey");
        assert_eq!(config.peers[0].endpoint, Some("192.168.1.101:51821".parse().unwrap()));
        assert_eq!(config.peers[0].allowed_ips, vec!["10.0.0.3/32"]);
        assert_eq!(config.peers[0].is_anchor, true);
        assert_eq!(config.peers[0].persistent, false);
        assert_eq!(config.role, PeerRole::Anchor);
        assert_eq!(config.keepalive_interval, 30);
        assert_eq!(config.peer_timeout, 300);
    }

    #[test]
    fn test_load_config_creates_default_when_file_missing() {
        let non_existent_path = "/tmp/non_existent_config_test_file_opentun.yml";
        
        // Ensure the file doesn't exist
        let _ = fs::remove_file(non_existent_path);

        let config = load_config(non_existent_path);

        // Verify default values
        assert_eq!(config.name, "utun0");
        assert_eq!(config.address, "10.0.0.1");
        assert_eq!(config.endpoint, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1194)));
        assert_eq!(config.peers.len(), 0);
        assert_eq!(config.role, PeerRole::Dynamic);
        assert_eq!(config.keepalive_interval, 30);
        assert_eq!(config.peer_timeout, 300);

        // Verify that keys are base64 encoded (should not be empty and have proper length)
        assert!(!config.secret.is_empty());
        assert!(!config.pubkey.is_empty());
        
        // Base64 encoded 32-byte keys should be 44 characters long (with padding)
        assert_eq!(config.secret.len(), 44);
        assert_eq!(config.pubkey.len(), 44);

        // Verify the file was created with default config
        assert!(std::path::Path::new(non_existent_path).exists());

        // Clean up the created file
        let _ = fs::remove_file(non_existent_path);
    }

    #[test]
    fn test_load_config_with_ipv6_endpoint() {
        let config_content = r#"
name: "ipv6_tun"
pubkey: "ipv6_pubkey"
address: "fd00::1"
endpoint: "[2001:db8::1]:51820"
secret: "ipv6_secret"
peers: []
role: Dynamic
keepalive_interval: 45
peer_timeout: 400
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = load_config(temp_file.path().to_str().unwrap());

        assert_eq!(config.name, "ipv6_tun");
        assert_eq!(config.address, "fd00::1");
        assert_eq!(config.endpoint, Some("[2001:db8::1]:51820".parse().unwrap()));
        assert_eq!(config.role, PeerRole::Dynamic);
        assert_eq!(config.keepalive_interval, 45);
        assert_eq!(config.peer_timeout, 400);
    }

    #[test]
    fn test_config_with_multiple_peers() {
        let config = Config {
            name: "multi_peer".to_string(),
            pubkey: "multi_pubkey".to_string(),
            address: "10.0.0.1".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820)),
            secret: "multi_secret".to_string(),
            peers: vec![
                PeerConfig {
                    pub_key: "peer1".to_string(),
                    endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 51821)),
                    allowed_ips: vec!["10.0.0.2/32".to_string()],
                    is_anchor: true,
                    persistent: true,
                },
                PeerConfig {
                    pub_key: "peer2".to_string(),
                    endpoint: None,
                    allowed_ips: vec!["10.0.0.3/32".to_string(), "10.0.0.4/32".to_string()],
                    is_anchor: false,
                    persistent: false,
                },
                PeerConfig {
                    pub_key: "peer3".to_string(),
                    endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 9999)),
                    allowed_ips: vec!["0.0.0.0/0".to_string()],
                    is_anchor: true,
                    persistent: true,
                },
            ],
            role: PeerRole::Anchor,
            keepalive_interval: 15,
            peer_timeout: 120,
        };

        let serialized = serde_yml::to_string(&config).unwrap();
        let deserialized: Config = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(config, deserialized);
        assert_eq!(deserialized.peers.len(), 3);
        
        // Test individual peer properties
        assert_eq!(deserialized.peers[0].is_anchor, true);
        assert_eq!(deserialized.peers[1].is_anchor, false);
        assert_eq!(deserialized.peers[2].is_anchor, true);
        
        assert_eq!(deserialized.peers[0].persistent, true);
        assert_eq!(deserialized.peers[1].persistent, false);
        assert_eq!(deserialized.peers[2].persistent, true);
        
        assert_eq!(deserialized.peers[1].allowed_ips.len(), 2);
    }

    #[test]
    fn test_config_edge_case_values() {
        let config = Config {
            name: String::new(), // Empty name
            pubkey: String::new(), // Empty pubkey
            address: String::new(), // Empty address
            endpoint: None,
            secret: String::new(), // Empty secret
            peers: vec![],
            role: PeerRole::Dynamic,
            keepalive_interval: 0, // Minimum value
            peer_timeout: u64::MAX, // Maximum value
        };

        let serialized = serde_yml::to_string(&config).unwrap();
        let deserialized: Config = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(config, deserialized);
        assert_eq!(deserialized.keepalive_interval, 0);
        assert_eq!(deserialized.peer_timeout, u64::MAX);
        assert!(deserialized.name.is_empty());
        assert!(deserialized.pubkey.is_empty());
        assert!(deserialized.address.is_empty());
        assert!(deserialized.secret.is_empty());
        assert!(deserialized.endpoint.is_none());
    }

    #[test]
    fn test_peer_config_clone() {
        let original = PeerConfig {
            pub_key: "clone_test".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)),
            allowed_ips: vec!["192.168.0.0/16".to_string()],
            is_anchor: true,
            persistent: false,
        };

        let cloned = original.clone();
        
        assert_eq!(original, cloned);
        assert_eq!(original.pub_key, cloned.pub_key);
        assert_eq!(original.endpoint, cloned.endpoint);
        assert_eq!(original.allowed_ips, cloned.allowed_ips);
        assert_eq!(original.is_anchor, cloned.is_anchor);
        assert_eq!(original.persistent, cloned.persistent);
        
        // Verify they are separate instances
        assert_ne!(&original as *const _, &cloned as *const _);
    }

    #[test]
    fn test_config_clone() {
        let original = Config {
            name: "original".to_string(),
            pubkey: "original_pubkey".to_string(),
            address: "10.0.0.1".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820)),
            secret: "original_secret".to_string(),
            peers: vec![
                PeerConfig {
                    pub_key: "peer_key".to_string(),
                    endpoint: None,
                    allowed_ips: vec!["10.0.0.0/8".to_string()],
                    is_anchor: false,
                    persistent: true,
                }
            ],
            role: PeerRole::Anchor,
            keepalive_interval: 30,
            peer_timeout: 300,
        };

        let cloned = original.clone();
        
        assert_eq!(original, cloned);
        assert_eq!(original.peers.len(), cloned.peers.len());
        assert_eq!(original.peers[0], cloned.peers[0]);
        
        // Verify they are separate instances
        assert_ne!(&original as *const _, &cloned as *const _);
    }

    #[test]
    fn test_peer_role_debug_format() {
        let anchor = PeerRole::Anchor;
        let dynamic = PeerRole::Dynamic;

        let anchor_debug = format!("{:?}", anchor);
        let dynamic_debug = format!("{:?}", dynamic);

        assert_eq!(anchor_debug, "Anchor");
        assert_eq!(dynamic_debug, "Dynamic");
    }

    #[test]
    fn test_peer_role_partial_eq() {
        assert_eq!(PeerRole::Anchor, PeerRole::Anchor);
        assert_eq!(PeerRole::Dynamic, PeerRole::Dynamic);
        assert_ne!(PeerRole::Anchor, PeerRole::Dynamic);
        assert_ne!(PeerRole::Dynamic, PeerRole::Anchor);
    }

    #[test]
    fn test_partial_eq_implementation() {
        let config1 = Config {
            name: "test".to_string(),
            pubkey: "key1".to_string(),
            address: "10.0.0.1".to_string(),
            endpoint: None,
            secret: "secret1".to_string(),
            peers: vec![],
            role: PeerRole::Dynamic,
            keepalive_interval: 30,
            peer_timeout: 300,
        };

        let config2 = Config {
            name: "test".to_string(),
            pubkey: "key1".to_string(),
            address: "10.0.0.1".to_string(),
            endpoint: None,
            secret: "secret1".to_string(),
            peers: vec![],
            role: PeerRole::Dynamic,
            keepalive_interval: 30,
            peer_timeout: 300,
        };

        let config3 = Config {
            name: "different".to_string(),
            pubkey: "key1".to_string(),
            address: "10.0.0.1".to_string(),
            endpoint: None,
            secret: "secret1".to_string(),
            peers: vec![],
            role: PeerRole::Dynamic,
            keepalive_interval: 30,
            peer_timeout: 300,
        };

        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_load_config_malformed_yaml() {
        let malformed_content = r#"
name: "test
pubkey: invalid yaml
endpoint: [this is not valid
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(malformed_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // This should panic due to unwrap() in load_config when parsing fails
        let result = std::panic::catch_unwind(|| {
            load_config(temp_file.path().to_str().unwrap())
        });
        
        assert!(result.is_err());
    }

    #[test]
    fn test_config_with_extremely_long_strings() {
        let long_string = "a".repeat(10000);
        let config = Config {
            name: long_string.clone(),
            pubkey: long_string.clone(),
            address: long_string.clone(),
            endpoint: None,
            secret: long_string.clone(),
            peers: vec![
                PeerConfig {
                    pub_key: long_string.clone(),
                    endpoint: None,
                    allowed_ips: vec![long_string.clone()],
                    is_anchor: true,
                    persistent: false,
                }
            ],
            role: PeerRole::Dynamic,
            keepalive_interval: 1,
            peer_timeout: 1,
        };

        let serialized = serde_yml::to_string(&config).unwrap();
        let deserialized: Config = serde_yml::from_str(&serialized).unwrap();
        
        assert_eq!(config, deserialized);
        assert_eq!(deserialized.name.len(), 10000);
        assert_eq!(deserialized.peers[0].pub_key.len(), 10000);
    }

    #[test]
    fn test_peer_config_boundary_values() {
        // Test with boundary port values
        let peer_config_min_port = PeerConfig {
            pub_key: "min_port_test".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1)),
            allowed_ips: vec!["127.0.0.1/32".to_string()],
            is_anchor: false,
            persistent: false,
        };

        let peer_config_max_port = PeerConfig {
            pub_key: "max_port_test".to_string(),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65535)),
            allowed_ips: vec!["127.0.0.1/32".to_string()],
            is_anchor: true,
            persistent: true,
        };

        let serialized_min = serde_yml::to_string(&peer_config_min_port).unwrap();
        let serialized_max = serde_yml::to_string(&peer_config_max_port).unwrap();

        let deserialized_min: PeerConfig = serde_yml::from_str(&serialized_min).unwrap();
        let deserialized_max: PeerConfig = serde_yml::from_str(&serialized_max).unwrap();

        assert_eq!(peer_config_min_port, deserialized_min);
        assert_eq!(peer_config_max_port, deserialized_max);
        
        assert_eq!(deserialized_min.endpoint.unwrap().port(), 1);
        assert_eq!(deserialized_max.endpoint.unwrap().port(), 65535);
    }
}
