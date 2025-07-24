use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Defines the role of a peer in the network
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PeerRole {
    /// Anchor peer with static IP that facilitates discovery
    Anchor,
    /// Dynamic peer that connects through anchors (behind NAT)
    Dynamic,
}

impl Default for PeerRole {
    fn default() -> Self {
        PeerRole::Dynamic
    }
}

/// Represents a peer in the VPN configuration.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct PeerConfig {
    /// The public key of the peer, used as its unique identifier.
    pub public_key: String,

    /// Optional name for the peer for easier identification
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The peer's role in the network
    #[serde(default)]
    pub role: PeerRole,

    /// The peer's optional static endpoint. Required for anchor peers.
    /// Example: "198.51.100.1:51820"
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,

    /// A list of IPs allowed to route through this peer.
    /// For a simple client, this would typically be the client's VPN IP.
    /// For a central or exit node, this could be "0.0.0.0/0".
    pub allowed_ips: Vec<String>,

    /// For dynamic peers: list of anchor peer public keys to use for discovery
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<String>,

    /// The tunnel IP address for this peer
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_ip: Option<String>,
}

/// Protocol configuration settings
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ProtocolConfig {
    /// Interval between keep-alive packets in seconds
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,

    /// Connection timeout in seconds (should be > 3 * keepalive_interval)
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,

    /// Timeout for hole punching attempts in seconds
    #[serde(default = "default_punch_timeout")]
    pub punch_timeout: u64,

    /// Maximum number of hole punching attempts
    #[serde(default = "default_max_punch_attempts")]
    pub max_punch_attempts: u32,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: default_keepalive_interval(),
            connection_timeout: default_connection_timeout(),
            punch_timeout: default_punch_timeout(),
            max_punch_attempts: default_max_punch_attempts(),
        }
    }
}

fn default_keepalive_interval() -> u64 { 20 }
fn default_connection_timeout() -> u64 { 75 }
fn default_punch_timeout() -> u64 { 10 }
fn default_max_punch_attempts() -> u32 { 5 }

/// Represents the main configuration for a network interface.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    /// The private key for this interface.
    pub private_key: String,

    /// Optional interface name
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Optional interface address (tunnel IP)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// Optional port to bind to
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Protocol configuration settings
    #[serde(default)]
    pub protocol: ProtocolConfig,

    /// The list of peers this interface will try to connect to.
    pub peers: Vec<PeerConfig>,
}

/// Loads a configuration from a given YAML file path.
///
/// If the file does not exist, it creates a default configuration
/// with a newly generated keypair and writes it to the path.
pub fn load_config(config_path: &str) -> Config {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yml::from_str(&content).expect("Failed to parse config file"),
        Err(_) => {
            println!("No config file found at '{}', creating a default one.", config_path);

            // Generate a new keypair for the default config.
            let (private_key, public_key) = crate::crypto::generate_keypair();

            let default_config = Config {
                private_key: base64::encode(private_key),
                name: Some("ipou0".to_string()),
                address: Some("10.0.0.1".to_string()),
                port: Some(51820),
                protocol: ProtocolConfig::default(),
                peers: vec![
                    PeerConfig {
                        public_key: base64::encode(public_key), // Example peer (self)
                        name: Some("localhost".to_string()),
                        role: PeerRole::Anchor,
                        endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                        allowed_ips: vec!["10.0.0.1/32".to_string()],
                        anchors: vec![],
                        tunnel_ip: Some("10.0.0.1".to_string()),
                    }
                ],
            };

            let yaml_config = serde_yml::to_string(&default_config).unwrap();
            std::fs::write(config_path, yaml_config).expect("Failed to write default config file");

            default_config
        }
    }
}