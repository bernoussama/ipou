use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Represents a peer in the VPN configuration.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct PeerConfig {
    /// The public key of the peer, used as its unique identifier.
    pub public_key: String,

    /// The peer's optional static endpoint. If this is present, the peer
    /// can act as an "Anchor Peer" for initial connections.
    /// Example: "198.51.100.1:51820"
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,

    /// A list of IPs allowed to route through this peer.
    /// For a simple client, this would typically be the client's VPN IP.
    /// For a central or exit node, this could be "0.0.0.0/0".
    pub allowed_ips: Vec<String>,
}

/// Represents the main configuration for a network interface.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    /// The private key for this interface.
    pub private_key: String,

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
                peers: vec![
                    PeerConfig {
                        public_key: base64::encode(public_key), // Example peer (self)
                        endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                        allowed_ips: vec!["10.0.0.1/32".to_string()],
                    }
                ],
            };

            let yaml_config = serde_yml::to_string(&default_config).unwrap();
            std::fs::write(config_path, yaml_config).expect("Failed to write default config file");

            default_config
        }
    }
}