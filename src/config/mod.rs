pub mod types;

use crate::crypto::keys::generate_keypair;
use crate::error::{IpouError, Result};
use std::collections::HashMap;
use std::path::Path;
pub use types::{Config, Peer};

pub fn load_or_create_config<P: AsRef<Path>>(config_path: P) -> Result<Config> {
    match std::fs::read_to_string(&config_path) {
        Ok(content) => {
            let config: Config = serde_yml::from_str(&content)?;
            Ok(config)
        }
        Err(_) => {
            log::warn!("No config file found! Creating default configuration.");
            let config = create_default_config()?;
            save_config(&config, &config_path)?;
            Ok(config)
        }
    }
}

pub fn save_config<P: AsRef<Path>>(config: &Config, config_path: P) -> Result<()> {
    let yaml_content = serde_yml::to_string(config)?;
    std::fs::write(config_path, yaml_content)
        .map_err(|e| IpouError::Config(format!("Failed to write config file: {}", e)))?;
    Ok(())
}

fn create_default_config() -> Result<Config> {
    let (private_key, public_key) = generate_keypair();
    
    let config = Config {
        name: "utun0".to_string(),
        address: "10.0.0.1".to_string(),
        secret: base64::encode(private_key),
        pubkey: base64::encode(public_key),
        port: 1194,
        peers: HashMap::new(),
    };
    
    Ok(config)
}

pub fn validate_config(config: &Config) -> Result<()> {
    // Validate address format
    config.address.parse::<std::net::Ipv4Addr>()
        .map_err(|e| IpouError::Config(format!("Invalid address format: {}", e)))?;
    
    // Validate secret key length
    let secret_bytes = base64::decode(&config.secret)?;
    if secret_bytes.len() != 32 {
        return Err(IpouError::InvalidKeyLength { 
            expected: 32, 
            actual: secret_bytes.len() 
        });
    }
    
    // Validate public key length
    let pubkey_bytes = base64::decode(&config.pubkey)?;
    if pubkey_bytes.len() != 32 {
        return Err(IpouError::InvalidKeyLength { 
            expected: 32, 
            actual: pubkey_bytes.len() 
        });
    }
    
    // Validate peer public keys
    for (ip, peer) in &config.peers {
        let peer_key_bytes = base64::decode(&peer.pub_key)?;
        if peer_key_bytes.len() != 32 {
            return Err(IpouError::Config(format!(
                "Invalid peer key length for {}: expected 32, got {}", 
                ip, peer_key_bytes.len()
            )));
        }
    }
    
    Ok(())
}