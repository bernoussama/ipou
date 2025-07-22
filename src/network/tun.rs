use crate::config::Config;
use crate::error::{IpouError, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;

pub const MTU: usize = 1504;

pub async fn create_tun_device(config: Arc<Config>) -> Result<::tun::AsyncDevice> {
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config.name)
        .address(config.address.parse::<Ipv4Addr>()
            .map_err(|e| IpouError::Config(format!("Invalid address: {}", e)))?)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config)
        .map_err(|e| IpouError::Network(format!("Failed to create TUN device: {}", e)))?;
    
    log::info!("Created TUN device: {}", config.name);
    Ok(dev)
}