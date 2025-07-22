use crate::config::Config;
use crate::error::{IpouError, Result};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn create_udp_socket(config: Arc<Config>) -> Result<UdpSocket> {
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let sock = UdpSocket::bind(&bind_addr).await
        .map_err(|e| IpouError::Network(format!("Failed to bind UDP socket to {}: {}", bind_addr, e)))?;
    
    log::info!("UDP socket bound to: {}", sock.local_addr()
        .map_err(|e| IpouError::Network(format!("Failed to get local address: {}", e)))?);
    
    Ok(sock)
}