use clap::Parser;
use ipou::cli::commands::{handle_genkey, handle_pubkey};
use ipou::cli::{Cli, Commands};
use ipou::config::{load_or_create_config, validate_config};
use ipou::error::Result;
use ipou::network::{tun, udp};
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    // Handle subcommands
    match &cli.command {
        Some(Commands::Genkey {}) => {
            return handle_genkey();
        }
        Some(Commands::Pubkey {}) => {
            return handle_pubkey();
        }
        None => {}
    }

    // Load configuration
    let config = load_or_create_config("config.yaml")?;
    validate_config(&config)?;
    let config = Arc::new(config);

    log::info!("Starting ipou with config: {}", config.name);

    // Create TUN device and UDP socket
    let dev = tun::create_tun_device(Arc::clone(&config)).await?;
    let sock = udp::create_udp_socket(Arc::clone(&config)).await?;

    // Create channels for communication between tasks
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (utx, mut urx) = mpsc::unbounded_channel::<(Vec<u8>, std::net::SocketAddr)>();

    // Main event loop
    loop {
        tokio::select! {
            // Handle incoming UDP packets
            result = async {
                let mut udp_buf = [0u8; tun::MTU + 512];
                let recv_result = sock.recv_from(&mut udp_buf).await;
                recv_result.map(|(len, addr)| (udp_buf, len, addr))
            } => {
                if let Ok((udp_buf, len, peer_addr)) = result {
                    let conf_clone = Arc::clone(&config);
                    let tx_clone = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_packet(&conf_clone, &udp_buf[..len], peer_addr, tx_clone).await {
                            log::error!("Failed to handle UDP packet: {}", e);
                        }
                    });
                }
            }

            // Send decrypted packets to TUN device
            Some(decrypted_packet) = rx.recv() => {
                match dev.send(&decrypted_packet).await {
                    Ok(sent) => log::debug!("Sent {} bytes to TUN device", sent),
                    Err(e) => log::error!("Failed to send to TUN: {}", e),
                }
            }

            // Send encrypted packets to UDP socket
            Some((encrypted_packet, peer_addr)) = urx.recv() => {
                match sock.send_to(&encrypted_packet, peer_addr).await {
                    Ok(sent) => log::debug!("Sent {} bytes to UDP socket", sent),
                    Err(e) => log::error!("Failed to send to UDP: {}", e),
                }
            }

            // Handle outgoing TUN packets
            result = async {
                let mut buf = [0u8; tun::MTU];
                let recv_result = dev.recv(&mut buf).await;
                recv_result.map(|len| (buf, len))
            } => {
                if let Ok((buf, len)) = result {
                    let utx_clone = utx.clone();
                    let conf_clone = Arc::clone(&config);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tun_packet(&conf_clone, &buf[..len], utx_clone).await {
                            log::error!("Failed to handle TUN packet: {}", e);
                        }
                    });
                }
            }
        }
    }
}

async fn handle_udp_packet(
    config: &Arc<ipou::config::Config>,
    packet: &[u8],
    peer_addr: std::net::SocketAddr,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<()> {
    use ipou::crypto::{decrypt_packet, keys::compute_shared_secret};
    
    log::debug!("UDP packet: {} bytes from {}", packet.len(), peer_addr);
    
    if packet.len() < 32 { // 12 bytes nonce + 16 bytes auth tag + min 4 bytes data
        return Err(ipou::error::IpouError::Packet("Packet too short".to_string()));
    }

    // Find peer by socket address
    let peer = config.peers.values()
        .find(|p| p.sock_addr == peer_addr)
        .ok_or_else(|| ipou::error::IpouError::PeerNotFound(format!("No peer found for address: {}", peer_addr)))?;

    let secret_bytes = base64::decode(&config.secret)?;
    let peer_key_bytes = base64::decode(&peer.pub_key)?;
    let shared_secret = compute_shared_secret(&secret_bytes, &peer_key_bytes)?;

    let decrypted = decrypt_packet(&shared_secret, packet)?;
    
    if decrypted.len() >= 20 {
        tx.send(decrypted)
            .map_err(|_| ipou::error::IpouError::ChannelSend)?;
    }
    
    Ok(())
}

async fn handle_tun_packet(
    config: &Arc<ipou::config::Config>,
    packet: &[u8],
    utx: mpsc::UnboundedSender<(Vec<u8>, std::net::SocketAddr)>,
) -> Result<()> {
    use ipou::crypto::{encrypt_packet, keys::compute_shared_secret};
    use ipou::network::packet::extract_dst_ip;
    
    if packet.len() < 20 {
        return Ok(());
    }

    let dst_ip = extract_dst_ip(packet)?;
    log::debug!("TUN packet: destination IP = {}", dst_ip);
    
    if let Some(peer) = config.peers.get(&dst_ip) {
        let secret_bytes = base64::decode(&config.secret)?;
        let peer_key_bytes = base64::decode(&peer.pub_key)?;
        let shared_secret = compute_shared_secret(&secret_bytes, &peer_key_bytes)?;

        let encrypted = encrypt_packet(&shared_secret, packet)?;
        
        log::debug!("Sending encrypted packet to peer: {}", peer.sock_addr);
        utx.send((encrypted, peer.sock_addr))
            .map_err(|_| ipou::error::IpouError::ChannelSend)?;
    } else {
        log::debug!("No peer found for destination IP: {}", dst_ip);
    }
    
    Ok(())
}