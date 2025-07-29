use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use futures::lock;
use opentun::cli::commands::{handle_gen_key, handle_pub_key};
use opentun::config::{PeerRole, RuntimeConfig};
use opentun::crypto::PublicKeyBytes;
use opentun::net::PeerConnections;
use opentun::proto::Packet;
use std::net::IpAddr;
use std::sync::Arc;
use std::{collections::HashMap, net::Ipv4Addr};

use clap::Parser;
use opentun::tasks;
use opentun::{IpouError, Result};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = opentun::cli::Cli::parse();
    // Subcommands
    match &cli.command {
        Some(opentun::cli::Commands::Genkey {}) => handle_gen_key(),
        Some(opentun::cli::Commands::Pubkey {}) => handle_pub_key(),
        None => Ok(()),
    }
    .expect("Failed to execute command");

    // Load config file
    let config_path = "config.yaml";
    let conf = opentun::config::load_config(config_path);
    let config = Arc::new(conf);

    let config_clone = Arc::clone(&config);
    // Initialize once after config load
    let mut shared_secrets: HashMap<PublicKeyBytes, _> = HashMap::new();
    let mut ciphers = HashMap::new();

    let mut secret_bytes = [0u8; 32];
    base64::decode_config_slice(&config.secret, base64::STANDARD, &mut secret_bytes).unwrap();
    let static_secret = StaticSecret::from(secret_bytes);

    let mut ips = HashMap::new();

    let mut ip_to_pubkey = HashMap::new();

    // Create peer manager
    let (config_update_tx, config_update_rx) = mpsc::unbounded_channel();
    let peer_manager = Arc::new(opentun::net::PeerManager::new(config_update_tx.clone()));

    for peer_conn in &config.peers {
        let mut pub_key_bytes = [0u8; 32];
        base64::decode_config_slice(&peer_conn.pub_key, base64::STANDARD, &mut pub_key_bytes)
            .unwrap();
        let pub_key = PublicKey::from(pub_key_bytes);
        let shared_secret = static_secret.diffie_hellman(&pub_key);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        shared_secrets.insert(pub_key_bytes, *shared_secret.as_bytes());
        if let Some(endpoint) = peer_conn.endpoint {
            ciphers.insert(endpoint, cipher);
        }

        for allowed_ip in &peer_conn.allowed_ips {
            if let Ok(ip) = allowed_ip.parse::<IpAddr>() {
                ips.insert(peer_conn.endpoint.unwrap(), ip);
                ip_to_pubkey.insert(ip, pub_key_bytes);
            } else if allowed_ip.contains("/") {
                let ip_parts = allowed_ip.split('/').next().unwrap();
                if let Ok(ip) = ip_parts.parse::<IpAddr>() {
                    ips.insert(peer_conn.endpoint.unwrap(), ip);
                    ip_to_pubkey.insert(ip, pub_key_bytes);
                } else {
                    eprintln!("Invalid IP address format: {allowed_ip}");
                    continue;
                }
            } else {
                eprintln!("Invalid IP address format: {allowed_ip}");
                continue;
            }
        }

        // Add peer to peer_manager if it has an endpoint
        if let Some(endpoint) = peer_conn.endpoint {
            let mut peer_connections = peer_manager.peer_connections.write().await;
            let peer_connection = peer_connections.entry(pub_key_bytes).or_insert(
                opentun::proto::state::PeerConnection::with_update_sender(
                    pub_key_bytes,
                    config_update_tx.clone(),
                ),
            );
            peer_connection.mark_connected(endpoint);
        }
    }

    let runtime_config = RuntimeConfig {
        shared_secrets,
        ciphers,
        ips,
        ip_to_pubkey,
    };

    let locked_runtime_conf = Arc::new(RwLock::new(runtime_config));

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config_clone.name)
        .address(config_clone.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(opentun::MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).expect("Failed to create TUN device");
    let sock = UdpSocket::bind(Arc::clone(&config).endpoint.ok_or(IpouError::Unknown(
        "endpoint must be configured in config.yaml".to_string(),
    ))?)
    .await
    .expect("Failed to bind UDP socket");
    println!(
        "UDP socket bound to: {}",
        sock.local_addr().expect("Failed to get local address")
    );
    let dev_arc = Arc::new(dev);
    let sock_arc = Arc::new(sock);

    // Create channel for sending decrypted packets to TUN device
    let (dtx, drx) = mpsc::channel::<opentun::DecryptedPacket>(opentun::CHANNEL_BUFFER_SIZE);
    // Create channel for sending encrypted packets and PROTOCOL packets to UDP socket
    let (etx, erx) = mpsc::channel::<opentun::EncryptedPacket>(opentun::CHANNEL_BUFFER_SIZE);

    let mut tasks = Vec::new();
    let tun_listener = tokio::spawn(tasks::tun_listener(
        Arc::clone(&dev_arc),
        Arc::clone(&peer_manager.peer_connections),
        Arc::clone(&locked_runtime_conf),
        etx.clone(),
    ));
    tasks.push(tun_listener);
    let udp_listener = tokio::spawn(tasks::udp_listener(
        Arc::clone(&sock_arc),
        Arc::clone(&config_clone),
        Arc::clone(&locked_runtime_conf),
        Arc::clone(&peer_manager),
        dtx.clone(),
        etx.clone(),
    ));
    tasks.push(udp_listener);
    let result_coordinator = tokio::spawn(tasks::result_coordinator(
        Arc::clone(&dev_arc),
        Arc::clone(&sock_arc),
        erx,
        drx,
    ));
    tasks.push(result_coordinator);

    // Spawn the config updater task
    let config_updater_handle = tokio::spawn(crate::tasks::config_updater(
        config_update_rx,
        Arc::clone(&config),
        Arc::clone(&locked_runtime_conf),
        config_path.to_string(),
        Arc::clone(&peer_manager),
    ));
    tasks.push(config_updater_handle);

    // if peer is dynamic, spawn keepalive task
    if config_clone.role == PeerRole::Dynamic {
        let handshake_task = tokio::spawn(tasks::handshake(
            Arc::clone(&sock_arc),
            Arc::clone(&config_clone),
            Arc::clone(&locked_runtime_conf),
            Arc::clone(&peer_manager),
        ));
        tasks.push(handshake_task);
        let anchor_addr = config_clone
            .peers
            .iter()
            .find(|p| p.is_anchor)
            .and_then(|p| p.endpoint)
            .expect("No anchor peer found in configuration");
        let keepalive_task = tokio::spawn(tasks::keepalive(anchor_addr, Arc::clone(&sock_arc)));
        tasks.push(keepalive_task);
    }

    futures::future::try_join_all(tasks)
        .await // Wait for all tasks to complete
        .map(|_| ())
        .expect("Error joining tasks");

    Ok(())
}
