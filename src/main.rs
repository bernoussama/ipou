use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

use trustun::cli::commands::{handle_gen_key, handle_pub_key};
use trustun::config::PeerRole;
use trustun::crypto::PublicKeyBytes;
use trustun::proto::state::{Peer, VpnState};
use trustun::tasks;
use trustun::{Error, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = trustun::cli::Cli::parse();
    // Subcommands
    match &cli.command {
        Some(trustun::cli::Commands::Genkey {}) => handle_gen_key(),
        Some(trustun::cli::Commands::Pubkey {}) => handle_pub_key(),
        None => Ok(()),
    }
    .expect("Failed to execute command");

    // Load config file
    let config_path = "config.yaml";
    let conf = trustun::config::load_config(config_path);
    let config = Arc::new(conf);

    // Initialize VpnState
    let mut shared_secrets: HashMap<PublicKeyBytes, _> = HashMap::new();
    let mut secret_bytes = [0u8; 32];
    base64::decode_config_slice(&config.secret, base64::STANDARD, &mut secret_bytes).unwrap();
    let static_secret = StaticSecret::from(secret_bytes);

    let mut peers: HashMap<PublicKeyBytes, Peer> = HashMap::new();
    let (config_update_tx, config_update_rx) = mpsc::unbounded_channel();

    for peer_config in &config.peers {
        let mut pub_key_bytes = [0u8; 32];
        base64::decode_config_slice(&peer_config.pub_key, base64::STANDARD, &mut pub_key_bytes)
            .unwrap();
        let pub_key = PublicKey::from(pub_key_bytes);
        let shared_secret = static_secret.diffie_hellman(&pub_key);
        shared_secrets.insert(pub_key_bytes, *shared_secret.as_bytes());

        let mut peer = Peer::with_update_sender(pub_key_bytes, config_update_tx.clone());
        if let Some(endpoint) = peer_config.endpoint {
            if let Ok(ip) = peer_config.allowed_ips[0].parse::<IpAddr>() {
                peer.mark_connected(endpoint, ip);
            }
        }
        peers.insert(pub_key_bytes, peer);
    }

    let state = Arc::new(VpnState {
        peers: RwLock::new(peers),
        ciphers: RwLock::new(HashMap::new()),
        ip_to_pubkey: RwLock::new(HashMap::new()),
        endpoint_to_pubkey: RwLock::new(HashMap::new()),
        shared_secrets,
    });

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config.name)
        .address(config.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(trustun::MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).expect("Failed to create TUN device");
    let sock = UdpSocket::bind(
        config
            .endpoint
            .ok_or(Error::Unknown(
                "endpoint must be configured in config.yaml".to_string(),
            ))?,
    )
    .await
    .expect("Failed to bind UDP socket");
    println!(
        "UDP socket bound to: {}",
        sock.local_addr().expect("Failed to get local address")
    );
    let dev_arc = Arc::new(dev);
    let sock_arc = Arc::new(sock);

    // Create channel for sending decrypted packets to TUN device
    let (dtx, drx) = mpsc::channel::<trustun::DecryptedPacket>(trustun::CHANNEL_BUFFER_SIZE);
    // Create channel for sending encrypted packets and PROTOCOL packets to UDP socket
    let (etx, erx) = mpsc::channel::<trustun::EncryptedPacket>(trustun::CHANNEL_BUFFER_SIZE);

    let mut tasks = Vec::new();
    let tun_listener = tokio::spawn(tasks::tun_listener(
        Arc::clone(&dev_arc),
        Arc::clone(&state),
        etx.clone(),
    ));
    tasks.push(tun_listener);
    let udp_listener = tokio::spawn(tasks::udp_listener(
        Arc::clone(&sock_arc),
        Arc::clone(&config),
        Arc::clone(&state),
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
        Arc::clone(&state),
        config_path.to_string(),
    ));
    tasks.push(config_updater_handle);

    // if peer is dynamic, spawn keepalive task
    if config.role == PeerRole::Dynamic {
        let handshake_task = tokio::spawn(tasks::handshake(
            Arc::clone(&sock_arc),
            Arc::clone(&config),
            Arc::clone(&state),
        ));
        tasks.push(handshake_task);
        let anchor_addr = config
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
