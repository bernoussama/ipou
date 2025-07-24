use ipou::cli::commands::{handle_gen_key, handle_pub_key};
use ipou::events::{EventSystem, EventHandler};
use ipou::net::PeerManager;
use ipou::protocol::state_machine::ProtocolStateMachine;
use std::sync::Arc;
use std::{
    net::{Ipv4Addr, SocketAddr},
};

use clap::Parser;
use ipou::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// Constants
const MTU: usize = 1420;
const CHANNEL_BUFFER_SIZE: usize = MTU + 512; // Buffered channels

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ipou::cli::Cli::parse();
    // Subcommands
    match &cli.command {
        Some(ipou::cli::Commands::Genkey {}) => {
            handle_gen_key()?;
            return Ok(());
        },
        Some(ipou::cli::Commands::Pubkey {}) => {
            handle_pub_key()?;
            return Ok(());
        },
        None => {},
    }

    // Load config file
    let config_path = "config.yaml";
    let conf = ipou::config::load_config(config_path);
    let config = Arc::new(conf.clone());

    // Create peer manager
    let mut peer_manager = PeerManager::new(&config);

    // Extract our public key from the private key
    let private_key_bytes = base64::decode(&conf.private_key)?;
    let our_public_key = {
        let mut key = [0u8; 32];
        key.copy_from_slice(&private_key_bytes);
        let private_key = x25519_dalek::StaticSecret::from(key);
        x25519_dalek::PublicKey::from(&private_key).to_bytes()
    };

    // Create event system
    let (_event_system, event_receiver) = EventSystem::new();
    
    // Start event processing
    EventHandler::start_event_loop(event_receiver).await;

    // Determine our endpoint
    let our_port = config.port.unwrap_or(51820);
    let our_endpoint = SocketAddr::from(([0, 0, 0, 0], our_port));

    // Create channel for sending encrypted packets to UDP socket
    let (utx, mut urx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_BUFFER_SIZE);

    // Create protocol state machine
    let protocol_manager = Arc::new(ProtocolStateMachine::new(
        conf.clone(),
        our_public_key,
        utx.clone(),
    ));

    // Set protocol manager in peer manager
    peer_manager.set_protocol_manager(protocol_manager.clone());

    // Start protocol state machine
    if let Err(e) = protocol_manager.start(our_endpoint).await {
        eprintln!("Failed to start protocol manager: {}", e);
    }

    let mut tun_config = tun::Configuration::default();
    
    // Use configured address or default
    let tun_address = config.address.as_ref()
        .map(|addr| addr.parse::<Ipv4Addr>().unwrap())
        .unwrap_or_else(|| {
            // Fallback to first peer's allowed IP if available
            if !config.peers.is_empty() && !config.peers[0].allowed_ips.is_empty() {
                config.peers[0].allowed_ips[0].parse::<Ipv4Addr>().unwrap()
            } else {
                "10.0.0.1".parse().unwrap()
            }
        });
    
    tun_config
        .tun_name(config.name.as_deref().unwrap_or("ipou"))
        .address(tun_address)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).expect("Failed to create TUN device");
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", our_port))
        .await
        .expect("Failed to bind UDP socket");
    println!(
        "UDP socket bound to: {}",
        sock.local_addr().expect("Failed to get local address")
    );

    // Create channel for sending decrypted packets to TUN device
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);

    // Pre-allocate buffers to avoid repeated allocations
    let mut udp_buf = [0u8; MTU + 512];
    let mut buf = [0u8; MTU];

    loop {
        tokio::select! {

        result = sock.recv_from(&mut udp_buf) => {
                   if let Ok((len, peer_addr)) = result {
                       let tx_clone = tx.clone();
                        if len >= 4 { // Minimum packet size
                            ipou::net::handle_udp_packet(&udp_buf, len, peer_addr, &peer_manager, tx_clone).await
                        }
                   }
        }

           // Receive decrypted packets from channel and send to TUN
           Some(decrypted_packet) = rx.recv() => {
               dev.send(&decrypted_packet).await.unwrap_or_default();
           }

           // Receive decrypted packets from channel and send to TUN
           Some((encrypted_packet, peer_addr)) = urx.recv() => {
               sock.send_to(&encrypted_packet, peer_addr).await.unwrap_or_default();
           }

            result = dev.recv(&mut buf) => {
                   // handle TUN device
                   if let Ok(len) =  result {
                       let utx_clone = utx.clone();
                       if len >= 20 {
                          ipou::net::handle_tun_packet(&buf, len, &peer_manager, utx_clone).await
                       }
                   }
               }
           }
    }
}