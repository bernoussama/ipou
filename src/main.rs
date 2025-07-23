use ipou::cli::commands::{handle_gen_key, handle_pub_key};
use ipou::net::PeerManager;
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
        Some(ipou::cli::Commands::Genkey {}) => handle_gen_key(),
        Some(ipou::cli::Commands::Pubkey {}) => handle_pub_key(),
        None => Ok(()),
    }
    .expect("Failed to execute command");

    // Load config file
    let config_path = "config.yaml";
    let conf = ipou::config::load_config(config_path);
    let config = Arc::new(conf);

    let peer_manager = PeerManager::new(&config);

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name("ipou") // Make this configurable
        .address(config.peers[0].allowed_ips[0].parse::<Ipv4Addr>().unwrap()) // Make this configurable
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).expect("Failed to create TUN device");
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", 51820)) // Make this configurable
        .await
        .expect("Failed to bind UDP socket");
    println!(
        "UDP socket bound to: {}",
        sock.local_addr().expect("Failed to get local address")
    );

    // Create channel for sending decrypted packets to TUN device
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
    // Create channel for sending encrypted packets to UDP socket
    let (utx, mut urx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_BUFFER_SIZE);

    // Pre-allocate buffers to avoid repeated allocations
    let mut udp_buf = [0u8; MTU + 512];
    let mut buf = [0u8; MTU];

    loop {
        tokio::select! {

        result = sock.recv_from(&mut udp_buf) => {
                   if let Ok((len, peer_addr)) = result {
                       let tx_clone = tx.clone();
                        if len >= 28 { // 12 bytes nonce + 16 bytes auth tag
                            ipou::net::handle_udp_packet(&udp_buf, len, peer_addr, &peer_manager,tx_clone).await
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