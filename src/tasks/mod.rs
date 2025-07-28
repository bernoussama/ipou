use std::{net::SocketAddr, sync::Arc};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use tokio::{
    net::UdpSocket,
    sync::{
        RwLock,
        mpsc::{Receiver, Sender},
    },
};
use tun::AsyncDevice;

use crate::{
    MAX_UDP_SIZE,
    config::{Config, ConfigUpdateEvent, ConfigUpdateReceiver, RuntimeConfig},
    crypto::PublicKeyBytes,
    net::{PeerConnections, PeerManager},
    proto::Packet,
};

// Spawned listeners
pub async fn tun_listener(
    dev: Arc<AsyncDevice>,
    peer_connections: PeerConnections,
    runtime_conf: Arc<RwLock<RuntimeConfig>>,
    etx: Sender<crate::EncryptedPacket>,
) -> crate::Result<()> {
    let mut tun_buf = [0u8; crate::MTU];

    loop {
        // Listen for TUN packets
        let len = dev.recv(&mut tun_buf).await?;
        // Spawn handler task for each packet
        if len >= 20 {
            tokio::spawn(crate::net::handle_tun_packet(
                tun_buf,
                len,
                Arc::clone(&peer_connections),
                Arc::clone(&runtime_conf),
                etx.clone(),
            ));
        }
        // Send raw packet + result channel to handler
    }
}

pub async fn udp_listener(
    sock: Arc<UdpSocket>,
    conf: Arc<Config>,
    runtime_conf: Arc<RwLock<RuntimeConfig>>,
    peer_manager: Arc<PeerManager>,
    dtx: Sender<crate::DecryptedPacket>,
    etx: Sender<crate::EncryptedPacket>,
) -> crate::Result<()> {
    let mut udp_buf = [0u8; MAX_UDP_SIZE];
    loop {
        // Listen for UDP packets
        let (len, peer_addr) = sock.recv_from(&mut udp_buf).await?;
        if len > 0 {
            // let packet_types = std::mem::variant_count::<Packet>(); // unstable feature

            // match on first byte to determine packet type
            match udp_buf[0] {
                0x01..=0x0F => {
                    if let Ok(packet) = Packet::decode(&udp_buf[1..len]) {
                        #[cfg(debug_assertions)]
                        println!("Received protocol packet from {peer_addr}: {packet:?}");
                        Arc::clone(&peer_manager)
                            .handle_proto_packet(Arc::clone(&conf), packet, peer_addr, etx.clone())
                            .await?;
                    } else {
                        #[cfg(debug_assertions)]
                        println!("Received invalid protocol packet from {peer_addr}");
                    }
                }
                0x10 => {
                    if len >= 30 {
                        #[cfg(debug_assertions)]
                        println!("Received encrypted packet from {peer_addr}");
                        // 12 bytes nonce + 16 bytes auth tag
                        tokio::spawn(crate::net::handle_udp_packet(
                            udp_buf[1..len].try_into().unwrap(), // skip first byte
                            len - 1,
                            peer_addr,
                            Arc::clone(&runtime_conf),
                            dtx.clone(),
                        ));
                    }
                }
                _ => {
                    #[cfg(debug_assertions)]
                    println!("Received unknown packet type from {peer_addr}");
                }
            }
        };
        // Send raw packet + result channel to handler
    }
}

pub async fn result_coordinator(
    dev: Arc<AsyncDevice>,
    sock: Arc<UdpSocket>,
    mut erx: Receiver<crate::EncryptedPacket>,
    mut drx: Receiver<crate::DecryptedPacket>,
) -> crate::Result<()> {
    // This task coordinates sending decrypted packets to TUN and encrypted packets to UDP
    // It runs indefinitely, processing packets as they arrive

    #[cfg(debug_assertions)]
    println!("Starting result coordinator...");

    loop {
        tokio::select! {
                   // Receive decrypted packets from channel and send to TUN
                   Some(decrypted_packet) = drx.recv() => {
                       match dev.send(&decrypted_packet).await {
                        Ok(sent) => {
                            #[cfg(debug_assertions)]
                            println!("Sent {sent} bytes to TUN dev");
                        },
                        Err(e) => {
                        eprintln!("Error sending packet to TUN device: {e}");
                        },
                       }
                   }

                   // Receive enccrypted packets from channel and send to UDP
                   Some((encrypted_packet, peer_addr)) = erx.recv() => {
                        #[cfg(debug_assertions)]
                        println!("Sending encrypted packet to peer: {peer_addr}");
                       match sock.send_to(&encrypted_packet, peer_addr).await {
                           Ok(sent) => {
                            #[cfg(debug_assertions)]
                            println!("Sent {sent} bytes to {peer_addr}");
                        },
                           Err(e) => {
                               eprintln!("Error sending encrypted packet to peer {peer_addr}: {e}");
                        },
                       }
                   }
        }
    }
}

/// This task sends periodic keepalive packets to the remote peer
pub async fn keepalive(remote_addr: SocketAddr, sock: Arc<UdpSocket>) -> crate::Result<()> {
    let keepalive_packet = Packet::KeepAlive {
        timestamp: crate::proto::now(),
    };
    let wire_packet = crate::proto::WirePacket {
        packet_type: crate::proto::PacketType::KeepAlive,
        payload: keepalive_packet,
    };

    loop {
        let packet_bytes = wire_packet.encode()?;
        if let Err(e) = sock.send_to(&packet_bytes, remote_addr).await {
            eprintln!("Error sending keepalive packet to {remote_addr}: {e}");
        }
        #[cfg(debug_assertions)]
        println!("sent keepalive packet to {remote_addr}");
        tokio::time::sleep(std::time::Duration::from_secs(crate::KEEPALIVE_INTERVAL)).await; // Adjust interval as needed
    }
}
/// task to initiate a handshake with the anchor peer
pub async fn handshake(
    sock: Arc<UdpSocket>,
    config: Arc<Config>,
    runtime_conf: Arc<RwLock<RuntimeConfig>>,
    peer_manager: Arc<PeerManager>,
) -> crate::Result<()> {
    #[cfg(debug_assertions)]
    println!("Starting handshake...");
    let mut pubkey_bytes = [0u8; 32];
    base64::decode_config_slice(&config.pubkey, base64::STANDARD, &mut pubkey_bytes)?;
    let handshake_packet = Packet::HandshakeInit {
        sender_pubkey: pubkey_bytes,
        timestamp: crate::proto::now(),
    };
    let wire_packet = crate::proto::WirePacket {
        packet_type: crate::proto::PacketType::HandshakeInit,
        payload: handshake_packet,
    };

    // check if every anchor peer is connected
    loop {
        // Send handshake packet to each anchor peer
        for peer in &config.peers {
            if let Some(endpoint) = peer.endpoint {
                let packet_bytes = wire_packet.encode()?;
                if let Err(e) = sock.send_to(&packet_bytes, endpoint).await {
                    eprintln!("Error sending handshake packet to {}: {e}", endpoint);
                } else {
                    #[cfg(debug_assertions)]
                    println!("Sent handshake packet to {}", endpoint);
                }
            }
        }

        let all_connected = peer_manager
            .peer_connections
            .read()
            .await
            .values()
            .all(|conn| conn.is_connected());
        if all_connected {
            #[cfg(debug_assertions)]
            println!("All anchor peers are connected.");
            break;
        }
        // Wait before sending again
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    Ok(())
}

pub async fn config_updater(
    mut update_rx: ConfigUpdateReceiver,
    config: Arc<Config>,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    config_path: String,
    peer_manager: Arc<PeerManager>,
) -> crate::Result<()> {
    while let Some(event) = update_rx.recv().await {
        match event {
            ConfigUpdateEvent::PeerConnected { pubkey, endpoint } => {
                // Update runtime config with new cipher if needed
                if let Some(shared_secret) = runtime_config.read().await.shared_secrets.get(&pubkey)
                {
                    let cipher = ChaCha20Poly1305::new(shared_secret.into());
                    runtime_config
                        .write()
                        .await
                        .ciphers
                        .insert(endpoint, cipher);
                }

                // Update persistent config file
                if let Err(e) = update_config_file(&config_path, &pubkey, Some(endpoint)).await {
                    eprintln!("Failed to update config file: {e}");
                }
            }
            ConfigUpdateEvent::PeerDisconnected { pubkey } => {
                // Remove from runtime config
                if let Some(peer) = peer_manager.peer_connections.read().await.get(&pubkey) {
                    if let Some(endpoint) = peer.last_endpoint {
                        runtime_config.write().await.ciphers.remove(&endpoint);
                    }
                }

                // Update persistent config file
                if let Err(e) = update_config_file(&config_path, &pubkey, None).await {
                    eprintln!("Failed to update config file: {e}");
                }
            }
            ConfigUpdateEvent::PeerStateChanged { pubkey, state } => {
                // Handle state changes as needed
                #[cfg(debug_assertions)]
                println!(
                    "Peer {} state changed to {:?}",
                    base64::encode(pubkey),
                    state
                );
            }
        }
    }
    Ok(())
}

async fn update_config_file(
    config_path: &str,
    pubkey: &PublicKeyBytes,
    endpoint: Option<SocketAddr>,
) -> crate::Result<()> {
    // Read current config
    let mut config: Config = {
        let content = tokio::fs::read_to_string(config_path).await?;
        serde_yml::from_str(&content)?
    };

    // Find and update the peer
    let pubkey_str = base64::encode(pubkey);
    if let Some(peer_config) = config.peers.iter_mut().find(|p| p.pub_key == pubkey_str) {
        peer_config.endpoint = endpoint;
    }

    // Write back to file
    let updated_content = serde_yml::to_string(&config)?;
    tokio::fs::write(config_path, updated_content).await?;

    #[cfg(debug_assertions)]
    println!("Updated config file for peer {}", pubkey_str);

    Ok(())
}
