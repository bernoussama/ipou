use std::{net::{SocketAddr, IpAddr}, sync::Arc};

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
    #[cfg(debug_assertions)]
    println!("[TUN_LISTENER] Starting TUN listener task");

    let mut tun_buf = [0u8; crate::MTU];

    loop {
        #[cfg(debug_assertions)]
        println!("[TUN_LISTENER] Waiting for TUN packets...");

        // Listen for TUN packets
        let len = dev.recv(&mut tun_buf).await?;

        #[cfg(debug_assertions)]
        println!("[TUN_LISTENER] Received packet of {len} bytes from TUN");

        // Spawn handler task for each packet
        if len >= 20 {
            #[cfg(debug_assertions)]
            println!("[TUN_LISTENER] Spawning handler for valid packet (>= 20 bytes)");

            tokio::spawn(crate::net::handle_tun_packet(
                tun_buf,
                len,
                Arc::clone(&peer_connections),
                Arc::clone(&runtime_conf),
                etx.clone(),
            ));
        } else {
            #[cfg(debug_assertions)]
            println!("[TUN_LISTENER] Dropping packet too small: {len} bytes");
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
    #[cfg(debug_assertions)]
    println!("[UDP_LISTENER] Starting UDP listener task");

    let mut udp_buf = [0u8; MAX_UDP_SIZE];
    loop {
        #[cfg(debug_assertions)]
        println!("[UDP_LISTENER] Waiting for UDP packets...");

        // Listen for UDP packets
        let (len, peer_addr) = sock.recv_from(&mut udp_buf).await?;

        #[cfg(debug_assertions)]
        println!("[UDP_LISTENER] Received {len} bytes from {peer_addr}");

        if len > 0 {
            // let packet_types = std::mem::variant_count::<Packet>(); // unstable feature

            // match on first byte to determine packet type
            #[cfg(debug_assertions)]
            println!(
                "[UDP_LISTENER] Processing packet type: 0x{:02x}",
                udp_buf[0]
            );

            match udp_buf[0] {
                0x01..=0x0F => {
                    #[cfg(debug_assertions)]
                    println!("[UDP_LISTENER] Processing protocol packet");

                    if let Ok(packet) = Packet::decode(&udp_buf[1..len]) {
                        #[cfg(debug_assertions)]
                        println!(
                            "[UDP_LISTENER] Received protocol packet from {peer_addr}: {packet:?}"
                        );
                        Arc::clone(&peer_manager)
                            .handle_proto_packet(
                                Arc::clone(&conf),
                                Arc::clone(&runtime_conf),
                                packet,
                                peer_addr,
                                etx.clone(),
                            )
                            .await?;
                    } else {
                        #[cfg(debug_assertions)]
                        println!(
                            "[UDP_LISTENER] Received invalid protocol packet from {peer_addr}"
                        );
                    }
                }
                0x10 => {
                    #[cfg(debug_assertions)]
                    println!("[UDP_LISTENER] Processing encrypted packet");

                    if len >= 30 {
                        #[cfg(debug_assertions)]
                        println!(
                            "[UDP_LISTENER] Received encrypted packet from {peer_addr} ({len} bytes)"
                        );
                        // 12 bytes nonce + 16 bytes auth tag
                        tokio::spawn(crate::net::handle_udp_packet(
                            udp_buf[1..len].try_into().unwrap(), // skip first byte
                            len - 1,
                            peer_addr,
                            Arc::clone(&runtime_conf),
                            dtx.clone(),
                        ));
                    } else {
                        #[cfg(debug_assertions)]
                        println!(
                            "[UDP_LISTENER] Dropping encrypted packet too small: {len} bytes"
                        );
                    }
                }
                _ => {
                    #[cfg(debug_assertions)]
                    println!(
                        "[UDP_LISTENER] Received unknown packet type 0x{:02x} from {peer_addr}",
                        udp_buf[0]
                    );
                }
            }
        } else {
            #[cfg(debug_assertions)]
            println!("[UDP_LISTENER] Received empty packet from {peer_addr}");
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
    println!("[RESULT_COORDINATOR] Starting result coordinator...");

    loop {
        #[cfg(debug_assertions)]
        println!("[RESULT_COORDINATOR] Waiting for packets to coordinate...");

        tokio::select! {
                   // Receive decrypted packets from channel and send to TUN
                   Some(decrypted_packet) = drx.recv() => {
                       #[cfg(debug_assertions)]
                       println!("[RESULT_COORDINATOR] Received decrypted packet ({} bytes) for TUN", decrypted_packet.len());

                       match dev.send(&decrypted_packet).await {
                        Ok(sent) => {
                            #[cfg(debug_assertions)]
                            println!("[RESULT_COORDINATOR] Successfully sent {sent} bytes to TUN dev");
                        },
                        Err(e) => {
                        #[cfg(debug_assertions)]
                        println!("[RESULT_COORDINATOR] Error sending packet to TUN device: {e}");
                        eprintln!("Error sending packet to TUN device: {e}");
                        },
                       }
                   }

                   // Receive enccrypted packets from channel and send to UDP
                   Some((encrypted_packet, peer_addr)) = erx.recv() => {
                        #[cfg(debug_assertions)]
                        println!("[RESULT_COORDINATOR] Received encrypted packet ({} bytes) for peer: {peer_addr}", encrypted_packet.len());

                       match sock.send_to(&encrypted_packet, peer_addr).await {
                           Ok(sent) => {
                            #[cfg(debug_assertions)]
                            println!("[RESULT_COORDINATOR] Successfully sent {sent} bytes to {peer_addr}");
                        },
                           Err(e) => {
                               #[cfg(debug_assertions)]
                               println!("[RESULT_COORDINATOR] Error sending encrypted packet to peer {peer_addr}: {e}");
                               eprintln!("Error sending encrypted packet to peer {peer_addr}: {e}");
                        },
                       }
                   }
        }
    }
}

/// This task sends periodic keepalive packets to the remote peer
pub async fn keepalive(remote_addr: SocketAddr, sock: Arc<UdpSocket>) -> crate::Result<()> {
    #[cfg(debug_assertions)]
    println!("[KEEPALIVE] Starting keepalive task for {remote_addr}");

    let keepalive_packet = Packet::KeepAlive {
        timestamp: crate::proto::now(),
    };
    let wire_packet = crate::proto::WirePacket {
        packet_type: crate::proto::PacketType::KeepAlive,
        payload: keepalive_packet,
    };

    #[cfg(debug_assertions)]
    println!("[KEEPALIVE] Prepared keepalive packet for {remote_addr}");

    loop {
        #[cfg(debug_assertions)]
        println!("[KEEPALIVE] Sending keepalive to {remote_addr}...");

        let packet_bytes = wire_packet.encode()?;

        #[cfg(debug_assertions)]
        println!(
            "[KEEPALIVE] Encoded packet ({} bytes) for {}",
            packet_bytes.len(),
            remote_addr
        );

        if let Err(e) = sock.send_to(&packet_bytes, remote_addr).await {
            #[cfg(debug_assertions)]
            println!("[KEEPALIVE] Error sending keepalive packet to {remote_addr}: {e}");
            eprintln!("Error sending keepalive packet to {remote_addr}: {e}");
        } else {
            #[cfg(debug_assertions)]
            println!("[KEEPALIVE] Successfully sent keepalive packet to {remote_addr}");
        }

        #[cfg(debug_assertions)]
        println!(
            "[KEEPALIVE] Sleeping for {} seconds before next keepalive",
            crate::KEEPALIVE_INTERVAL
        );

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
    println!("[HANDSHAKE] Starting handshake task...");

    let mut pubkey_bytes = [0u8; 32];
    base64::decode_config_slice(&config.pubkey, base64::STANDARD, &mut pubkey_bytes)?;

    #[cfg(debug_assertions)]
    println!(
        "[HANDSHAKE] Decoded public key: {}",
        base64::encode(pubkey_bytes)
    );

    let private_ip: IpAddr = config.address.parse()
        .map_err(|e| crate::IpouError::Unknown(format!("Invalid private IP in config: {e}")))?;

    let handshake_packet = Packet::HandshakeInit {
        sender_pubkey: pubkey_bytes,
        sender_private_ip: private_ip,
        timestamp: crate::proto::now(),
    };
    let wire_packet = crate::proto::WirePacket {
        packet_type: crate::proto::PacketType::HandshakeInit,
        payload: handshake_packet,
    };

    #[cfg(debug_assertions)]
    println!("[HANDSHAKE] Prepared handshake packet");

    // check if every anchor peer is connected
    loop {
        #[cfg(debug_assertions)]
        println!(
            "[HANDSHAKE] Starting handshake round with {} peers",
            config.peers.len()
        );

        // Send handshake packet to each anchor peer
        for (i, peer) in config.peers.iter().enumerate() {
            if let Some(endpoint) = peer.endpoint {
                #[cfg(debug_assertions)]
                println!(
                    "[HANDSHAKE] Sending handshake to peer {}/{}: {}",
                    i + 1,
                    config.peers.len(),
                    endpoint
                );

                let packet_bytes = wire_packet.encode()?;
                if let Err(e) = sock.send_to(&packet_bytes, endpoint).await {
                    #[cfg(debug_assertions)]
                    println!(
                        "[HANDSHAKE] Error sending handshake packet to {endpoint}: {e}"
                    );
                    eprintln!("Error sending handshake packet to {endpoint}: {e}");
                } else {
                    #[cfg(debug_assertions)]
                    println!(
                        "[HANDSHAKE] Successfully sent handshake packet to {endpoint}"
                    );
                }
            } else {
                #[cfg(debug_assertions)]
                println!(
                    "[HANDSHAKE] Skipping peer {}/{} (no endpoint)",
                    i + 1,
                    config.peers.len()
                );
            }
        }

        #[cfg(debug_assertions)]
        println!("[HANDSHAKE] Checking connection status of all peers...");

        let all_connected = peer_manager
            .peer_connections
            .read()
            .await
            .values()
            .all(|conn| conn.is_connected());

        #[cfg(debug_assertions)]
        println!("[HANDSHAKE] All peers connected: {all_connected}");

        if all_connected {
            #[cfg(debug_assertions)]
            println!("[HANDSHAKE] All anchor peers are connected. Handshake task completed.");
            break;
        }

        #[cfg(debug_assertions)]
        println!("[HANDSHAKE] Not all peers connected, waiting 5 seconds before retry...");

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
    #[cfg(debug_assertions)]
    println!("[CONFIG_UPDATER] Starting config updater task");

    while let Some(event) = update_rx.recv().await {
        #[cfg(debug_assertions)]
        println!("[CONFIG_UPDATER] Received config update event: {event:?}");

        match event {
            ConfigUpdateEvent::PeerConnected { pubkey, endpoint } => {
                #[cfg(debug_assertions)]
                println!(
                    "[CONFIG_UPDATER] Processing peer connected event for {}",
                    base64::encode(pubkey)
                );

                // Update runtime config with new cipher if needed
                if let Some(shared_secret) = runtime_config.read().await.shared_secrets.get(&pubkey)
                {
                    #[cfg(debug_assertions)]
                    println!(
                        "[CONFIG_UPDATER] Creating cipher for peer {} at endpoint {}",
                        base64::encode(pubkey),
                        endpoint
                    );

                    let cipher = ChaCha20Poly1305::new(shared_secret.into());
                    runtime_config
                        .write()
                        .await
                        .ciphers
                        .insert(endpoint, cipher);

                    #[cfg(debug_assertions)]
                    println!("[CONFIG_UPDATER] Cipher added to runtime config");
                } else {
                    #[cfg(debug_assertions)]
                    println!(
                        "[CONFIG_UPDATER] No shared secret found for peer {}",
                        base64::encode(pubkey)
                    );
                }

                #[cfg(debug_assertions)]
                println!("[CONFIG_UPDATER] Updating persistent config file...");

                // Update persistent config file
                if let Err(e) = update_config_file(&config_path, &pubkey, Some(endpoint)).await {
                    #[cfg(debug_assertions)]
                    println!("[CONFIG_UPDATER] Failed to update config file: {e}");
                    eprintln!("Failed to update config file: {e}");
                } else {
                    #[cfg(debug_assertions)]
                    println!("[CONFIG_UPDATER] Config file updated successfully");
                }
            }
            ConfigUpdateEvent::PeerDisconnected { pubkey } => {
                #[cfg(debug_assertions)]
                println!(
                    "[CONFIG_UPDATER] Processing peer disconnected event for {}",
                    base64::encode(pubkey)
                );

                // Remove from runtime config
                if let Some(peer) = peer_manager.peer_connections.read().await.get(&pubkey) {
                    if let Some(endpoint) = peer.last_endpoint {
                        #[cfg(debug_assertions)]
                        println!(
                            "[CONFIG_UPDATER] Removing cipher for endpoint {endpoint} from runtime config"
                        );

                        runtime_config.write().await.ciphers.remove(&endpoint);
                    } else {
                        #[cfg(debug_assertions)]
                        println!("[CONFIG_UPDATER] No last endpoint found for disconnected peer");
                    }
                } else {
                    #[cfg(debug_assertions)]
                    println!(
                        "[CONFIG_UPDATER] Peer connection not found for {}",
                        base64::encode(pubkey)
                    );
                }

                #[cfg(debug_assertions)]
                println!("[CONFIG_UPDATER] Updating persistent config file for disconnection...");

                // Update persistent config file
                if let Err(e) = update_config_file(&config_path, &pubkey, None).await {
                    #[cfg(debug_assertions)]
                    println!("[CONFIG_UPDATER] Failed to update config file: {e}");
                    eprintln!("Failed to update config file: {e}");
                } else {
                    #[cfg(debug_assertions)]
                    println!("[CONFIG_UPDATER] Config file updated successfully for disconnection");
                }
            }
            ConfigUpdateEvent::PeerStateChanged { pubkey, state } => {
                #[cfg(debug_assertions)]
                println!(
                    "[CONFIG_UPDATER] Peer {} state changed to {:?}",
                    base64::encode(pubkey),
                    state
                );
            }
        }
    }

    #[cfg(debug_assertions)]
    println!("[CONFIG_UPDATER] Config updater task ended");

    Ok(())
}

async fn update_config_file(
    config_path: &str,
    pubkey: &PublicKeyBytes,
    endpoint: Option<SocketAddr>,
) -> crate::Result<()> {
    #[cfg(debug_assertions)]
    println!(
        "[UPDATE_CONFIG_FILE] Starting config file update for peer {}",
        base64::encode(pubkey)
    );

    // Read current config
    #[cfg(debug_assertions)]
    println!("[UPDATE_CONFIG_FILE] Reading config file: {config_path}");

    let mut config: Config = {
        let content = tokio::fs::read_to_string(config_path).await?;

        #[cfg(debug_assertions)]
        println!(
            "[UPDATE_CONFIG_FILE] Config file read successfully ({} bytes)",
            content.len()
        );

        serde_yml::from_str(&content)?
    };

    #[cfg(debug_assertions)]
    println!("[UPDATE_CONFIG_FILE] Config parsed successfully");

    // Find and update the peer
    let pubkey_str = base64::encode(pubkey);

    #[cfg(debug_assertions)]
    println!("[UPDATE_CONFIG_FILE] Looking for peer {pubkey_str} in config");

    if let Some(peer_config) = config.peers.iter_mut().find(|p| p.pub_key == pubkey_str) {
        #[cfg(debug_assertions)]
        println!(
            "[UPDATE_CONFIG_FILE] Found peer config, updating endpoint from {:?} to {:?}",
            peer_config.endpoint, endpoint
        );

        peer_config.endpoint = endpoint;

        #[cfg(debug_assertions)]
        println!("[UPDATE_CONFIG_FILE] Peer config updated");
    } else {
        #[cfg(debug_assertions)]
        println!("[UPDATE_CONFIG_FILE] Peer {pubkey_str} not found in config");
    }

    #[cfg(debug_assertions)]
    println!("[UPDATE_CONFIG_FILE] Serializing updated config...");

    // Write back to file
    let updated_content = serde_yml::to_string(&config)?;

    #[cfg(debug_assertions)]
    println!(
        "[UPDATE_CONFIG_FILE] Writing updated config ({} bytes) to file",
        updated_content.len()
    );

    tokio::fs::write(config_path, updated_content).await?;

    #[cfg(debug_assertions)]
    println!("[UPDATE_CONFIG_FILE] Updated config file for peer {pubkey_str}");

    Ok(())
}
