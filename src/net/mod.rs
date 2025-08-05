use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use crate::Error;
use crate::config::{Config, ConfigUpdateSender, PeerRole, RuntimeConfig};
use crate::crypto::{PublicKeyBytes, generate_shared_secret};
use crate::proto::state::PeerConnection;
use crate::proto::{Packet, PacketType, WirePacket};

pub type PeerConnections = Arc<RwLock<HashMap<PublicKeyBytes, PeerConnection>>>;

pub struct PeerManager {
    pub peer_connections: PeerConnections,
    pub config_update_tx: ConfigUpdateSender,
}

impl PeerManager {
    pub fn new(config_update_tx: ConfigUpdateSender) -> Self {
        Self {
            peer_connections: Arc::new(RwLock::new(HashMap::new())),
            config_update_tx,
        }
    }
    pub async fn handle_proto_packet(
        &self,
        conf: Arc<Config>,
        runtime_conf: Arc<RwLock<RuntimeConfig>>,
        packet: Packet,
        sender_addr: SocketAddr,
        etx: mpsc::Sender<crate::EncryptedPacket>,
    ) -> crate::Result<()> {
        // if there is a response
        if let Some(res) = match packet {
            Packet::HandshakeInit {
                sender_pubkey,
                sender_private_ip,
                timestamp,
            } => {
                let mut peer_connections = self.peer_connections.write().await;
                let connection = peer_connections.entry(sender_pubkey).or_insert(
                    PeerConnection::with_update_sender(
                        sender_pubkey,
                        self.config_update_tx.clone(),
                    ),
                );
                connection.mark_connected(sender_addr);
                connection.last_seen = timestamp;

                runtime_conf
                    .write()
                    .await
                    .ips
                    .insert(sender_addr, sender_private_ip);
                runtime_conf
                    .write()
                    .await
                    .ip_to_pubkey
                    .insert(sender_private_ip, sender_pubkey);

                // Create cipher for the peer if we don't have one yet
                if !runtime_conf.read().await.ciphers.contains_key(&sender_pubkey) {
                    if let Some(shared_secret) =
                        runtime_conf.read().await.shared_secrets.get(&sender_pubkey)
                    {
                        let cipher = ChaCha20Poly1305::new(shared_secret.into());
                        runtime_conf
                            .write()
                            .await
                            .ciphers
                            .insert(sender_pubkey, cipher);

                        #[cfg(debug_assertions)]
                        println!(
                            "[HANDSHAKE] Created cipher for peer {} at endpoint {}",
                            base64::encode(sender_pubkey),
                            sender_addr
                        );
                    } else {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "[HANDSHAKE] No shared secret found for peer {}",
                            base64::encode(sender_pubkey)
                        );
                        //Create shared secret if it doesn't exist
                        let shared_secret =
                            generate_shared_secret(&conf.secret, &base64::encode(sender_pubkey));

                        // Save shared secret for future use
                        runtime_conf
                            .write()
                            .await
                            .shared_secrets
                            .insert(sender_pubkey, shared_secret);

                        #[cfg(debug_assertions)]
                        println!(
                            "[CONFIG_UPDATER] Creating cipher for peer {} at endpoint {}",
                            base64::encode(sender_pubkey),
                            sender_addr
                        );

                        let cipher = ChaCha20Poly1305::new(&shared_secret.into());
                        runtime_conf
                            .write()
                            .await
                            .ciphers
                            .insert(sender_pubkey, cipher);

                        #[cfg(debug_assertions)]
                        println!("[CONFIG_UPDATER] Cipher added to runtime config");
                    }
                }

                // Update current endpoint for this peer
                runtime_conf
                    .write()
                    .await
                    .current_endpoints
                    .insert(sender_pubkey, sender_addr);

                // Store the association between public key, private IP, and socket address
                #[cfg(debug_assertions)]
                println!(
                    "[HANDSHAKE] Associated peer {} (private IP: {}) with socket: {}",
                    base64::encode(sender_pubkey),
                    sender_private_ip,
                    sender_addr
                );

                // Respond with HandshakeResponse
                Some(WirePacket {
                    packet_type: PacketType::HandshakeResponse,
                    payload: Packet::HandshakeResponse {
                        success: true,
                        message: "Handshake successful".to_string(),
                    },
                })
            }
            Packet::HandshakeResponse { success, message } => {
                if success {
                    #[cfg(debug_assertions)]
                    println!("Handshake successful: {message}");
                    let sender_pubkey = runtime_conf
                        .read()
                        .await
                        .ip_to_pubkey
                        .get(
                            &runtime_conf
                                .read()
                                .await
                                .ips
                                .get(&sender_addr)
                                .copied()
                                .unwrap(),
                        )
                        .copied()
                        .unwrap();
                    let mut peer_connections = self.peer_connections.write().await;

                    let connection = peer_connections.get_mut(&sender_pubkey).unwrap();
                    connection.mark_connected(sender_addr);
                    connection.last_seen = crate::proto::now();
                } else {
                    #[cfg(debug_assertions)]
                    eprintln!("Handshake failed: {message}");
                }
                None
            }
            Packet::RequestPeer { target_pubkey } => {
                let peer_connections = self.peer_connections.read().await;
                if let Some(peer) = peer_connections.get(&target_pubkey) {
                    // Respond with PeerInfo
                    Some(WirePacket {
                        packet_type: PacketType::PeerInfo,
                        payload: Packet::PeerInfo {
                            pubkey: target_pubkey,
                            endpoint: peer.last_endpoint,
                            last_seen: peer.last_seen,
                        },
                    })
                } else {
                    eprintln!("Peer {} not found!", base64::encode(target_pubkey));
                    Some(WirePacket {
                        packet_type: PacketType::PeerInfo,
                        payload: Packet::PeerInfo {
                            pubkey: target_pubkey,
                            endpoint: None,
                            last_seen: 0,
                        },
                    })
                }
            }
            Packet::PeerInfo {
                pubkey,
                endpoint,
                last_seen,
            } => {
                #[cfg(debug_assertions)]
                println!(
                    "Received PeerInfo for {}: {:?}, last seen: {}",
                    base64::encode(pubkey),
                    endpoint,
                    last_seen
                );
                if let Some(endpoint) = endpoint {
                    // self.initiate_connection(pubkey, endpoint).await;
                    self.peer_connections
                        .write()
                        .await
                        .entry(pubkey)
                        .or_insert(PeerConnection::new(pubkey))
                        .mark_connected(endpoint);
                }
                None
            }

            Packet::KeepAlive { timestamp } => {
                #[cfg(debug_assertions)]
                println!("Received KeepAlive at {timestamp}");
                // Reply with keepalive to maintain NAT mapping
                if conf.role == PeerRole::Anchor {
                    #[cfg(debug_assertions)]
                    println!("Anchor peer received KeepAlive from {sender_addr}");

                    Some(WirePacket {
                        packet_type: PacketType::KeepAlive,
                        payload: Packet::KeepAlive {
                            timestamp: crate::proto::now(),
                        },
                    })
                } else {
                    #[cfg(debug_assertions)]
                    println!("Regular peer received KeepAlive from {sender_addr}");
                    None
                }
            }
            _ => None,
        } {
            let packet_bytes = res.encode()?;
            if let Err(e) = etx.send((packet_bytes.clone(), sender_addr)).await {
                #[cfg(debug_assertions)]
                eprintln!("Error sending encrypted packet through channel: {e}");
                Err(Error::Unknown("Sending packet failed".to_string()))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

pub async fn handle_udp_packet(
    udp_buf: [u8; crate::MAX_UDP_SIZE],
    len: usize,
    peer_addr: SocketAddr,
    runtime_conf: Arc<RwLock<RuntimeConfig>>,
    dtx: mpsc::Sender<crate::DecryptedPacket>,
) {
    // Extract nonce and encrypted data
    let nonce = Nonce::from_slice(&udp_buf[..12]);
    let encrypted_data = &udp_buf[12..len];

    // Look up the public key for this peer address via private IP
    let runtime_config = runtime_conf.read().await;
    let maybe_pubkey = runtime_config
        .ips
        .get(&peer_addr)
        .and_then(|ip| runtime_config.ip_to_pubkey.get(ip))
        .copied();

    if let Some(pubkey) = maybe_pubkey {
        if let Some(cipher) = runtime_config.ciphers.get(&pubkey) {
            match cipher.decrypt(nonce, encrypted_data) {
                Ok(decrypted) => {
                    if decrypted.len() >= 20 {
                        if let Err(e) = dtx.send(decrypted).await {
                            eprintln!("Error sending decrypted packet through channel: {e}");
                        }
                    } else {
                        eprintln!("Decrypted packet too short: {} bytes", decrypted.len());
                    }
                }
                Err(e) => {
                    eprintln!("Decryption failed for peer {peer_addr:?}: {e}");
                }
            }
        } else {
            eprintln!("No cipher found for peer pubkey: {}", base64::encode(pubkey));
        }
    } else {
        eprintln!("No cipher found for peer: {peer_addr:?}");
    }
}

pub async fn handle_tun_packet(
    buf: [u8; crate::MTU],
    len: usize,
    peer_connections: PeerConnections,
    runtime_conf: Arc<RwLock<RuntimeConfig>>,
    etx: mpsc::Sender<crate::EncryptedPacket>,
) {
    let mut packet = Vec::with_capacity(crate::MTU + crate::ENCRYPTION_OVERHEAD);
    if let Some(dst_ip) = extract_dst_ip(&buf) {
        if let Some(&pub_key) = runtime_conf.read().await.ip_to_pubkey.get(&dst_ip) {
            #[cfg(debug_assertions)]
            println!(
                "Destination IP: {dst_ip}, Public Key: {}",
                base64::encode(pub_key)
            );
            if let Some(peer) = peer_connections.read().await.get(&pub_key) {
                #[cfg(debug_assertions)]
                println!(
                    "Found peer connection for destination IP: {dst_ip}, Public Key: {}",
                    base64::encode(pub_key)
                );
                if let Some(cipher) = runtime_conf
                    .read()
                    .await
                    .ciphers
                    .get(&pub_key)
                {
                    #[cfg(debug_assertions)]
                    println!(
                        "Using cipher for destination IP: {dst_ip}, Public Key: {}",
                        base64::encode(pub_key)
                    );
                    let mut nonce_bytes = [0u8; 12];
                    rand::rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let data = &buf[..len];
                    match cipher.encrypt(nonce, data) {
                        Ok(encrypted) => {
                            packet.clear();
                            packet.push(0x10); // Protocol packet type
                            packet.extend_from_slice(&nonce_bytes); // Include nonce
                            packet.extend_from_slice(&encrypted);
                            #[cfg(debug_assertions)]
                            println!(
                                "Sending encrypted packet to {:?}: {} bytes",
                                peer.last_endpoint,
                                packet.len()
                            );
                            if let Err(e) = etx
                                .send((
                                    packet.clone(),
                                    peer.last_endpoint.expect("last_endpoint is None"),
                                ))
                                .await
                            {
                                #[cfg(debug_assertions)]
                                eprintln!("Error sending encrypted packet through channel: {e}");
                            }
                        }
                        Err(_e) => {
                            #[cfg(debug_assertions)]
                            eprintln!("Error encrypting packet for destination IP: {dst_ip}");
                        }
                    }
                } else {
                    // Try to create cipher if we have a shared secret
                    if let Some(shared_secret) = runtime_conf.read().await.shared_secrets.get(&pub_key) {
                        #[cfg(debug_assertions)]
                        println!(
                            "Creating missing cipher for destination IP: {dst_ip}, Public Key: {}",
                            base64::encode(pub_key)
                        );
                        
                        let cipher = ChaCha20Poly1305::new(shared_secret.into());
                        runtime_conf
                            .write()
                            .await
                            .ciphers
                            .insert(pub_key, cipher.clone());
                        
                        // Now retry the encryption
                        let mut nonce_bytes = [0u8; 12];
                        rand::rng().fill_bytes(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        let data = &buf[..len];
                        match cipher.encrypt(nonce, data) {
                            Ok(encrypted) => {
                                packet.clear();
                                packet.push(0x10); // Protocol packet type
                                packet.extend_from_slice(&nonce_bytes); // Include nonce
                                packet.extend_from_slice(&encrypted);
                                #[cfg(debug_assertions)]
                                println!(
                                    "Sending encrypted packet to {:?}: {} bytes (with new cipher)",
                                    peer.last_endpoint,
                                    packet.len()
                                );
                                if let Err(e) = etx
                                    .send((
                                        packet.clone(),
                                        peer.last_endpoint.expect("last_endpoint is None"),
                                    ))
                                    .await
                                {
                                    #[cfg(debug_assertions)]
                                    eprintln!("Error sending encrypted packet through channel: {e}");
                                }
                            }
                            Err(_e) => {
                                #[cfg(debug_assertions)]
                                eprintln!("Error encrypting packet for destination IP: {dst_ip} (with new cipher)");
                            }
                        }
                    } else {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "No cipher and no shared secret found for destination IP: {dst_ip}, Public Key: {}",
                            base64::encode(pub_key)
                        );
                    }
                }
            } else {
                #[cfg(debug_assertions)]
                eprintln!(
                    "No peer connection found for destination IP: {dst_ip}, Public Key: {}",
                    base64::encode(pub_key)
                );
            }
        } else {
            #[cfg(debug_assertions)]
            println!("No public key found for destination IP: {dst_ip}");
        }
    } else {
        #[cfg(debug_assertions)]
        eprintln!("Failed to extract destination IP from packet");
    }
}

fn _extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }

    if packet[0] >> 4 == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )))
    } else {
        None
    }
}

fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        #[cfg(debug_assertions)]
        eprintln!("Packet too short: {} bytes", packet.len());
        return None;
    }

    let version = packet[0] >> 4;
    #[cfg(debug_assertions)]
    eprintln!(
        "IP version: {}, first bytes: {:02x} {:02x} {:02x} {:02x}",
        version, packet[0], packet[1], packet[2], packet[3]
    );

    if version == 4 {
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        #[cfg(debug_assertions)]
        eprintln!("Extracted destination IP: {dst_ip}");
        Some(dst_ip)
    } else {
        #[cfg(debug_assertions)]
        eprintln!("Non-IPv4 packet, version: {version}");
        None
    }
}
