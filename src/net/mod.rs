use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::{rng, RngCore};
use std::net::{IpAddr, Ipv4Addr};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

use crate::config::{Config, PeerRole};
use crate::crypto::generate_shared_secret;
use crate::proto::state::{Peer, VpnState};
use crate::proto::{Packet, PacketType, WirePacket};
use crate::Error;

pub async fn handle_proto_packet(
    conf: Arc<Config>,
    state: Arc<VpnState>,
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
            let mut peers = state.peers.write().await;
            let peer = peers
                .entry(sender_pubkey)
                .or_insert_with(|| Peer::new(sender_pubkey));
            peer.mark_connected(sender_addr, sender_private_ip);
            peer.last_seen = timestamp;

            state
                .endpoint_to_pubkey
                .write()
                .await
                .insert(sender_addr, sender_pubkey);
            state
                .ip_to_pubkey
                .write()
                .await
                .insert(sender_private_ip, sender_pubkey);

            // Create cipher for the peer if we don't have one yet
            if !state.ciphers.read().await.contains_key(&sender_private_ip) {
                if let Some(shared_secret) = state.shared_secrets.get(&sender_pubkey) {
                    let cipher = ChaCha20Poly1305::new(shared_secret.into());
                    state
                        .ciphers
                        .write()
                        .await
                        .insert(sender_private_ip, cipher);

                    #[cfg(debug_assertions)]
                    println!(
                        "[HANDSHAKE] Created cipher for peer {} (private IP: {}) at endpoint {}",
                        base64::encode(sender_pubkey),
                        sender_private_ip,
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

                    #[cfg(debug_assertions)]
                    println!(
                        "[CONFIG_UPDATER] Creating cipher for peer {} at endpoint {}",
                        base64::encode(sender_pubkey),
                        sender_addr
                    );

                    let cipher = ChaCha20Poly1305::new(&shared_secret.into());
                    state
                        .ciphers
                        .write()
                        .await
                        .insert(sender_private_ip, cipher);

                    #[cfg(debug_assertions)]
                    println!("[CONFIG_UPDATER] Cipher added to runtime config");
                }
            }

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
                if let Some(sender_pubkey) = state.endpoint_to_pubkey.read().await.get(&sender_addr)
                {
                    let mut peers = state.peers.write().await;
                    if let Some(peer) = peers.get_mut(sender_pubkey) {
                        if let Some(private_ip) = peer.private_ip {
                            peer.mark_connected(sender_addr, private_ip);
                            peer.last_seen = crate::proto::now();
                        }
                    }
                }
            } else {
                #[cfg(debug_assertions)]
                eprintln!("Handshake failed: {message}");
            }
            None
        }
        Packet::RequestPeer { target_pubkey } => {
            let peers = state.peers.read().await;
            if let Some(peer) = peers.get(&target_pubkey) {
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
                let mut peers = state.peers.write().await;
                let peer = peers.entry(pubkey).or_insert_with(|| Peer::new(pubkey));
                if let Some(private_ip) = peer.private_ip {
                    peer.mark_connected(endpoint, private_ip);
                }
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
            return Err(Error::Unknown("Sending packet failed".to_string()));
        }
    }
    Ok(())
}

pub async fn handle_udp_packet(
    packet_data: Vec<u8>,
    peer_addr: SocketAddr,
    state: Arc<VpnState>,
    dtx: mpsc::Sender<crate::DecryptedPacket>,
) {
    let len = packet_data.len();
    if len < 12 {
        return;
    }
    // Extract nonce and encrypted data
    let nonce = Nonce::from_slice(&packet_data[..12]);
    let encrypted_data = &packet_data[12..];

    if let Some(pubkey) = state.endpoint_to_pubkey.read().await.get(&peer_addr) {
        if let Some(peer) = state.peers.read().await.get(pubkey) {
            if let Some(private_ip) = peer.private_ip {
                if let Some(cipher) = state.ciphers.read().await.get(&private_ip) {
                    match cipher.decrypt(nonce, encrypted_data) {
                        Ok(decrypted) => {
                            if decrypted.len() >= 20 {
                                if let Err(e) = dtx.send(decrypted).await {
                                    eprintln!(
                                        "Error sending decrypted packet through channel: {e}"
                                    );
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
                    eprintln!("No cipher found for peer: {peer_addr:?}");
                }
            }
        }
    }
}

pub async fn handle_tun_packet(
    buf: [u8; crate::MTU],
    len: usize,
    state: Arc<VpnState>,
    etx: mpsc::Sender<crate::EncryptedPacket>,
) {
    let mut packet = Vec::with_capacity(crate::MTU + crate::ENCRYPTION_OVERHEAD);
    if let Some(dst_ip) = extract_dst_ip(&buf) {
        if let Some(cipher) = state.ciphers.read().await.get(&dst_ip) {
            let mut nonce_bytes = [0u8; 12];
            rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let data = &buf[..len];
            match cipher.encrypt(nonce, data) {
                Ok(encrypted) => {
                    packet.clear();
                    packet.push(0x10); // Protocol packet type
                    packet.extend_from_slice(&nonce_bytes); // Include nonce
                    packet.extend_from_slice(&encrypted);

                    if let Some(pubkey) = state.ip_to_pubkey.read().await.get(&dst_ip) {
                        if let Some(peer) = state.peers.read().await.get(pubkey) {
                            if let Some(endpoint) = peer.last_endpoint {
                                #[cfg(debug_assertions)]
                                println!(
                                    "Sending encrypted packet to {:?}: {} bytes",
                                    peer.last_endpoint,
                                    packet.len()
                                );
                                if let Err(e) = etx.send((packet.clone(), endpoint)).await {
                                    #[cfg(debug_assertions)]
                                    eprintln!(
                                        "Error sending encrypted packet through channel: {e}"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    #[cfg(debug_assertions)]
                    eprintln!("Error encrypting packet for destination IP: {dst_ip}");
                }
            }
        } else {
            #[cfg(debug_assertions)]
            eprintln!("No cipher found for source IP: {dst_ip}")
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
