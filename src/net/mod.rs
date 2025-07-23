use chacha20poly1305::aead::{Aead, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use ipnet::IpNet;
use std::str::FromStr;
use rand::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::sync::{Arc};
use tokio::sync::{mpsc, RwLock};

use crate::config::Config;

/// Represents the runtime state of a peer.
pub struct RuntimePeer {
    pub public_key: [u8; 32],
    pub cipher: ChaCha20Poly1305,
    pub last_endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
}

/// Manages the runtime state of all peers.
#[derive(Clone)]
pub struct PeerManager {
    peers: Arc<RwLock<HashMap<[u8; 32], RuntimePeer>>>,
}

impl PeerManager {
    pub fn new(config: &Config) -> Self {
        let mut peers = HashMap::new();
        let private_key = base64::decode(&config.private_key).unwrap();

        for peer_config in &config.peers {
            let public_key_bytes = base64::decode(&peer_config.public_key).unwrap();
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&public_key_bytes);

            let shared_secret = crate::crypto::diffie_hellman(&private_key, &public_key);
            let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());

            let allowed_ips = peer_config
                .allowed_ips
                .iter()
                .map(|ip_str| IpNet::from_str(ip_str).unwrap())
                .collect();

            peers.insert(
                public_key,
                RuntimePeer {
                    public_key,
                    cipher,
                    last_endpoint: peer_config.endpoint,
                    allowed_ips,
                },
            );
        }

        Self { peers: Arc::new(RwLock::new(peers)) }
    }

    pub async fn find_peer_by_ip(&self, ip: IpAddr) -> Option<([u8; 32], SocketAddr)> {
        let peers = self.peers.read().await;
        for (key, peer) in peers.iter() {
            if let Some(endpoint) = peer.last_endpoint {
                for network in &peer.allowed_ips {
                    if network.contains(&ip) {
                        return Some((*key, endpoint));
                    }
                }
            }
        }
        None
    }
}

pub async fn handle_udp_packet(
    udp_buf: &[u8],
    len: usize,
    peer_addr: SocketAddr,
    peer_manager: &PeerManager,
    tx_clone: mpsc::Sender<Vec<u8>>,
) {
    if len < 12 { return; }
    let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&udp_buf[..12]);
    let encrypted_data = &udp_buf[12..len];

    let peers = peer_manager.peers.read().await;
    for peer in peers.values() {
        if let Ok(decrypted) = peer.cipher.decrypt(nonce, encrypted_data) {
            if decrypted.len() >= 20 {
                if let Err(e) = tx_clone.send(decrypted).await {
                    eprintln!("Error sending decrypted packet through channel: {e}");
                }
                return; // Exit after first successful decryption
            }
        }
    }
    eprintln!("Decryption failed for packet from: {peer_addr}");
}

pub async fn handle_tun_packet(
    buf: &[u8],
    len: usize,
    peer_manager: &PeerManager,
    utx_clone: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) {
    if let Some(dst_ip) = extract_dst_ip(&buf[..len]) {
        if let Some((peer_key, endpoint)) = peer_manager.find_peer_by_ip(dst_ip).await {
            let peers = peer_manager.peers.read().await;
            if let Some(peer) = peers.get(&peer_key) {
                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

                if let Ok(encrypted) = peer.cipher.encrypt(nonce, &buf[..len]) {
                    let mut packet = Vec::with_capacity(12 + encrypted.len());
                    packet.extend_from_slice(&nonce_bytes);
                    packet.extend_from_slice(&encrypted);

                    if let Err(e) = utx_clone.send((packet, endpoint)).await {
                        eprintln!("Error sending encrypted packet through channel: {e}");
                    }
                }
            }
        }
    }
}

fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 { return None; }
    let version = packet[0] >> 4;
    if version == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])))
    } else {
        None
    }
}