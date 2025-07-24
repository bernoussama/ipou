
use std::net::SocketAddr;
use tokio::sync::mpsc;
use crate::net::PeerManager;
use chacha20poly1305::aead::{Aead, Nonce};


pub async fn handle_udp_packet(
    udp_buf: &[u8],
    len: usize,
    peer_addr: SocketAddr,
    peer_manager: &PeerManager,
    tx_clone: mpsc::Sender<Vec<u8>>,
) {
    if len < 12 { return; }
    let nonce = Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(&udp_buf[..12]);
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
    if let Some(dst_ip) = crate::net::extract_dst_ip(&buf[..len]) {
        if let Some((peer_key, endpoint)) = peer_manager.find_peer_by_ip(dst_ip).await {
            let peers = peer_manager.peers.read().await;
            if let Some(peer) = peers.get(&peer_key) {
                let mut nonce_bytes = [0u8; 12];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce_bytes);
                let nonce = Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(&nonce_bytes);

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
