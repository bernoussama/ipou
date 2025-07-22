pub mod packet;
pub mod tun;
pub mod udp;

use crate::config::{Config, Peer};
use crate::crypto::{decrypt_packet, encrypt_packet, keys::compute_shared_secret};
use crate::error::{IpouError, Result};
use crate::network::packet::{extract_dst_ip, validate_packet_size};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct NetworkManager {
    config: Arc<Config>,
    tun_device: ::tun::AsyncDevice,
    udp_socket: tokio::net::UdpSocket,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    udp_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
}

impl NetworkManager {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let tun_device = tun::create_tun_device(Arc::clone(&config)).await?;
        let udp_socket = udp::create_udp_socket(Arc::clone(&config)).await?;
        
        let (tun_tx, _) = mpsc::unbounded_channel();
        let (udp_tx, _) = mpsc::unbounded_channel();

        Ok(NetworkManager {
            config,
            tun_device,
            udp_socket,
            tun_tx,
            udp_tx,
        })
    }

    pub fn get_channels(&self) -> (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>) {
        (self.tun_tx.clone(), self.udp_tx.clone())
    }

    pub async fn handle_udp_packet(&self, packet: &[u8], peer_addr: SocketAddr) -> Result<Option<Vec<u8>>> {
        validate_packet_size(packet, 32)?; // 12 bytes nonce + 16 bytes auth tag + min 4 bytes data

        // Find peer by socket address
        let peer = self.find_peer_by_addr(peer_addr)?;
        let shared_secret = self.compute_peer_shared_secret(peer)?;
        
        let decrypted = decrypt_packet(&shared_secret, packet)?;
        
        // Validate IP packet
        validate_packet_size(&decrypted, 20)?;
        
        Ok(Some(decrypted))
    }

    pub async fn handle_tun_packet(&self, packet: &[u8]) -> Result<Option<(Vec<u8>, SocketAddr)>> {
        validate_packet_size(packet, 20)?;
        
        let dst_ip = extract_dst_ip(packet)?;
        log::debug!("TUN packet: destination IP = {}", dst_ip);
        
        let peer = self.config.peers.get(&dst_ip)
            .ok_or_else(|| IpouError::PeerNotFound(format!("No peer found for destination IP: {}", dst_ip)))?;
        
        let shared_secret = self.compute_peer_shared_secret(peer)?;
        let encrypted = encrypt_packet(&shared_secret, packet)?;
        
        log::debug!("Sending encrypted packet to peer: {}", peer.sock_addr);
        Ok(Some((encrypted, peer.sock_addr)))
    }

    fn find_peer_by_addr(&self, addr: SocketAddr) -> Result<&Peer> {
        self.config.peers.values()
            .find(|peer| peer.sock_addr == addr)
            .ok_or_else(|| IpouError::PeerNotFound(format!("No peer found for address: {}", addr)))
    }

    fn compute_peer_shared_secret(&self, peer: &Peer) -> Result<[u8; 32]> {
        let secret_bytes = base64::decode(&self.config.secret)?;
        let peer_key_bytes = base64::decode(&peer.pub_key)?;
        
        compute_shared_secret(&secret_bytes, &peer_key_bytes)
    }
}