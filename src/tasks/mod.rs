use std::sync::Arc;

use bincode::{
    config::{self, BigEndian},
    error,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender},
};
use tun::AsyncDevice;

use crate::{
    MAX_UDP_SIZE,
    config::{Config, RuntimeConfig},
    net::{PeerConnections, PeerManager},
    proto::Packet,
};

// Spawned listeners
pub async fn tun_listener(
    dev: Arc<AsyncDevice>,
    peer_connections: PeerConnections,
    runtime_conf: Arc<RuntimeConfig>,
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
    runtime_conf: Arc<RuntimeConfig>,
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
                        Arc::clone(&peer_manager)
                            .handle_proto_packet(packet, peer_addr, etx.clone())
                            .await?;
                    } else {
                        #[cfg(debug_assertions)]
                        println!("Received invalid protocol packet from {peer_addr}");
                    }
                }
                0x10 => {
                    if len >= 30 {
                        // 12 bytes nonce + 16 bytes auth tag
                        tokio::spawn(crate::net::handle_udp_packet(
                            udp_buf,
                            len,
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
