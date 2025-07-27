use std::{net::SocketAddr, sync::Arc};

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
    conf: Arc<Config>,
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
    runtime_conf: Arc<RuntimeConfig>,
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
