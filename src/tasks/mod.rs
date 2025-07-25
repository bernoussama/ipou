use std::sync::Arc;

use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender},
};
use tun::AsyncDevice;

use crate::config::{Config, RuntimeConfig};

// Spawned listeners
pub async fn tun_listener(
    dev: Arc<AsyncDevice>,
    conf_clone: Arc<Config>,
    runtime_conf: Arc<RuntimeConfig>,
    tx: Sender<crate::Packet>,
) -> crate::Result<()> {
    let mut tun_buf = [0u8; crate::MTU];
    
    // Create channel for encrypted packets from handlers
    let (etx, mut erx) = tokio::sync::mpsc::channel::<crate::EncryptedPacket>(crate::CHANNEL_BUFFER_SIZE);
    
    // Spawn task to forward encrypted packets as Packet::Encrypted
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        while let Some(encrypted_packet) = erx.recv().await {
            if tx_clone.send(crate::Packet::Encrypted(encrypted_packet)).await.is_err() {
                break;
            }
        }
    });

    loop {
        // Listen for TUN packets
        let len = dev.recv(&mut tun_buf).await?;
        // Spawn handler task for each packet
        if len >= 20 {
            tokio::spawn(crate::net::handle_tun_packet(
                tun_buf,
                len,
                Arc::clone(&conf_clone),
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
    tx: Sender<crate::Packet>,
) -> crate::Result<()> {
    let mut udp_buf = [0u8; crate::MTU + 512];
    
    // Create channel for decrypted packets from handlers
    let (dtx, mut drx) = tokio::sync::mpsc::channel::<crate::DecryptedPacket>(crate::CHANNEL_BUFFER_SIZE);
    
    // Spawn task to forward decrypted packets as Packet::Decrypted
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        while let Some(decrypted_packet) = drx.recv().await {
            if tx_clone.send(crate::Packet::Decrypted(decrypted_packet)).await.is_err() {
                break;
            }
        }
    });
    
    loop {
        // Listen for UDP packets
        let (len, peer_addr) = sock.recv_from(&mut udp_buf).await?;
        // Spawn handler task for each packet
        if len >= 28 {
            // 12 bytes nonce + 16 bytes auth tag
            tokio::spawn(crate::net::handle_udp_packet(
                udp_buf,
                len,
                peer_addr,
                Arc::clone(&runtime_conf),
                dtx.clone(),
            ));
        };
        // Send raw packet + result channel to handler
    }
}

pub async fn result_coordinator(
    dev: Arc<AsyncDevice>,
    sock: Arc<UdpSocket>,
    mut rx: Receiver<crate::Packet>,
) -> crate::Result<()> {
    // This task coordinates sending decrypted packets to TUN and encrypted packets to UDP
    // It runs indefinitely, processing packets as they arrive

    #[cfg(debug_assertions)]
    println!("Starting result coordinator...");

    loop {
        match rx.recv().await {
            Some(crate::Packet::Decrypted(decrypted_packet)) => {
                // Receive decrypted packets from channel and send to TUN
                match dev.send(&decrypted_packet).await {
                    Ok(sent) => {
                        #[cfg(debug_assertions)]
                        println!("Sent {sent} bytes to TUN dev");
                    }
                    Err(e) => {
                        eprintln!("Error sending packet to TUN device: {e}");
                    }
                }
            }

            Some(crate::Packet::Encrypted((encrypted_packet, peer_addr))) => {
                // Receive enccrypted packets from channel and send to UDP
                #[cfg(debug_assertions)]
                println!("Sending encrypted packet to peer: {peer_addr}");
                match sock.send_to(&encrypted_packet, peer_addr).await {
                    Ok(sent) => {
                        #[cfg(debug_assertions)]
                        println!("Sent {sent} bytes to {peer_addr}");
                    }
                    Err(e) => {
                        eprintln!("Error sending encrypted packet to peer {peer_addr}: {e}");
                    }
                }
            }
            None => continue,
        }
    }
}
