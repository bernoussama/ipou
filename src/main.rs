use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::io;
use std::sync::Arc;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub secret: String,
    pub pubkey: String,
    pub peers: HashMap<IpAddr, Peer>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}

struct RuntimeConfig {
    shared_secrets: HashMap<IpAddr, [u8; 32]>,
    ciphers: HashMap<IpAddr, ChaCha20Poly1305>,
    ips: HashMap<SocketAddr, IpAddr>,
}

// Constants
const MTU: usize = 1504;
const CHANNEL_BUFFER_SIZE: usize = MTU + 512; // Buffered channels

// CLI
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional name to operate on
    name: Option<String>,
    address: Option<String>,
    port: Option<u16>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    // generate private key
    Genkey {},
    Pubkey {},
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    // Subcommands
    match &cli.command {
        Some(Commands::Genkey {}) => {
            let private_key = StaticSecret::random();
            let private_key_bytes = private_key.to_bytes();
            println!("{}", base64::encode(private_key_bytes));
            return Ok(());
        }
        Some(Commands::Pubkey {}) => {
            println!("Enter your base64 encoded private key (32 bytes): ");
            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .expect("Failed to read input");
            let input = input.trim();

            let private_key_bytes = base64::decode(input).expect("Invalid base64 private key");
            if private_key_bytes.len() != 32 {
                panic!("Private key must be 32 bytes");
            }

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&private_key_bytes);
            let private_key = StaticSecret::from(key_array);
            let public_key = PublicKey::from(&private_key);
            println!("{}", base64::encode(public_key.to_bytes()));
            return Ok(());
        }
        None => {}
    }

    // Load config file
    let config_path = "config.yaml";
    let conf: Config = match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found! using defaults.");
            let private_key = StaticSecret::random();
            let public_key = PublicKey::from(&private_key);

            let alice_secret = EphemeralSecret::random();
            let alice_public = PublicKey::from(&alice_secret);

            let mut peers: HashMap<IpAddr, Peer> = HashMap::new();

            peers.insert(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Peer {
                    sock_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 68, 100, 1)), 1194),
                    pub_key: base64::encode(alice_public.to_bytes()),
                },
            );
            peers.insert(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                Peer {
                    sock_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 68, 100, 2)), 1194),
                    pub_key: base64::encode(alice_public.to_bytes()),
                },
            );
            let conf = Config {
                name: "utun0".to_string(),
                address: "10.0.0.1".to_string(),
                secret: base64::encode(private_key.to_bytes()),
                pubkey: base64::encode(public_key.to_bytes()),
                port: 1194,
                peers,
            };
            std::fs::write(config_path, serde_yml::to_string(&conf).unwrap())
                .expect("Failed to write default config file");
            conf
        }
    };
    let config = Arc::new(conf);

    let config_clone = Arc::clone(&config);
    // Initialize once after config load
    let mut shared_secrets = HashMap::new();
    let mut ciphers = HashMap::new();

    let mut secret_bytes = [0u8; 32];
    base64::decode_config_slice(&config.secret, base64::STANDARD, &mut secret_bytes).unwrap();
    let static_secret = StaticSecret::from(secret_bytes);

    let mut ips = HashMap::new();
    for (ip, peer) in &config.peers {
        let mut pub_key_bytes = [0u8; 32];
        base64::decode_config_slice(&peer.pub_key, base64::STANDARD, &mut pub_key_bytes).unwrap();
        let pub_key = PublicKey::from(pub_key_bytes);
        let shared_secret = static_secret.diffie_hellman(&pub_key);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        shared_secrets.insert(*ip, *shared_secret.as_bytes());
        ciphers.insert(*ip, cipher);
        ips.insert(peer.sock_addr, *ip);
    }

    let runtime_config = Arc::new(RuntimeConfig {
        shared_secrets,
        ciphers,
        ips,
    });

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config_clone.name)
        .address(config_clone.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config)?;
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", Arc::clone(&config).port)).await?;
    println!("UDP socket bound to: {}", sock.local_addr()?);

    // Create channel for sending decrypted packets to TUN device
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
    // Create channel for sending encrypted packets to UDP socket
    let (utx, mut urx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_BUFFER_SIZE);

    // Pre-allocate buffers to avoid repeated allocations
    let mut udp_buf = [0u8; MTU + 512];
    let mut buf = [0u8; MTU];

    loop {
        tokio::select! {

            result = async {
                let recv_result =sock.recv_from(&mut udp_buf).await;
                recv_result.map(|(len,addr)| (udp_buf, len, addr)) } => {
                       if let Ok((udp_buf, len, peer_addr)) =result {
                            let runtime_conf = Arc::clone(&runtime_config);
                           let tx_clone = tx.clone();
                               if len >= 32 { // 12 bytes nonce + 16 bytes auth tag + min 4 bytes data
                                   // Extract nonce and encrypted data
                                   let nonce = Nonce::from_slice(&udp_buf[..12]);
                                   let encrypted_data = &udp_buf[12..len];

                                       // let shared_secret = runtime_conf.shared_secrets.get(&peer.sock_addr.ip()).unwrap_or(&[0u8; 32]);

                                       // let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
                                    if let Some(ip) = runtime_conf.ips.get(&peer_addr) {
                                       if let Some(cipher) = runtime_conf.ciphers.get(&ip) {
                                        match cipher.decrypt(nonce, encrypted_data) {
                                            Ok(decrypted) => {
                                                if decrypted.len() >= 20 {
                                                    if let Err(e) = tx_clone.send(decrypted).await {
                                                    }
                                                }
                                            }
                                            Err(_e) => {},
                                        }
                                        }else {
                                            #[cfg(debug_assertions)]
                                           eprintln!("No cipher found for peer: {}", ip);
                                        }
                                    } else {
                                        #[cfg(debug_assertions)]
                                        eprintln!("No IP found for peer address: {}", peer_addr);
                                    }
                               }
                       }
        }

               // Receive decrypted packets from channel and send to TUN
               Some(decrypted_packet) = rx.recv() => {
                   match dev.send(&decrypted_packet).await {
                       Ok(_sent) => {},
                       Err(_e) => {},
                   }
               }

               // Receive decrypted packets from channel and send to TUN
               Some((encrypted_packet, peer_addr)) = urx.recv() => {
                   match sock.send_to(&encrypted_packet, peer_addr).await {
                       Ok(_sent) => {},
                       Err(_e) => {},
                   }
               }

                result = async {
                    let recv_result = dev.recv(&mut buf).await;
                    recv_result.map(|len| (buf, len))
                } => {
                       // handle TUN device
                       if let Ok((buf,len)) =  result {
                           let utx_clone = utx.clone();
                           let conf_clone = Arc::clone(&config);
                            let runtime_conf = Arc::clone(&runtime_config);
                           if len >= 20 {
                               if let Some(dst_ip) = extract_dst_ip(&buf[..len]) {
                                   if let Some(peer) = conf_clone.peers.get(&dst_ip) {
                                       // Encrypt packet

                                       if let Some(cipher) = runtime_conf.ciphers.get(&dst_ip)  {
                                        let mut nonce_bytes = [0u8; 12];
                                        rand::rng().fill_bytes(&mut nonce_bytes);
                                        let nonce = Nonce::from_slice(&nonce_bytes);

                                        match cipher.encrypt(nonce, &buf[..len]) {
                                            Ok(encrypted) => {
                                                // Prepend nonce to encrypted data
                                                let mut packet = Vec::with_capacity(12 + encrypted.len());
                                                packet.extend_from_slice(&nonce_bytes);
                                                packet.extend_from_slice(&encrypted);


                                                if let Err(e) = utx_clone.send((packet, peer.sock_addr)).await {
                                                    eprintln!("Failed to send to channel: {e}");
                                                }
                                            }
                                            Err(_e) => {},
                                        }

                                    } else {
                                        #[cfg(debug_assertions)]
                                       eprintln!("No cipher found for peer: {}", dst_ip);
                                    }

                                   } else {
                                        #[cfg(debug_assertions)]
                                       eprintln!("No peer found for destination IP: {dst_ip}");
                                   }
                               } else {
                                    #[cfg(debug_assertions)]
                                   eprintln!("Failed to extract destination IP from packet");
                               }
                           }
                       }
                   }
               }
    }
}

fn extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
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
