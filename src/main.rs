use clap::{Parser, Subcommand};
use std::io;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub struct Config {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub peers: HashMap<IpAddr, Peer>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: [u8; 32],
}

// Constants
const MTU: usize = 1504;

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
    let config: Config = match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found, using defaults");
            return Ok(());
        }
    };

    let name = cli.name.clone().unwrap_or("utun0".to_string());
    let address = cli.address.unwrap_or("10.0.0.1".to_string());

    let port = cli.port.unwrap_or(1194);

    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&config)?;
    let sock = UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
    println!("UDP socket bound to: {}", sock.local_addr()?);

    let mut peers: HashMap<IpAddr, Peer> = HashMap::new();

    let mut buf = [0u8; MTU];
    let mut udp_buf = [0u8; MTU];

    let alice_secret = EphemeralSecret::random();
    let alice_public = PublicKey::from(&alice_secret);

    peers.insert(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Peer {
            sock_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 68, 100, 1)), 1194),
            pub_key: alice_public.to_bytes(),
        },
    );
    peers.insert(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        Peer {
            sock_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 68, 100, 2)), 1194),
            pub_key: alice_public.to_bytes(),
        },
    );

    loop {
        tokio::select! {
            result = sock.recv_from(&mut udp_buf) => {

                if let Ok((len, peer_addr)) =result {
                    println!("UDP packet: {len} bytes from {peer_addr}");
                    if len >= 20 {
                        let ip_packet = &udp_buf[..len];
                        if let Some(src_ip) = extract_src_ip(ip_packet) {
                            if let Some(_peer) = peers.get(&src_ip) {
                                match dev.send(ip_packet).await {
                                    Ok(sent) => println!("Sent {sent} bytes to TUN device"),
                                    Err(e) => eprintln!("Failed to send to TUN: {e}"),
                                }
                            }
                        }
                    }
                }
            }

            result = dev.recv(&mut buf) => {

                // handle TUN device
                if let Ok(len) =  result {
                    if len >= 20 {
                        eprintln!("Available peers: {:?}", peers.keys().collect::<Vec<_>>());
                        if let Some(dst_ip) = extract_dst_ip(&buf[..len]) {
                            println!("TUN packet: destination IP = {dst_ip}");
                            if let Some(peer) = peers.get(&dst_ip) {
                                println!("Sending to peer: {}", peer.sock_addr);
                                sock.send_to(&buf[..len], peer.sock_addr).await?;
                            } else {
                                eprintln!("No peer found for destination IP: {dst_ip}");
                            }
                        } else {
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
        eprintln!("Packet too short: {} bytes", packet.len());
        return None;
    }

    let version = packet[0] >> 4;
    eprintln!(
        "IP version: {}, first bytes: {:02x} {:02x} {:02x} {:02x}",
        version, packet[0], packet[1], packet[2], packet[3]
    );

    if version == 4 {
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        eprintln!("Extracted destination IP: {dst_ip}");
        Some(dst_ip)
    } else {
        eprintln!("Non-IPv4 packet, version: {version}");
        None
    }
}
