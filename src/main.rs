use clap::Parser;
use std::io;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::net::UdpSocket;

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
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let name = cli.name.clone().unwrap_or("utun0".to_string());
    let address = cli.address.unwrap_or("10.0.0.1".to_string());

    let port = cli.port.unwrap_or(1194);

    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(address.parse::<Ipv4Addr>().unwrap())
        // .destination(Ipv4Addr::new(10, 0, 0, 0))
        .broadcast(Ipv4Addr::BROADCAST)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&config)?;
    let sock = UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
    println!("UDP socket bound to: {}", sock.local_addr()?);

    let mut peers: HashMap<IpAddr, SocketAddr> = HashMap::new();

    let mut buf = [0u8; MTU];
    let mut udp_buf = [0u8; MTU];

    peers.insert(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 68, 100, 1)), 1194),
    );
    peers.insert(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 68, 100, 141)), 1194),
    );

    loop {
        tokio::select! {
            result = sock.recv_from(&mut udp_buf) => {

                if let Ok((len, peer_addr)) =result {
                    println!("UDP packet: {len} bytes from {peer_addr}");
                    if len >= 20 {
                        let ip_packet = &udp_buf[..len];
                        if let Some(src_ip) = extract_src_ip(ip_packet) {
                            peers.entry(src_ip).or_insert(peer_addr);
                        }
                        match dev.send(ip_packet).await {
                            Ok(sent) => println!("Sent {sent} bytes to TUN device"),
                            Err(e) => eprintln!("Failed to send to TUN: {e}"),
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
                            if let Some(peer_addr) = peers.get(&dst_ip) {
                                println!("Sending to peer: {peer_addr}");
                                sock.send_to(&buf[..len], *peer_addr).await?;
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
        eprintln!("Extracted destination IP: {}", dst_ip);
        Some(dst_ip)
    } else {
        eprintln!("Non-IPv4 packet, version: {}", version);
        None
    }
}
