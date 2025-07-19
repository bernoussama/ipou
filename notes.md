## Use `mio` for event-driven I/O

Add to `Cargo.toml`:

```toml
[dependencies]
mio = "0.8"
```

Then refactor to use proper event loop:

[file:src/main.rs](src/main.rs) line:1-70

```rust
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket;
use tun::TunPacket;

const TUN_TOKEN: Token = Token(0);
const UDP_TOKEN: Token = Token(1);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let mut dev = tun::create(&config)?;
    
    let mut sock = UdpSocket::bind("0.0.0.0:1194".parse()?)?;
    
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);
    
    // Register TUN interface (if supported by tun crate)
    // poll.registry().register(&mut dev, TUN_TOKEN, Interest::READABLE)?;
    poll.registry().register(&mut sock, UDP_TOKEN, Interest::READABLE)?;

    let mut peers: HashMap<IpAddr, SocketAddr> = HashMap::new();
    let mut buf = [0u8; 1500];
    let mut udp_buf = [0u8; 1500];

    loop {
        poll.poll(&mut events, Some(std::time::Duration::from_millis(10)))?;
        
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    while let Ok((len, peer_addr)) = sock.recv_from(&mut udp_buf) {
                        if len >= 20 {
                            let ip_packet = &udp_buf[..len];
                            if let Some(src_ip) = extract_source_ip(ip_packet) {
                                peers.insert(src_ip, peer_addr);
                            }
                            dev.send(&ip_packet)?;
                        }
                    }
                }
                _ => {}
            }
        }
        
        // Handle TUN interface (non-blocking)
        while let Ok(packet) = dev.recv(&mut buf) {
            let len = packet.get_bytes().len();
            if len >= 20 {
                if let Some(dst_ip) = extract_destination_ip(&buf[4..len]) {
                    if let Some(&peer_addr) = peers.get(&dst_ip) {
                        sock.send_to(&buf[4..len], peer_addr)?;
                    }
                }
            }
        }
    }
}

fn extract_source_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])))
    } else {
        None
    }
}

fn extract_destination_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])))
    } else {
        None
    }
}
```

The `mio` approach is best for production code as it provides proper event-driven I/O without busy-waiting.

## Use Tokio for async I/O

Tokio would be excellent for this! It provides proper async I/O which is much better than the blocking approach you currently have. Here's how to refactor your code to use Tokio:

## Add Tokio dependencies to Cargo.toml

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
tokio-tun = "0.11"
```

## Tokio-based implementation

[file:src/main.rs](src/main.rs) line:1-80

```rust
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_tun::TunBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tun = TunBuilder::new()
        .name("tun0")
        .tap(false)
        .packet_info(false)
        .mtu(1500)
        .up()
        .address(Ipv4Addr::new(10, 0, 0, 1))
        .destination(Ipv4Addr::new(10, 0, 0, 1))
        .broadcast(Ipv4Addr::BROADCAST)
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .try_build()
        .await?;

    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun);
    
    let sock = UdpSocket::bind("0.0.0.0:1194").await?;
    let sock = Arc::new(sock);
    
    let peers: Arc<RwLock<HashMap<IpAddr, SocketAddr>>> = Arc::new(RwLock::new(HashMap::new()));

    // Task 1: Handle packets from TUN interface -> UDP
    let sock_clone = sock.clone();
    let peers_clone = peers.clone();
    let tun_to_udp = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tun_reader, &mut buf).await {
                Ok(len) if len >= 20 => {
                    if let Some(dst_ip) = extract_destination_ip(&buf[..len]) {
                        let peers_guard = peers_clone.read().await;
                        if let Some(&peer_addr) = peers_guard.get(&dst_ip) {
                            if let Err(e) = sock_clone.send_to(&buf[..len], peer_addr).await {
                                eprintln!("Failed to send to peer: {}", e);
                            }
                        }
                    }
                }
                Ok(_) => {
                    // Packet too short, ignore
                }
                Err(e) => {
                    eprintln!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });

    // Task 2: Handle packets from UDP -> TUN interface  
    let sock_clone = sock.clone();
    let peers_clone = peers.clone();
    let udp_to_tun = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match sock_clone.recv_from(&mut buf).await {
                Ok((len, peer_addr)) if len >= 20 => {
                    if let Some(src_ip) = extract_source_ip(&buf[..len]) {
                        let mut peers_guard = peers_clone.write().await;
                        peers_guard.insert(src_ip, peer_addr);
                    }
                    
                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut tun_writer, &buf[..len]).await {
                        eprintln!("Failed to write to TUN: {}", e);
                        break;
                    }
                }
                Ok(_) => {
                    // Packet too short, ignore
                }
                Err(e) => {
                    eprintln!("UDP recv error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for both tasks
    tokio::try_join!(tun_to_udp, udp_to_tun)?;
    
    Ok(())
}

fn extract_source_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15]
        )))
    } else {
        None
    }
}

fn extract_destination_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19] 
        )))
    } else {
        None
    }
}
```

## Benefits of the Tokio approach

1. **True async I/O**: No blocking operations
2. **Better concurrency**: Separate tasks for each direction
3. **Memory efficiency**: Single-threaded async runtime
4. **Error handling**: Proper async error propagation
5. **Scalability**: Can handle many connections efficiently

This is much more robust than your current blocking implementation and follows Rust async best practices.
