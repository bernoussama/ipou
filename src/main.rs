use anyhow::Context;
use clap::Parser;
use ipou::{
    cli::commands::{handle_gen_key, handle_pub_key},
    config::load_config,
    net::{tasks::{handle_tun_packet, handle_udp_packet}, PeerManager},
    Result,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
};
use tun::AsyncDevice;

const MTU: usize = 1420;
const CHANNEL_BUFFER_SIZE: usize = MTU + 512;

async fn run() -> Result<()> {
    let config_path = "config.yaml";
    let conf = load_config(config_path)?;
    let config = Arc::new(conf);

    let peer_manager = Arc::new(PeerManager::new(&config));

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name("ipou")
        .address(
            config.peers[0]
                .allowed_ips[0]
                .parse::<Ipv4Addr>()
                .context("Failed to parse TUN address")?,
        )
        .netmask((255, 255, 255, 0))
        .mtu(MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).context("Failed to create TUN device")?;
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", 51820))
        .await
        .context("Failed to bind UDP socket")?;
    println!(
        "UDP socket bound to: {}",
        sock.local_addr().context("Failed to get local address")?
    );

    let (to_tun_tx, to_tun_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
    let (to_udp_tx, to_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_BUFFER_SIZE);

    let dev = Arc::new(dev);
    let sock = Arc::new(sock);
    let to_tun_rx = Arc::new(Mutex::new(to_tun_rx));
    let to_udp_rx = Arc::new(Mutex::new(to_udp_rx));

    let udp_receiver = tokio::spawn(udp_receiver(
        sock.clone(),
        peer_manager.clone(),
        to_tun_tx,
    ));
    let tun_writer = tokio::spawn(tun_writer(dev.clone(), to_tun_rx));
    let tun_reader = tokio::spawn(tun_reader(dev, peer_manager, to_udp_tx));
    let udp_sender = tokio::spawn(udp_sender(sock, to_udp_rx));

    tokio::try_join!(udp_receiver, tun_writer, tun_reader, udp_sender).map(|_| ())?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ipou::cli::Cli::parse();
    match &cli.command {
        Some(ipou::cli::Commands::Genkey {}) => handle_gen_key()?,
        Some(ipou::cli::Commands::Pubkey {}) => handle_pub_key()?,
        None => {
            if let Err(e) = run().await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

async fn udp_receiver(
    sock: Arc<UdpSocket>,
    peer_manager: Arc<PeerManager>,
    to_tun: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut udp_buf = [0u8; MTU + 512];
    loop {
        let (len, peer_addr) = sock
            .recv_from(&mut udp_buf)
            .await
            .context("Failed to receive from UDP socket")?;
        if len >= 28 {
            handle_udp_packet(&udp_buf, len, peer_addr, &peer_manager, to_tun.clone()).await;
        }
    }
}

async fn tun_writer(
    dev: Arc<AsyncDevice>,
    to_tun_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
) -> Result<()> {
    let mut to_tun_rx = to_tun_rx.lock().await;
    while let Some(packet) = to_tun_rx.recv().await {
        dev.send(&packet)
            .await
            .context("Failed to send packet to TUN device")?;
    }
    Ok(())
}

async fn tun_reader(
    dev: Arc<AsyncDevice>,
    peer_manager: Arc<PeerManager>,
    to_udp: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    let mut buf = [0u8; MTU];
    loop {
        let len = dev
            .recv(&mut buf)
            .await
            .context("Failed to receive from TUN device")?;
        if len >= 20 {
            handle_tun_packet(&buf, len, &peer_manager, to_udp.clone()).await;
        }
    }
}

async fn udp_sender(
    sock: Arc<UdpSocket>,
    to_udp_rx: Arc<Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
) -> Result<()> {
    let mut to_udp_rx = to_udp_rx.lock().await;
    while let Some((packet, peer_addr)) = to_udp_rx.recv().await {
        sock.send_to(&packet, peer_addr)
            .await
            .context("Failed to send packet to UDP socket")?;
    }
    Ok(())
}
