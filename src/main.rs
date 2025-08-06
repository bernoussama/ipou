use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::RwLock;
use trustun::{
    config::{config_update_channel, Config, RuntimeConfig},
    net::PeerManager,
    tasks,
};

#[derive(Parser)]
#[command(name = "trustun")]
#[command(bin_name = "trustun")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Run the trustun daemon")]
    Run { config_path: String },
    #[command(about = "Generate a new keypair")]
    Genkey,
    #[command(about = "Get the public key from a private key")]
    Pubkey { input: String },
}

fn main() -> trustun::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config_path } => {
            let config_path = config_path.to_string();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            runtime.block_on(async {
                // Load configuration
                let config_str = tokio::fs::read_to_string(&config_path).await?;
                let config: Config = serde_yml::from_str(&config_str)?;
                let config = Arc::new(config);

                // Create a TUN device
                let mut tun_config = tun::Configuration::default();
                tun_config
                    .address(config.address.parse::<std::net::IpAddr>().unwrap())
                    .netmask(std::net::Ipv4Addr::new(255, 255, 255, 0))
                    .up();

                let dev = tun::create_as_async(&tun_config)?;
                let dev = Arc::new(dev);

                // Create a UDP socket
                let sock = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", config.listen_port)).await?;
                let sock = Arc::new(sock);

                // Create a shared runtime configuration
                let runtime_conf = Arc::new(RwLock::new(RuntimeConfig::new()));

                // Create channels for encrypted and decrypted packets
                let (etx, erx) = tokio::sync::mpsc::channel(trustun::CHANNEL_BUFFER_SIZE);
                let (dtx, drx) = tokio::sync::mpsc::channel(trustun::CHANNEL_BUFFER_SIZE);

                // Create a channel for config updates
                let (config_update_tx, config_update_rx) = config_update_channel();

                // Create a peer manager
                let peer_manager = Arc::new(PeerManager::new(config_update_tx.clone()));

                // Spawn tasks
                tokio::spawn(tasks::tun_listener(
                    dev.clone(),
                    peer_manager.peer_connections.clone(),
                    runtime_conf.clone(),
                    etx.clone(),
                ));
                tokio::spawn(tasks::udp_listener(
                    sock.clone(),
                    config.clone(),
                    runtime_conf.clone(),
                    peer_manager.clone(),
                    dtx,
                    etx,
                ));
                tokio::spawn(tasks::result_coordinator(dev, sock.clone(), erx, drx));
                tokio::spawn(tasks::handshake(
                    sock.clone(),
                    config.clone(),
                    runtime_conf.clone(),
                    peer_manager.clone(),
                ));
                tokio::spawn(tasks::config_updater(
                    config_update_rx,
                    config.clone(),
                    runtime_conf.clone(),
                    config_path,
                    peer_manager.clone(),
                ));

                // Wait for Ctrl+C
                tokio::signal::ctrl_c().await?;

                Ok(())
            })
        }
        Commands::Genkey => trustun::cli::commands::genkey(),
        Commands::Pubkey { input } => trustun::cli::commands::pubkey(&input),
    }
}
