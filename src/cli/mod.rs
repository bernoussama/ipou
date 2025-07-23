pub mod commands;
use clap::{Parser, Subcommand};
// CLI
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Optional name to operate on
    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    // generate private key
    Genkey {},
    Pubkey {},
}
