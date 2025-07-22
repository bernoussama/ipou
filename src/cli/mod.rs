pub mod commands;

use clap::{Parser, Subcommand};

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
    /// Generate private key
    Genkey {},
    /// Generate public key from private key
    Pubkey {},
}