# ipou - IP over UDP

A simple, high-performance IP-over-UDP tunnel implementation written in Rust using async I/O.

## Overview

**ipou** creates a TUN interface that tunnels IP packets over UDP, enabling secure communication between peers across networks. It uses Tokio for efficient async networking and supports automatic peer discovery.

## Features

- ✅ **IP-over-UDP tunneling** - Encapsulate IP packets in UDP for transport
- ✅ **Async I/O** - Built with Tokio for high performance
- ✅ **Automatic peer discovery** - Learns peer addresses from incoming packets
- ✅ **IPv4 support** - Full IPv4 packet routing
- ⏳ **Planned**: Encryption, authentication, IPv6 support

## Quick Start

### Prerequisites

- Rust 1.70+
- Linux/macOS (requires TUN interface support)
- Root privileges (for TUN interface creation)

### Installation

```bash
git clone <repository-url>
cd ipou
cargo build --release
```

### Basic Usage

```bash
# Run with default settings (interface: utun0, address: 10.0.0.1, port: 1194)
sudo ./target/release/ipou

# Custom configuration
sudo ./target/release/ipou tun1 10.0.1.1 8080
```

### Using the Helper Script

```bash
# Build and run with proper capabilities
chmod +x run.sh
./run.sh
```

## Command Line Options

```
Usage: ipou [NAME] [ADDRESS] [PORT]

Arguments:
  [NAME]     TUN interface name (default: utun0)
  [ADDRESS]  Local IP address (default: 10.0.0.1)
  [PORT]     UDP port to bind (default: 1194)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## How It Works

1. **TUN Interface**: Creates a virtual network interface that captures IP packets
2. **UDP Transport**: Encapsulates captured packets in UDP for network transmission  
3. **Peer Discovery**: Automatically learns peer addresses from incoming UDP packets
4. **Bidirectional Routing**: Routes packets between TUN interface and UDP peers

```
┌─────────────┐    UDP    ┌─────────────┐
│   Client A  │◄─────────►│   Client B  │
│             │           │             │
│ TUN: tun0   │           │ TUN: tun0   │
│ IP: 10.0.0.1│           │ IP: 10.0.0.2│
└─────────────┘           └─────────────┘
```

## Configuration Examples

### Two-Node Setup

**Node A:**

```bash
sudo ./target/release/ipou utun0 10.0.0.1 1194
```

**Node B:**

```bash
sudo ./target/release/ipou utun0 10.0.0.2 1194
# Send a packet to Node A to establish the tunnel
ping 10.0.0.1
```

### Network Configuration

After starting ipou, configure routing:

```bash
# Add route for the tunnel network
sudo ip route add 10.0.0.0/24 dev utun0

# Bring interface up (if needed)
sudo ip link set up dev utun0
```

## Architecture

- **Async Design**: Uses `tokio::select!` for concurrent TUN/UDP handling
- **Zero-Copy**: Efficient packet forwarding with minimal allocations
- **Peer Table**: HashMap-based routing table for destination lookup
- **Error Resilience**: Continues operation despite individual packet errors

## Development Status

This project is in active development. See [PRD.md](PRD.md) for the roadmap.

### Current Limitations

- No encryption or authentication
- IPv4 only
- Basic error handling
- No rate limiting or DoS protection

## License

[Add your license here]

## Security Notice

⚠️ **This software is currently unencrypted and unauthenticated.** Do not use in production environments without additional security measures.

