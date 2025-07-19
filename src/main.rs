use std::collections::HashMap;
use std::io;
use std::net::UdpSocket;

// struct Peer {
//     private_ip: String,
//     public_ip: String,
// }
//
static MTU: usize = 1500; // Maximum Transmission Unit => 1500 + 4 for the header

fn main() -> io::Result<()> {
    let mut peers = HashMap::new();
    peers.insert("10.0.0.5", "0.0.0.0:8081");
    let vnic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; MTU]; // MTU 
    let sock = UdpSocket::bind("0.0.0.0:8080")?;
    sock.set_nonblocking(true)?;
    let mut udp_buf = [0; MTU];

    loop {
        // if udp packet is received, send it to the vnic
        match sock.recv_from(&mut udp_buf) {
            Ok((len, addr)) => {
                println!("{len:?} bytes received from {addr:?}");

                // let len = sock.send_to(&udp_buf[..len], addr)?;
                // println!("{len:?} bytes sent");
                match vnic.send(&udp_buf[..len]) {
                    Ok(_) => println!("Sent {len} bytes to vnic"),
                    Err(e) => eprintln!("Error sending data to vnic: {e}"),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No UDP data available, continue to check VNIC
                match vnic.recv(&mut buf) {
                    Ok(len) => {
                        let flags = u16::from_be_bytes([buf[0], buf[1]]);
                        let proto = u16::from_be_bytes([buf[2], buf[3]]);

                        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..len]) {
                            Ok(p) => {
                                // let src_ip = p.source_addr();
                                let dst_ip = p.destination_addr();

                                println!(
                                    "Received {len} bytes. (flags: {flags:x?}, proto: {proto:x?})"
                                );
                                if let Some(peer_addr) = peers.get(dst_ip.to_string().as_str()) {
                                    let len = sock.send_to(&buf[..len], peer_addr)?;
                                    println!("{len:?} bytes sent over udp");
                                }
                            }
                            Err(e) => {
                                eprintln!("Error parsing IPv4 header: {e}");
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving data: {e}");
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving UDP data: {e}");
                continue;
            }
        }
    }

    Ok(())
}
