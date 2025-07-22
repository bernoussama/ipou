use crate::error::{IpouError, Result};
use std::net::IpAddr;

pub fn extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }

    if packet[0] >> 4 == 4 {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )))
    } else {
        None
    }
}

pub fn extract_dst_ip(packet: &[u8]) -> Result<IpAddr> {
    if packet.len() < 20 {
        return Err(IpouError::Packet(format!("Packet too short: {} bytes", packet.len())));
    }

    let version = packet[0] >> 4;
    log::debug!("IP version: {}, first bytes: {:02x} {:02x} {:02x} {:02x}",
        version, packet[0], packet[1], packet[2], packet[3]);

    if version == 4 {
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        log::debug!("Extracted destination IP: {}", dst_ip);
        Ok(dst_ip)
    } else {
        Err(IpouError::Packet(format!("Non-IPv4 packet, version: {}", version)))
    }
}

pub fn validate_packet_size(packet: &[u8], min_size: usize) -> Result<()> {
    if packet.len() < min_size {
        return Err(IpouError::Packet(format!(
            "Packet too small: {} bytes, minimum: {} bytes", 
            packet.len(), min_size
        )));
    }
    Ok(())
}