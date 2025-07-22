pub mod keys;

use crate::error::{IpouError, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;

pub fn encrypt_packet(shared_secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(shared_secret.into());
    
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, data)
        .map_err(|e| IpouError::Crypto(format!("Encryption failed: {}", e)))?;

    let mut packet = Vec::with_capacity(12 + encrypted.len());
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&encrypted);
    
    Ok(packet)
}

pub fn decrypt_packet(shared_secret: &[u8; 32], packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < 28 { // 12 bytes nonce + 16 bytes auth tag + min data
        return Err(IpouError::Crypto("Packet too short for decryption".to_string()));
    }

    let nonce = Nonce::from_slice(&packet[..12]);
    let encrypted_data = &packet[12..];

    let cipher = ChaCha20Poly1305::new(shared_secret.into());
    let decrypted = cipher.decrypt(nonce, encrypted_data)
        .map_err(|e| IpouError::Crypto(format!("Decryption failed: {}", e)))?;

    Ok(decrypted)
}