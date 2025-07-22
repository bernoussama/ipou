use crate::error::{IpouError, Result};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let private_key = StaticSecret::random();
    let public_key = PublicKey::from(&private_key);
    (private_key.to_bytes(), public_key.to_bytes())
}

pub fn derive_public_key(private_key_bytes: &[u8]) -> Result<[u8; 32]> {
    if private_key_bytes.len() != 32 {
        return Err(IpouError::InvalidKeyLength { 
            expected: 32, 
            actual: private_key_bytes.len() 
        });
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(private_key_bytes);
    let private_key = StaticSecret::from(key_array);
    let public_key = PublicKey::from(&private_key);
    Ok(public_key.to_bytes())
}

pub fn compute_shared_secret(private_key: &[u8], peer_public_key: &[u8]) -> Result<[u8; 32]> {
    if private_key.len() != 32 {
        return Err(IpouError::InvalidKeyLength { 
            expected: 32, 
            actual: private_key.len() 
        });
    }
    if peer_public_key.len() != 32 {
        return Err(IpouError::InvalidKeyLength { 
            expected: 32, 
            actual: peer_public_key.len() 
        });
    }

    let mut private_array = [0u8; 32];
    private_array.copy_from_slice(private_key);
    let private_secret = StaticSecret::from(private_array);

    let mut public_array = [0u8; 32];
    public_array.copy_from_slice(peer_public_key);
    let public_key = PublicKey::from(public_array);

    let shared_secret = private_secret.diffie_hellman(&public_key);
    Ok(shared_secret.to_bytes())
}