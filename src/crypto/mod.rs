use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand::distributions::{Alphanumeric, DistString};
use rand::Rng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub type PublicKeyBytes = [u8; 32];

/// Generate a new keypair
pub fn generate_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (
        general_purpose::STANDARD.encode(public.as_bytes()),
        general_purpose::STANDARD.encode(secret.to_bytes()),
    )
}

/// Convert a public key to a base64 string
pub fn public_key_to_str(key: PublicKey) -> String {
    general_purpose::STANDARD.encode(key.as_bytes())
}

/// Convert a secret key to a base64 string
pub fn secret_to_str(secret: StaticSecret) -> String {
    general_purpose::STANDARD.encode(secret.to_bytes())
}

/// Generate a shared secret from a public key and a secret key
pub fn generate_shared_secret(secret: &str, pubkey: &str) -> SharedSecret {
    let mut secret_bytes = [0u8; 32];
    general_purpose::STANDARD
        .decode_slice(secret, &mut secret_bytes)
        .expect("Failed to decode secret key");

    let mut pubkey_bytes = [0u8; 32];
    general_purpose::STANDARD
        .decode_slice(pubkey, &mut pubkey_bytes)
        .expect("Failed to decode public key");

    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(pubkey_bytes);

    secret.diffie_hellman(&public)
}

/// Encrypt a message with a shared secret
pub fn encrypt(message: &[u8], shared_secret: &SharedSecret) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(shared_secret.as_bytes()));
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let mut encrypted = cipher.encrypt(nonce, message).unwrap();
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted
}

/// Decrypt a message with a shared secret
pub fn decrypt(encrypted: &[u8], shared_secret: &SharedSecret) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(shared_secret.as_bytes()));
    let (encrypted_message, nonce_bytes) = encrypted.split_at(encrypted.len() - 12);
    let nonce = GenericArray::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, encrypted_message)
        .map_err(|e| e.to_string())
}

/// Generate a random string of a given length
pub fn generate_random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}