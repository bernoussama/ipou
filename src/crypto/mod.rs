use x25519_dalek::{PublicKey, StaticSecret};

/// generate a new X25519 keypair
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let private_key = StaticSecret::random();
    let public_key = PublicKey::from(&private_key);
    (public_key.to_bytes(), private_key.to_bytes())
}

pub fn gen_base64_private_key() -> String {
    let private_key = StaticSecret::random();
    base64::encode(private_key.to_bytes())
}

pub fn gen_base64_public_key(private_key: &str) -> String {
    let private_key_bytes = base64::decode(private_key).expect("Invalid base64 private key");
    if private_key_bytes.len() != 32 {
        eprintln!("Private key must be 32 bytes");
        return String::from("");
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);
    let private_key = StaticSecret::from(key_array);
    let public_key = PublicKey::from(&private_key);
    base64::encode(public_key.to_bytes())
}
