use x25519_dalek::{PublicKey, StaticSecret};

pub type PrivateKeyBytes = [u8; 32];
pub type PublicKeyBytes = [u8; 32];

/// generate a new X25519 keypair ()->(private_key, public_key)
pub fn generate_keypair() -> (PrivateKeyBytes, PublicKeyBytes) {
    let private_key = StaticSecret::random();
    let public_key = PublicKey::from(&private_key);
    (private_key.to_bytes(), public_key.to_bytes())
}

pub fn gen_base64_private_key() -> String {
    let private_key = StaticSecret::random();
    base64::encode(private_key.to_bytes())
}

pub fn gen_base64_public_key(private_key: &str) -> crate::Result<String> {
    let private_key_bytes = base64::decode(private_key).expect("Invalid base64 private key");
    if private_key_bytes.len() != 32 {
        return Err(crate::Error::InvalidKeyLength(private_key_bytes.len()));
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);
    let private_key = StaticSecret::from(key_array);
    let public_key = PublicKey::from(&private_key);
    Ok(base64::encode(public_key.to_bytes()))
}

pub fn generate_shared_secret(base64_secret: &str, base64_pubkey: &str) -> [u8; 32] {
    let mut secret_bytes = [0u8; 32];
    base64::decode_config_slice(base64_secret, base64::STANDARD, &mut secret_bytes).unwrap();
    let static_secret = StaticSecret::from(secret_bytes);

    let mut pub_key_bytes = [0u8; 32];
    base64::decode_config_slice(base64_pubkey, base64::STANDARD, &mut pub_key_bytes).unwrap();
    let pub_key = PublicKey::from(pub_key_bytes);

    static_secret.diffie_hellman(&pub_key).to_bytes()
}
