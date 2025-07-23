use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

type PrivateKeyBytes = [u8; 32];
type PublicKeyBytes = [u8; 32];

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
        return Err(crate::IpouError::InvalidKeyLength(private_key_bytes.len()));
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);
    let private_key = StaticSecret::from(key_array);
    let public_key = PublicKey::from(&private_key);
    Ok(base64::encode(public_key.to_bytes()))
}

/// Perform a Diffie-Hellman key exchange.
pub fn diffie_hellman(private_key: &[u8], public_key: &[u8]) -> SharedSecret {
    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(private_key);
    let private_key = StaticSecret::from(private_key_bytes);

    let mut public_key_bytes = [0u8; 32];
    public_key_bytes.copy_from_slice(public_key);
    let public_key = PublicKey::from(public_key_bytes);

    private_key.diffie_hellman(&public_key)
}