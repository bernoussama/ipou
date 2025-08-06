use crate::crypto;
use base64::{engine::general_purpose, Engine as _};

pub fn genkey() -> crate::Result<()> {
    let (public_key, private_key) = crypto::generate_keypair();
    println!("Private key: {private_key}");
    println!("Public key: {public_key}");
    Ok(())
}

pub fn pubkey(input: &str) -> crate::Result<()> {
    let mut private_key_bytes = [0u8; 32];
    general_purpose::STANDARD
        .decode_slice(input, &mut private_key_bytes)
        .unwrap();
    let secret = x25519_dalek::StaticSecret::from(private_key_bytes);
    let public: x25519_dalek::PublicKey = (&secret).into();
    println!(
        "Public key: {}",
        general_purpose::STANDARD.encode(public.as_bytes())
    );
    Ok(())
}
