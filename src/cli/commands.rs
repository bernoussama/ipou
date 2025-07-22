use crate::crypto::keys::{generate_keypair, derive_public_key};
use crate::error::{IpouError, Result};
use std::io::{self, Write};

pub fn handle_genkey() -> Result<()> {
    let (private_key, _) = generate_keypair();
    println!("{}", base64::encode(private_key));
    Ok(())
}

pub fn handle_pubkey() -> Result<()> {
    print!("Enter your base64 encoded private key (32 bytes): ");
    io::stdout().flush().map_err(IpouError::Io)?;
    
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(IpouError::Io)?;
    
    let input = input.trim();
    let private_key_bytes = base64::decode(input)?;
    
    if private_key_bytes.len() != 32 {
        return Err(IpouError::InvalidKeyLength { 
            expected: 32, 
            actual: private_key_bytes.len() 
        });
    }

    let public_key = derive_public_key(&private_key_bytes)?;
    println!("{}", base64::encode(public_key));
    Ok(())
}