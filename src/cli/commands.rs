use crate::error::Result;

pub fn handle_gen_key() -> Result<()> {
    let private_key = crate::crypto::gen_base64_private_key();
    println!("{private_key}");
    Ok(())
}

pub fn handle_pub_key() -> Result<()> {
    println!("Enter your base64 encoded private key (32 bytes): ");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
    let input = input.trim();

    let public_key = crate::crypto::gen_base64_public_key(input);
    println!("{public_key}");
    Ok(())
}
