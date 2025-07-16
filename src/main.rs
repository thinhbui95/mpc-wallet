mod cores;
pub mod wallet;
pub use wallet::*;

fn main() {
    println!("🔐 MPC Wallet - Demo");
    println!("Run the tests to see mnemonic splitting in action:");
    println!("cargo test test_create_and_split_mnemonic -- --nocapture");
    // Provide None for the optional seed_value argument
    let _ = wallet::create_and_split_mnemonic(5, 3, None);
    let mnemonic  = wallet::load_and_reconstruct_mnemonic(None);
    match mnemonic {
        Ok(mnemonic) => println!("Reconstructed mnemonic: {}", mnemonic),
        Err(e) => eprintln!("Error reconstructing mnemonic: {}", e),
    }
}
