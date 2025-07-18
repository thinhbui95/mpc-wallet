pub mod cores;
pub mod wallet;
pub mod ui;
pub use wallet::*;
pub use ui::*;



fn main() {
    //ui::create_wallet_ui();
    //let _ = wallet::load_and_reconstruct_mnemonic();
    // ui::reshare_wallet_ui();
    //ui::reshare_wallet_ui();
    ui::interact_ui();
    // println!("🔐 MPC Wallet - Demo");
    // println!("Run the tests to see mnemonic splitting in action:");
    // println!("cargo test test_create_and_split_mnemonic -- --nocapture");
    // // Provide None for the optional seed_value argument
    // let _ = wallet::create_and_split_mnemonic(5, 3, None);
    // let mnemonic  = wallet::load_and_reconstruct_mnemonic(None);
    // match mnemonic {
    //     Ok(mnemonic) => println!("Reconstructed mnemonic: {}", mnemonic),
    //     Err(e) => eprintln!("Error reconstructing mnemonic: {}", e),
    // }

    // // Reshare to 7 shares with threshold 4, using any 3 existing shares, and clean old shares
    // let (mnemonic, new_shares) = wallet::reshare_mnemonic(7, 4, Some(3), true).unwrap();
    // println!("Reshared mnemonic: {}", mnemonic);
    // for (i, share) in new_shares.iter().enumerate() {
    //     println!("New share {}: {}", i + 1, share);
}

