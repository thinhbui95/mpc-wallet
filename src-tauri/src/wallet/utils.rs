use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::Network;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::str::FromStr;
use bitcoin::secp256k1::Secp256k1;

/// Derives the Ethereum private key from a mnemonic phrase using BIP-44 path m/44'/60'/0'/0/0.
///
/// # Arguments
/// * `mnemonic_phrase` - The BIP-39 mnemonic phrase.
///
/// # Returns
/// * `Ok(SigningKey)` - The derived signing key.
/// * `Err(String)` - An error message if derivation fails.
fn derive_ethereum_key(mnemonic_phrase: &str) -> Result<SigningKey, String> {
    let mnemonic = Mnemonic::parse_normalized(mnemonic_phrase)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;
    let seed = mnemonic.to_seed("");
    
    let secp = Secp256k1::new();
    let master_key = Xpriv::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Failed to derive master key: {}", e))?;
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let child_xprv = master_key
        .derive_priv(&secp, &derivation_path)
        .map_err(|e| format!("Failed to derive child key: {}", e))?;
    
    SigningKey::from_bytes(&child_xprv.private_key.secret_bytes().into())
        .map_err(|e| format!("Failed to create signing key: {}", e))
}

/// Converts a BIP-39 mnemonic phrase to an Ethereum address (EIP-55 compliant).
///
/// # Arguments
/// * `mnemonic_phrase` - The BIP-39 mnemonic phrase (12, 15, 18, 21, or 24 words).
///
/// # Returns
/// * `Ok(String)` - The Ethereum address in EIP-55 checksum format (e.g., "0x...").
/// * `Err(String)` - An error message if the mnemonic is invalid or derivation fails.
pub fn mnemonic_to_ethereum_address(mnemonic_phrase: &str) -> Result<String, String> {
    // Derive the signing key
    let signing_key = derive_ethereum_key(mnemonic_phrase)?;
    
    // Compute public key and Ethereum address
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key_bytes = &public_key.as_bytes()[1..]; // Skip 0x04
    
    let hash = Keccak256::digest(public_key_bytes);
    let address = &hash[12..]; // Last 20 bytes
    let address_hex = hex::encode(address);
    let address_lower = address_hex.to_lowercase();
    
    // Apply EIP-55 checksum
    let hash = Keccak256::digest(address_lower.as_bytes());
    let hash_hex = hex::encode(hash);
    let checksummed: String = address_hex
        .chars()
        .zip(hash_hex.chars())
        .map(|(c, h)| {
            if c.is_digit(10) {
                c
            } else if h.to_digit(16).unwrap_or(0) >= 8 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    
    Ok(format!("0x{}", checksummed))
}

/// Converts a BIP-39 mnemonic phrase to an Ethereum private key.
///
/// # Arguments
/// * `mnemonic_phrase` - The BIP-39 mnemonic phrase (12, 15, 18, 21, or 24 words).
///
/// # Returns
/// * `Ok(String)` - The private key in hex format (e.g., "0x...").
/// * `Err(String)` - An error message if the mnemonic is invalid or derivation fails.
pub fn convert_mnemonic_to_private_key(mnemonic_phrase: &str) -> Result<String, String> {
    let signing_key = derive_ethereum_key(mnemonic_phrase)?;
    Ok(format!("0x{}", hex::encode(signing_key.to_bytes())))
}