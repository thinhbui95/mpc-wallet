use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::Network;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::str::FromStr;
use bitcoin::secp256k1::Secp256k1;

pub fn mnemonic_to_ethereum_address(mnemonic_phrase: &str) -> Result<String, String> {
    // Step 1: Parse the mnemonic
    let mnemonic = Mnemonic::parse_normalized(mnemonic_phrase)
        .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;

    // Step 2: Derive the seed
    let seed = mnemonic.to_seed(""); // Empty passphrase

    // Step 3: Derive master key using BIP-32
    let master_key = Xpriv::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Failed to derive master key: {}", e))?;

    // Step 4: Derive the key for BIP-44 path m/44'/60'/0'/0/0 (Ethereum)
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let secp = Secp256k1::new();
    let child_xprv = master_key
        .derive_priv(&secp, &derivation_path)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    // Step 5: Create signing key from derived private key
    let signing_key = SigningKey::from_bytes(&child_xprv.private_key.secret_bytes().into())
        .map_err(|e| format!("Failed to create signing key: {}", e))?;

    // Step 6: Compute public key
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key_uncompressed = public_key.as_bytes();

    // Step 7: Compute Ethereum address
    // - Remove 0x04 prefix (uncompressed public key)
    // - Apply Keccak-256 hash
    // - Take last 20 bytes
    let public_key_bytes = &public_key_uncompressed[1..]; // Skip 0x04
    let mut hasher = Keccak256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();
    let address = &hash[12..]; // Last 20 bytes

    // Step 8: Format as hex string
    // EIP-55 checksum encoding
    let address_hex = hex::encode(address);
    let address_lower = address_hex.to_lowercase();

    // Hash the lowercase hex address
    let mut hasher = Keccak256::new();
    hasher.update(address_lower.as_bytes());
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);

    // Apply checksum: uppercase if hash nibble >= 8
    let checksummed: String = address_hex
        .chars()
        .zip(hash_hex.chars())
        .map(|(c, h)| {
            if c.is_digit(10) {
                c
            } else if h.to_digit(16).unwrap() >= 8 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();

    Ok(format!("0x{}", checksummed))
}

pub fn convert_mnemonic_to_private_key(mnemonic_phrase: &str) -> Result<String, String> {
    // Step 1: Parse the mnemonic
    let mnemonic = Mnemonic::parse_normalized(mnemonic_phrase)
        .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;

    // Step 2: Derive the seed
    let seed = mnemonic.to_seed(""); // Empty passphrase

    // Step 3: Derive master key using BIP-32
    let master_key = Xpriv::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Failed to derive master key: {}", e))?;

    // Step 4: Derive the key for BIP-44 path m/44'/60'/0'/0/0 (Ethereum)
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let secp = Secp256k1::new();
    let child_xprv = master_key
        .derive_priv(&secp, &derivation_path)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    let signing_key = SigningKey::from_bytes(&child_xprv.private_key.secret_bytes().into())
        .map_err(|e| format!("Failed to create signing key: {}", e))?;

    // Step 5: Return the private key in hex format
    Ok(format!("0x{}",hex::encode(signing_key.to_bytes())))
}