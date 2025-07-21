use std::{fs, path::Path, io::Write};
use rand::{rngs::StdRng, SeedableRng};
use eyre::{Result, eyre};
use ethers::core::rand::seq::SliceRandom;

use crate::cores::bip39::{Bip39Dictionary, Bip39Secret, Bip39Share};
use crate::cores::shamir::ShamirSecretSharing;
use crate::wallet::utils::*;
    
const FOLDER_PATH: &str = "key_share";
    
/// Generate a new mnemonic and split it into shares, saving each share to a file
pub fn create_and_split_mnemonic(
    n_shares: u8, 
    threshold: u8,
    seed_value: Option<u64>
) -> Result<(String, Vec<String>)> {
    // Load the BIP-39 dictionary
    let dictionary = Bip39Dictionary::load("assets/bip39-en.txt")
        .map_err(|e| eyre!("Failed to load dictionary: {}", e))?;
        
    // Create RNG with seed for reproducible results (or use random seed)
    let mut rng = match seed_value {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            StdRng::seed_from_u64(seed)
        },
    };
        
    // Generate a random BIP-39 secret using the generate_random_mnemonic method
    let original_mnemonic = Bip39Secret::generate_random_mnemonic(&mut rng, &dictionary);

    // Delete old share files if they exist
    if Path::new(FOLDER_PATH).exists() {
        fs::remove_dir_all(FOLDER_PATH)
            .map_err(|e| eyre!("Failed to delete old share directory {}: {}", FOLDER_PATH, e))?;
    }
    
    // Create secret from the generated mnemonic for splitting
    split_mnemonic(&original_mnemonic, n_shares, threshold)
        .map(|(mnemonic, share_strings)| (mnemonic, share_strings))
        .map_err(|e| eyre!("Failed to create and split mnemonic: {}", e))
}

fn split_mnemonic(
    mnemonic: &str,
    n_shares: u8,
    threshold: u8,
) -> Result<(String, Vec<String>)> {
    // Load the BIP-39 dictionary
    let dictionary = Bip39Dictionary::load("assets/bip39-en.txt")
        .map_err(|e| eyre!("Failed to load dictionary: {}", e))?;
    
    // Create secret from the provided mnemonic
    let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary)
        .map_err(|e| eyre!("Failed to create secret from mnemonic: {}", e))?;
    
    // Validate inputs
    if threshold > n_shares {
        return Err(eyre!("Threshold ({}) cannot be greater than number of shares ({})", threshold, n_shares));
    }
    if n_shares == 0 || threshold == 0 {
        return Err(eyre!("Number of shares and threshold must be greater than 0"));
    }
    
    // Split the secret into shares
    let mut rng = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            StdRng::seed_from_u64(seed)
        };
    let shares = secret.split(n_shares, threshold, &mut rng);
    
    // Create the key_share directory if it doesn't exist
    fs::create_dir_all(FOLDER_PATH)
        .map_err(|e| eyre!("Failed to create directory {}: {}", FOLDER_PATH, e))?;
    
    // Save each share to a separate file and collect the share strings
    let mut share_strings = Vec::new();
    
    for (i, share) in shares.iter().enumerate() {
        let share_string = share.to_share_string(&dictionary);
        let filename = format!("{}/share_{}.txt", FOLDER_PATH, i + 1);
        
        // Add n_shares and threshold as a header
        let header = format!("n_shares:{} threshold:{}\n", n_shares, threshold);
        let file_content = format!("{}{}", header, share_string);
        
        // Write share to file
        let mut file = fs::File::create(&filename)
            .map_err(|e| eyre!("Failed to create file {}: {}", filename, e))?;

        file.write_all(file_content.as_bytes())
            .map_err(|e| eyre!("Failed to write to file {}: {}", filename, e))?;
        share_strings.push(share_string);
    }
    Ok((mnemonic.to_string(), share_strings))
}

/// Load shares from files and reconstruct the original mnemonic
pub fn load_and_reconstruct_mnemonic() -> Result<String> {

    let dictionary = Bip39Dictionary::load("assets/bip39-en.txt")
        .map_err(|e| eyre!("Failed to load dictionary: {}", e))?;

    // Read all share files from the directory
    let mut share_paths = Vec::new();

    if !Path::new(FOLDER_PATH).exists() {
        return Err(eyre!("Share directory '{}' does not exist", FOLDER_PATH));
    }

    for entry in fs::read_dir(FOLDER_PATH)
        .map_err(|e| eyre!("Failed to read directory {}: {}", FOLDER_PATH, e))? {
        let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        if path.is_file() && path.extension().map(|ext| ext == "txt").unwrap_or(false) {
            share_paths.push(path);
        }
    }

    if share_paths.is_empty() {
        return Err(eyre!("No valid share files found in directory {}", FOLDER_PATH));
    }

    // Pick a random file to get the threshold
    let mut rng = ethers::core::rand::thread_rng();
    let random_path = match share_paths.choose(&mut rng) {
        Some(path) => path,
        None => return Err(eyre!("No share files available to pick threshold from")),
    };
    let content = fs::read_to_string(random_path)
        .map_err(|e| eyre!("Failed to read file {:?}: {}", random_path, e))?;
    let first_line = content.lines().next().unwrap_or("");
    let threshold = if first_line.starts_with("n_shares:") {
        // Parse threshold from header
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let threshold_part = parts.iter().find(|s| s.starts_with("threshold:"));
        if let Some(thresh_str) = threshold_part {
            thresh_str.trim_start_matches("threshold:").parse::<usize>().unwrap_or(0)
        } else {
            return Err(eyre!("Failed to parse threshold from file header"));
        }
    } else {
        return Err(eyre!("No threshold header found in share file"));
    };

    if threshold == 0 || threshold > share_paths.len() {
        return Err(eyre!("Invalid threshold value in share file"));
    }

    // Randomly pick 'threshold' number of share files
    let picked_paths = share_paths.choose_multiple(&mut rng, threshold);

    let mut shares = Vec::new();
    for path in picked_paths {
        let contents = fs::read_to_string(path)
            .map_err(|e| eyre!("Failed to read file {:?}: {}", path, e))?;
        let mut lines = contents.lines();
        let first_line = lines.next().unwrap_or("");
        let share_line = if first_line.starts_with("n_shares:") {
            lines.next().unwrap_or("")
        } else {
            first_line
        };
        let share = Bip39Share::from_share_string(share_line.trim(), &dictionary)
            .map_err(|e| eyre!("Failed to parse share from file {:?}: {}", path, e))?;
        shares.push(share);
    }

    // Reconstruct the secret
    let reconstructed_secret = Bip39Secret::reconstruct(&shares);
    let reconstructed_mnemonic = reconstructed_secret.to_mnemonic(&dictionary);

    // Validate the reconstructed secret
    reconstructed_secret.is_valid()
        .map_err(|e| eyre!("Reconstructed secret is invalid: {}", e))?;

    Ok(reconstructed_mnemonic)
}

/// List all available share files
#[allow(dead_code)]
pub fn list_share_files() -> Result<Vec<String>> {
    let mut files = Vec::new();
    
    if !Path::new(FOLDER_PATH).exists() {
        return Ok(files);
    }
    
    for entry in fs::read_dir(FOLDER_PATH)
        .map_err(|e| eyre!("Failed to read directory {}: {}", FOLDER_PATH, e))? {
        
        let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map(|ext| ext == "txt").unwrap_or(false) {
            if let Some(filename) = path.file_name().and_then(|name| name.to_str()) {
                files.push(filename.to_string());
            }
        }
    }
    
    files.sort();
    Ok(files)
}

/// Delete all share files
fn clean_share_files() -> Result<()> {
    if !Path::new(FOLDER_PATH).exists() {
        return Ok(());
    }
    
    for entry in fs::read_dir(FOLDER_PATH)
        .map_err(|e| eyre!("Failed to read directory {}: {}", FOLDER_PATH, e))? {
        
        let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map(|ext| ext == "txt").unwrap_or(false) {
            fs::remove_file(&path)
                .map_err(|e| eyre!("Failed to delete file {:?}: {}", path, e))?;
        }
    }
    
    Ok(())
}

/// Load or create a keypair (updated version of your original function)
#[allow(dead_code)]
pub fn load_or_create_keypair(create_new: bool, n_shares: u8, threshold: u8) -> Result<String> {
    if create_new {
        // Clean existing files first
        let _ = clean_share_files();
        
        // Create new mnemonic and split it
        let (mnemonic, _) = create_and_split_mnemonic(n_shares, threshold, None)?;
        Ok(mnemonic)
    } else {
        // Try to load and reconstruct from existing files
        match load_and_reconstruct_mnemonic() {
            Ok(mnemonic) => Ok(mnemonic),
            Err(_) => {
                println!("No valid shares found, creating new mnemonic...");
                let (mnemonic, _) = create_and_split_mnemonic(n_shares, threshold, None)?;
                Ok(mnemonic)
            }
        }
    }
}

/// Reshare: reconstruct the secret from existing shares and split into new shares.
/// Optionally deletes old share files and saves new ones.
pub fn reshare_mnemonic(new_n: u8, new_t: u8, clean_old: bool) -> Result<(String, Vec<String>)> {
    // Step 1: Reconstruct the mnemonic from the required number of shares
    let mnemonic = load_and_reconstruct_mnemonic()?;
    
    // Step 2: Clear old share files if requested
    if clean_old {
        let _ = clean_share_files();
    }

    // Step 3: Split the reconstructed mnemonic into new shares
    let (reshared_mnemonic, new_share_strings) = split_mnemonic(&mnemonic, new_n, new_t)
        .map_err(|e| eyre!("Failed to reshare mnemonic: {}", e))?;  
    Ok((reshared_mnemonic, new_share_strings))
}

pub fn get_ethereum_address(mnemonic: &str) -> Result<String> {
    let address = mnemonic_to_ethereum_address(mnemonic)
        .map_err(|e| eyre!("Failed to convert mnemonic to Ethereum address: {}", e))?;
    
    Ok(address)
}

pub fn get_private_key_from_mnemonic(mnemonic: &str) -> Result<String> {
    let private_key = convert_mnemonic_to_private_key(mnemonic)
        .map_err(|e| eyre!("Failed to convert mnemonic to private key: {}", e))?;
    Ok(private_key)
}

