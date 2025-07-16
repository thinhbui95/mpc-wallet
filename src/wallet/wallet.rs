use std::{fs, path::Path, io::Write};
use rand::{rngs::StdRng, SeedableRng};
use eyre::{Result, eyre};

use crate::cores::bip39::{Bip39Dictionary, Bip39Secret, Bip39Share};
use crate::cores::shamir::ShamirSecretSharing;

pub mod wallet {
    use super::*;
    
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
        
        // Create secret from the generated mnemonic for splitting
        let secret = Bip39Secret::from_mnemonic(&original_mnemonic, &dictionary)
            .map_err(|e| eyre!("Failed to create secret from generated mnemonic: {}", e))?;
        let original_mnemonic = secret.to_mnemonic(&dictionary);
        
        // Validate inputs
        if threshold > n_shares {
            return Err(eyre!("Threshold ({}) cannot be greater than number of shares ({})", threshold, n_shares));
        }
        if n_shares == 0 || threshold == 0 {
            return Err(eyre!("Number of shares and threshold must be greater than 0"));
        }
        
        // Split the secret into shares
        let shares = secret.split(n_shares, threshold, &mut rng);
        
        // Create the key_share directory if it doesn't exist
        fs::create_dir_all(FOLDER_PATH)
            .map_err(|e| eyre!("Failed to create directory {}: {}", FOLDER_PATH, e))?;
        
        // Save each share to a separate file and collect the share strings
        let mut share_strings = Vec::new();
        
        for (i, share) in shares.iter().enumerate() {
            let share_string = share.to_share_string(&dictionary);
            let filename = format!("{}/share_{}.txt", FOLDER_PATH, i + 1);
            
            // Write share to file
            let mut file = fs::File::create(&filename)
                .map_err(|e| eyre!("Failed to create file {}: {}", filename, e))?;
            
            file.write_all(share_string.as_bytes())
                .map_err(|e| eyre!("Failed to write to file {}: {}", filename, e))?;
            
            share_strings.push(share_string);
            
            println!("Saved share {} to: {}", i + 1, filename);
        }
        
        println!("Original mnemonic: {}", original_mnemonic);
        println!("Successfully split into {} shares with threshold {}", n_shares, threshold);
        println!("Shares saved to directory: {}", FOLDER_PATH);
        
        Ok((original_mnemonic, share_strings))
    }
    
    /// Load shares from files and reconstruct the original mnemonic
    pub fn load_and_reconstruct_mnemonic(required_shares: Option<usize>) -> Result<String> {
        let dictionary = Bip39Dictionary::load("assets/bip39-en.txt")
            .map_err(|e| eyre!("Failed to load dictionary: {}", e))?;
        
        // Read all share files from the directory
        let mut shares = Vec::new();
        
        if !Path::new(FOLDER_PATH).exists() {
            return Err(eyre!("Share directory '{}' does not exist", FOLDER_PATH));
        }
        
        for entry in fs::read_dir(FOLDER_PATH)
            .map_err(|e| eyre!("Failed to read directory {}: {}", FOLDER_PATH, e))? {
            
            let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map(|ext| ext == "txt").unwrap_or(false) {
                let contents = fs::read_to_string(&path)
                    .map_err(|e| eyre!("Failed to read file {:?}: {}", path, e))?;
                
                let share = Bip39Share::from_share_string(&contents.trim(), &dictionary)
                    .map_err(|e| eyre!("Failed to parse share from file {:?}: {}", path, e))?;
                
                shares.push(share);
                println!("Loaded share from: {:?}", path);
            }
        }
        
        if shares.is_empty() {
            return Err(eyre!("No valid share files found in directory {}", FOLDER_PATH));
        }
        
        // Use only the required number of shares if specified
        if let Some(count) = required_shares {
            if count > shares.len() {
                return Err(eyre!("Requested {} shares but only {} available", count, shares.len()));
            }
            shares.truncate(count);
        }
        
        println!("Using {} shares for reconstruction", shares.len());
        
        // Reconstruct the secret
        let reconstructed_secret = Bip39Secret::reconstruct(&shares);
        let reconstructed_mnemonic = reconstructed_secret.to_mnemonic(&dictionary);
        
        // Validate the reconstructed secret
        reconstructed_secret.is_valid()
            .map_err(|e| eyre!("Reconstructed secret is invalid: {}", e))?;
        
        println!("Successfully reconstructed mnemonic: {}", reconstructed_mnemonic);
        
        Ok(reconstructed_mnemonic)
    }
    
    /// List all available share files
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
    pub fn clean_share_files() -> Result<()> {
        if !Path::new(FOLDER_PATH).exists() {
            return Ok(());
        }
        
        let mut deleted_count = 0;
        
        for entry in fs::read_dir(FOLDER_PATH)
            .map_err(|e| eyre!("Failed to read directory {}: {}", FOLDER_PATH, e))? {
            
            let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map(|ext| ext == "txt").unwrap_or(false) {
                fs::remove_file(&path)
                    .map_err(|e| eyre!("Failed to delete file {:?}: {}", path, e))?;
                deleted_count += 1;
                println!("Deleted: {:?}", path);
            }
        }
        
        println!("Deleted {} share files", deleted_count);
        Ok(())
    }
    
    /// Load or create a keypair (updated version of your original function)
    pub fn load_or_create_keypair(create_new: bool, n_shares: u8, threshold: u8) -> Result<String> {
        if create_new {
            // Clean existing files first
            let _ = clean_share_files();
            
            // Create new mnemonic and split it
            let (mnemonic, _) = create_and_split_mnemonic(n_shares, threshold, None)?;
            Ok(mnemonic)
        } else {
            // Try to load and reconstruct from existing files
            match load_and_reconstruct_mnemonic(None) {
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
    pub fn reshare_mnemonic(new_n: u8, new_t: u8, required_shares: Option<usize>, clean_old: bool) -> Result<(String, Vec<String>)> {
        // Step 1: Reconstruct the mnemonic from the required number of shares
        let mnemonic = load_and_reconstruct_mnemonic(required_shares)?;
        let dictionary = Bip39Dictionary::load("assets/bip39-en.txt")
            .map_err(|e| eyre!("Failed to load dictionary: {}", e))?;
        let secret = Bip39Secret::from_mnemonic(&mnemonic, &dictionary)?;

        // Step 2: Optionally clean old shares
        if clean_old {
            let _ = clean_share_files();
        }

        // Step 3: Split into new shares and save
        create_and_split_mnemonic(new_n, new_t, None)
    }
}

#[cfg(test)]
mod tests {
    use super::wallet::*;
    use std::{fs, path::Path};
    
    #[test]
    fn test_create_and_split_mnemonic() {
        // Clean up any existing files
        let _ = clean_share_files();
        
        // Create a mnemonic and split it into 5 shares with threshold of 3
        let result = create_and_split_mnemonic(5, 3, Some(12345));
        assert!(result.is_ok());
        
        let (original_mnemonic, share_strings) = result.unwrap();
        
        // Verify we got 5 shares
        assert_eq!(share_strings.len(), 5);
        
        // Verify all shares are different
        for i in 0..share_strings.len() {
            for j in (i + 1)..share_strings.len() {
                assert_ne!(share_strings[i], share_strings[j]);
            }
        }
        
        // Verify files were created
        let files = list_share_files().unwrap();
        assert_eq!(files.len(), 5);
        
        // Test reconstruction
        let reconstructed = load_and_reconstruct_mnemonic(Some(3)).unwrap();
        assert_eq!(original_mnemonic, reconstructed);
        
        println!("✅ Original mnemonic: {}", original_mnemonic);
        println!("✅ Reconstructed mnemonic: {}", reconstructed);
        
        // Clean up
        let _ = clean_share_files();
    }
    
    #[test]
    fn test_load_or_create_keypair_workflow() {
        // Clean up first
        let _ = clean_share_files();
        
        // Test creating new keypair
        let mnemonic1 = load_or_create_keypair(true, 4, 2).unwrap();
        
        // Test loading existing keypair
        let mnemonic2 = load_or_create_keypair(false, 4, 2).unwrap();
        
        // They should be the same
        assert_eq!(mnemonic1, mnemonic2);
        
        println!("✅ Keypair workflow test passed");
        println!("✅ Mnemonic: {}", mnemonic1);
        
        // Clean up
        let _ = clean_share_files();
    }
    
    #[test]
    fn test_share_string_format() {
        // Clean up first
        let _ = clean_share_files();
        
        // Create shares
        let (original_mnemonic, share_strings) = create_and_split_mnemonic(3, 2, Some(54321)).unwrap();
        
        // Verify share string format
        for (i, share_string) in share_strings.iter().enumerate() {
            assert!(share_string.starts_with(&format!("ID:{}", i + 1)));
            assert!(share_string.contains(" ")); // Should have space between ID and mnemonic
            
            // The mnemonic part should have 24 words
            let parts: Vec<&str> = share_string.splitn(2, ' ').collect();
            assert_eq!(parts.len(), 2);
            
            let mnemonic_part = parts[1];
            let words: Vec<&str> = mnemonic_part.split_whitespace().collect();
            assert_eq!(words.len(), 24);
            
            println!("✅ Share {}: {}", i + 1, share_string);
        }
        
        // Test reconstruction with only 2 shares
        let reconstructed = load_and_reconstruct_mnemonic(Some(2)).unwrap();
        assert_eq!(original_mnemonic, reconstructed);
        
        println!("✅ Share string format test passed");
        
        // Clean up
        let _ = clean_share_files();
    }
    
    #[test]
    fn test_file_operations() {
        // Clean up first
        let _ = clean_share_files();
        
        // Initially no files should exist
        let files = list_share_files().unwrap();
        assert_eq!(files.len(), 0);
        
        // Create shares
        let _ = create_and_split_mnemonic(3, 2, Some(99999)).unwrap();
        
        // Now should have 3 files
        let files = list_share_files().unwrap();
        assert_eq!(files.len(), 3);
        
        // Check file names
        for (i, filename) in files.iter().enumerate() {
            assert_eq!(filename, &format!("share_{}.txt", i + 1));
        }
        
        // Verify file contents
        for i in 1..=3 {
            let filepath = format!("key_share/share_{}.txt", i);
            assert!(Path::new(&filepath).exists());
            
            let content = fs::read_to_string(&filepath).unwrap();
            assert!(content.starts_with(&format!("ID:{}", i)));
        }
        
        // Clean up and verify deletion
        clean_share_files().unwrap();
        let files = list_share_files().unwrap();
        assert_eq!(files.len(), 0);
        
        println!("✅ File operations test passed");
    }
}