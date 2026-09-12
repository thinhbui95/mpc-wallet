use std::{fs, io::Write, path::{Path, PathBuf}};
use rand::{rngs::StdRng, SeedableRng};
use eyre::{Result, eyre};
use ethers::core::rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::cores::bip39::{Bip39Dictionary, Bip39Secret, Bip39Share};
use crate::cores::shamir::ShamirSecretSharing;
use crate::wallet::utils::*;

// When running via Tauri, cwd is `src-tauri/`, so keep shares at the repo root.
const ROOT_PATH: &str = "../key_share";
const ACTIVE_FILE: &str = "../key_share/active.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletInfo {
    pub address: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveWallet {
    active_address: String,
}

fn normalize_address(address: &str) -> String {
    let trimmed = address.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        format!("0x{}", hex.to_ascii_lowercase())
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn root_dir() -> PathBuf {
    PathBuf::from(ROOT_PATH)
}

fn wallet_dir(address: &str) -> PathBuf {
    root_dir().join(normalize_address(address))
}

fn load_dictionary() -> Result<Bip39Dictionary> {
    Bip39Dictionary::load("assets/bip39-en.txt")
        .map_err(|e| eyre!("Failed to load dictionary: {}", e))
}

fn ensure_root() -> Result<()> {
    fs::create_dir_all(root_dir())
        .map_err(|e| eyre!("Failed to create {}: {}", ROOT_PATH, e))
}

fn set_active_address(address: &str) -> Result<()> {
    ensure_root()?;
    let payload = ActiveWallet {
        active_address: normalize_address(address),
    };
    let json = serde_json::to_string_pretty(&payload)
        .map_err(|e| eyre!("Failed to serialize active wallet: {}", e))?;
    fs::write(ACTIVE_FILE, json)
        .map_err(|e| eyre!("Failed to write {}: {}", ACTIVE_FILE, e))?;
    Ok(())
}

pub fn get_active_address() -> Result<Option<String>> {
    if !Path::new(ACTIVE_FILE).exists() {
        // Fall back to first wallet folder if any.
        let wallets = list_wallets()?;
        return Ok(wallets.into_iter().next().map(|w| w.address));
    }
    let content = fs::read_to_string(ACTIVE_FILE)
        .map_err(|e| eyre!("Failed to read {}: {}", ACTIVE_FILE, e))?;
    let active: ActiveWallet = serde_json::from_str(&content)
        .map_err(|e| eyre!("Failed to parse {}: {}", ACTIVE_FILE, e))?;
    Ok(Some(normalize_address(&active.active_address)))
}

pub fn set_active_wallet(address: String) -> Result<String> {
    let address = normalize_address(&address);
    let dir = wallet_dir(&address);
    if !dir.exists() {
        return Err(eyre!("Wallet folder not found for {}", address));
    }
    set_active_address(&address)?;
    Ok(address)
}

pub fn list_wallets() -> Result<Vec<WalletInfo>> {
    ensure_root()?;
    let mut wallets = Vec::new();
    for entry in fs::read_dir(root_dir())
        .map_err(|e| eyre!("Failed to read {}: {}", ROOT_PATH, e))?
    {
        let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("0x") && name.len() == 42 {
            wallets.push(WalletInfo {
                address: name.clone(),
                path: path.display().to_string(),
            });
        }
    }
    wallets.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(wallets)
}

fn clear_wallet_dir(address: &str) -> Result<()> {
    let dir = wallet_dir(address);
    if dir.exists() {
        fs::remove_dir_all(&dir)
            .map_err(|e| eyre!("Failed to clear wallet dir {}: {}", dir.display(), e))?;
    }
    Ok(())
}

fn split_mnemonic_into(
    mnemonic: &str,
    n_shares: u8,
    threshold: u8,
    address: &str,
) -> Result<Vec<String>> {
    let dictionary = load_dictionary()?;
    let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary)
        .map_err(|e| eyre!("Failed to create secret from mnemonic: {}", e))?;

    if threshold > n_shares {
        return Err(eyre!(
            "Threshold ({}) cannot be greater than number of shares ({})",
            threshold,
            n_shares
        ));
    }
    if n_shares == 0 || threshold == 0 {
        return Err(eyre!("Number of shares and threshold must be greater than 0"));
    }

    let mut rng = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        StdRng::seed_from_u64(seed)
    };
    let shares = secret.split(n_shares, threshold, &mut rng);

    let dir = wallet_dir(address);
    fs::create_dir_all(&dir)
        .map_err(|e| eyre!("Failed to create directory {}: {}", dir.display(), e))?;

    let mut share_strings = Vec::new();
    for (i, share) in shares.iter().enumerate() {
        let share_string = share.to_share_string(&dictionary);
        let filename = dir.join(format!("share_{}.txt", i + 1));
        let header = format!("n_shares:{} threshold:{}\n", n_shares, threshold);
        let file_content = format!("{}{}", header, share_string);
        let mut file = fs::File::create(&filename)
            .map_err(|e| eyre!("Failed to create file {}: {}", filename.display(), e))?;
        file.write_all(file_content.as_bytes())
            .map_err(|e| eyre!("Failed to write to file {}: {}", filename.display(), e))?;
        share_strings.push(share_string);
    }
    Ok(share_strings)
}

/// Generate a new mnemonic and split it into shares under key_share/<address>/.
pub fn create_and_split_mnemonic(
    n_shares: u8,
    threshold: u8,
    seed_value: Option<u64>,
) -> Result<(String, Vec<String>, String)> {
    let dictionary = load_dictionary()?;
    let mut rng = match seed_value {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            StdRng::seed_from_u64(seed)
        }
    };

    let mnemonic = Bip39Secret::generate_random_mnemonic(&mut rng, &dictionary);
    let address = get_ethereum_address(&mnemonic)?;
    let folder = normalize_address(&address);

    ensure_root()?;
    clear_wallet_dir(&folder)?;
    let share_strings = split_mnemonic_into(&mnemonic, n_shares, threshold, &folder)?;
    set_active_address(&folder)?;

    Ok((mnemonic, share_strings, folder))
}

/// Import an existing mnemonic, split it, and store under key_share/<address>/.
pub fn import_and_split_mnemonic(
    mnemonic: &str,
    n_shares: u8,
    threshold: u8,
) -> Result<(String, Vec<String>, String)> {
    let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    if mnemonic.is_empty() {
        return Err(eyre!("Mnemonic is required"));
    }

    let dictionary = load_dictionary()?;
    // Validate mnemonic against BIP-39 dictionary / share format.
    let _secret = Bip39Secret::from_mnemonic(&mnemonic, &dictionary)
        .map_err(|e| eyre!("Invalid mnemonic: {}", e))?;

    let address = get_ethereum_address(&mnemonic)?;
    let folder = normalize_address(&address);

    ensure_root()?;
    clear_wallet_dir(&folder)?;
    let share_strings = split_mnemonic_into(&mnemonic, n_shares, threshold, &folder)?;
    set_active_address(&folder)?;

    Ok((mnemonic, share_strings, folder))
}

fn load_shares_from_dir(dir: &Path) -> Result<String> {
    let dictionary = load_dictionary()?;
    let mut share_paths = Vec::new();

    if !dir.exists() {
        return Err(eyre!("Share directory '{}' does not exist", dir.display()));
    }

    for entry in fs::read_dir(dir)
        .map_err(|e| eyre!("Failed to read directory {}: {}", dir.display(), e))?
    {
        let entry = entry.map_err(|e| eyre!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        if path.is_file() && path.extension().map(|ext| ext == "txt").unwrap_or(false) {
            share_paths.push(path);
        }
    }

    if share_paths.is_empty() {
        return Err(eyre!("No valid share files found in directory {}", dir.display()));
    }

    let mut rng = ethers::core::rand::thread_rng();
    let random_path = match share_paths.choose(&mut rng) {
        Some(path) => path,
        None => return Err(eyre!("No share files available to pick threshold from")),
    };
    let content = fs::read_to_string(random_path)
        .map_err(|e| eyre!("Failed to read file {:?}: {}", random_path, e))?;
    let first_line = content.lines().next().unwrap_or("");
    let threshold = if first_line.starts_with("n_shares:") {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let threshold_part = parts.iter().find(|s| s.starts_with("threshold:"));
        if let Some(thresh_str) = threshold_part {
            thresh_str
                .trim_start_matches("threshold:")
                .parse::<usize>()
                .unwrap_or(0)
        } else {
            return Err(eyre!("Failed to parse threshold from file header"));
        }
    } else {
        return Err(eyre!("No threshold header found in share file"));
    };

    if threshold == 0 || threshold > share_paths.len() {
        return Err(eyre!("Invalid threshold value in share file"));
    }

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

    let reconstructed_secret = Bip39Secret::reconstruct(&shares);
    let reconstructed_mnemonic = reconstructed_secret.to_mnemonic(&dictionary);
    reconstructed_secret
        .is_valid()
        .map_err(|e| eyre!("Reconstructed secret is invalid: {}", e))?;

    Ok(reconstructed_mnemonic)
}

/// Load shares from the active wallet folder and reconstruct the mnemonic.
pub fn load_and_reconstruct_mnemonic() -> Result<String> {
    let address = get_active_address()?
        .ok_or_else(|| eyre!("No active wallet. Create or import one first."))?;
    load_shares_from_dir(&wallet_dir(&address))
}

/// Reshare the active wallet into new shares in the same address folder.
pub fn reshare_mnemonic(new_n: u8, new_t: u8, clean_old: bool) -> Result<(String, Vec<String>, String)> {
    let address = get_active_address()?
        .ok_or_else(|| eyre!("No active wallet. Create or import one first."))?;
    let mnemonic = load_and_reconstruct_mnemonic()?;

    if clean_old {
        clear_wallet_dir(&address)?;
    }

    let share_strings = split_mnemonic_into(&mnemonic, new_n, new_t, &address)?;
    set_active_address(&address)?;
    Ok((mnemonic, share_strings, normalize_address(&address)))
}

pub fn get_ethereum_address(mnemonic: &str) -> Result<String> {
    let address = mnemonic_to_ethereum_address(mnemonic)
        .map_err(|e| eyre!("Failed to convert mnemonic to Ethereum address: {}", e))?;
    Ok(normalize_address(&address))
}

pub fn get_private_key_from_mnemonic(mnemonic: &str) -> Result<String> {
    let private_key = convert_mnemonic_to_private_key(mnemonic)
        .map_err(|e| eyre!("Failed to convert mnemonic to private key: {}", e))?;
    Ok(private_key)
}
