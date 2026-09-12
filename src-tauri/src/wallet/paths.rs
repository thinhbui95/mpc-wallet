use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Legacy locations used when the process cwd was `src-tauri/` during `tauri dev`.
const LEGACY_RPC: &[&str] = &["../rpc_config.json", "rpc_config.json"];
const LEGACY_TOKENS: &[&str] = &["../tokens_config.json", "tokens_config.json"];
const LEGACY_KEY_SHARE: &[&str] = &["../key_share", "key_share"];

pub fn init(dir: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create app data dir: {e}"))?;
    let _ = DATA_DIR.set(dir);
    migrate_legacy_files()?;
    Ok(())
}

fn data_dir() -> PathBuf {
    DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("mpc-wallet-data"))
}

pub fn rpc_config() -> PathBuf {
    data_dir().join("rpc_config.json")
}

pub fn tokens_config() -> PathBuf {
    data_dir().join("tokens_config.json")
}

pub fn key_share_dir() -> PathBuf {
    data_dir().join("key_share")
}

pub fn active_wallet_file() -> PathBuf {
    key_share_dir().join("active.json")
}

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

fn copy_file_if_missing(src: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() || !src.exists() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    fs::copy(src, dest).map_err(|e| {
        format!(
            "Failed to migrate {} → {}: {e}",
            src.display(),
            dest.display()
        )
    })?;
    Ok(())
}

fn copy_dir_if_missing(src: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() || !src.exists() {
        return Ok(());
    }
    copy_dir_recursive(src, dest)
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("Failed to create {}: {e}", dest.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("Failed to read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("Failed to read dir entry: {e}"))?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            fs::copy(&from, &to).map_err(|e| {
                format!("Failed to copy {} → {}: {e}", from.display(), to.display())
            })?;
        }
    }
    Ok(())
}

fn migrate_legacy_files() -> Result<(), String> {
    if let Some(src) = first_existing(LEGACY_RPC) {
        copy_file_if_missing(&src, &rpc_config())?;
    }
    if let Some(src) = first_existing(LEGACY_TOKENS) {
        copy_file_if_missing(&src, &tokens_config())?;
    }
    if let Some(src) = first_existing(LEGACY_KEY_SHARE) {
        copy_dir_if_missing(&src, &key_share_dir())?;
    }
    Ok(())
}
