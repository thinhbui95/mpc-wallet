use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const CONFIG_PATH: &str = "../tokens_config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredToken {
    pub id: String,
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTokens {
    pub network_id: String,
    pub network_name: String,
    pub rpc_url: String,
    pub tokens: Vec<StoredToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TokensConfig {
    /// All imported tokens grouped by network.
    #[serde(default)]
    pub networks: Vec<NetworkTokens>,
    /// Legacy formats kept only for migration.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_network: std::collections::HashMap<String, Vec<StoredToken>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<StoredToken>,
}

use std::collections::HashMap;

fn config_path() -> PathBuf {
    PathBuf::from(CONFIG_PATH)
}

fn normalize_rpc_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn save_config(config: &TokensConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
        }
    }
    // Persist only the networks list (drop legacy fields from disk).
    let clean = TokensConfig {
        networks: config.networks.clone(),
        by_network: HashMap::new(),
        tokens: Vec::new(),
    };
    let json = serde_json::to_string_pretty(&clean)
        .map_err(|e| format!("Failed to serialize tokens config: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

fn load_raw_config() -> Result<TokensConfig, String> {
    let path = config_path();
    if !Path::new(&path).exists() {
        let config = TokensConfig::default();
        save_config(&config)?;
        return Ok(config);
    }
    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse {}: {e}", path.display()))
}

fn migrate_legacy(
    config: &mut TokensConfig,
    network_id: &str,
    network_name: &str,
    rpc_url: &str,
) -> Result<(), String> {
    let mut changed = false;

    // Old flat list → current network.
    if !config.tokens.is_empty() {
        let legacy = std::mem::take(&mut config.tokens);
        upsert_network(config, network_id, network_name, rpc_url);
        if let Some(network) = find_network_mut(config, network_id, rpc_url) {
            for token in legacy {
                if !network
                    .tokens
                    .iter()
                    .any(|t| t.address.eq_ignore_ascii_case(&token.address))
                {
                    network.tokens.push(token);
                }
            }
        }
        changed = true;
    }

    // Old byNetwork map → networks[].
    if !config.by_network.is_empty() {
        let map = std::mem::take(&mut config.by_network);
        for (id, tokens) in map {
            let (name, url) = if id == network_id {
                (network_name.to_string(), normalize_rpc_url(rpc_url))
            } else {
                (format!("Network {id}"), String::new())
            };
            upsert_network(config, &id, &name, &url);
            if let Some(network) = find_network_mut(config, &id, &url) {
                for token in tokens {
                    if !network
                        .tokens
                        .iter()
                        .any(|t| t.address.eq_ignore_ascii_case(&token.address))
                    {
                        network.tokens.push(token);
                    }
                }
            }
        }
        changed = true;
    }

    if changed {
        save_config(config)?;
    }
    Ok(())
}

fn find_network_mut<'a>(
    config: &'a mut TokensConfig,
    network_id: &str,
    rpc_url: &str,
) -> Option<&'a mut NetworkTokens> {
    let url = normalize_rpc_url(rpc_url);
    if let Some(idx) = config.networks.iter().position(|n| n.network_id == network_id) {
        return Some(&mut config.networks[idx]);
    }
    if !url.is_empty() {
        if let Some(idx) = config
            .networks
            .iter()
            .position(|n| normalize_rpc_url(&n.rpc_url).eq_ignore_ascii_case(&url))
        {
            return Some(&mut config.networks[idx]);
        }
    }
    None
}

fn upsert_network(
    config: &mut TokensConfig,
    network_id: &str,
    network_name: &str,
    rpc_url: &str,
) {
    let url = normalize_rpc_url(rpc_url);
    if let Some(network) = find_network_mut(config, network_id, &url) {
        network.network_id = network_id.to_string();
        network.network_name = network_name.to_string();
        if !url.is_empty() {
            network.rpc_url = url;
        }
        return;
    }
    config.networks.push(NetworkTokens {
        network_id: network_id.to_string(),
        network_name: network_name.to_string(),
        rpc_url: url,
        tokens: Vec::new(),
    });
}

fn normalize_address(address: &str) -> Result<String, String> {
    let address = address.trim();
    if address.len() != 42 || !address.starts_with("0x") {
        return Err("Invalid token address! Must be 42 characters starting with 0x.".into());
    }
    Ok(format!("0x{}", &address[2..].to_ascii_lowercase()))
}

pub fn list_tokens(
    network_id: &str,
    network_name: &str,
    rpc_url: &str,
) -> Result<Vec<StoredToken>, String> {
    let mut config = load_raw_config()?;
    migrate_legacy(&mut config, network_id, network_name, rpc_url)?;
    Ok(find_network_mut(&mut config, network_id, rpc_url)
        .map(|n| n.tokens.clone())
        .unwrap_or_default())
}

pub fn add_token(
    network_id: &str,
    network_name: &str,
    rpc_url: &str,
    address: String,
    name: String,
    symbol: String,
    decimals: u8,
) -> Result<StoredToken, String> {
    let address = normalize_address(&address)?;
    let mut config = load_raw_config()?;
    migrate_legacy(&mut config, network_id, network_name, rpc_url)?;
    upsert_network(&mut config, network_id, network_name, rpc_url);

    let network = find_network_mut(&mut config, network_id, rpc_url)
        .ok_or_else(|| "Failed to create network token bucket".to_string())?;

    if network
        .tokens
        .iter()
        .any(|t| t.address.eq_ignore_ascii_case(&address))
    {
        return Err("Token already imported on this network".into());
    }

    let token = StoredToken {
        id: Uuid::new_v4().to_string(),
        address,
        name,
        symbol,
        decimals,
    };
    network.tokens.push(token.clone());
    save_config(&config)?;
    Ok(token)
}

pub fn remove_token(
    network_id: &str,
    network_name: &str,
    rpc_url: &str,
    id: String,
) -> Result<Vec<StoredToken>, String> {
    let mut config = load_raw_config()?;
    migrate_legacy(&mut config, network_id, network_name, rpc_url)?;
    let network = find_network_mut(&mut config, network_id, rpc_url)
        .ok_or_else(|| "Network token list not found".to_string())?;
    let before = network.tokens.len();
    network.tokens.retain(|t| t.id != id);
    if network.tokens.len() == before {
        return Err("Token not found on this network".into());
    }
    let tokens = network.tokens.clone();
    save_config(&config)?;
    Ok(tokens)
}

/// Remove stored tokens for a deleted RPC network (by id or url).
pub fn clear_network(network_id: &str, rpc_url: &str) -> Result<(), String> {
    let mut config = load_raw_config()?;
    let url = normalize_rpc_url(rpc_url);
    config.networks.retain(|n| {
        n.network_id != network_id
            && (url.is_empty() || !normalize_rpc_url(&n.rpc_url).eq_ignore_ascii_case(&url))
    });
    save_config(&config)
}
