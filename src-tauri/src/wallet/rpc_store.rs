use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const CONFIG_PATH: &str = "../rpc_config.json";
const LEGACY_RPC_PATHS: &[&str] = &["src/wallet/RPC", "wallet/RPC"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcEndpoint {
    pub id: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcConfig {
    pub active_id: String,
    pub endpoints: Vec<RpcEndpoint>,
}

fn config_path() -> PathBuf {
    PathBuf::from(CONFIG_PATH)
}

fn default_config() -> RpcConfig {
    let id = Uuid::new_v4().to_string();
    let url = read_legacy_rpc_url()
        .unwrap_or_else(|| "https://rpc-testnet.viction.xyz".to_string());
    RpcConfig {
        active_id: id.clone(),
        endpoints: vec![RpcEndpoint {
            id,
            name: "Viction Testnet".to_string(),
            url,
        }],
    }
}

fn read_legacy_rpc_url() -> Option<String> {
    for path in LEGACY_RPC_PATHS {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if let Some(url) = line.strip_prefix("RPC_URL=") {
                    let url = url.trim();
                    if !url.is_empty() {
                        return Some(url.to_string());
                    }
                }
            }
        }
    }
    None
}

fn save_config(config: &RpcConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
        }
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize RPC config: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

pub fn load_config() -> Result<RpcConfig, String> {
    let path = config_path();
    if !Path::new(&path).exists() {
        let config = default_config();
        save_config(&config)?;
        return Ok(config);
    }

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let mut config: RpcConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;

    if config.endpoints.is_empty() {
        config = default_config();
        save_config(&config)?;
        return Ok(config);
    }

    if !config.endpoints.iter().any(|e| e.id == config.active_id) {
        config.active_id = config.endpoints[0].id.clone();
        save_config(&config)?;
    }

    Ok(config)
}

pub fn list_endpoints() -> Result<RpcConfig, String> {
    load_config()
}

pub fn add_endpoint(name: String, url: String) -> Result<RpcConfig, String> {
    let name = name.trim().to_string();
    let url = url.trim().to_string();
    if name.is_empty() {
        return Err("Name is required".into());
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("URL must start with http:// or https://".into());
    }

    let mut config = load_config()?;
    if config
        .endpoints
        .iter()
        .any(|e| e.url.eq_ignore_ascii_case(&url))
    {
        return Err("An endpoint with this URL already exists".into());
    }

    let endpoint = RpcEndpoint {
        id: Uuid::new_v4().to_string(),
        name,
        url,
    };
    config.active_id = endpoint.id.clone();
    config.endpoints.push(endpoint);
    save_config(&config)?;
    Ok(config)
}

pub fn set_active(id: String) -> Result<RpcConfig, String> {
    let mut config = load_config()?;
    if !config.endpoints.iter().any(|e| e.id == id) {
        return Err("RPC endpoint not found".into());
    }
    config.active_id = id;
    save_config(&config)?;
    Ok(config)
}

pub fn remove_endpoint(id: String) -> Result<RpcConfig, String> {
    let mut config = load_config()?;
    if config.endpoints.len() <= 1 {
        return Err("Keep at least one RPC endpoint".into());
    }
    let before = config.endpoints.len();
    config.endpoints.retain(|e| e.id != id);
    if config.endpoints.len() == before {
        return Err("RPC endpoint not found".into());
    }
    if config.active_id == id {
        config.active_id = config.endpoints[0].id.clone();
    }
    save_config(&config)?;
    Ok(config)
}

pub fn active_url() -> Result<String, String> {
    let config = load_config()?;
    config
        .endpoints
        .iter()
        .find(|e| e.id == config.active_id)
        .map(|e| e.url.clone())
        .ok_or_else(|| "Active RPC endpoint not found".into())
}

pub fn active_id() -> Result<String, String> {
    Ok(load_config()?.active_id)
}

pub fn active_endpoint() -> Result<RpcEndpoint, String> {
    let config = load_config()?;
    config
        .endpoints
        .into_iter()
        .find(|e| e.id == config.active_id)
        .ok_or_else(|| "Active RPC endpoint not found".into())
}
