mod cores;
mod wallet;

use ethers::providers::Middleware;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::U256;
use serde::Serialize;
use wallet::{interact, rpc_store, token_store, wallet_manager};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletResult {
    mnemonic: String,
    address: String,
    shares: Vec<String>,
    folder: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferResult {
    tx_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletsState {
    active_address: Option<String>,
    wallets: Vec<wallet_manager::WalletInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenView {
    id: String,
    address: String,
    name: String,
    symbol: String,
    decimals: u8,
    balance: String,
    balance_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeBalanceView {
    balance: String,
    balance_wei: String,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokensState {
    active_wallet: Option<String>,
    network_id: String,
    network_name: String,
    native: NativeBalanceView,
    tokens: Vec<TokenView>,
}

fn format_token_amount(raw: U256, decimals: u8) -> String {
    let decimals = decimals as usize;
    let s = raw.to_string();
    if decimals == 0 {
        return s;
    }
    let padded = format!("{:0>width$}", s, width = decimals + 1);
    let split = padded.len() - decimals;
    let whole = &padded[..split];
    let frac = padded[split..].trim_end_matches('0');
    if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    }
}

async fn fetch_native_balance(
    active_wallet: Option<&str>,
    rpc_url: &str,
) -> NativeBalanceView {
    match active_wallet {
        None => NativeBalanceView {
            balance: "—".into(),
            balance_wei: "0".into(),
            error: Some("No active wallet".into()),
        },
        Some(wallet) => {
            let provider = interact::get_provider(&rpc_url.to_string());
            match interact::native::get_balance(provider, wallet).await {
                Ok(raw) => NativeBalanceView {
                    balance: format_token_amount(raw, 18),
                    balance_wei: raw.to_string(),
                    error: None,
                },
                Err(e) => NativeBalanceView {
                    balance: "—".into(),
                    balance_wei: "0".into(),
                    error: Some(e.to_string()),
                },
            }
        }
    }
}

async fn build_token_view(
    token: token_store::StoredToken,
    active_wallet: Option<&str>,
    rpc_url: &str,
) -> TokenView {
    let mut balance = "—".to_string();
    let mut balance_error = None;

    match active_wallet {
        None => balance_error = Some("No active wallet".into()),
        Some(wallet) => {
            let provider = interact::get_provider(&rpc_url.to_string());
            match interact::fungible_token::fetch_balance(provider, &token.address, wallet).await {
                Ok(raw) => balance = format_token_amount(raw, token.decimals),
                Err(e) => balance_error = Some(e.to_string()),
            }
        }
    }

    TokenView {
        id: token.id,
        address: token.address,
        name: token.name,
        symbol: token.symbol,
        decimals: token.decimals,
        balance,
        balance_error,
    }
}

async fn tokens_state() -> Result<TokensState, String> {
    let active_wallet = wallet_manager::get_active_address().map_err(|e| e.to_string())?;
    let endpoint = rpc_store::active_endpoint()?;
    let native = fetch_native_balance(active_wallet.as_deref(), &endpoint.url).await;
    let stored = token_store::list_tokens(&endpoint.id, &endpoint.name, &endpoint.url)?;
    let mut tokens = Vec::new();
    for token in stored {
        tokens.push(build_token_view(token, active_wallet.as_deref(), &endpoint.url).await);
    }
    Ok(TokensState {
        active_wallet,
        network_id: endpoint.id,
        network_name: endpoint.name,
        native,
        tokens,
    })
}

#[tauri::command]
fn create_wallet(shares: u8, threshold: u8) -> Result<WalletResult, String> {
    let (mnemonic, share_strings, address) =
        wallet_manager::create_and_split_mnemonic(shares, threshold, None)
            .map_err(|e| e.to_string())?;
    Ok(WalletResult {
        folder: format!("key_share/{}", address),
        mnemonic,
        address,
        shares: share_strings,
    })
}

#[tauri::command]
fn import_wallet(mnemonic: String, shares: u8, threshold: u8) -> Result<WalletResult, String> {
    let (mnemonic, share_strings, address) =
        wallet_manager::import_and_split_mnemonic(&mnemonic, shares, threshold)
            .map_err(|e| e.to_string())?;
    Ok(WalletResult {
        folder: format!("key_share/{}", address),
        mnemonic,
        address,
        shares: share_strings,
    })
}

#[tauri::command]
fn reshare_wallet(shares: u8, threshold: u8) -> Result<WalletResult, String> {
    let (mnemonic, share_strings, address) =
        wallet_manager::reshare_mnemonic(shares, threshold, true).map_err(|e| e.to_string())?;
    Ok(WalletResult {
        folder: format!("key_share/{}", address),
        mnemonic,
        address,
        shares: share_strings,
    })
}

#[tauri::command]
fn list_wallets() -> Result<WalletsState, String> {
    let wallets = wallet_manager::list_wallets().map_err(|e| e.to_string())?;
    let active_address = wallet_manager::get_active_address().map_err(|e| e.to_string())?;
    Ok(WalletsState {
        active_address,
        wallets,
    })
}

#[tauri::command]
fn set_active_wallet(address: String) -> Result<WalletsState, String> {
    wallet_manager::set_active_wallet(address).map_err(|e| e.to_string())?;
    list_wallets()
}

#[tauri::command]
fn list_rpcs() -> Result<rpc_store::RpcConfig, String> {
    rpc_store::list_endpoints()
}

#[tauri::command]
fn set_active_rpc(id: String) -> Result<rpc_store::RpcConfig, String> {
    rpc_store::set_active(id)
}

#[tauri::command]
fn add_rpc(name: String, url: String) -> Result<rpc_store::RpcConfig, String> {
    rpc_store::add_endpoint(name, url)
}

#[tauri::command]
fn remove_rpc(id: String) -> Result<rpc_store::RpcConfig, String> {
    let config = rpc_store::list_endpoints()?;
    let url = config
        .endpoints
        .iter()
        .find(|e| e.id == id)
        .map(|e| e.url.clone())
        .unwrap_or_default();
    token_store::clear_network(&id, &url)?;
    rpc_store::remove_endpoint(id)
}

#[tauri::command]
fn get_rpc_url() -> Result<String, String> {
    rpc_store::active_url()
}

#[tauri::command]
async fn list_tokens() -> Result<TokensState, String> {
    tokens_state().await
}

#[tauri::command]
async fn get_native_balance() -> Result<NativeBalanceView, String> {
    let active_wallet = wallet_manager::get_active_address().map_err(|e| e.to_string())?;
    let rpc_url = rpc_store::active_url()?;
    Ok(fetch_native_balance(active_wallet.as_deref(), &rpc_url).await)
}

#[tauri::command]
async fn import_token(address: String) -> Result<TokensState, String> {
    validate_address(&address)?;
    let endpoint = rpc_store::active_endpoint()?;
    let provider = interact::get_provider(&endpoint.url);
    let (name, symbol, decimals) = interact::fungible_token::fetch_metadata(provider, &address)
        .await
        .map_err(|e| format!("Failed to read token metadata: {e}"))?;
    token_store::add_token(
        &endpoint.id,
        &endpoint.name,
        &endpoint.url,
        address,
        name,
        symbol,
        decimals,
    )?;
    tokens_state().await
}

#[tauri::command]
async fn remove_token(id: String) -> Result<TokensState, String> {
    let endpoint = rpc_store::active_endpoint()?;
    token_store::remove_token(&endpoint.id, &endpoint.name, &endpoint.url, id)?;
    tokens_state().await
}

#[tauri::command]
async fn transfer_tokens(
    contract_address: String,
    to_address: String,
    amount: u64,
) -> Result<TransferResult, String> {
    validate_address(&to_address)?;
    let rpc_url = rpc_store::active_url()?;
    let provider = interact::get_provider(&rpc_url);

    let mnemonic = wallet_manager::load_and_reconstruct_mnemonic().map_err(|e| e.to_string())?;
    let private_key =
        wallet_manager::get_private_key_from_mnemonic(&mnemonic).map_err(|e| e.to_string())?;
    let chain_id = provider
        .get_chainid()
        .await
        .map_err(|e| format!("Failed to get chain id: {e}"))?;
    let wallet: LocalWallet = private_key
        .parse::<LocalWallet>()
        .map_err(|e| format!("Invalid private key: {e}"))?
        .with_chain_id(chain_id.as_u64());

    let receipt = interact::fungible_token::transfer(
        provider,
        &contract_address,
        wallet,
        &to_address,
        amount.into(),
    )
    .await
    .map_err(|e| e.to_string())?;

    Ok(TransferResult {
        tx_hash: format!("0x{:x}", receipt.transaction_hash),
    })
}

#[tauri::command]
async fn transfer_native(to_address: String, amount: String) -> Result<TransferResult, String> {
    validate_address(&to_address)?;
    let value = ethers::utils::parse_ether(amount.trim())
        .map_err(|e| format!("Invalid amount: {e}"))?;
    if value.is_zero() {
        return Err("Amount must be greater than 0".into());
    }

    let rpc_url = rpc_store::active_url()?;
    let provider = interact::get_provider(&rpc_url);

    let mnemonic = wallet_manager::load_and_reconstruct_mnemonic().map_err(|e| e.to_string())?;
    let private_key =
        wallet_manager::get_private_key_from_mnemonic(&mnemonic).map_err(|e| e.to_string())?;
    let chain_id = provider
        .get_chainid()
        .await
        .map_err(|e| format!("Failed to get chain id: {e}"))?;
    let wallet: LocalWallet = private_key
        .parse::<LocalWallet>()
        .map_err(|e| format!("Invalid private key: {e}"))?
        .with_chain_id(chain_id.as_u64());

    let receipt = interact::native::transfer_native(provider, wallet, &to_address, value)
        .await
        .map_err(|e| e.to_string())?;

    Ok(TransferResult {
        tx_hash: format!("0x{:x}", receipt.transaction_hash),
    })
}

fn validate_address(address: &str) -> Result<(), String> {
    if address.len() != 42 || !address.starts_with("0x") {
        return Err(
            "Invalid Ethereum address! Must be 42 characters starting with 0x.".into(),
        );
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            use tauri::Manager;
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;
            wallet::paths::init(data_dir)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_wallet,
            import_wallet,
            reshare_wallet,
            list_wallets,
            set_active_wallet,
            list_rpcs,
            add_rpc,
            set_active_rpc,
            remove_rpc,
            get_rpc_url,
            list_tokens,
            get_native_balance,
            import_token,
            remove_token,
            transfer_tokens,
            transfer_native,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
