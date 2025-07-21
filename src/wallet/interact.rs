use ethers::prelude::*;
use ethers::{
    providers::{Provider, Http},
    signers::LocalWallet,
};
use std::sync::Arc;

pub fn get_provider(rpc_url: &String) -> Arc<Provider<Http>> {
    let provider = Provider::<Http>::try_from(rpc_url.as_str()).unwrap();
    let provider = Arc::new(provider);
    provider
}

pub mod fungible_token {
    use super::*;
    // Generate Rust bindings for your contract
    abigen!(
        MyToken,
        "./src/wallet/abi.json"
    );
    #[allow(dead_code)]
    pub fn get_contract(contract_address: &String, provider: Arc<Provider<Http>>) -> MyToken<Provider<Http>> {
        let contract_address: Address = contract_address.parse().unwrap();
        let contract = MyToken::new(contract_address, provider);
        contract
    }

    #[allow(dead_code)]
    pub async fn get_balance(contract: MyToken<Provider<Http>>, address: &String) -> Result<U256, Box<dyn std::error::Error>> {
        let address: Address = address.parse().unwrap();
        let balance = contract.balance_of(address).call().await?;
        Ok(balance)
    }

    #[allow(dead_code)]
    pub async fn get_total_supply(contract: MyToken<Provider<Http>>) -> Result<U256, Box<dyn std::error::Error>> {
        let total_supply = contract.total_supply().call().await?;
        Ok(total_supply)
    }

    #[allow(dead_code)]
    pub async fn get_name(contract: MyToken<Provider<Http>>) -> Result<String, Box<dyn std::error::Error>> {
        let name = contract.name().call().await?;
        Ok(name)
    }

    #[allow(dead_code)]
    pub async fn get_symbol(contract: MyToken<Provider<Http>>) -> Result<String, Box<dyn std::error::Error>> {
        let symbol = contract.symbol().call().await?;
        Ok(symbol)
    }

    #[allow(dead_code)]
    pub async fn get_decimals(contract: MyToken<Provider<Http>>) -> Result<u8, Box<dyn std::error::Error>> {
        let decimals = contract.decimals().call().await?;
        Ok(decimals)
    }

    pub async fn transfer(
        provider: Arc<Provider<Http>>,
        contract_address: &str,
        wallet: LocalWallet,
        to: &str,
        amount: U256,
    ) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
        let to_address: Address = to.parse()?;
        let contract_address: Address = contract_address.parse()?;

        // connect the wallet to the provider
        let client = SignerMiddleware::new(provider, wallet);
        let contract_instance = MyToken::new(contract_address, Arc::new(client));
        let call = contract_instance
            .transfer(to_address, amount)
            .gas(4000000) // Set your desired gas limit here
            .legacy(); // Use legacy transaction to avoid EIP-1559 error
        let pending_tx = call.send().await?;
        let receipt = pending_tx.await?.ok_or("Transaction failed")?;
    
        Ok(receipt)
    }
}

pub mod native {
    use super::*;
    pub async fn transfer_native(
        provider: Arc<Provider<Http>>,
        wallet: LocalWallet,
        to: &str,
        amount: U256,
    ) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
        let to_address: Address = to.parse()?;
        
        // connect the wallet to the provider
        let client = SignerMiddleware::new(provider, wallet);
        
        // Create a transaction request
        let tx = TransactionRequest::new()
            .to(to_address)
            .value(amount);
        
        // Send the transaction
        let pending_tx = client.send_transaction(tx, None).await?;
        
        // get the mined tx
        let receipt = pending_tx.await?.ok_or_else(|| eyre::format_err!("tx dropped from mempool"))?;
        let _ = client.get_transaction(receipt.transaction_hash).await?;
        
        Ok(receipt)
    }
}





