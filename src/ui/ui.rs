/// src/ui/ui.rs
use crate::wallet::*;
use cursive::views::{Dialog, EditView, LinearLayout, TextView};
use cursive::view::{Nameable, Resizable};
use std::fs;
use ethers::signers::LocalWallet;
use clipboard::ClipboardProvider;
use ethers::providers::Middleware;
use ethers::signers::Signer;


fn create_wallet_ui() {
    let mut siv = cursive::default(); // Creates the Cursive root

    // Create a vertical layout for the form
    let form = LinearLayout::vertical()
        .child(TextView::new("Create Wallet"))
        .child(TextView::new("Enter number of shares:"))
        .child(EditView::new().with_name("shares").fixed_width(10))
        .child(TextView::new("Enter threshold:"))
        .child(EditView::new().with_name("threshold").fixed_width(10));

    // Create a dialog with the form and buttons
    siv.add_layer(
        Dialog::around(form)
            .title("Create Wallet")
            .button("Create", |s| {
                // Retrieve values from the form
                let shares = s
                    .call_on_name("shares", |view: &mut EditView| view.get_content())
                    .unwrap();
                let threshold = s
                    .call_on_name("threshold", |view: &mut EditView| view.get_content())
                    .unwrap();

                // Convert shares and threshold to u8
                let shares: u8 = match shares.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        s.add_layer(Dialog::info("Invalid number of shares!"));
                        return;
                    }
                };
                let threshold: u8 = match threshold.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        s.add_layer(Dialog::info("Invalid threshold!"));
                        return;
                    }
                };

                // Call the create_and_split_mnemonic function
                // Assuming mnemonic needs to be handled as a string, adjust as needed
                match wallet_manager::create_and_split_mnemonic(shares, threshold, None) {
                    Ok((mnemonic, _share_strings)) => {
                        let address = wallet_manager::get_ethereum_address(&mnemonic).unwrap_or_default();
                        let address_str = address.to_string();
                        let mnemonic_clone = mnemonic.clone();

                        s.add_layer(
                            Dialog::info(format!("Wallet created successfully!\nAddress: {}", address_str))
                                .button("Copy Address", move |s| {
                                    if let Err(e) = clipboard::ClipboardProvider::new()
                                        .and_then(|mut c: clipboard::ClipboardContext| c.set_contents(address_str.clone())) {
                                        s.add_layer(Dialog::info(format!("Failed to copy address: {}", e)));
                                    } else {
                                        s.add_layer(Dialog::info("Address copied to clipboard!"));
                                    }
                                })
                                .button("Show Mnemonic", move |s| {
                                    let mnemonic_for_copy = mnemonic_clone.clone();
                                    s.add_layer(
                                        Dialog::info(mnemonic_clone.clone())
                                            .button("Copy Mnemonic", move |s| {
                                                if let Err(e) = clipboard::ClipboardProvider::new()
                                                    .and_then(|mut c: clipboard::ClipboardContext| c.set_contents(mnemonic_for_copy.clone())) {
                                                    s.add_layer(Dialog::info(format!("Failed to copy mnemonic: {}", e)));
                                                } else {
                                                    s.add_layer(Dialog::info("Mnemonic copied to clipboard!"));
                                                }
                                            })
                                            .button("OK", |s| { s.pop_layer(); })
                                    );
                                })
                                .button("OK", |s| s.quit())
                        );
                    }
                    Err(e) => {
                        s.add_layer(
                            Dialog::info(format!("Error creating wallet: {}", e))
                                .button("OK", |s| { s.pop_layer(); }),
                        );
                    }
                }
            })
            .button("Back to Menu", |s| {
                        s.pop_layer();
                        show_main_menu(s);
            })
    );

    // Start the Cursive event loop
    siv.run();
}

fn reshare_wallet_ui() {
    let mut siv = cursive::default(); // Creates the Cursive root

    // Create a vertical layout for the form
    let form = LinearLayout::vertical()
        .child(TextView::new("Reshare"))
        .child(TextView::new("Enter shares (comma separated):"))
        .child(EditView::new().with_name("shares").fixed_width(50))
        .child(TextView::new("Enter threshold:"))
        .child(EditView::new().with_name("threshold").fixed_width(10));

    // Create a dialog with the form and buttons
    siv.add_layer(
        Dialog::around(form)
            .title("Reshare Wallet")
            .button("Reshare", |s| {
                // Retrieve values from the form
                let shares = s
                    .call_on_name("shares", |view: &mut EditView| view.get_content())
                    .unwrap();

                // Convert shares and threshold to u8
                let shares: u8 = match shares.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        s.add_layer(Dialog::info("Invalid number of shares!"));
                        return;
                    }
                };
                let threshold = s
                    .call_on_name("threshold", |view: &mut EditView| view.get_content())
                    .unwrap();

                let threshold: u8 = match threshold.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        s.add_layer(Dialog::info("Invalid threshold!"));
                        return;
                    }
                };

                // Call the load_and_reconstruct_mnemonic function
                match wallet_manager::reshare_mnemonic(shares, threshold, true) {
                    Ok((mnemonic, share_strings)) => {
                        let shares_display = share_strings.join("\n");
                        let message = format!(
                            "Reshare mnemonic: {}\nShares:\n{}",
                            mnemonic, shares_display
                        );
                        s.add_layer(
                            Dialog::info(message)
                                .button("OK", |s| s.quit()),
                        );
                    }
                    Err(e) => {
                        s.add_layer(
                            Dialog::info(format!("Error reconstructing wallet: {}", e))
                                .button("OK", |s| { s.pop_layer(); }),
                        );
                    }
                }
            })
            .button("Back to Menu", |s| {
                        s.pop_layer();
                        show_main_menu(s);
            })
    );

    // Start the Cursive event loop
    siv.run();
}

fn interact_ui() {
    let content = fs::read_to_string("src/wallet/RPC").unwrap();
    for line in content.lines() {
        if let Some(url) = line.strip_prefix("RPC_URL=") {
            let url = url.trim().to_string();
            let mut siv = cursive::default();
            let provider = interact::get_provider(&url);

            let form = LinearLayout::vertical()
                .child(TextView::new("Interact"))
                .child(TextView::new("RPC URL:"))
                .child(TextView::new(url.clone()))
                .child(TextView::new("Contract Address:"))
                .child(EditView::new().with_name("contract_address").fixed_width(42))
                .child(TextView::new("Recipient Address:"))
                .child(EditView::new().with_name("address").fixed_width(42))
                .child(TextView::new("Amount:"))
                .child(EditView::new().with_name("amount").fixed_width(20));

            siv.add_layer(
                Dialog::around(form)
                    .title("Token Interaction")
                    .button("Transfer Tokens", {
                        let provider = provider.clone();
                        move |s| {
                            let cb_sink = s.cb_sink().clone();
                            let contract_address = s.call_on_name("contract_address", |view: &mut EditView| view.get_content()).unwrap().to_string();
                            let address = s.call_on_name("address", |view: &mut EditView| view.get_content()).unwrap().to_string();
                            let amount = s.call_on_name("amount", |view: &mut EditView| view.get_content()).unwrap().to_string();
                            let provider = provider.clone();

                            std::thread::spawn(move || {
                                let fut = async move {
                                    let amount: u64 = match amount.parse() {
                                        Ok(n) => n,
                                        Err(_) => {
                                            cb_sink.send(Box::new(|siv| {
                                                siv.add_layer(Dialog::info("Invalid amount! Must be a number."));
                                            })).unwrap();
                                            return;
                                        }
                                    };
                                    if address.len() != 42 || !address.starts_with("0x") {
                                        cb_sink.send(Box::new(|siv| {
                                            siv.add_layer(Dialog::info("Invalid Ethereum address! Must be 42 characters starting with 0x."));
                                        })).unwrap();
                                        return;
                                    }
                                    let mnemonic = match wallet_manager::load_and_reconstruct_mnemonic() {
                                        Ok(w) => w,
                                        Err(e) => {
                                            cb_sink.send(Box::new(move |siv| {
                                                siv.add_layer(Dialog::info(format!("Error loading wallet: {}", e)));
                                            })).unwrap();
                                            return;
                                        }
                                    };
                                    let private_key = match wallet_manager::get_private_key_from_mnemonic(&mnemonic) {
                                        Ok(pk) => pk,
                                        Err(e) => {
                                            cb_sink.send(Box::new(move |siv| {
                                                siv.add_layer(Dialog::info(format!("Failed to convert mnemonic to private key: {}", e)));
                                            })).unwrap();
                                            return;
                                        }
                                    };
                                    let chain_id  = provider.get_chainid().await.unwrap();
                                    let wallet: LocalWallet = private_key
                                            .parse::<LocalWallet>().unwrap()
                                            .with_chain_id(chain_id.as_u64());

                                    match interact::fungible_token::transfer(provider, &contract_address, wallet, &address, amount.into()).await {
                                        Ok(receipt) => {
                                            let tx_hash = receipt.transaction_hash;
                                            let msg = format!(
                                                "Tokens transferred successfully!\nTx Hash: 0x{:x}",
                                                tx_hash
                                            );
                                            let tx_hash_str = format!("0x{:x}", tx_hash);
                                            cb_sink.send(Box::new(move |siv| {
                                                siv.add_layer(
                                                    Dialog::info(msg)
                                                        .button("Copy Tx Hash", {
                                                            let tx_hash_str = tx_hash_str.clone();
                                                            move |s| {
                                                                if let Err(e) = clipboard::ClipboardProvider::new()
                                                                    .and_then(|mut c: clipboard::ClipboardContext| c.set_contents(tx_hash_str.clone())) {
                                                                    s.add_layer(Dialog::info(format!("Failed to copy tx hash: {}", e)));
                                                                } else {
                                                                    s.add_layer(Dialog::info("Tx hash copied to clipboard!"));
                                                                }
                                                            }
                                                        })
                                                        .button("OK", |s| { s.pop_layer(); })
                                                );
                                            })).unwrap();
                                        }
                                        Err(e) => {
                                            let err_msg = format!("Error transferring tokens: {}", e);
                                            cb_sink.send(Box::new(move |siv| {
                                                siv.add_layer(Dialog::info(err_msg).button("OK", |s| { s.pop_layer(); }));
                                            })).unwrap();
                                        }
                                    }
                                };
                                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                                runtime.block_on(fut);
                            });
                        }
                    })
                    .button("Transfer Native", {
                        let provider = provider.clone();
                        move |s| {
                            let cb_sink = s.cb_sink().clone();
                            let address = s.call_on_name("address", |view: &mut EditView| view.get_content()).unwrap().to_string();
                            let amount = s.call_on_name("amount", |view: &mut EditView| view.get_content()).unwrap().to_string();
                            let provider = provider.clone();

                            std::thread::spawn(move || {
                                let fut = async move {
                                    let amount: u64 = match amount.parse() {
                                        Ok(n) => n,
                                        Err(_) => {
                                            cb_sink.send(Box::new(|siv| {
                                                siv.add_layer(Dialog::info("Invalid amount! Must be a number."));
                                            })).unwrap();
                                            return;
                                        }
                                    };
                                    if address.len() != 42 || !address.starts_with("0x") {
                                        cb_sink.send(Box::new(|siv| {
                                            siv.add_layer(Dialog::info("Invalid Ethereum address! Must be 42 characters starting with 0x."));
                                        })).unwrap();
                                        return;
                                    }
                                    let mnemonic = match wallet_manager::load_and_reconstruct_mnemonic() {
                                        Ok(w) => w,
                                        Err(e) => {
                                            cb_sink.send(Box::new(move |siv| {
                                                siv.add_layer(Dialog::info(format!("Error loading wallet: {}", e)));
                                            })).unwrap();
                                            return;
                                        }
                                    };
                                    let private_key = match wallet_manager::get_private_key_from_mnemonic(&mnemonic) {
                                        Ok(pk) => pk,
                                        Err(e) => {
                                            cb_sink.send(Box::new(move |siv| {
                                                siv.add_layer(Dialog::info(format!("Failed to convert mnemonic to private key: {}", e)));
                                            })).unwrap();
                                            return;
                                        }
                                    };
                                    let chain_id  = provider.get_chainid().await.unwrap();
                                    let wallet: LocalWallet = private_key
                                            .parse::<LocalWallet>().unwrap()
                                            .with_chain_id(chain_id.as_u64());
                                            match interact::native::transfer_native(provider, wallet, &address, amount.into()).await {
                                                Ok(receipt) => {
                                                    let tx_hash = receipt.transaction_hash;
                                                    let msg = format!(
                                                        "Native currency transferred successfully!\nTx Hash: 0x{:x}",
                                                        tx_hash
                                                    );
                                                    let tx_hash_str = format!("0x{:x}", tx_hash);
                                                    cb_sink.send(Box::new(move |siv| {
                                                        siv.add_layer(
                                                            Dialog::info(msg)
                                                                .button("Copy Tx Hash", {
                                                                    let tx_hash_str = tx_hash_str.clone();
                                                                    move |s| {
                                                                        if let Err(e) = clipboard::ClipboardProvider::new()
                                                                            .and_then(|mut c: clipboard::ClipboardContext| c.set_contents(tx_hash_str.clone())) {
                                                                            s.add_layer(Dialog::info(format!("Failed to copy tx hash: {}", e)));
                                                                        } else {
                                                                            s.add_layer(Dialog::info("Tx hash copied to clipboard!"));
                                                                        }
                                                                    }
                                                                })
                                                                .button("OK", |s| { s.pop_layer(); })
                                                        );
                                                    })).unwrap();
                                                }
                                                Err(e) => {
                                                    let err_msg = format!("Error transferring native currency: {}", e);
                                                    cb_sink.send(Box::new(move |siv| {
                                                        siv.add_layer(Dialog::info(err_msg).button("OK", |s| { s.pop_layer(); }));
                                                    })).unwrap();
                                                }
                                            }
                                };
                                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                                runtime.block_on(fut);
                            });
                        }
                    })
                    .button("Back to Menu", |s| {
                        s.pop_layer();
                        show_main_menu(s);
                    })
            );
            // Start the Cursive event loop
            siv.run();
        }
    }
}

pub fn main_wallet_ui() {
    let mut siv = cursive::default();
    show_main_menu(&mut siv);
    siv.run();
}

fn show_main_menu(siv: &mut cursive::Cursive) {
    siv.add_layer(
        Dialog::text("Welcome to MPC Wallet!\n\nSelect an action:")
            .title("MPC Wallet Main Menu")
            .button("Create Wallet", |_s| {
                // Close the menu and open the create wallet UI
                cursive::Cursive::quit(_s);
                create_wallet_ui();
            })
            .button("Reshare Wallet", |_s| {
                cursive::Cursive::quit(_s);
                reshare_wallet_ui();
            })
            .button("Interact with Blockchain", |_s| {
                cursive::Cursive::quit(_s);
                interact_ui();
            })
            .button("Quit", |s| s.quit())
    );
}
