pub mod cores;
pub mod wallet;
pub mod ui;
pub use wallet::*;
fn main() {
    ui::main_wallet_ui();
}