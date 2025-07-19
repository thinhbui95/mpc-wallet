pub mod cores;
pub mod wallet;
pub mod ui;
pub use wallet::*;
pub use ui::*;



fn main() {
    ui::main_wallet_ui();
}

