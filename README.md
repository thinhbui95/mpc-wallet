# mpc-wallet

MPC wallet for BIP-39 mnemonic management and Ethereum operations. Shares are split with Shamir secret sharing. The UI is built with **Tauri** (desktop + iOS).

## Features

- Create and split BIP-39 mnemonics into shares
- Reshare existing wallets
- Generate Ethereum addresses from mnemonics
- Transfer ERC-20 tokens and native currency on EVM chains

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js](https://nodejs.org/) (18+)
- **Desktop (macOS):** Xcode Command Line Tools (`xcode-select --install`)
- **iOS:** macOS + full [Xcode](https://developer.apple.com/xcode/) from the App Store, plus CocoaPods (`sudo gem install cocoapods`)

### Install & run (desktop)

```sh
npm install
npm run tauri dev
```

## Build desktop app

Produces a native macOS app (`.app`) and installer (`.dmg`) for your machine’s architecture:

```sh
npm install
npm run tauri build
```

Artifacts are under `src-tauri/target/release/bundle/`:

- `macos/MPC Wallet.app` — run directly
- `dmg/MPC Wallet_*.dmg` — drag-to-Applications installer

Optional:

```sh
# App bundle only (no DMG)
npm run tauri build -- --bundles app

# Universal binary (Apple Silicon + Intel)
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run tauri build -- --target universal-apple-darwin
```

## Build iOS app

iOS builds require a **Mac with Xcode**. Initialize the iOS project once, then develop or package:

```sh
npm install

# One-time: create the Xcode / Apple project under src-tauri/gen/apple
npm run tauri ios init

# Run on simulator or a connected device (dev)
npm run tauri ios dev

# Release build / IPA
npm run tauri ios build
```

Open the generated Xcode project (archive, signing, App Store):

```sh
npm run tauri ios build -- --open
```

App Store Connect export (needs Apple Developer signing set up):

```sh
npm run tauri ios build -- --export-method app-store-connect
```

See Tauri’s [iOS](https://v2.tauri.app/develop/ios/) and [App Store](https://v2.tauri.app/distribute/app-store/) docs for signing and distribution.

## App structure

- `src/` — Vite frontend (Create / Reshare / Networks / Tokens / Interact)
- `src-tauri/` — Rust backend (wallet logic + Tauri commands)
- App data (RPC, tokens, key shares) is stored in the OS app data directory  
  (on macOS: `~/Library/Application Support/com.mpcwallet.app/`)
- `src-tauri/src/wallet/RPC` — legacy seed used only if no config file exists yet
