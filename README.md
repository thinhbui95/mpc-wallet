# mpc-wallet

MPC wallet for BIP-39 mnemonic management and Ethereum operations. Shares are split with Shamir secret sharing. The desktop UI is built with **Tauri**.

## Features

- Create and split BIP-39 mnemonics into shares
- Reshare existing wallets
- Generate Ethereum addresses from mnemonics
- Transfer ERC-20 tokens and native currency on EVM chains

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js](https://nodejs.org/) (18+)
- On macOS: Xcode CLT

### Install & run

```sh
npm install
npm run tauri dev
```

### Build

```sh
npm run tauri build
```

## App structure

- `src/` — Vite frontend (Create / Reshare / Networks / Interact)
- `src-tauri/` — Rust backend (wallet logic + Tauri commands)
- `key_share/` — share files written at the repo root
- `rpc_config.json` — saved RPC endpoints + active selection (created on first run)
- `tokens_config.json` — imported tokens grouped by network (`networkId`, `networkName`, `rpcUrl`)
- `src-tauri/src/wallet/RPC` — legacy seed used only if no config file exists yet

