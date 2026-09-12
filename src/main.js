import { invoke as tauriInvoke } from "@tauri-apps/api/core";

const statusEl = document.getElementById("status");
const rpcEl = document.getElementById("rpc-url");
const rpcCardsEl = document.getElementById("rpc-cards");
const walletCardsEl = document.getElementById("wallet-cards");
const tokenCardsEl = document.getElementById("token-cards");
const activeWalletLabel = document.getElementById("active-wallet-label");
const reshareActiveEl = document.getElementById("reshare-active");
const interactWalletEl = document.getElementById("interact-wallet");
const tokensWalletEl = document.getElementById("tokens-wallet");
const tokensNetworkEl = document.getElementById("tokens-network");

let rpcConfig = null;
let walletsState = null;
let tokensState = null;

const interactTokenEl = document.getElementById("interact-token");
const interactTokenHintEl = document.getElementById("interact-token-hint");
const transferTokenBtn = document.getElementById("transfer-token-btn");
const amountHintEl = document.getElementById("amount-hint");

function isTauriRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function invoke(cmd, args) {
  if (!isTauriRuntime()) {
    throw new Error(
      "Open the MPC Wallet desktop window from `npm run tauri dev` — not http://localhost:1420 in a browser.",
    );
  }
  return tauriInvoke(cmd, args);
}

function setStatus(message, isError = false) {
  statusEl.textContent = message || "";
  statusEl.style.color = isError ? "var(--warn)" : "var(--muted)";
}

function showView(name) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === `view-${name}`);
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.view === name);
  });
  setStatus("");
  if (name === "networks" || name === "interact") {
    refreshRpcs().catch((error) => setStatus(String(error), true));
  }
  if (name === "wallets" || name === "menu" || name === "reshare" || name === "interact" || name === "tokens") {
    refreshWallets().catch((error) => setStatus(String(error), true));
  }
  if (name === "tokens" || name === "interact") {
    refreshTokens().catch((error) => setStatus(String(error), true));
  }
  if (name === "menu" || name === "interact") {
    refreshNativeBalance().catch((error) => setStatus(String(error), true));
  }
}

function activeEndpoint(config = rpcConfig) {
  if (!config) return null;
  return config.endpoints.find((endpoint) => endpoint.id === config.activeId) || null;
}

function formatWalletResult(result, title) {
  return [
    title,
    `Address: ${result.address}`,
    `Folder: ${result.folder}`,
    "",
    "Mnemonic:",
    result.mnemonic,
    "",
    "Shares:",
    ...result.shares.map((share, i) => `${i + 1}. ${share}`),
  ].join("\n");
}

function renderWallets(state) {
  walletsState = state;
  const active = state.activeAddress || "none";
  activeWalletLabel.textContent = active;
  reshareActiveEl.textContent = active;
  interactWalletEl.textContent = active;

  walletCardsEl.innerHTML = "";
  if (!state.wallets.length) {
    walletCardsEl.innerHTML = `<p class="lead">No wallets yet. Create or import one.</p>`;
    return;
  }

  for (const wallet of state.wallets) {
    const isActive = wallet.address === state.activeAddress;
    const card = document.createElement("article");
    card.className = `rpc-card${isActive ? " active" : ""}`;
    card.innerHTML = `
      ${isActive ? `<span class="badge">Active</span>` : ""}
      <h3></h3>
      <div class="url"></div>
      <div class="row">
        <button type="button" class="primary" data-action="use"></button>
      </div>
    `;
    card.querySelector("h3").textContent = wallet.address;
    card.querySelector(".url").textContent = wallet.path;
    const useBtn = card.querySelector('[data-action="use"]');
    useBtn.textContent = isActive ? "Selected" : "Use";
    useBtn.disabled = isActive;
    useBtn.addEventListener("click", async () => {
      setStatus("Switching wallet…");
      try {
        const next = await invoke("set_active_wallet", { address: wallet.address });
        renderWallets(next);
        await refreshNativeBalance();
        setStatus(`Active wallet: ${wallet.address}`);
      } catch (error) {
        setStatus(String(error), true);
      }
    });
    walletCardsEl.appendChild(card);
  }
}

async function refreshWallets() {
  const state = await invoke("list_wallets");
  renderWallets(state);
  return state;
}

function renderRpcCards(config) {
  rpcConfig = config;
  const active = activeEndpoint(config);
  rpcEl.textContent = active ? `${active.name} · ${active.url}` : "none selected";

  rpcCardsEl.innerHTML = "";
  if (!config.endpoints.length) {
    rpcCardsEl.innerHTML = `<p class="lead">No RPC endpoints yet. Add one below.</p>`;
    return;
  }

  for (const endpoint of config.endpoints) {
    const isActive = endpoint.id === config.activeId;
    const card = document.createElement("article");
    card.className = `rpc-card${isActive ? " active" : ""}`;
    card.innerHTML = `
      ${isActive ? `<span class="badge">Active</span>` : ""}
      <h3></h3>
      <div class="url"></div>
      <div class="row">
        <button type="button" class="primary" data-action="use"></button>
        <button type="button" class="danger" data-action="remove">Remove</button>
      </div>
    `;
    card.querySelector("h3").textContent = endpoint.name;
    card.querySelector(".url").textContent = endpoint.url;
    const useBtn = card.querySelector('[data-action="use"]');
    useBtn.textContent = isActive ? "Selected" : "Use";
    useBtn.disabled = isActive;

    useBtn.addEventListener("click", async () => {
      setStatus("Switching RPC…");
      try {
        tokenCardsEl.innerHTML = `<p class="lead">Loading tokens for this network…</p>`;
        const next = await invoke("set_active_rpc", { id: endpoint.id });
        renderRpcCards(next);
        await Promise.all([refreshNativeBalance(), refreshTokens()]);
        setStatus(`Active RPC: ${endpoint.name}`);
      } catch (error) {
        setStatus(String(error), true);
      }
    });

    card.querySelector('[data-action="remove"]').addEventListener("click", async () => {
      setStatus("Removing RPC…");
      try {
        const next = await invoke("remove_rpc", { id: endpoint.id });
        renderRpcCards(next);
        setStatus("RPC removed.");
      } catch (error) {
        setStatus(String(error), true);
      }
    });

    rpcCardsEl.appendChild(card);
  }
}

async function refreshRpcs() {
  const config = await invoke("list_rpcs");
  renderRpcCards(config);
  return config;
}

function renderNativeBalance(native) {
  const nodes = document.querySelectorAll(".native-balance-text");
  nodes.forEach((el) => {
    if (!native) {
      el.textContent = "—";
      el.removeAttribute("title");
      return;
    }
    if (native.error) {
      el.textContent = "unavailable";
      el.title = native.error;
    } else {
      el.textContent = native.balance;
      el.title = `${native.balanceWei} wei`;
    }
  });
}

async function refreshNativeBalance() {
  const native = await invoke("get_native_balance");
  renderNativeBalance(native);
  return native;
}

function selectedInteractToken() {
  const id = interactTokenEl.value;
  if (!id || !tokensState?.tokens) return null;
  return tokensState.tokens.find((token) => token.id === id) || null;
}

function updateInteractTokenHint() {
  const token = selectedInteractToken();
  if (!token) {
    interactTokenHintEl.textContent = "Import tokens on the Tokens tab first.";
    amountHintEl.textContent =
      "Native: enter any amount (e.g. 0.01). Token: pick a token above first.";
    transferTokenBtn.disabled = true;
    return;
  }
  const balance = token.balanceError
    ? "balance unavailable"
    : `${token.balance} ${token.symbol}`;
  interactTokenHintEl.textContent = `${token.address} · ${balance}`;
  amountHintEl.textContent = `Native: any amount (e.g. 0.01). Token (${token.symbol}): whole units for now.`;
  transferTokenBtn.disabled = false;
}

function populateInteractTokens(state) {
  const previous = interactTokenEl.value;
  interactTokenEl.innerHTML = "";

  if (!state.tokens.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No tokens imported on this network";
    interactTokenEl.appendChild(option);
    updateInteractTokenHint();
    return;
  }

  for (const token of state.tokens) {
    const option = document.createElement("option");
    option.value = token.id;
    option.textContent = `${token.symbol} — ${token.name}`;
    interactTokenEl.appendChild(option);
  }

  if (previous && state.tokens.some((token) => token.id === previous)) {
    interactTokenEl.value = previous;
  }
  updateInteractTokenHint();
}

function renderTokens(state) {
  tokensState = state;
  tokensWalletEl.textContent = state.activeWallet || "none";
  tokensNetworkEl.textContent = state.networkName || "none";
  renderNativeBalance(state.native);
  tokenCardsEl.innerHTML = "";
  populateInteractTokens(state);

  if (!state.tokens.length) {
    tokenCardsEl.innerHTML = `<p class="lead">No tokens imported on this network yet.</p>`;
    return;
  }

  for (const token of state.tokens) {
    const card = document.createElement("article");
    card.className = "rpc-card";
    card.innerHTML = `
      <h3></h3>
      <div class="token-meta"></div>
      <div class="url"></div>
      <div class="token-balance"></div>
      <div class="row">
        <button type="button" class="secondary" data-action="refresh">Refresh</button>
        <button type="button" class="danger" data-action="remove">Remove</button>
      </div>
    `;
    card.querySelector("h3").textContent = `${token.name} (${token.symbol})`;
    card.querySelector(".token-meta").textContent = `${token.decimals} decimals`;
    card.querySelector(".url").textContent = token.address;
    const balanceEl = card.querySelector(".token-balance");
    if (token.balanceError) {
      balanceEl.textContent = "Balance unavailable";
      balanceEl.title = token.balanceError;
    } else {
      balanceEl.textContent = `${token.balance} ${token.symbol}`;
    }

    card.querySelector('[data-action="refresh"]').addEventListener("click", async () => {
      setStatus("Refreshing balances…");
      try {
        await refreshTokens();
        setStatus("");
      } catch (error) {
        setStatus(String(error), true);
      }
    });

    card.querySelector('[data-action="remove"]').addEventListener("click", async () => {
      setStatus("Removing token…");
      try {
        const next = await invoke("remove_token", { id: token.id });
        renderTokens(next);
        setStatus("");
      } catch (error) {
        setStatus(String(error), true);
      }
    });

    tokenCardsEl.appendChild(card);
  }
}

async function refreshTokens() {
  setStatus("Loading tokens…");
  const state = await invoke("list_tokens");
  renderTokens(state);
  setStatus("");
  return state;
}

document.getElementById("tabs").addEventListener("click", (event) => {
  const tab = event.target.closest("[data-view]");
  if (!tab) return;
  showView(tab.dataset.view);
});

document.querySelectorAll("[data-goto]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.goto));
});

document.getElementById("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const shares = Number(form.shares.value);
  const threshold = Number(form.threshold.value);
  const resultEl = document.getElementById("create-result");

  setStatus("Creating wallet…");
  resultEl.hidden = true;
  resultEl.textContent = "";

  try {
    await invoke("create_wallet", { shares, threshold });
    resultEl.hidden = true;
    resultEl.textContent = "";
    setStatus("");
    await refreshWallets();
    showView("wallets");
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const mnemonic = form.mnemonic.value.trim();
  const shares = Number(form.shares.value);
  const threshold = Number(form.threshold.value);
  const resultEl = document.getElementById("import-result");

  setStatus("Importing mnemonic…");
  resultEl.hidden = true;

  try {
    const result = await invoke("import_wallet", { mnemonic, shares, threshold });
    resultEl.hidden = false;
    resultEl.textContent = formatWalletResult(result, "Mnemonic imported successfully.");
    form.reset();
    await refreshWallets();
    setStatus(`Stored in ${result.folder}`);
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("reshare-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const shares = Number(form.shares.value);
  const threshold = Number(form.threshold.value);
  const resultEl = document.getElementById("reshare-result");

  setStatus("Resharing…");
  resultEl.hidden = true;

  try {
    const result = await invoke("reshare_wallet", { shares, threshold });
    resultEl.hidden = false;
    resultEl.textContent = formatWalletResult(result, "Reshare complete.");
    setStatus(`Updated ${result.folder}`);
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("add-rpc-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const name = form.name.value.trim();
  const url = form.url.value.trim();

  setStatus("Saving RPC…");
  try {
    const next = await invoke("add_rpc", { name, url });
    form.reset();
    renderRpcCards(next);
    await Promise.all([refreshNativeBalance(), refreshTokens()]);
    setStatus("RPC saved and set active.");
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("import-token-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const address = form.address.value.trim();

  setStatus("Importing token…");
  try {
    const next = await invoke("import_token", { address });
    form.reset();
    renderTokens(next);
    setStatus("");
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("refresh-native-balance").addEventListener("click", async () => {
  setStatus("Checking native balance…");
  try {
    await refreshNativeBalance();
    setStatus("");
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("refresh-native-balance-interact").addEventListener("click", async () => {
  setStatus("Checking native balance…");
  try {
    await refreshNativeBalance();
    setStatus("");
  } catch (error) {
    setStatus(String(error), true);
  }
});

document.getElementById("interact-token").addEventListener("change", () => {
  updateInteractTokenHint();
});

document.getElementById("interact-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const submitter = event.submitter;
  const mode = submitter?.value || "token";
  const to = form.to.value.trim();
  const amountRaw = form.amount.value.trim();
  const resultEl = document.getElementById("interact-result");

  if (!amountRaw || Number(amountRaw) <= 0) {
    setStatus("Enter an amount greater than 0.", true);
    return;
  }

  let contract = "";
  if (mode !== "native") {
    const token = selectedInteractToken();
    if (!token) {
      setStatus("Select a token from the list (or import one on the Tokens tab).", true);
      return;
    }
    contract = token.address;
  }

  setStatus(mode === "native" ? "Sending native transfer…" : "Sending token transfer…");
  resultEl.hidden = true;

  try {
    const result =
      mode === "native"
        ? await invoke("transfer_native", { toAddress: to, amount: amountRaw })
        : await invoke("transfer_tokens", {
            contractAddress: contract,
            toAddress: to,
            amount: Math.trunc(Number(amountRaw)),
          });

    resultEl.hidden = false;
    resultEl.textContent = `Transfer succeeded.\nTx Hash: ${result.txHash}`;
    setStatus("Transfer succeeded.");
    refreshNativeBalance().catch(() => {});
    if (mode !== "native") {
      refreshTokens().catch(() => {});
    }
  } catch (error) {
    setStatus(String(error), true);
  }
});

async function bootstrap() {
  try {
    await Promise.all([refreshRpcs(), refreshWallets(), refreshNativeBalance()]);
  } catch (error) {
    rpcEl.textContent = "unavailable";
    setStatus(String(error), true);
  }
}

bootstrap();
