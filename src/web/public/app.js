// Scarcity Web Wallet - Frontend Application

const API_BASE = '/api';
let initialized = false;

// Token validity window: ~576 days (default, configurable in backend)
// This must match NullifierGossip.maxNullifierAge and TransferValidator.maxTokenAge
// See src/constants.ts for the authoritative default value
const TOKEN_VALIDITY_MS = 24 * 24 * 24 * 3600 * 1000;
const EXPIRY_WARNING_DAYS = 90; // Show warning when less than this many days remain

// PIN Protection
const PIN_HASH_KEY = 'scarcity_pin_hash';
const PIN_MIN_LENGTH = 4;
const PIN_MAX_LENGTH = 8;

// Utility functions
const $ = (id) => document.getElementById(id);
const $$ = (selector) => document.querySelectorAll(selector);

/**
 * Calculate token expiration info
 * @param {number} created - Token creation timestamp (ms)
 * @returns {{ expiresAt: number, daysRemaining: number, isExpiring: boolean, isExpired: boolean }}
 */
function getExpirationInfo(created) {
  const expiresAt = created + TOKEN_VALIDITY_MS;
  const now = Date.now();
  const msRemaining = expiresAt - now;
  const daysRemaining = Math.floor(msRemaining / (24 * 3600 * 1000));

  return {
    expiresAt,
    daysRemaining,
    isExpiring: daysRemaining > 0 && daysRemaining <= EXPIRY_WARNING_DAYS,
    isExpired: daysRemaining <= 0
  };
}

/**
 * Format expiration display text
 * @param {{ daysRemaining: number, isExpired: boolean, expiresAt: number }} info
 * @returns {string}
 */
function formatExpiration(info) {
  if (info.isExpired) {
    return 'Expired';
  }
  if (info.daysRemaining === 0) {
    return 'Expires today';
  }
  if (info.daysRemaining === 1) {
    return 'Expires tomorrow';
  }
  if (info.daysRemaining <= EXPIRY_WARNING_DAYS) {
    return `Expires in ${info.daysRemaining} days`;
  }
  // For tokens not expiring soon, show the date
  return `Valid until ${new Date(info.expiresAt).toLocaleDateString()}`;
}

/**
 * Update the expiry warning banner visibility
 * @param {number} expiringCount - Number of tokens expiring soon
 * @param {number} soonestExpiry - Days until soonest expiring token
 */
function updateExpiryBanner(expiringCount, soonestExpiry) {
  const banner = $('expiry-banner');
  if (!banner) return;

  if (expiringCount === 0) {
    banner.style.display = 'none';
    return;
  }

  banner.style.display = 'block';
  const tokenText = expiringCount === 1 ? '1 token is' : `${expiringCount} tokens are`;
  const daysText = soonestExpiry === 1 ? 'tomorrow' : `in ${soonestExpiry} days`;

  banner.innerHTML = `
    <strong>Action Required:</strong> ${tokenText} expiring soon (soonest: ${daysText}).
    Transfer tokens to yourself to refresh their validity window.
  `;
}

// PIN Protection Functions

/**
 * Hash a PIN using SHA-256 (browser crypto API)
 * @param {string} pin
 * @returns {Promise<string>} Hex-encoded hash
 */
async function hashPIN(pin) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pin + 'scarcity_salt');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Check if a PIN has been set
 * @returns {boolean}
 */
function isPINSet() {
  return localStorage.getItem(PIN_HASH_KEY) !== null;
}

/**
 * Verify a PIN against the stored hash
 * @param {string} pin
 * @returns {Promise<boolean>}
 */
async function verifyPIN(pin) {
  const storedHash = localStorage.getItem(PIN_HASH_KEY);
  if (!storedHash) return false;
  const inputHash = await hashPIN(pin);
  return storedHash === inputHash;
}

/**
 * Set a new PIN
 * @param {string} pin
 * @returns {Promise<void>}
 */
async function setPIN(pin) {
  const hash = await hashPIN(pin);
  localStorage.setItem(PIN_HASH_KEY, hash);
}

/**
 * Show PIN modal and return a promise that resolves with the result
 * @param {'set' | 'verify' | 'change'} mode
 * @returns {Promise<boolean>} True if PIN was successfully set/verified
 */
function showPINModal(mode) {
  return new Promise((resolve) => {
    const modal = $('pin-modal');
    const title = $('pin-modal-title');
    const subtitle = $('pin-modal-subtitle');
    const input = $('pin-input');
    const confirmGroup = $('pin-confirm-group');
    const confirmInput = $('pin-confirm');
    const errorText = $('pin-error');
    const submitBtn = $('pin-submit');

    // Reset state
    input.value = '';
    confirmInput.value = '';
    errorText.style.display = 'none';
    confirmGroup.style.display = 'none';

    if (mode === 'set') {
      title.textContent = 'Set a PIN';
      subtitle.textContent = `Choose a ${PIN_MIN_LENGTH}-${PIN_MAX_LENGTH} digit PIN to protect your wallet secrets.`;
      confirmGroup.style.display = 'block';
      submitBtn.textContent = 'Set PIN';
    } else if (mode === 'verify') {
      title.textContent = 'Enter PIN';
      subtitle.textContent = 'Enter your PIN to access wallet secrets.';
      submitBtn.textContent = 'Verify';
    } else if (mode === 'change') {
      title.textContent = 'Change PIN';
      subtitle.textContent = 'Enter your current PIN, then set a new one.';
      submitBtn.textContent = 'Verify Current PIN';
    }

    modal.style.display = 'flex';
    input.focus();

    let isChangingPIN = mode === 'change';
    let currentPINVerified = false;

    const cleanup = () => {
      modal.style.display = 'none';
      submitBtn.onclick = null;
      $('pin-cancel').onclick = null;
      input.onkeydown = null;
    };

    const handleSubmit = async () => {
      const pin = input.value;

      // Validate PIN length
      if (pin.length < PIN_MIN_LENGTH || pin.length > PIN_MAX_LENGTH) {
        errorText.textContent = `PIN must be ${PIN_MIN_LENGTH}-${PIN_MAX_LENGTH} digits`;
        errorText.style.display = 'block';
        return;
      }

      // Validate PIN is numeric
      if (!/^\d+$/.test(pin)) {
        errorText.textContent = 'PIN must contain only numbers';
        errorText.style.display = 'block';
        return;
      }

      if (mode === 'verify') {
        const valid = await verifyPIN(pin);
        if (valid) {
          cleanup();
          resolve(true);
        } else {
          errorText.textContent = 'Incorrect PIN';
          errorText.style.display = 'block';
          input.value = '';
          input.focus();
        }
      } else if (mode === 'set' || (isChangingPIN && currentPINVerified)) {
        const confirm = confirmInput.value;
        if (pin !== confirm) {
          errorText.textContent = 'PINs do not match';
          errorText.style.display = 'block';
          return;
        }
        await setPIN(pin);
        cleanup();
        showSuccess('PIN set successfully');
        resolve(true);
      } else if (isChangingPIN && !currentPINVerified) {
        const valid = await verifyPIN(pin);
        if (valid) {
          currentPINVerified = true;
          title.textContent = 'Set New PIN';
          subtitle.textContent = `Choose a new ${PIN_MIN_LENGTH}-${PIN_MAX_LENGTH} digit PIN.`;
          confirmGroup.style.display = 'block';
          submitBtn.textContent = 'Set New PIN';
          input.value = '';
          confirmInput.value = '';
          errorText.style.display = 'none';
          input.focus();
        } else {
          errorText.textContent = 'Incorrect PIN';
          errorText.style.display = 'block';
          input.value = '';
          input.focus();
        }
      }
    };

    submitBtn.onclick = handleSubmit;
    input.onkeydown = (e) => {
      if (e.key === 'Enter') {
        if (confirmGroup.style.display === 'block' && document.activeElement === input) {
          confirmInput.focus();
        } else {
          handleSubmit();
        }
      }
    };
    confirmInput.onkeydown = (e) => {
      if (e.key === 'Enter') handleSubmit();
    };

    $('pin-cancel').onclick = () => {
      cleanup();
      resolve(false);
    };
  });
}

/**
 * Require PIN verification before proceeding
 * If no PIN is set, prompts user to set one first
 * @returns {Promise<boolean>} True if verified/set successfully
 */
async function requirePIN() {
  if (!isPINSet()) {
    // First time: require setting a PIN
    return showPINModal('set');
  }
  return showPINModal('verify');
}

function showLoading(text = 'Processing...') {
  $('loading').style.display = 'flex';
  $('loading-text').textContent = text;
  $('loading-steps').innerHTML = '';
  $('loading-steps').style.display = 'none';
}

function hideLoading() {
  $('loading').style.display = 'none';
  $('loading-steps').innerHTML = '';
}

/**
 * Show loading with step-by-step progress
 * @param {string} title - Main title
 * @param {string[]} steps - Array of step descriptions
 */
function showProgressLoading(title, steps) {
  $('loading').style.display = 'flex';
  $('loading-text').textContent = title;

  const stepsContainer = $('loading-steps');
  stepsContainer.style.display = 'block';
  stepsContainer.innerHTML = steps.map((step, i) =>
    `<div class="progress-step" id="progress-step-${i}">
      <span class="step-indicator"></span>
      <span class="step-text">${step}</span>
    </div>`
  ).join('');
}

/**
 * Update a specific step's status
 * @param {number} stepIndex - Step index (0-based)
 * @param {'pending' | 'active' | 'complete' | 'error'} status
 */
function updateProgressStep(stepIndex, status) {
  const step = $(`progress-step-${stepIndex}`);
  if (!step) return;

  step.className = `progress-step ${status}`;
}

/**
 * Run through progress steps with a callback for each step
 * @param {string} title
 * @param {Array<{name: string, action: () => Promise<any>}>} steps
 * @returns {Promise<any>} Result of the last step
 */
async function runWithProgress(title, steps) {
  showProgressLoading(title, steps.map(s => s.name));

  let result;
  for (let i = 0; i < steps.length; i++) {
    updateProgressStep(i, 'active');
    try {
      result = await steps[i].action();
      updateProgressStep(i, 'complete');
    } catch (error) {
      updateProgressStep(i, 'error');
      throw error;
    }
  }

  return result;
}

function showError(message) {
  const toast = $('error-toast');
  toast.textContent = message;
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 5000);
}

function showSuccess(message) {
  const toast = $('success-toast');
  toast.textContent = message;
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 3000);
}

async function apiCall(endpoint, method = 'GET', body = null) {
  try {
    const options = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, options);
    const data = await response.json();

    if (!data.success) {
      throw new Error(data.error || 'Request failed');
    }

    return data.data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
}

// Tab navigation
function setupTabs() {
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;

      // Update buttons
      $$('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Update content
      $$('.tab-content').forEach(c => c.classList.remove('active'));
      $(`${tab}-tab`).classList.add('active');

      // Load tab-specific data
      if (tab === 'wallets') loadWallets();
      if (tab === 'tokens') loadTokens();
      if (tab === 'send') loadSendOptions();
      if (tab === 'receive') loadReceiveOptions();
      if (tab === 'operations') loadOperationsOptions();
    });
  });
}

// Initialize network
async function initializeNetwork() {
  try {
    showLoading('Connecting to Scarcity network...');
    await apiCall('/init', 'POST');
    initialized = true;

    // Update UI
    $('init-section').style.display = 'none';
    $('main-app').style.display = 'block';
    $('status-indicator').classList.add('online');
    $('status-text').textContent = 'Connected';

    showSuccess('Connected to Scarcity network');
    loadWallets();
  } catch (error) {
    showError('Failed to initialize: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Wallet management
async function loadWallets() {
  try {
    const data = await apiCall('/wallets');
    const walletList = $('wallet-list');
    walletList.innerHTML = '';

    if (data.wallets.length === 0) {
      walletList.innerHTML = '<p style="text-align: center; color: var(--text-light);">No wallets yet. Create one to get started!</p>';
      return;
    }

    for (const wallet of data.wallets) {
      const balance = await apiCall(`/wallets/${wallet.name}/balance`);
      const card = document.createElement('div');
      card.className = `wallet-card ${wallet.isDefault ? 'default' : ''}`;
      card.innerHTML = `
        <div class="wallet-header">
          <div class="wallet-name">
            ${wallet.name}
            ${wallet.isDefault ? '<span class="wallet-badge">DEFAULT</span>' : ''}
          </div>
          <div class="wallet-actions">
            ${!wallet.isDefault ? `<button class="btn btn-small" onclick="setDefaultWallet('${wallet.name}')">Set Default</button>` : ''}
            <button class="btn btn-small btn-secondary" onclick="exportWallet('${wallet.name}')">Export</button>
          </div>
        </div>
        <div class="wallet-pubkey">${wallet.publicKey}</div>
        <div class="wallet-balance">
          <span>Balance:</span>
          <span class="wallet-balance-amount">${balance.balance}</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-light); margin-top: 0.5rem;">
          ${balance.tokenCount} token${balance.tokenCount !== 1 ? 's' : ''}
        </div>
      `;
      walletList.appendChild(card);
    }

    // Update wallet dropdowns
    updateWalletDropdowns(data.wallets);
  } catch (error) {
    showError('Failed to load wallets: ' + error.message);
  }
}

function updateWalletDropdowns(wallets) {
  const selects = ['mint-wallet', 'receive-wallet', 'token-wallet-filter'];

  selects.forEach(selectId => {
    const select = $(selectId);
    const currentValue = select.value;
    select.innerHTML = selectId === 'token-wallet-filter' ? '<option value="">All wallets</option>' : '<option value="">Select wallet</option>';

    wallets.forEach(wallet => {
      const option = document.createElement('option');
      option.value = wallet.name;
      option.textContent = wallet.name;
      select.appendChild(option);
    });

    if (currentValue) select.value = currentValue;
  });
}

async function createWallet() {
  const name = $('new-wallet-name').value.trim();
  const setDefault = $('set-default').checked;

  if (!name) {
    showError('Please enter a wallet name');
    return;
  }

  try {
    showLoading('Creating wallet...');
    await apiCall('/wallets', 'POST', { name, setDefault });
    showSuccess('Wallet created successfully');
    $('create-wallet-form').style.display = 'none';
    $('new-wallet-name').value = '';
    loadWallets();
  } catch (error) {
    showError('Failed to create wallet: ' + error.message);
  } finally {
    hideLoading();
  }
}

async function importWallet() {
  const name = $('import-wallet-name').value.trim();
  const secretKey = $('import-secret-key').value.trim();

  if (!name || !secretKey) {
    showError('Please enter wallet name and secret key');
    return;
  }

  try {
    showLoading('Importing wallet...');
    await apiCall('/wallets/import', 'POST', { name, secretKey, setDefault: false });
    showSuccess('Wallet imported successfully');
    $('import-wallet-form').style.display = 'none';
    $('import-wallet-name').value = '';
    $('import-secret-key').value = '';
    loadWallets();
  } catch (error) {
    showError('Failed to import wallet: ' + error.message);
  } finally {
    hideLoading();
  }
}

async function setDefaultWallet(name) {
  try {
    showLoading('Setting default wallet...');
    await apiCall(`/wallets/${name}/default`, 'POST');
    showSuccess('Default wallet updated');
    loadWallets();
  } catch (error) {
    showError('Failed to set default: ' + error.message);
  } finally {
    hideLoading();
  }
}

async function exportWallet(name) {
  try {
    // Require PIN verification before showing secret
    const verified = await requirePIN();
    if (!verified) {
      return; // User cancelled
    }

    const data = await apiCall(`/wallets/${name}/export`);

    // Show secret key in a secure modal instead of prompt()
    showSecretModal(name, data.secretKey);
  } catch (error) {
    showError('Failed to export wallet: ' + error.message);
  }
}

/**
 * Show secret key in a secure modal with copy functionality
 * @param {string} walletName
 * @param {string} secretKey
 */
function showSecretModal(walletName, secretKey) {
  const modal = $('secret-modal');
  const walletNameEl = $('secret-wallet-name');
  const secretDisplay = $('secret-display');
  const copyBtn = $('secret-copy');
  const closeBtn = $('secret-close');

  walletNameEl.textContent = walletName;
  secretDisplay.textContent = secretKey;
  modal.style.display = 'flex';

  // Auto-clear after 60 seconds for security
  const clearTimer = setTimeout(() => {
    modal.style.display = 'none';
    secretDisplay.textContent = '';
  }, 60000);

  copyBtn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(secretKey);
      showSuccess('Secret key copied to clipboard');
      copyBtn.textContent = 'Copied!';
      setTimeout(() => {
        copyBtn.textContent = 'Copy to Clipboard';
      }, 2000);
    } catch (err) {
      showError('Failed to copy to clipboard');
    }
  };

  closeBtn.onclick = () => {
    clearTimeout(clearTimer);
    modal.style.display = 'none';
    secretDisplay.textContent = '';
  };
}

// Token management
async function loadTokens() {
  try {
    const wallet = $('token-wallet-filter').value;
    const data = await apiCall(`/tokens?wallet=${wallet || ''}&spent=false`);

    // Calculate total balance
    const balance = data.tokens.reduce((sum, t) => sum + t.amount, 0);
    $('total-balance').textContent = balance;
    $('token-count').textContent = `${data.tokens.length} token${data.tokens.length !== 1 ? 's' : ''}`;

    const tokenList = $('token-list');
    tokenList.innerHTML = '';

    if (data.tokens.length === 0) {
      tokenList.innerHTML = '<p style="text-align: center; color: var(--text-light);">No tokens yet. Mint one to get started!</p>';
      return;
    }

    // Check for expiring tokens to show banner
    let expiringCount = 0;
    let soonestExpiry = Infinity;

    data.tokens.forEach(token => {
      const expiryInfo = getExpirationInfo(token.created);

      if (!token.spent && expiryInfo.isExpiring) {
        expiringCount++;
        soonestExpiry = Math.min(soonestExpiry, expiryInfo.daysRemaining);
      }

      // Determine card state classes
      let cardClass = 'token-card';
      if (token.spent) {
        cardClass += ' spent';
      } else if (expiryInfo.isExpired) {
        cardClass += ' expired';
      } else if (expiryInfo.isExpiring) {
        cardClass += ' expiring';
      }

      const card = document.createElement('div');
      card.className = cardClass;
      card.innerHTML = `
        <div class="token-info">
          <div class="token-id">${token.id}</div>
          <div class="token-amount">${token.amount}</div>
          <div class="token-meta">
            Wallet: ${token.wallet} •
            ${token.metadata?.type ? token.metadata.type.charAt(0).toUpperCase() + token.metadata.type.slice(1) : 'Unknown'} •
            ${new Date(token.created).toLocaleDateString()}
          </div>
          <div class="token-expiry ${expiryInfo.isExpiring ? 'warning' : ''} ${expiryInfo.isExpired ? 'expired' : ''}">
            ${formatExpiration(expiryInfo)}
          </div>
        </div>
        <div class="token-status ${token.spent ? 'spent' : expiryInfo.isExpired ? 'expired' : 'available'}">
          ${token.spent ? 'Spent' : expiryInfo.isExpired ? 'Expired' : 'Available'}
        </div>
      `;
      tokenList.appendChild(card);
    });

    // Show/hide expiry warning banner
    updateExpiryBanner(expiringCount, soonestExpiry);
  } catch (error) {
    showError('Failed to load tokens: ' + error.message);
  }
}

async function mintToken() {
  const wallet = $('mint-wallet').value;
  const amount = parseInt($('mint-amount').value);

  if (!wallet || !amount || amount <= 0) {
    showError('Please select wallet and enter valid amount');
    return;
  }

  try {
    showLoading('Minting token...');
    const data = await apiCall('/tokens/mint', 'POST', { wallet, amount });
    showSuccess(`Token minted: ${data.id}`);
    $('mint-form').style.display = 'none';
    $('mint-amount').value = '';
    loadTokens();
  } catch (error) {
    showError('Failed to mint token: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Send/Receive
async function loadSendOptions() {
  try {
    const data = await apiCall('/tokens?spent=false');
    const select = $('send-token');
    select.innerHTML = '<option value="">Select token to send</option>';

    data.tokens.forEach(token => {
      const option = document.createElement('option');
      option.value = token.id;
      option.textContent = `${token.id.substring(0, 16)}... (${token.amount}) - ${token.wallet}`;
      option.dataset.wallet = token.wallet;
      select.appendChild(option);
    });
  } catch (error) {
    showError('Failed to load tokens: ' + error.message);
  }
}

async function loadReceiveOptions() {
  // Just make sure wallets are loaded in dropdown
  try {
    const data = await apiCall('/wallets');
    updateWalletDropdowns(data.wallets);
  } catch (error) {
    showError('Failed to load wallets: ' + error.message);
  }
}

async function sendToken() {
  const tokenId = $('send-token').value;
  const recipientPublicKey = $('send-recipient').value.trim();
  const selectedOption = $('send-token').selectedOptions[0];
  const wallet = selectedOption ? selectedOption.dataset.wallet : null;

  if (!tokenId || !recipientPublicKey) {
    showError('Please select token and enter recipient public key');
    return;
  }

  try {
    // Show progress steps
    const steps = [
      { name: 'Creating nullifier', delay: 200 },
      { name: 'Blinding recipient commitment', delay: 300 },
      { name: 'Generating ownership proof', delay: 250 },
      { name: 'Getting witness timestamp', delay: 400 },
      { name: 'Broadcasting to network', delay: 200 }
    ];

    showProgressLoading('Sending Token', steps.map(s => s.name));

    // Start the actual transfer in the background
    const transferPromise = apiCall('/tokens/transfer', 'POST', {
      tokenId,
      recipientPublicKey,
      wallet
    });

    // Animate through steps while transfer is in progress
    let stepIndex = 0;
    for (const step of steps) {
      updateProgressStep(stepIndex, 'active');
      await new Promise(resolve => setTimeout(resolve, step.delay));
      updateProgressStep(stepIndex, 'complete');
      stepIndex++;
    }

    // Wait for the actual transfer to complete
    const data = await transferPromise;

    const transferJson = JSON.stringify(data.transfer, null, 2);
    $('send-result').style.display = 'block';
    $('send-result').innerHTML = `
      <h4>Transfer Created Successfully</h4>
      <p>Share this transfer data with the recipient:</p>
      <pre>${transferJson}</pre>
      <button class="btn btn-small" onclick="copyTransfer(${JSON.stringify(transferJson).replace(/"/g, '&quot;')})">Copy Transfer Data</button>
      <div class="transfer-details">
        <p><strong>Nullifier:</strong> <code>${data.transfer.nullifier.substring(0, 32)}...</code></p>
        <p><strong>Timestamp:</strong> ${new Date(data.transfer.proof.timestamp).toLocaleString()}</p>
        <p><strong>Witnesses:</strong> ${data.transfer.proof.witnessIds?.length || 0} signatures</p>
      </div>
    `;

    showSuccess('Token sent successfully');
    $('send-token').value = '';
    $('send-recipient').value = '';
  } catch (error) {
    showError('Failed to send token: ' + error.message);
  } finally {
    hideLoading();
  }
}

function copyTransfer(data) {
  navigator.clipboard.writeText(data).then(() => {
    showSuccess('Transfer data copied to clipboard');
  });
}

async function receiveToken() {
  const wallet = $('receive-wallet').value;
  const transferText = $('receive-transfer').value.trim();

  if (!wallet || !transferText) {
    showError('Please select wallet and paste transfer data');
    return;
  }

  try {
    const transfer = JSON.parse(transferText);

    showLoading('Receiving token...');
    const data = await apiCall('/tokens/receive', 'POST', { transfer, wallet });

    $('receive-result').style.display = 'block';
    $('receive-result').innerHTML = `
      <h4>Token Received Successfully</h4>
      <p><strong>Token ID:</strong> ${data.id}</p>
      <p><strong>Amount:</strong> ${data.amount}</p>
    `;

    showSuccess('Token received successfully');
    $('receive-transfer').value = '';
  } catch (error) {
    showError('Failed to receive token: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Operations
async function loadOperationsOptions() {
  try {
    const data = await apiCall('/tokens?spent=false');

    // Split dropdown
    const splitSelect = $('split-token');
    splitSelect.innerHTML = '<option value="">Select token to split</option>';

    // Merge checkboxes
    const mergeCheckboxes = $('merge-token-checkboxes');
    mergeCheckboxes.innerHTML = '';

    if (data.tokens.length === 0) {
      mergeCheckboxes.innerHTML = '<p style="text-align: center; color: var(--text-light);">No tokens available</p>';
      return;
    }

    data.tokens.forEach(token => {
      // Split option
      const option = document.createElement('option');
      option.value = token.id;
      option.textContent = `${token.id.substring(0, 16)}... (${token.amount}) - ${token.wallet}`;
      option.dataset.wallet = token.wallet;
      splitSelect.appendChild(option);

      // Merge checkbox
      const checkboxDiv = document.createElement('div');
      checkboxDiv.className = 'checkbox-item';
      checkboxDiv.innerHTML = `
        <input type="checkbox" id="merge-${token.id}" value="${token.id}" data-wallet="${token.wallet}">
        <label for="merge-${token.id}" style="cursor: pointer; flex: 1;">
          <strong>${token.amount}</strong> - ${token.id.substring(0, 32)}... (${token.wallet})
        </label>
      `;
      mergeCheckboxes.appendChild(checkboxDiv);
    });
  } catch (error) {
    showError('Failed to load tokens: ' + error.message);
  }
}

async function splitToken() {
  const tokenId = $('split-token').value;
  const amountsText = $('split-amounts').value.trim();
  const selectedOption = $('split-token').selectedOptions[0];
  const wallet = selectedOption ? selectedOption.dataset.wallet : null;

  if (!tokenId || !amountsText) {
    showError('Please select token and enter amounts');
    return;
  }

  try {
    const amounts = amountsText.split(',').map(a => parseInt(a.trim()));
    if (amounts.some(a => isNaN(a) || a <= 0)) {
      throw new Error('Invalid amounts format');
    }

    showLoading('Splitting token...');
    const data = await apiCall('/tokens/split', 'POST', { tokenId, amounts, wallet });

    $('split-result').style.display = 'block';
    $('split-result').innerHTML = `
      <h4>Token Split Successfully</h4>
      <p>Created ${data.tokens.length} new tokens:</p>
      <ul>
        ${data.tokens.map(t => `<li>${t.id.substring(0, 32)}... (${t.amount})</li>`).join('')}
      </ul>
    `;

    showSuccess('Token split successfully');
    $('split-token').value = '';
    $('split-amounts').value = '';
    loadOperationsOptions();
    loadTokens();
  } catch (error) {
    showError('Failed to split token: ' + error.message);
  } finally {
    hideLoading();
  }
}

async function mergeTokens() {
  const checkboxes = $$('#merge-token-checkboxes input[type="checkbox"]:checked');
  const tokenIds = Array.from(checkboxes).map(cb => cb.value);

  if (tokenIds.length < 2) {
    showError('Please select at least 2 tokens to merge');
    return;
  }

  // Get wallet from first checked token
  const wallet = checkboxes[0].dataset.wallet;

  try {
    showLoading('Merging tokens...');
    const data = await apiCall('/tokens/merge', 'POST', { tokenIds, wallet });

    $('merge-result').style.display = 'block';
    $('merge-result').innerHTML = `
      <h4>Tokens Merged Successfully</h4>
      <p><strong>New Token ID:</strong> ${data.id}</p>
      <p><strong>Total Amount:</strong> ${data.amount}</p>
    `;

    showSuccess('Tokens merged successfully');
    loadOperationsOptions();
    loadTokens();
  } catch (error) {
    showError('Failed to merge tokens: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();

  // Privacy info modal
  $('privacy-info-btn').addEventListener('click', () => {
    $('privacy-modal').style.display = 'flex';
  });

  $('privacy-close').addEventListener('click', () => {
    $('privacy-modal').style.display = 'none';
  });

  // Close modals on backdrop click
  $$('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.style.display = 'none';
      }
    });
  });

  // Initialize
  $('init-btn').addEventListener('click', initializeNetwork);

  // Wallet events
  $('create-wallet-btn').addEventListener('click', () => {
    $('create-wallet-form').style.display = 'block';
    $('import-wallet-form').style.display = 'none';
  });

  $('create-wallet-cancel').addEventListener('click', () => {
    $('create-wallet-form').style.display = 'none';
  });

  $('create-wallet-submit').addEventListener('click', createWallet);

  $('import-wallet-btn').addEventListener('click', () => {
    $('import-wallet-form').style.display = 'block';
    $('create-wallet-form').style.display = 'none';
  });

  $('import-wallet-cancel').addEventListener('click', () => {
    $('import-wallet-form').style.display = 'none';
  });

  $('import-wallet-submit').addEventListener('click', importWallet);

  // Token events
  $('token-wallet-filter').addEventListener('change', loadTokens);

  $('mint-token-btn').addEventListener('click', () => {
    $('mint-form').style.display = $('mint-form').style.display === 'none' ? 'block' : 'none';
  });

  $('mint-cancel').addEventListener('click', () => {
    $('mint-form').style.display = 'none';
  });

  $('mint-submit').addEventListener('click', mintToken);

  // Send/Receive events
  $('send-submit').addEventListener('click', sendToken);
  $('receive-submit').addEventListener('click', receiveToken);

  // Operations events
  $('split-submit').addEventListener('click', splitToken);
  $('merge-submit').addEventListener('click', mergeTokens);

  // Register service worker for PWA support
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => {
        console.log('[SW] Service worker registered:', registration.scope);

        // Check for updates periodically
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              // New version available
              showUpdateBanner();
            }
          });
        });
      })
      .catch((error) => {
        console.warn('[SW] Service worker registration failed:', error);
      });
  }
});

/**
 * Show update available banner
 */
function showUpdateBanner() {
  const banner = document.createElement('div');
  banner.className = 'update-banner';
  banner.innerHTML = `
    <span>A new version is available!</span>
    <button onclick="location.reload()">Update</button>
  `;
  document.body.appendChild(banner);
}
