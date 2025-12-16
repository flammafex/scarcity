/**
 * Scarbucks Main Application
 * "Cash That Bleeds" - 90-second demo tokens
 */

const ScarbucksApp = (() => {
  // State
  let currentWallet = null;
  let currentToken = null;
  let timerInterval = null;
  let lastTimerValue = null;

  // DOM Elements (cached on init)
  const DOM = {};

  /**
   * Initialize the application
   */
  async function init() {
    // Cache DOM elements
    cacheDOM();

    // Check for claim parameter in URL
    const params = new URLSearchParams(window.location.search);
    const claimCode = params.get('claim');
    const pathMatch = window.location.pathname.match(/^\/t\/([a-z0-9]+)$/i);

    if (claimCode || pathMatch) {
      const code = claimCode || pathMatch[1];
      await handleClaim(code);
      return;
    }

    // Bind event listeners
    bindEvents();

    // Show landing screen
    showScreen('landing');

    // Check for existing active token
    const activeTokens = ScarbucksWallet.getActiveTokens();
    if (activeTokens.length > 0) {
      currentToken = activeTokens[0];
      await resumeToken();
    }

    console.log('Scarbucks initialized');
  }

  /**
   * Cache DOM elements
   */
  function cacheDOM() {
    DOM.screens = {
      landing: document.getElementById('screen-landing'),
      creating: document.getElementById('screen-creating'),
      active: document.getElementById('screen-active'),
      receive: document.getElementById('screen-receive'),
      death: document.getElementById('screen-death'),
      expired: document.getElementById('screen-expired'),
      error: document.getElementById('screen-error')
    };

    DOM.timer = document.getElementById('timer');
    DOM.decayBar = document.getElementById('decay-bar');
    DOM.tokenId = document.getElementById('token-id');
    DOM.tokenStatus = document.getElementById('token-status');
    DOM.qrCode = document.getElementById('qr-code');
    DOM.shareUrl = document.getElementById('share-url');
    DOM.loadingText = document.querySelector('.loading-text');
    DOM.errorMessage = document.getElementById('error-message');
    DOM.receiveLoading = document.getElementById('receive-loading');
    DOM.receiveResult = document.getElementById('receive-result');

    // Send mode elements
    DOM.sendQr = document.getElementById('send-qr');
    DOM.sendLink = document.getElementById('send-link');
    DOM.btnModeQr = document.getElementById('btn-mode-qr');
    DOM.btnModeLink = document.getElementById('btn-mode-link');
  }

  /**
   * Bind event listeners
   */
  function bindEvents() {
    // Create button
    document.getElementById('btn-create')?.addEventListener('click', createToken);
    document.getElementById('btn-create-another')?.addEventListener('click', createToken);
    document.getElementById('btn-create-new')?.addEventListener('click', createToken);

    // Cancel/destroy button
    document.getElementById('btn-cancel')?.addEventListener('click', destroyToken);

    // Copy button
    document.getElementById('btn-copy')?.addEventListener('click', copyLink);

    // Send mode toggles
    DOM.btnModeQr?.addEventListener('click', () => setSendMode('qr'));
    DOM.btnModeLink?.addEventListener('click', () => setSendMode('link'));

    // Back to home
    document.getElementById('btn-back-home')?.addEventListener('click', () => showScreen('landing'));
  }

  /**
   * Show a specific screen
   * @param {string} screenName
   */
  function showScreen(screenName) {
    Object.values(DOM.screens).forEach(screen => {
      screen?.classList.remove('active');
    });
    DOM.screens[screenName]?.classList.add('active');
  }

  /**
   * Create a new token
   */
  async function createToken() {
    showScreen('creating');
    updateLoadingText('Generating keypair...');

    try {
      // Get or create wallet
      await new Promise(r => setTimeout(r, 300)); // Brief pause for effect
      currentWallet = await ScarbucksWallet.getOrCreateWallet();
      updateLoadingText('Creating Scarbuck...');

      await new Promise(r => setTimeout(r, 300));

      // Create token
      currentToken = await ScarbucksClient.createToken(currentWallet);
      updateLoadingText('Preparing share link...');

      await new Promise(r => setTimeout(r, 200));

      // Create shareable URL
      const share = await ScarbucksClient.createShareableUrl(currentToken);
      currentToken.shareUrl = share.url;
      currentToken.shareCode = share.code;

      // Update display and start timer
      await showActiveToken();

    } catch (error) {
      console.error('Failed to create token:', error);
      showError('Failed to create Scarbuck. Please try again.');
    }
  }

  /**
   * Resume an existing active token
   */
  async function resumeToken() {
    if (!currentToken) return;

    // Recreate wallet
    currentWallet = await ScarbucksWallet.getOrCreateWallet();

    // Recreate share URL if needed
    if (!currentToken.shareUrl) {
      const share = await ScarbucksClient.createShareableUrl(currentToken);
      currentToken.shareUrl = share.url;
      currentToken.shareCode = share.code;
    }

    await showActiveToken();
  }

  /**
   * Show the active token screen
   */
  async function showActiveToken() {
    // Update token ID display
    DOM.tokenId.textContent = `TOKEN: ${currentToken.id}`;

    // Generate QR code
    ScarbucksQR.render(DOM.qrCode, currentToken.shareUrl, {
      moduleSize: 5,
      margin: 2,
      foreground: '#ff0000',
      background: '#000000',
      glow: true
    });

    // Set share URL
    DOM.shareUrl.textContent = currentToken.shareUrl;

    // Show screen and start timer
    showScreen('active');
    setSendMode('qr');
    startTimer();
  }

  /**
   * Start the countdown timer
   */
  function startTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
    }

    updateTimerDisplay();

    timerInterval = setInterval(() => {
      updateTimerDisplay();
    }, 100); // Update frequently for smooth decay bar
  }

  /**
   * Update timer display
   */
  function updateTimerDisplay() {
    if (!currentToken) return;

    const remaining = ScarbucksClient.getRemainingTime(currentToken);
    const percentage = ScarbucksClient.getDecayPercentage(currentToken);

    if (remaining <= 0) {
      // Token is dead
      handleDeath();
      return;
    }

    // Update timer text (only when seconds change)
    const seconds = Math.ceil(remaining / 1000);
    if (seconds !== lastTimerValue) {
      lastTimerValue = seconds;
      DOM.timer.textContent = ScarbucksClient.formatTime(remaining);

      // Add critical class when under 15 seconds
      if (seconds <= 15) {
        DOM.timer.classList.add('critical');
        DOM.decayBar.classList.add('critical');
        DOM.tokenStatus.textContent = 'BLEEDING OUT';
      } else if (seconds <= 30) {
        DOM.tokenStatus.textContent = 'DRAINING';
      } else {
        DOM.timer.classList.remove('critical');
        DOM.decayBar.classList.remove('critical');
        DOM.tokenStatus.textContent = 'ALIVE';
      }
    }

    // Update decay bar
    DOM.decayBar.style.width = `${percentage}%`;
  }

  /**
   * Handle token death
   */
  function handleDeath() {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }

    // Update display
    DOM.timer.textContent = '0';
    DOM.timer.classList.add('dead');
    DOM.timer.classList.remove('critical');
    DOM.decayBar.style.width = '0%';
    DOM.decayBar.classList.remove('critical');

    // Mark token as dead
    if (currentToken) {
      currentToken.status = 'dead';
      ScarbucksWallet.deleteToken(currentToken.id);
    }

    // Show death screen with animation
    document.body.classList.add('shake');
    setTimeout(() => {
      document.body.classList.remove('shake');
      showScreen('death');
    }, 500);

    currentToken = null;
  }

  /**
   * Destroy current token voluntarily
   */
  function destroyToken() {
    if (currentToken) {
      ScarbucksWallet.deleteToken(currentToken.id);
      currentToken = null;
    }

    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }

    showScreen('landing');
  }

  /**
   * Set send mode (QR or link)
   * @param {string} mode - 'qr' or 'link'
   */
  function setSendMode(mode) {
    if (mode === 'qr') {
      DOM.sendQr.classList.remove('hidden');
      DOM.sendLink.classList.add('hidden');
      DOM.btnModeQr.classList.add('active');
      DOM.btnModeLink.classList.remove('active');
    } else {
      DOM.sendQr.classList.add('hidden');
      DOM.sendLink.classList.remove('hidden');
      DOM.btnModeQr.classList.remove('active');
      DOM.btnModeLink.classList.add('active');
    }
  }

  /**
   * Copy share link to clipboard
   */
  async function copyLink() {
    if (!currentToken?.shareUrl) return;

    try {
      await navigator.clipboard.writeText(currentToken.shareUrl);

      // Visual feedback
      const btn = document.getElementById('btn-copy');
      const originalText = btn.textContent;
      btn.textContent = 'COPIED!';
      setTimeout(() => {
        btn.textContent = originalText;
      }, 1500);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }

  /**
   * Handle claim from URL
   * @param {string} code - Short code from URL
   */
  async function handleClaim(code) {
    showScreen('receive');

    try {
      // Get wallet
      currentWallet = await ScarbucksWallet.getOrCreateWallet();

      // Retrieve transfer package
      const pkg = await ScarbucksClient.getTransferPackage(code);

      if (!pkg) {
        showScreen('error');
        DOM.errorMessage.textContent = 'Transfer not found. Link may be invalid or already claimed.';
        return;
      }

      if (pkg.expired) {
        showScreen('expired');
        return;
      }

      // Claim the token
      const result = await ScarbucksClient.claimToken(pkg, currentWallet);

      if (!result.success) {
        if (result.error === 'expired') {
          showScreen('expired');
        } else {
          showScreen('error');
          DOM.errorMessage.textContent = result.message || 'Failed to claim token.';
        }
        return;
      }

      // Success! Show the received token
      currentToken = result.token;

      // Create share URL for forwarding
      const share = await ScarbucksClient.createShareableUrl(currentToken);
      currentToken.shareUrl = share.url;
      currentToken.shareCode = share.code;

      // Clear URL params and show active screen
      window.history.replaceState({}, '', '/');

      await showActiveToken();

    } catch (error) {
      console.error('Failed to claim:', error);
      showScreen('error');
      DOM.errorMessage.textContent = 'Something went wrong. Please try again.';
    }
  }

  /**
   * Show error screen
   * @param {string} message
   */
  function showError(message) {
    DOM.errorMessage.textContent = message;
    showScreen('error');
  }

  /**
   * Update loading text
   * @param {string} text
   */
  function updateLoadingText(text) {
    if (DOM.loadingText) {
      DOM.loadingText.textContent = text;
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Public API (for debugging)
  return {
    init,
    getToken: () => currentToken,
    getWallet: () => currentWallet
  };
})();
