/**
 * Scarbucks Scarcity Client
 * Handles token creation, transfer, and receiving
 * Connects to Metacan infrastructure or runs in demo mode
 */

const ScarbucksClient = (() => {
  // Configuration
  const CONFIG = {
    // Demo mode: 90-second token validity
    TOKEN_VALIDITY_MS: 90000,

    // Infrastructure endpoints
    FREEBIRD_ISSUER: 'https://issuer.metacan.org',
    FREEBIRD_VERIFIER: 'https://verifier.metacan.org',
    WITNESS_URL: 'https://witness1.metacan.org',
    RELAY_URL: 'wss://relay.metacan.org',

    // Short URL service (local for demo)
    SHORT_URL_API: '/api/transfer',

    // Base URL for sharing
    BASE_URL: typeof window !== 'undefined' ? window.location.origin : 'https://scarbucks.com'
  };

  /**
   * Create a new Scarbuck token
   * @param {Object} wallet - Wallet from ScarbucksWallet
   * @returns {Promise<Object>} Token data
   */
  async function createToken(wallet) {
    const now = Date.now();
    const expiresAt = now + CONFIG.TOKEN_VALIDITY_MS;

    // Create token ID
    const tokenId = await ScarbucksWallet.createTokenId(wallet.publicKey, now);

    // Create blinding factor for commitment
    const blindingFactor = ScarbucksWallet.randomBytes(32);

    // Create commitment (for Freebird integration)
    const commitment = await ScarbucksWallet.createCommitment(
      wallet.publicKey,
      blindingFactor
    );

    // Try to get authorization from Freebird (if available)
    let authorization = null;
    try {
      authorization = await getFreebirdAuthorization(commitment);
    } catch (e) {
      console.log('Running in demo mode without Freebird authorization');
    }

    // Create the token object
    const token = {
      id: tokenId,
      publicKey: ScarbucksWallet.toHex(wallet.publicKey),
      secretKey: ScarbucksWallet.toHex(wallet.secretKey),
      blindingFactor: ScarbucksWallet.toHex(blindingFactor),
      commitment: ScarbucksWallet.toHex(commitment),
      authorization: authorization,
      createdAt: now,
      expiresAt: expiresAt,
      status: 'active'
    };

    // Store locally
    ScarbucksWallet.storeToken(token);

    return token;
  }

  /**
   * Get Freebird authorization for a commitment
   * @param {Uint8Array} commitment
   * @returns {Promise<Object|null>}
   */
  async function getFreebirdAuthorization(commitment) {
    try {
      const response = await fetch(`${CONFIG.FREEBIRD_ISSUER}/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          blinded: ScarbucksWallet.toHex(commitment)
        })
      });

      if (!response.ok) {
        throw new Error(`Freebird error: ${response.status}`);
      }

      return await response.json();
    } catch (e) {
      console.warn('Freebird authorization failed:', e.message);
      return null;
    }
  }

  /**
   * Create a transfer package for sending a token
   * @param {Object} token - Token to transfer
   * @returns {Promise<Object>} Transfer package
   */
  async function createTransferPackage(token) {
    const secretKey = ScarbucksWallet.fromHex(token.secretKey);

    // Create nullifier for this transfer
    const nullifier = await ScarbucksWallet.createNullifier(secretKey, token.id);

    // Create ownership proof
    const proofMessage = await ScarbucksWallet.sha256(
      nullifier,
      token.id,
      String(token.expiresAt)
    );
    const ownershipProof = await ScarbucksWallet.createOwnershipProof(
      secretKey,
      proofMessage
    );

    // Transfer package contains everything needed to claim
    const transferPackage = {
      tokenId: token.id,
      commitment: token.commitment,
      nullifier: ScarbucksWallet.toHex(nullifier),
      ownershipProof: ScarbucksWallet.toHex(ownershipProof),
      blindingFactor: token.blindingFactor,
      authorization: token.authorization,
      expiresAt: token.expiresAt,
      createdAt: token.createdAt
    };

    return transferPackage;
  }

  /**
   * Create a shareable short URL for a token
   * @param {Object} token - Token to share
   * @returns {Promise<{url: string, code: string}>}
   */
  async function createShareableUrl(token) {
    const transferPackage = await createTransferPackage(token);

    // Try to store on server
    try {
      const response = await fetch(CONFIG.SHORT_URL_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: transferPackage,
          expiresAt: token.expiresAt
        })
      });

      if (response.ok) {
        const data = await response.json();
        return {
          url: `${CONFIG.BASE_URL}/t/${data.code}`,
          code: data.code
        };
      }
    } catch (e) {
      console.warn('Short URL server unavailable, using fallback');
    }

    // Fallback: encode package in URL (longer but works offline)
    const encoded = btoa(JSON.stringify(transferPackage));
    const code = ScarbucksWallet.generateShortCode(8);

    // Store in sessionStorage as fallback
    sessionStorage.setItem(`transfer_${code}`, encoded);

    return {
      url: `${CONFIG.BASE_URL}?claim=${code}`,
      code: code,
      fallback: true,
      encoded: encoded
    };
  }

  /**
   * Retrieve a transfer package from short code
   * @param {string} code - Short code
   * @returns {Promise<Object|null>}
   */
  async function getTransferPackage(code) {
    // Try server first
    try {
      const response = await fetch(`${CONFIG.SHORT_URL_API}/${code}`);

      if (response.ok) {
        const data = await response.json();
        return data.package;
      }

      if (response.status === 410) {
        // Gone - expired
        return { expired: true };
      }

      if (response.status === 404) {
        // Try sessionStorage fallback
        const stored = sessionStorage.getItem(`transfer_${code}`);
        if (stored) {
          return JSON.parse(atob(stored));
        }
      }
    } catch (e) {
      console.warn('Server unavailable, checking local storage');

      // Fallback to sessionStorage
      const stored = sessionStorage.getItem(`transfer_${code}`);
      if (stored) {
        return JSON.parse(atob(stored));
      }
    }

    return null;
  }

  /**
   * Claim/receive a token from a transfer package
   * @param {Object} transferPackage - Transfer package
   * @param {Object} wallet - Recipient wallet
   * @returns {Promise<Object>} Claimed token or error
   */
  async function claimToken(transferPackage, wallet) {
    // Check expiration
    if (transferPackage.expired || Date.now() > transferPackage.expiresAt) {
      return {
        success: false,
        error: 'expired',
        message: 'This Scarbuck has bled out'
      };
    }

    // Calculate remaining time
    const remainingMs = transferPackage.expiresAt - Date.now();

    // Create new token for recipient
    const claimedToken = {
      id: transferPackage.tokenId + '_claimed',
      originalId: transferPackage.tokenId,
      publicKey: wallet.publicKeyHex,
      secretKey: ScarbucksWallet.toHex(wallet.secretKey),
      commitment: transferPackage.commitment,
      claimedAt: Date.now(),
      expiresAt: transferPackage.expiresAt,
      remainingMs: remainingMs,
      status: 'active'
    };

    // Store the claimed token
    ScarbucksWallet.storeToken(claimedToken);

    return {
      success: true,
      token: claimedToken,
      remainingMs: remainingMs
    };
  }

  /**
   * Check if a token is still valid
   * @param {Object} token
   * @returns {boolean}
   */
  function isTokenValid(token) {
    return token && token.expiresAt > Date.now();
  }

  /**
   * Get remaining time for a token
   * @param {Object} token
   * @returns {number} Milliseconds remaining (can be negative)
   */
  function getRemainingTime(token) {
    if (!token) return 0;
    return token.expiresAt - Date.now();
  }

  /**
   * Format remaining time for display
   * @param {number} ms - Milliseconds
   * @returns {string}
   */
  function formatTime(ms) {
    if (ms <= 0) return '0';

    const seconds = Math.ceil(ms / 1000);
    if (seconds < 60) {
      return String(seconds);
    }

    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${String(remainingSeconds).padStart(2, '0')}`;
  }

  /**
   * Calculate decay percentage (for progress bar)
   * @param {Object} token
   * @returns {number} 0-100
   */
  function getDecayPercentage(token) {
    if (!token) return 0;

    const total = CONFIG.TOKEN_VALIDITY_MS;
    const remaining = Math.max(0, token.expiresAt - Date.now());
    return (remaining / total) * 100;
  }

  // Public API
  return {
    CONFIG,
    createToken,
    createTransferPackage,
    createShareableUrl,
    getTransferPackage,
    claimToken,
    isTokenValid,
    getRemainingTime,
    formatTime,
    getDecayPercentage
  };
})();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ScarbucksClient;
}
