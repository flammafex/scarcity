/**
 * Scarbucks Browser Wallet
 * Generates and manages ephemeral keypairs in browser storage
 * Uses Web Crypto API for cryptographic operations
 */

const ScarbucksWallet = (() => {
  const STORAGE_KEY = 'scarbucks_wallet';
  const TOKENS_KEY = 'scarbucks_tokens';

  /**
   * Generate random bytes using Web Crypto API
   * @param {number} length - Number of bytes
   * @returns {Uint8Array}
   */
  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  /**
   * Convert bytes to hex string
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  function toHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Convert hex string to bytes
   * @param {string} hex
   * @returns {Uint8Array}
   */
  function fromHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  /**
   * SHA-256 hash
   * @param {...(Uint8Array|string)} inputs
   * @returns {Promise<Uint8Array>}
   */
  async function sha256(...inputs) {
    const combined = inputs.map(input => {
      if (typeof input === 'string') {
        return new TextEncoder().encode(input);
      }
      return input;
    });

    const totalLength = combined.reduce((sum, arr) => sum + arr.length, 0);
    const merged = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of combined) {
      merged.set(arr, offset);
      offset += arr.length;
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', merged);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Generate a new keypair
   * For demo purposes, we use a simple secret key that derives a "public key"
   * In production, this would use proper ECC (P-256 or similar)
   * @returns {Promise<{secretKey: Uint8Array, publicKey: Uint8Array}>}
   */
  async function generateKeypair() {
    // Generate 32-byte secret key
    const secretKey = randomBytes(32);

    // Derive public key via hash (simplified for demo)
    // In production, would use proper EC key derivation
    const publicKey = await sha256(secretKey, 'scarbucks-pk');

    return { secretKey, publicKey };
  }

  /**
   * Create a unique token ID
   * @param {Uint8Array} publicKey
   * @param {number} timestamp
   * @returns {Promise<string>}
   */
  async function createTokenId(publicKey, timestamp) {
    const data = new Uint8Array(publicKey.length + 8);
    data.set(publicKey);
    // Add timestamp as bytes
    const view = new DataView(data.buffer);
    view.setBigUint64(publicKey.length, BigInt(timestamp), false);

    const hash = await sha256(data);
    return toHex(hash).slice(0, 16); // Short ID for display
  }

  /**
   * Create a commitment (blinded value for Freebird)
   * @param {Uint8Array} publicKey
   * @param {Uint8Array} blindingFactor
   * @returns {Promise<Uint8Array>}
   */
  async function createCommitment(publicKey, blindingFactor) {
    return await sha256(publicKey, blindingFactor, 'commitment');
  }

  /**
   * Create a nullifier for the token (unique spend identifier)
   * @param {Uint8Array} secretKey
   * @param {string} tokenId
   * @returns {Promise<Uint8Array>}
   */
  async function createNullifier(secretKey, tokenId) {
    return await sha256(secretKey, tokenId, 'nullifier');
  }

  /**
   * Create ownership proof (simplified Schnorr-like signature)
   * @param {Uint8Array} secretKey
   * @param {Uint8Array} message
   * @returns {Promise<Uint8Array>}
   */
  async function createOwnershipProof(secretKey, message) {
    const k = randomBytes(32); // Nonce
    const R = await sha256(k, 'R'); // Commitment
    const e = await sha256(R, message); // Challenge

    // Response (simplified)
    const s = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      s[i] = (k[i] + secretKey[i] * e[i]) & 0xff;
    }

    // Proof = R || s
    const proof = new Uint8Array(64);
    proof.set(R.slice(0, 32));
    proof.set(s, 32);

    return proof;
  }

  /**
   * Get or create wallet from storage
   * @returns {Promise<{secretKey: Uint8Array, publicKey: Uint8Array, publicKeyHex: string}>}
   */
  async function getOrCreateWallet() {
    const stored = localStorage.getItem(STORAGE_KEY);

    if (stored) {
      try {
        const data = JSON.parse(stored);
        return {
          secretKey: fromHex(data.secretKey),
          publicKey: fromHex(data.publicKey),
          publicKeyHex: data.publicKey
        };
      } catch (e) {
        console.warn('Failed to parse stored wallet, creating new one');
      }
    }

    const keypair = await generateKeypair();
    const walletData = {
      secretKey: toHex(keypair.secretKey),
      publicKey: toHex(keypair.publicKey),
      created: Date.now()
    };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(walletData));

    return {
      secretKey: keypair.secretKey,
      publicKey: keypair.publicKey,
      publicKeyHex: walletData.publicKey
    };
  }

  /**
   * Store a token
   * @param {Object} token
   */
  function storeToken(token) {
    const tokens = getTokens();
    tokens[token.id] = token;
    localStorage.setItem(TOKENS_KEY, JSON.stringify(tokens));
  }

  /**
   * Get all stored tokens
   * @returns {Object}
   */
  function getTokens() {
    try {
      return JSON.parse(localStorage.getItem(TOKENS_KEY) || '{}');
    } catch {
      return {};
    }
  }

  /**
   * Get a specific token
   * @param {string} id
   * @returns {Object|null}
   */
  function getToken(id) {
    return getTokens()[id] || null;
  }

  /**
   * Delete a token
   * @param {string} id
   */
  function deleteToken(id) {
    const tokens = getTokens();
    delete tokens[id];
    localStorage.setItem(TOKENS_KEY, JSON.stringify(tokens));
  }

  /**
   * Get active (non-expired) tokens
   * @returns {Array}
   */
  function getActiveTokens() {
    const tokens = getTokens();
    const now = Date.now();
    return Object.values(tokens).filter(t => t.expiresAt > now);
  }

  /**
   * Clear wallet and all tokens
   */
  function clearAll() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(TOKENS_KEY);
  }

  /**
   * Generate a short code for sharing
   * @param {number} length
   * @returns {string}
   */
  function generateShortCode(length = 8) {
    const chars = 'abcdefghjkmnpqrstuvwxyz23456789'; // Avoid confusing chars
    let code = '';
    const bytes = randomBytes(length);
    for (let i = 0; i < length; i++) {
      code += chars[bytes[i] % chars.length];
    }
    return code;
  }

  // Public API
  return {
    randomBytes,
    toHex,
    fromHex,
    sha256,
    generateKeypair,
    createTokenId,
    createCommitment,
    createNullifier,
    createOwnershipProof,
    getOrCreateWallet,
    storeToken,
    getTokens,
    getToken,
    deleteToken,
    getActiveTokens,
    clearAll,
    generateShortCode
  };
})();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ScarbucksWallet;
}
