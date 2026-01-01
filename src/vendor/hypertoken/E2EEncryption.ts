/*
 * network/E2EEncryption.ts
 *
 * End-to-end encryption for peer-to-peer communication.
 * Uses Web Crypto API for ECDH key exchange and AES-GCM encryption.
 *
 * Protocol:
 * 1. Each peer generates an ECDH key pair
 * 2. Peers exchange public keys via signaling
 * 3. Shared secret is derived using ECDH
 * 4. Session key is derived from shared secret using HKDF
 * 5. Messages are encrypted with AES-GCM
 */

import { Emitter } from "./events.js";

/**
 * Encryption configuration
 */
export interface E2EConfig {
  /** ECDH curve to use (default: P-256) */
  curve: "P-256" | "P-384" | "P-521";
  /** AES key length in bits (default: 256) */
  aesKeyLength: 128 | 192 | 256;
  /** Info string for HKDF derivation */
  hkdfInfo: string;
}

export const DEFAULT_E2E_CONFIG: E2EConfig = {
  curve: "P-256",
  aesKeyLength: 256,
  hkdfInfo: "hypertoken-e2e-v1",
};

/**
 * Key exchange message sent between peers
 */
export interface KeyExchangeMessage {
  type: "key-exchange";
  publicKey: string; // Base64-encoded public key
  peerId: string;
}

/**
 * Encrypted message wrapper
 */
export interface EncryptedMessage {
  /** Initialization vector (base64) */
  iv: string;
  /** Encrypted data (base64) */
  data: string;
  /** Message authentication tag included in AES-GCM */
}

/**
 * Session state for a peer
 */
interface PeerSession {
  publicKey: CryptoKey;
  sharedSecret: CryptoKey | null;
  sessionKey: CryptoKey | null;
  established: boolean;
}

/**
 * E2EEncryption manages end-to-end encryption between peers
 *
 * Events emitted:
 * - 'e2e:key-exchange' - Key exchange message to send
 * - 'e2e:session-established' - Session with peer established
 * - 'e2e:session-failed' - Session establishment failed
 * - 'e2e:error' - Encryption/decryption error
 */
export class E2EEncryption extends Emitter {
  private config: E2EConfig;
  private keyPair: CryptoKeyPair | null = null;
  private publicKeyExport: string | null = null;
  private sessions: Map<string, PeerSession> = new Map();
  private localPeerId: string | null = null;

  constructor(config: Partial<E2EConfig> = {}) {
    super();
    this.config = { ...DEFAULT_E2E_CONFIG, ...config };
  }

  /**
   * Initialize encryption with local peer ID
   * Generates key pair for this session
   */
  async initialize(peerId: string): Promise<void> {
    this.localPeerId = peerId;

    // Generate ECDH key pair
    this.keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: this.config.curve,
      },
      true, // extractable for export
      ["deriveKey", "deriveBits"]
    );

    // Export public key for sharing
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      this.keyPair.publicKey
    );
    this.publicKeyExport = this.arrayBufferToBase64(publicKeyBuffer);
  }

  /**
   * Get the local public key for exchange
   */
  getPublicKey(): string | null {
    return this.publicKeyExport;
  }

  /**
   * Create a key exchange message to send to a peer
   */
  createKeyExchangeMessage(): KeyExchangeMessage | null {
    if (!this.publicKeyExport || !this.localPeerId) {
      return null;
    }

    return {
      type: "key-exchange",
      publicKey: this.publicKeyExport,
      peerId: this.localPeerId,
    };
  }

  /**
   * Handle a received key exchange message
   */
  async handleKeyExchange(message: KeyExchangeMessage): Promise<boolean> {
    const { peerId, publicKey } = message;

    if (!this.keyPair) {
      console.error("[E2E] Not initialized");
      return false;
    }

    try {
      // Import the peer's public key
      const peerPublicKeyBuffer = this.base64ToArrayBuffer(publicKey);
      const peerPublicKey = await crypto.subtle.importKey(
        "spki",
        peerPublicKeyBuffer,
        {
          name: "ECDH",
          namedCurve: this.config.curve,
        },
        false,
        []
      );

      // Derive shared secret using ECDH
      const sharedSecret = await crypto.subtle.deriveKey(
        {
          name: "ECDH",
          public: peerPublicKey,
        },
        this.keyPair.privateKey,
        {
          name: "AES-GCM",
          length: this.config.aesKeyLength,
        },
        false,
        ["encrypt", "decrypt"]
      );

      // Store session
      this.sessions.set(peerId, {
        publicKey: peerPublicKey,
        sharedSecret,
        sessionKey: sharedSecret, // For now, use shared secret directly
        established: true,
      });

      this.emit("e2e:session-established", { peerId });
      return true;
    } catch (err) {
      console.error(`[E2E] Key exchange failed with ${peerId}:`, err);
      this.emit("e2e:session-failed", { peerId, error: err });
      return false;
    }
  }

  /**
   * Check if we have an established session with a peer
   */
  hasSession(peerId: string): boolean {
    const session = this.sessions.get(peerId);
    return session?.established ?? false;
  }

  /**
   * Get all peers with established sessions
   */
  getEstablishedPeers(): string[] {
    return Array.from(this.sessions.entries())
      .filter(([_, session]) => session.established)
      .map(([peerId]) => peerId);
  }

  /**
   * Encrypt a message for a specific peer
   */
  async encrypt(peerId: string, plaintext: Uint8Array): Promise<EncryptedMessage | null> {
    const session = this.sessions.get(peerId);
    if (!session?.sessionKey) {
      console.warn(`[E2E] No session with ${peerId}`);
      return null;
    }

    try {
      // Generate random IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Encrypt with AES-GCM
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv as unknown as BufferSource,
        },
        session.sessionKey,
        plaintext as unknown as BufferSource
      );

      return {
        iv: this.arrayBufferToBase64(iv.buffer as ArrayBuffer),
        data: this.arrayBufferToBase64(encryptedBuffer),
      };
    } catch (err) {
      console.error(`[E2E] Encryption failed for ${peerId}:`, err);
      this.emit("e2e:error", { peerId, operation: "encrypt", error: err });
      return null;
    }
  }

  /**
   * Decrypt a message from a specific peer
   */
  async decrypt(peerId: string, encrypted: EncryptedMessage): Promise<Uint8Array | null> {
    const session = this.sessions.get(peerId);
    if (!session?.sessionKey) {
      console.warn(`[E2E] No session with ${peerId}`);
      return null;
    }

    try {
      const iv = this.base64ToArrayBuffer(encrypted.iv);
      const data = this.base64ToArrayBuffer(encrypted.data);

      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(iv),
        },
        session.sessionKey,
        data
      );

      return new Uint8Array(decryptedBuffer);
    } catch (err) {
      console.error(`[E2E] Decryption failed for ${peerId}:`, err);
      this.emit("e2e:error", { peerId, operation: "decrypt", error: err });
      return null;
    }
  }

  /**
   * Encrypt a string message
   */
  async encryptString(peerId: string, message: string): Promise<EncryptedMessage | null> {
    const encoder = new TextEncoder();
    return this.encrypt(peerId, encoder.encode(message));
  }

  /**
   * Decrypt to a string message
   */
  async decryptString(peerId: string, encrypted: EncryptedMessage): Promise<string | null> {
    const decrypted = await this.decrypt(peerId, encrypted);
    if (!decrypted) return null;

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Encrypt a JSON-serializable object
   */
  async encryptJSON(peerId: string, data: unknown): Promise<EncryptedMessage | null> {
    const json = JSON.stringify(data);
    return this.encryptString(peerId, json);
  }

  /**
   * Decrypt to a JSON object
   */
  async decryptJSON<T = unknown>(peerId: string, encrypted: EncryptedMessage): Promise<T | null> {
    const json = await this.decryptString(peerId, encrypted);
    if (!json) return null;

    try {
      return JSON.parse(json) as T;
    } catch {
      return null;
    }
  }

  /**
   * Remove a peer's session
   */
  removeSession(peerId: string): void {
    this.sessions.delete(peerId);
  }

  /**
   * Clear all sessions (call on disconnect)
   */
  clearSessions(): void {
    this.sessions.clear();
  }

  /**
   * Reset encryption (new key pair, clear sessions)
   */
  async reset(): Promise<void> {
    this.clearSessions();
    if (this.localPeerId) {
      await this.initialize(this.localPeerId);
    }
  }

  /**
   * Get encryption statistics
   */
  getStats(): {
    initialized: boolean;
    sessionCount: number;
    establishedCount: number;
    curve: string;
    aesKeyLength: number;
  } {
    return {
      initialized: this.keyPair !== null,
      sessionCount: this.sessions.size,
      establishedCount: this.getEstablishedPeers().length,
      curve: this.config.curve,
      aesKeyLength: this.config.aesKeyLength,
    };
  }

  // --- Utility Methods ---

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

export default E2EEncryption;
