/**
 * Wallet management for CLI
 *
 * Handles secure storage of keys and wallet operations
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { Crypto } from '../crypto.js';
import type { PublicKey } from '../types.js';

export interface WalletData {
  name: string;
  publicKey: string;
  secretKey: string;
  created: number;
}

export interface WalletStore {
  version: string;
  wallets: { [name: string]: WalletData };
  defaultWallet?: string;
}

export class WalletManager {
  private walletPath: string;
  private store: WalletStore;

  constructor(customPath?: string) {
    this.walletPath = customPath || join(homedir(), '.scarcity', 'wallets.json');
    this.ensureWalletDir();
    this.store = this.loadStore();
  }

  /**
   * Ensure wallet directory exists
   */
  private ensureWalletDir(): void {
    const dir = join(homedir(), '.scarcity');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Load wallet store from disk
   */
  private loadStore(): WalletStore {
    if (!existsSync(this.walletPath)) {
      return {
        version: '1.0',
        wallets: {}
      };
    }

    try {
      const data = readFileSync(this.walletPath, 'utf-8');
      return JSON.parse(data);
    } catch (error) {
      console.warn('Failed to load wallet store, creating new one');
      return {
        version: '1.0',
        wallets: {}
      };
    }
  }

  /**
   * Save wallet store to disk
   */
  private saveStore(): void {
    const data = JSON.stringify(this.store, null, 2);
    writeFileSync(this.walletPath, data, 'utf-8');
  }

  /**
   * Create a new wallet
   */
  createWallet(name: string, setDefault = true): WalletData {
    if (this.store.wallets[name]) {
      throw new Error(`Wallet '${name}' already exists`);
    }

    const secret = Crypto.randomBytes(32);
    const publicKey = Crypto.hash(secret, 'PUBLIC_KEY');

    const wallet: WalletData = {
      name,
      publicKey: Crypto.toHex(publicKey),
      secretKey: Crypto.toHex(secret),
      created: Date.now()
    };

    this.store.wallets[name] = wallet;

    if (setDefault || !this.store.defaultWallet) {
      this.store.defaultWallet = name;
    }

    this.saveStore();
    return wallet;
  }

  /**
   * Import a wallet from secret key
   */
  importWallet(name: string, secretKeyHex: string, setDefault = false): WalletData {
    if (this.store.wallets[name]) {
      throw new Error(`Wallet '${name}' already exists`);
    }

    const secret = Crypto.fromHex(secretKeyHex);
    const publicKey = Crypto.hash(secret, 'PUBLIC_KEY');

    const wallet: WalletData = {
      name,
      publicKey: Crypto.toHex(publicKey),
      secretKey: secretKeyHex,
      created: Date.now()
    };

    this.store.wallets[name] = wallet;

    if (setDefault || !this.store.defaultWallet) {
      this.store.defaultWallet = name;
    }

    this.saveStore();
    return wallet;
  }

  /**
   * Get a wallet by name
   */
  getWallet(name?: string): WalletData {
    const walletName = name || this.store.defaultWallet;

    if (!walletName) {
      throw new Error('No wallet specified and no default wallet set');
    }

    const wallet = this.store.wallets[walletName];
    if (!wallet) {
      throw new Error(`Wallet '${walletName}' not found`);
    }

    return wallet;
  }

  /**
   * List all wallets
   */
  listWallets(): WalletData[] {
    return Object.values(this.store.wallets);
  }

  /**
   * Delete a wallet
   */
  deleteWallet(name: string): void {
    if (!this.store.wallets[name]) {
      throw new Error(`Wallet '${name}' not found`);
    }

    delete this.store.wallets[name];

    if (this.store.defaultWallet === name) {
      const remaining = Object.keys(this.store.wallets);
      this.store.defaultWallet = remaining.length > 0 ? remaining[0] : undefined;
    }

    this.saveStore();
  }

  /**
   * Set default wallet
   */
  setDefault(name: string): void {
    if (!this.store.wallets[name]) {
      throw new Error(`Wallet '${name}' not found`);
    }

    this.store.defaultWallet = name;
    this.saveStore();
  }

  /**
   * Export wallet secret (for backup)
   */
  exportSecret(name?: string): string {
    const wallet = this.getWallet(name);
    return wallet.secretKey;
  }

  /**
   * Get public key for a wallet
   */
  getPublicKey(name?: string): PublicKey {
    const wallet = this.getWallet(name);
    return {
      bytes: Crypto.fromHex(wallet.publicKey)
    };
  }

  /**
   * Get secret key for a wallet
   */
  getSecretKey(name?: string): Uint8Array {
    const wallet = this.getWallet(name);
    return Crypto.fromHex(wallet.secretKey);
  }

  /**
   * Get default wallet name
   */
  getDefaultWalletName(): string | undefined {
    return this.store.defaultWallet;
  }
}
