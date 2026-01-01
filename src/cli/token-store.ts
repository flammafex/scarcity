/**
 * Token storage for CLI
 *
 * Manages local storage of tokens and their metadata
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export interface StoredToken {
  id: string;
  amount: number;
  secretKey: string;
  wallet: string;
  created: number;
  spent: boolean;
  spentAt?: number;
  metadata?: {
    type?: 'minted' | 'received' | 'split' | 'merged';
    source?: string;
    notes?: string;
  };
}

export interface TokenStore {
  version: string;
  tokens: { [id: string]: StoredToken };
}

export class TokenStorage {
  private storePath: string;
  private store: TokenStore;

  constructor(customPath?: string) {
    this.storePath = customPath || join(homedir(), '.scarcity', 'tokens.json');
    this.ensureStoreDir();
    this.store = this.loadStore();
  }

  /**
   * Ensure storage directory exists
   */
  private ensureStoreDir(): void {
    const dir = join(homedir(), '.scarcity');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Load store from disk
   */
  private loadStore(): TokenStore {
    if (!existsSync(this.storePath)) {
      return {
        version: '1.0',
        tokens: {}
      };
    }

    try {
      const data = readFileSync(this.storePath, 'utf-8');
      return JSON.parse(data);
    } catch (error) {
      console.warn('Failed to load token store, creating new one');
      return {
        version: '1.0',
        tokens: {}
      };
    }
  }

  /**
   * Save store to disk
   */
  private saveStore(): void {
    const data = JSON.stringify(this.store, null, 2);
    writeFileSync(this.storePath, data, 'utf-8');
  }

  /**
   * Add a token to storage
   */
  addToken(token: StoredToken): void {
    this.store.tokens[token.id] = token;
    this.saveStore();
  }

  /**
   * Get a token by ID
   */
  getToken(id: string): StoredToken | undefined {
    return this.store.tokens[id];
  }

  /**
   * List all tokens
   */
  listTokens(filter?: {
    wallet?: string;
    spent?: boolean;
  }): StoredToken[] {
    let tokens = Object.values(this.store.tokens);

    if (filter?.wallet) {
      tokens = tokens.filter(t => t.wallet === filter.wallet);
    }

    if (filter?.spent !== undefined) {
      tokens = tokens.filter(t => t.spent === filter.spent);
    }

    return tokens.sort((a, b) => b.created - a.created);
  }

  /**
   * Mark token as spent
   */
  markSpent(id: string): void {
    const token = this.store.tokens[id];
    if (token) {
      token.spent = true;
      token.spentAt = Date.now();
      this.saveStore();
    }
  }

  /**
   * Delete a token
   */
  deleteToken(id: string): void {
    delete this.store.tokens[id];
    this.saveStore();
  }

  /**
   * Get total balance for a wallet
   */
  getBalance(wallet: string): number {
    return this.listTokens({ wallet, spent: false })
      .reduce((sum, token) => sum + token.amount, 0);
  }

  /**
   * Get token count
   */
  getTokenCount(wallet?: string, spent?: boolean): number {
    return this.listTokens({ wallet, spent }).length;
  }
}
