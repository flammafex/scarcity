/**
 * Configuration management for CLI
 *
 * Manages network settings (Witness, Freebird, HyperToken, Tor)
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export interface ScarcityConfig {
  version: string;
  witness: {
    gatewayUrl: string;
    networkId: string;
  };
  freebird: {
    issuerEndpoints: string[];
    verifierUrl: string;
  };
  hypertoken: {
    relayUrl: string;
  };
  tor: {
    enabled: boolean;
    proxyHost: string;
    proxyPort: number;
  };
}

export const DEFAULT_CONFIG: ScarcityConfig = {
  version: '1.0',
  witness: {
    gatewayUrl: 'http://localhost:8080',
    networkId: 'scarcity-testnet'
  },
  freebird: {
    issuerEndpoints: ['http://localhost:8081'],
    verifierUrl: 'http://localhost:8082'
  },
  hypertoken: {
    relayUrl: 'ws://localhost:3000'
  },
  tor: {
    enabled: false,
    proxyHost: 'localhost',
    proxyPort: 9050
  }
};

export class ConfigManager {
  private configPath: string;
  private config: ScarcityConfig;

  constructor(customPath?: string) {
    this.configPath = customPath || join(homedir(), '.scarcity', 'config.json');
    this.ensureConfigDir();
    this.config = this.loadConfig();
  }

  /**
   * Ensure config directory exists
   */
  private ensureConfigDir(): void {
    const dir = join(homedir(), '.scarcity');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Load config from disk and apply environment overrides
   */
  private loadConfig(): ScarcityConfig {
    let loadedConfig: Partial<ScarcityConfig> = {};

    // 1. Load from file if exists
    if (existsSync(this.configPath)) {
      try {
        const data = readFileSync(this.configPath, 'utf-8');
        loadedConfig = JSON.parse(data);
      } catch (error) {
        console.warn('Failed to load config file, using defaults');
      }
    }

    // 2. Merge with defaults
    const config = {
      ...DEFAULT_CONFIG,
      ...loadedConfig,
      witness: { ...DEFAULT_CONFIG.witness, ...loadedConfig.witness },
      freebird: { ...DEFAULT_CONFIG.freebird, ...loadedConfig.freebird },
      hypertoken: { ...DEFAULT_CONFIG.hypertoken, ...loadedConfig.hypertoken },
      tor: { ...DEFAULT_CONFIG.tor, ...loadedConfig.tor }
    };

    // 3. Apply Environment Variable Overrides (Docker/Cloud support)
    // These take precedence over both defaults and local config file
    
    if (process.env.WITNESS_GATEWAY_URL) {
      config.witness.gatewayUrl = process.env.WITNESS_GATEWAY_URL;
    }
    
    if (process.env.WITNESS_NETWORK_ID) {
      config.witness.networkId = process.env.WITNESS_NETWORK_ID;
    }

    if (process.env.FREEBIRD_ISSUER_URL) {
      // Docker env usually provides a single URL, treat as single-endpoint list
      config.freebird.issuerEndpoints = [process.env.FREEBIRD_ISSUER_URL];
    }

    if (process.env.FREEBIRD_VERIFIER_URL) {
      config.freebird.verifierUrl = process.env.FREEBIRD_VERIFIER_URL;
    }

    if (process.env.HYPERTOKEN_RELAY_URL) {
      config.hypertoken.relayUrl = process.env.HYPERTOKEN_RELAY_URL;
    }

    if (process.env.TOR_ENABLED) {
      config.tor.enabled = process.env.TOR_ENABLED === 'true';
    }

    if (process.env.TOR_PROXY) {
      try {
        // Parse socks5://host:port
        const url = new URL(process.env.TOR_PROXY);
        config.tor.proxyHost = url.hostname;
        config.tor.proxyPort = parseInt(url.port, 10);
      } catch (e) {
        // Ignore invalid proxy URL
      }
    }

    return config;
  }

  /**
   * Save config to disk
   */
  private saveConfig(): void {
    const data = JSON.stringify(this.config, null, 2);
    writeFileSync(this.configPath, data, 'utf-8');
  }

  /**
   * Get entire config
   */
  getAll(): ScarcityConfig {
    return { ...this.config };
  }

  /**
   * Get config value by key path (e.g., 'witness.gatewayUrl')
   */
  get(keyPath: string): any {
    const keys = keyPath.split('.');
    let value: any = this.config;

    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Set config value by key path
   */
  set(keyPath: string, value: any): void {
    const keys = keyPath.split('.');
    const lastKey = keys.pop()!;
    let target: any = this.config;

    // Navigate to the parent object
    for (const key of keys) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }
      target = target[key];
    }

    // Set the value
    target[lastKey] = value;
    this.saveConfig();
  }

  /**
   * Reset to defaults
   */
  reset(): void {
    this.config = { ...DEFAULT_CONFIG };
    this.saveConfig();
  }

  /**
   * Get Witness adapter config
   */
  getWitnessConfig() {
    return {
      gatewayUrl: this.config.witness.gatewayUrl,
      networkId: this.config.witness.networkId
    };
  }

  /**
   * Get Freebird adapter config
   */
  getFreebirdConfig() {
    return {
      issuerEndpoints: this.config.freebird.issuerEndpoints,
      verifierUrl: this.config.freebird.verifierUrl,
      tor: this.config.tor.enabled ? {
        proxyHost: this.config.tor.proxyHost,
        proxyPort: this.config.tor.proxyPort
      } : undefined
    };
  }

  /**
   * Get HyperToken adapter config
   */
  getHyperTokenConfig() {
    return {
      relayUrl: this.config.hypertoken.relayUrl
    };
  }

  /**
   * Get Tor config
   */
  getTorConfig() {
    return this.config.tor.enabled ? {
      proxyHost: this.config.tor.proxyHost,
      proxyPort: this.config.tor.proxyPort
    } : undefined;
  }
}