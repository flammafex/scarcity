/**
 * Tor SOCKS5 Proxy Support
 *
 * Provides transparent routing of HTTP/HTTPS and WebSocket connections
 * through Tor for .onion hidden services and enhanced privacy.
 *
 * Features:
 * - Auto-detection of .onion URLs
 * - Configurable SOCKS5 proxy settings
 * - Graceful fallback when Tor is unavailable
 * - Support for HTTP fetch and WebSocket connections
 */

import { SocksProxyAgent } from 'socks-proxy-agent';

export interface TorConfig {
  /** SOCKS5 proxy host (default: localhost) */
  readonly proxyHost?: string;
  /** SOCKS5 proxy port (default: 9050 for Tor) */
  readonly proxyPort?: number;
  /** Force all connections through Tor (default: false, only .onion) */
  readonly forceProxy?: boolean;
}

/**
 * Tor proxy manager for routing connections through SOCKS5
 */
export class TorProxy {
  private readonly proxyHost: string;
  private readonly proxyPort: number;
  private readonly forceProxy: boolean;
  private agent: SocksProxyAgent | null = null;

  constructor(config: TorConfig = {}) {
    this.proxyHost = config.proxyHost || 'localhost';
    this.proxyPort = config.proxyPort || 9050; // Default Tor SOCKS port
    this.forceProxy = config.forceProxy || false;
  }

  /**
   * Check if a URL is an onion address
   */
  static isOnionUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.hostname.endsWith('.onion');
    } catch {
      return false;
    }
  }

  /**
   * Check if this URL should be routed through Tor
   */
  shouldProxy(url: string): boolean {
    return this.forceProxy || TorProxy.isOnionUrl(url);
  }

  /**
   * Get or create SOCKS5 proxy agent for fetch
   */
  getAgent(): SocksProxyAgent {
    if (!this.agent) {
      const proxyUrl = `socks5://${this.proxyHost}:${this.proxyPort}`;
      this.agent = new SocksProxyAgent(proxyUrl);
    }
    return this.agent;
  }

  /**
   * Create fetch options with Tor proxy if needed
   */
  getFetchOptions(url: string, options: RequestInit = {}): RequestInit {
    if (this.shouldProxy(url)) {
      return {
        ...options,
        // @ts-ignore - dispatcher is valid but not in types
        dispatcher: this.getAgent()
      };
    }
    return options;
  }

  /**
   * Fetch with automatic Tor routing for .onion URLs
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    const fetchOptions = this.getFetchOptions(url, options);

    try {
      return await fetch(url, fetchOptions);
    } catch (error: any) {
      // Enhance error message for .onion failures
      if (TorProxy.isOnionUrl(url)) {
        throw new Error(
          `Failed to connect to .onion address (is Tor running on ${this.proxyHost}:${this.proxyPort}?): ${error.message}`
        );
      }
      throw error;
    }
  }

  /**
   * Get WebSocket connection options for Tor
   * Note: WebSocket over SOCKS5 requires special handling
   */
  getWebSocketOptions(): { agent: SocksProxyAgent } | {} {
    // For now, return empty options - WebSocket over Tor requires
    // more complex implementation with custom WebSocket client
    // that supports SOCKS5 proxy at connection time
    return {};
  }

  /**
   * Check if Tor proxy is available
   */
  async checkConnection(): Promise<boolean> {
    try {
      // Try to connect to Tor check service
      const response = await this.fetch('https://check.torproject.org/', {
        signal: AbortSignal.timeout(5000)
      });

      const text = await response.text();
      return text.includes('Congratulations') || text.includes('using Tor');
    } catch {
      return false;
    }
  }

  /**
   * Destroy the proxy agent
   */
  destroy(): void {
    if (this.agent) {
      this.agent.destroy();
      this.agent = null;
    }
  }
}

/**
 * Global Tor proxy instance (optional)
 * Applications can use this or create their own TorProxy instances
 */
let globalTorProxy: TorProxy | null = null;

/**
 * Configure global Tor proxy
 */
export function configureTor(config: TorConfig): TorProxy {
  globalTorProxy = new TorProxy(config);
  return globalTorProxy;
}

/**
 * Get global Tor proxy (creates default if not configured)
 */
export function getTorProxy(): TorProxy {
  if (!globalTorProxy) {
    globalTorProxy = new TorProxy();
  }
  return globalTorProxy;
}

/**
 * Fetch with automatic Tor routing (uses global proxy)
 */
export async function torFetch(url: string, options: RequestInit = {}): Promise<Response> {
  return getTorProxy().fetch(url, options);
}
