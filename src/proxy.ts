/**
 * SOCKS5 proxy transport for network-level privacy.
 *
 * Provides an injectable `fetch` that routes outbound HTTP through a SOCKS5
 * proxy (e.g. Tor at localhost:9050, or any SOCKS5 proxy). This lets the
 * Freebird and Witness adapters hide the client's IP address from the issuer,
 * verifier, and gateway — closing the network-metadata privacy gap without
 * changing the underlying services.
 *
 * The returned `fetch` is passed into the SDK clients via their injectable
 * `fetch` hooks (Freebird `ClientConfig.fetch`, Witness `WitnessClient.fetch`).
 */

import { SocksProxyAgent } from 'socks-proxy-agent';

export interface ProxyConfig {
  /** SOCKS5 proxy host (default: localhost) */
  readonly proxyHost?: string;
  /** SOCKS5 proxy port (default: 9050 for Tor) */
  readonly proxyPort?: number;
}

/**
 * Build a `fetch` implementation that routes through the given SOCKS5 proxy.
 *
 * Returns `null` when no proxy is configured, so callers can fall back to the
 * global `fetch`.
 */
export function proxyFetch(config?: ProxyConfig): typeof fetch | null {
  if (!config) return null;

  const host = config.proxyHost || 'localhost';
  const port = config.proxyPort || 9050;
  const agent = new SocksProxyAgent(`socks5://${host}:${port}`);

  return (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    return fetch(input, {
      ...init,
      // @ts-ignore - `dispatcher` is a valid undici option not in the DOM types.
      dispatcher: agent,
    });
  };
}
