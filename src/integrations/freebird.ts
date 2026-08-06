/**
 * Freebird integration adapter (legacy V4/V5 admission).
 *
 * Scarcity uses Freebird only for privacy-preserving admission and
 * authorization. Freebird credentials do not encode Scarcity token IDs,
 * amounts, owners, nullifiers, or demurrage state.
 *
 * NOTE — this is ONE of THREE parallel Freebird surfaces in this repo:
 *   1. This adapter (V4/V5 admission tokens), wired into the core protocol.
 *   2. `src/circulation-v1/` (hand-written Freebird V2 public-bearer exchange +
 *      V2 graph-issuance), a separate subsystem exported as `circulationV1`.
 *   3. `src/vendor/freebird/` (vendored SDK crypto: voprf.ts / p256.ts).
 * A Freebird compatibility review must cover ALL THREE. See AGENTS.md
 * "Freebird integration surfaces".
 *
 * The adapter shells the vendored `@freebird/sdk` `FreebirdClient` (an inner
 * client per issuer endpoint) behind Scarcity's `AdmissionClient` interface.
 * The SDK handles VOPRF blinding/finalization, scope-digest validation, key
 * rotation, and PoW sybil proofs; this adapter preserves the multi-issuer
 * redundancy loop, the insecure-fallback shell, and warn-once plumbing.
 */

import { Crypto } from '../crypto.js';
import type { FreebirdClient } from '../types.js';
import { FreebirdClient as SdkFreebirdClient } from '../vendor/freebird-sdk/index.js';
import { proxyFetch, type ProxyConfig } from '../proxy.js';

/**
 * Decodes a base64url string into bytes.
 * Local helper (the vendored Freebird SDK no longer exports this).
 */
function base64UrlToBytes(base64: string): Uint8Array {
  const normalized = base64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
  const binString = atob(padded);
  return Uint8Array.from(binString, (m) => m.codePointAt(0)!);
}

/**
 * Encodes bytes into a base64url string.
 * Local helper (the vendored Freebird SDK no longer exports this).
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export interface FreebirdAdapterConfig {
  readonly issuerEndpoints: string[];
  readonly verifierUrl: string;
  /**
   * Enables insecure offline fallback behavior when issuer/verifier are unavailable.
   * Intended for local development/testing only.
   */
  readonly allowInsecureFallback?: boolean;
  /**
   * Optional SOCKS5 proxy for routing issuer/verifier HTTP traffic through a
   * privacy-preserving transport (e.g. Tor). When set, all SDK fetches go
   * through the proxy; when omitted, direct connections are used.
   */
  readonly proxy?: ProxyConfig;
}

export class FreebirdAdapter implements FreebirdClient {
  private readonly issuerEndpoints: string[];
  private readonly verifierUrl: string;
  private readonly allowInsecureFallback: boolean;
  private readonly proxy?: ProxyConfig;
  // One SDK client per issuer endpoint (multi-issuer redundancy).
  private readonly clients = new Map<string, SdkFreebirdClient>();
  private noIssuersWarningLogged = false;
  private warningKeys = new Set<string>();

  constructor(config: FreebirdAdapterConfig) {
    if (!config.issuerEndpoints || config.issuerEndpoints.length === 0) {
      throw new Error('At least one issuer endpoint is required');
    }

    this.issuerEndpoints = config.issuerEndpoints;
    this.verifierUrl = config.verifierUrl;
    this.proxy = config.proxy;
    const envFallback =
      typeof process !== 'undefined' &&
      !!process.env &&
      process.env.SCARCITY_ALLOW_INSECURE_FALLBACK === 'true';
    this.allowInsecureFallback = config.allowInsecureFallback ?? envFallback;

    if (this.issuerEndpoints.length > 1) {
      console.log(`[Freebird] Configured with ${this.issuerEndpoints.length} issuers for redundancy`);
    }
  }

  private async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    const pf = proxyFetch(this.proxy);
    return pf ? pf(url, options) : fetch(url, options);
  }

  private warningOnce(key: string, message: string): void {
    if (this.warningKeys.has(key)) return;
    this.warningKeys.add(key);
    console.warn(message);
  }

  private summarizeError(error: unknown): string {
    if (error instanceof Error) {
      const code = (error as { code?: unknown }).code;
      if (typeof code === 'string' && code.length > 0) {
        return `${code}: ${error.message}`;
      }
      return error.message || error.name;
    }
    if (error && typeof error === 'object') {
      const code = (error as { code?: unknown }).code;
      const message = (error as { message?: unknown }).message;
      if (typeof code === 'string' && typeof message === 'string') {
        return `${code}: ${message}`;
      }
      if (typeof message === 'string') {
        return message;
      }
      if (typeof code === 'string') {
        return code;
      }
    }
    return String(error ?? 'unknown error');
  }

  /**
   * Build (lazily) the SDK client for a single issuer endpoint.
   *
   * When the verifier is unreachable and insecure fallback is enabled, the
   * client is constructed with the fallback scope override and NO verifierUrl,
   * so the SDK's `init()` does not throw on the verifier fetch (matching the
   * adapter's historical degraded-mode behavior).
   */
  private clientFor(url: string): SdkFreebirdClient {
    const existing = this.clients.get(url);
    if (existing) return existing;

    const config: {
      issuerUrl: string;
      verifierUrl?: string;
      verifierId?: string;
      audience?: string;
      fetch?: typeof fetch;
    } = { issuerUrl: url };

    if (this.verifierUrl) {
      config.verifierUrl = this.verifierUrl;
    } else if (this.allowInsecureFallback) {
      config.verifierId = 'scarcity-dev-verifier';
      config.audience = 'scarcity';
    }

    const pf = proxyFetch(this.proxy);
    if (pf) config.fetch = pf;

    return new SdkFreebirdClient(config);
  }

  private async init(): Promise<void> {
    if (this.clients.size > 0) return;

    const results = await Promise.allSettled(
      this.issuerEndpoints.map(async (url) => {
        const client = this.clientFor(url);
        await client.init();
        return { url, client };
      })
    );

    // Only retain clients whose init() succeeded. A client whose init() threw
    // (e.g. issuer unreachable) must NOT be counted as available — otherwise
    // issueAdmissionToken would try it and fail instead of falling back.
    for (const r of results) {
      if (r.status === 'fulfilled') {
        this.clients.set(r.value.url, r.value.client);
      }
    }

    const successCount = this.clients.size;

    if (successCount > 0) {
      console.log(`[Freebird] Connected to ${successCount}/${this.issuerEndpoints.length} issuers`);
      this.noIssuersWarningLogged = false;
    } else if (!this.noIssuersWarningLogged) {
      console.warn('[Freebird] No issuers available, using configured fallback/error behavior');
      this.noIssuersWarningLogged = true;
    }
  }

  /**
   * Issue a Freebird V4 private-verification admission token.
   */
  async issueAdmissionToken(): Promise<Uint8Array> {
    await this.init();

    if (this.clients.size === 0) {
      if (!this.allowInsecureFallback) {
        throw new Error(
          'Admission token issuance failed: no Freebird issuer available. ' +
          'Set SCARCITY_ALLOW_INSECURE_FALLBACK=true (or allowInsecureFallback) for local/dev fallback mode.'
        );
      }
      this.warningOnce(
        'issueAdmissionToken:fallback',
        '[Freebird] No issuer available, using INSECURE fallback admission token. DO NOT USE IN PRODUCTION.'
      );
      return Crypto.hash(new TextEncoder().encode('freebird-fallback-admission'), Crypto.randomBytes(32), Date.now());
    }

    for (const url of this.issuerEndpoints) {
      const client = this.clients.get(url);
      if (!client) continue;

      try {
        const token = await client.issueToken();
        console.log(`[Freebird] V4 admission token issued from ${url}`);
        return base64UrlToBytes(token.tokenValue);
      } catch (error) {
        this.warningOnce(
          `issueAdmission:${url}`,
          `[Freebird] Request to ${url} failed (${this.summarizeError(error)}), trying next`
        );
      }
    }

    throw new Error('All configured issuers failed to issue admission token');
  }

  async verifyAdmissionToken(token: Uint8Array): Promise<boolean> {
    if (!this.verifierUrl) {
      throw new Error('Admission token verification failed: no verifier URL configured');
    }

    try {
      // Any one client suffices for verification (it only needs the verifier).
      const client = this.clients.values().next().value as SdkFreebirdClient | undefined;
      if (!client) {
        throw new Error('no Freebird client initialized');
      }
      // The SDK's verifyToken only reads tokenValue; issuerId is unused, so pass
      // an empty string (never parse the fallback blob, which is not V4 wire).
      const valid = await client.verifyTokenValid({ tokenValue: bytesToBase64Url(token), issuerId: '' });
      return valid;
    } catch (error) {
      if (!this.allowInsecureFallback) {
        throw error;
      }
      this.warningOnce(
        'verifyAdmissionToken:fallback',
        `[Freebird] Verifier unreachable (${this.summarizeError(error)}), using insecure fallback`
      );
      return token.length > 0;
    }
  }
}
