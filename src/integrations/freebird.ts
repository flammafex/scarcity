/**
 * Freebird integration adapter.
 *
 * Scarcity uses Freebird only for privacy-preserving admission and
 * authorization. Freebird credentials do not encode Scarcity token IDs,
 * amounts, owners, nullifiers, or demurrage state.
 */

import { Crypto } from '../crypto.js';
import type { FreebirdClient, TorConfig } from '../types.js';
import * as voprf from '../vendor/freebird/voprf.js';
import { TorProxy } from '../tor.js';

export interface FreebirdAdapterConfig {
  readonly issuerEndpoints: string[];
  readonly verifierUrl: string;
  readonly tor?: TorConfig;
  /**
   * Enables insecure offline fallback behavior when issuer/verifier are unavailable.
   * Intended for local development/testing only.
   */
  readonly allowInsecureFallback?: boolean;
}

interface IssuerMetadata {
  issuer_id: string;
  voprf: {
    kid: string;
    pubkey: string;
  };
}

interface VerifierMetadata {
  verifier_id: string;
  audience: string;
  scope_digest_b64: string;
}

export class FreebirdAdapter implements FreebirdClient {
  private readonly issuerEndpoints: string[];
  private readonly verifierUrl: string;
  private readonly context: Uint8Array;
  private readonly tor: TorProxy | null;
  private readonly allowInsecureFallback: boolean;
  private metadata: Map<string, IssuerMetadata> = new Map();
  private verifierMetadata?: VerifierMetadata;
  private noIssuersWarningLogged = false;
  private warningKeys = new Set<string>();

  constructor(config: FreebirdAdapterConfig) {
    if (!config.issuerEndpoints || config.issuerEndpoints.length === 0) {
      throw new Error('At least one issuer endpoint is required');
    }

    this.issuerEndpoints = config.issuerEndpoints;
    this.verifierUrl = config.verifierUrl;
    this.tor = config.tor ? new TorProxy(config.tor) : null;
    const envFallback =
      typeof process !== 'undefined' &&
      !!process.env &&
      process.env.SCARCITY_ALLOW_INSECURE_FALLBACK === 'true';
    this.allowInsecureFallback = config.allowInsecureFallback ?? envFallback;
    this.context = new TextEncoder().encode('freebird:v4');

    const hasOnion = this.issuerEndpoints.some(url => TorProxy.isOnionUrl(url)) ||
      TorProxy.isOnionUrl(this.verifierUrl);

    if (hasOnion) {
      if (this.tor) {
        console.log('[Freebird] Tor enabled for .onion addresses');
      } else {
        console.warn('[Freebird] .onion URL detected but Tor not configured');
      }
    }

    if (this.issuerEndpoints.length > 1) {
      console.log(`[Freebird] Configured with ${this.issuerEndpoints.length} issuers for redundancy`);
    }
  }

  private async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    if (this.tor) {
      return this.tor.fetch(url, options);
    }
    return fetch(url, options);
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

  private async init(): Promise<void> {
    if (this.metadata.size > 0) return;

    const metadataPromises = this.issuerEndpoints.map(async (url, index) => {
      try {
        const response = await this.fetch(`${url}/.well-known/issuer`);
        if (response.ok) {
          const data = await response.json() as IssuerMetadata;
          this.metadata.set(url, data);
          return { url, index, success: true, data };
        }
        return { url, index, success: false };
      } catch (error) {
        this.warningOnce(
          `init:${url}`,
          `[Freebird] Issuer ${url} not available (${this.summarizeError(error)})`
        );
        return { url, index, success: false };
      }
    });

    const results = await Promise.all(metadataPromises);
    const successCount = results.filter(r => r.success).length;

    if (successCount > 0) {
      console.log(`[Freebird] Connected to ${successCount}/${this.issuerEndpoints.length} issuers`);
      this.noIssuersWarningLogged = false;
    } else if (!this.noIssuersWarningLogged) {
      console.warn('[Freebird] No issuers available, using configured fallback/error behavior');
      this.noIssuersWarningLogged = true;
    }
  }

  private async getVerifierMetadata(): Promise<VerifierMetadata> {
    if (this.verifierMetadata) {
      return this.verifierMetadata;
    }

    try {
      const response = await this.fetch(`${this.verifierUrl}/.well-known/verifier`);
      if (!response.ok) {
        throw new Error(`verifier returned ${response.status}`);
      }
      const metadata = await response.json() as VerifierMetadata;
      const expectedScopeDigest = voprf.buildScopeDigest(metadata.verifier_id, metadata.audience);
      const scopeDigest = voprf.base64UrlToBytes(metadata.scope_digest_b64);
      if (!this.bytesEqual(scopeDigest, expectedScopeDigest)) {
        throw new Error('verifier scope metadata is inconsistent');
      }
      this.verifierMetadata = metadata;
      return metadata;
    } catch (error) {
      if (!this.allowInsecureFallback) {
        throw error;
      }
      this.warningOnce(
        'verifierMetadata:fallback',
        `[Freebird] Verifier metadata unavailable (${this.summarizeError(error)}), using insecure fallback scope`
      );
      const verifier_id = 'scarcity-dev-verifier';
      const audience = 'scarcity';
      return {
        verifier_id,
        audience,
        scope_digest_b64: voprf.bytesToBase64Url(voprf.buildScopeDigest(verifier_id, audience))
      };
    }
  }

  /**
   * Issue a Freebird V4 private-verification admission token.
   */
  async issueAdmissionToken(): Promise<Uint8Array> {
    await this.init();

    if (this.metadata.size === 0) {
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

    const verifier = await this.getVerifierMetadata();
    const scopeDigest = voprf.base64UrlToBytes(verifier.scope_digest_b64);

    for (const url of this.issuerEndpoints) {
      const metadata = this.metadata.get(url);
      if (!metadata) continue;

      try {
        const nonce = Crypto.randomBytes(32);
        const input = voprf.buildPrivateTokenInput(
          metadata.issuer_id,
          metadata.voprf.kid,
          nonce,
          scopeDigest
        );
        const { blinded, state } = voprf.blind(input, this.context);

        const response = await this.fetch(`${url}/v1/oprf/issue`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            blinded_element_b64: voprf.bytesToBase64Url(blinded)
          })
        });

        if (!response.ok) {
          console.warn(`[Freebird] Issuer ${url} returned ${response.status}, trying next`);
          continue;
        }

        const data = await response.json() as { token: string; kid: string; issuer_id: string };
        if (data.kid !== metadata.voprf.kid || data.issuer_id !== metadata.issuer_id) {
          throw new Error('issuer metadata changed during issuance');
        }

        const authenticator = voprf.finalize(
          state,
          data.token,
          metadata.voprf.pubkey,
          this.context
        );

        console.log(`[Freebird] V4 admission token issued from ${url}`);
        return voprf.buildRedemptionToken(
          nonce,
          scopeDigest,
          data.kid,
          data.issuer_id,
          authenticator
        );
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
      const response = await this.fetch(`${this.verifierUrl}/v1/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token_b64: voprf.bytesToBase64Url(token)
        })
      });

      if (!response.ok) {
        throw new Error(`admission verification returned ${response.status}`);
      }

      const data = await response.json();
      return data.ok === true;
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

  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }
}
