/**
 * Witness integration adapter
 *
 * Provides timestamped attestations for Scarcity transfers using
 * threshold signature-based timestamping without blockchain.
 *
 * Supports both Ed25519 multi-sig and BLS12-381 aggregated signatures.
 */

import { Crypto } from '../crypto.js';
import type {
  WitnessClient,
  Attestation,
  SophiaWitnessSignedAttestation,
} from '../types.js';
import { WitnessVerifier } from '../vendor/witness-sdk/verify/index.js';
import { proxyFetch, type ProxyConfig } from '../proxy.js';

export interface WitnessAdapterConfig {
  readonly gatewayUrl?: string; // Single gateway (backward compatibility)
  readonly gatewayUrls?: string[]; // Multiple gateways for quorum
  readonly networkId?: string;
  readonly powDifficulty?: number; // Proof-of-work difficulty in bits (default: 0 = disabled)
  readonly quorumThreshold?: number; // Minimum agreements required (default: 2 for 2-of-3)
  /**
   * Enables insecure offline fallback behavior when gateways are unavailable.
   * Intended for local development/testing only.
   */
  readonly allowInsecureFallback?: boolean;
  /**
   * Optional SOCKS5 proxy for routing gateway HTTP traffic through a
   * privacy-preserving transport (e.g. Tor). When set, all gateway fetches go
   * through the proxy; when omitted, direct connections are used.
   */
  readonly proxy?: ProxyConfig;
}

const CONTRACT_VERSION = 'sophia/v1' as const;

/**
 * Thrown when the Witness gateway reports a definitive job failure
 * (status === 'failed'). This is a server-side verdict, NOT an
 * unreachable-gateway condition, so it must never drift into the
 * insecure fallback path (AGENTS.md constraint #6).
 */
class WitnessJobFailedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WitnessJobFailedError';
  }
}

function lowerHex(value: string, name: string): string {
  const normalized = value.toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(`${name} must be lowercase hex`);
  }
  return normalized;
}

function sha256Hex(value: string, name: string): string {
  const normalized = lowerHex(value, name);
  if (normalized.length !== 64) {
    throw new Error(`${name} must be a 32-byte SHA-256 hex value`);
  }
  return normalized;
}

function timestampSeconds(timestamp: number): number {
  return timestamp > 4_200_000_000 ? Math.floor(timestamp / 1000) : timestamp;
}

function timestampMilliseconds(timestamp: number): number {
  return timestamp < 4_200_000_000 ? timestamp * 1000 : timestamp;
}

function normalizeSignatureSet(raw: any): SophiaWitnessSignedAttestation['signatures'] {
  if (Array.isArray(raw)) {
    return {
      kind: 'multisig',
      signatures: raw.map((signature: any, index: number) => ({
        witness_id: String(signature.witness_id),
        signature: lowerHex(String(signature.signature), `signatures[${index}].signature`),
      })),
    };
  }

  if (raw?.kind === 'multisig' && Array.isArray(raw.signatures)) {
    return {
      kind: 'multisig',
      signatures: raw.signatures.map((signature: any, index: number) => ({
        witness_id: String(signature.witness_id),
        signature: lowerHex(String(signature.signature), `signatures[${index}].signature`),
      })),
    };
  }

  if (raw?.kind === 'aggregated' && raw.signature && Array.isArray(raw.signers)) {
    return {
      kind: 'aggregated',
      signature: lowerHex(String(raw.signature), 'signatures.signature'),
      signers: raw.signers.map(String),
    };
  }

  if (Array.isArray(raw?.signatures)) {
    return {
      kind: 'multisig',
      signatures: raw.signatures.map((signature: any, index: number) => ({
        witness_id: String(signature.witness_id),
        signature: lowerHex(String(signature.signature), `signatures[${index}].signature`),
      })),
    };
  }

  if (raw?.signature && Array.isArray(raw.signers)) {
    return {
      kind: 'aggregated',
      signature: lowerHex(String(raw.signature), 'signatures.signature'),
      signers: raw.signers.map(String),
    };
  }

  throw new Error('Witness signatures must be multisig or aggregated');
}

function normalizeSignedAttestation(raw: any): SophiaWitnessSignedAttestation {
  const signed = raw?.attestation?.attestation ? raw.attestation : raw;
  const attestation = signed?.attestation;
  if (!attestation) {
    throw new Error('Witness signed attestation missing attestation');
  }

  return {
    contract_version: CONTRACT_VERSION,
    artifact_type: 'witness.signed_attestation',
    attestation: {
      hash: sha256Hex(String(attestation.hash), 'attestation.hash'),
      timestamp: timestampSeconds(Number(attestation.timestamp)),
      network_id: String(attestation.network_id ?? attestation.networkId),
      sequence: Number(attestation.sequence ?? 0),
    },
    signatures: normalizeSignatureSet(signed.signatures),
  };
}

function signatureCount(canonical: SophiaWitnessSignedAttestation): number {
  return canonical.signatures.kind === 'multisig'
    ? canonical.signatures.signatures.length
    : canonical.signatures.signers.length;
}

function signatureStrings(canonical: SophiaWitnessSignedAttestation): string[] {
  return canonical.signatures.kind === 'multisig'
    ? canonical.signatures.signatures.map(signature => signature.signature)
    : [canonical.signatures.signature];
}

function signerIds(canonical: SophiaWitnessSignedAttestation): string[] {
  return canonical.signatures.kind === 'multisig'
    ? canonical.signatures.signatures.map(signature => signature.witness_id)
    : [...canonical.signatures.signers];
}

function toWireSignedAttestation(canonical: SophiaWitnessSignedAttestation): any {
  const signatures = canonical.signatures.kind === 'multisig'
    ? {
        signatures: canonical.signatures.signatures.map(signature => ({
          witness_id: signature.witness_id,
          signature: signature.signature,
        })),
      }
    : {
        signature: canonical.signatures.signature,
        signers: [...canonical.signatures.signers],
      };

  return {
    attestation: { ...canonical.attestation },
    signatures,
  };
}

/**
 * Adapter for Witness timestamping service
 *
 * Connects to a Witness gateway that coordinates threshold signatures
 * from multiple independent witness nodes for tamper-proof timestamps.
 */
export class WitnessAdapter implements WitnessClient {
  private readonly gatewayUrls: string[];
  private readonly networkId: string;
  private readonly powDifficulty: number;
  private readonly quorumThreshold: number;
  private readonly allowInsecureFallback: boolean;
  private readonly proxy?: ProxyConfig;
  private config: any = null;
  // Local WASM verifier pinned to the fetched network config (Fix: SDK adoption).
  // null when the config is unavailable or the WASM module fails to load —
  // preserves the existing "cannot verify locally → fall through" control flow.
  private verifier: WitnessVerifier | null = null;
  private readonly fallbackWitnessIds = ['fallback-witness-1', 'fallback-witness-2'];
  private warningKeys = new Set<string>();
  private noGatewayWarningLogged = false;
  // Bounded polling budget for attestation jobs (Fix 1)
  private readonly jobPollTimeoutMs = 30_000;
  private readonly jobPollBaseDelayMs = 500;
  private readonly jobPollMaxDelayMs = 5_000;

  constructor(config: WitnessAdapterConfig) {
    // Support both single gateway (backward compatibility) and multiple gateways
    if (config.gatewayUrls && config.gatewayUrls.length > 0) {
      this.gatewayUrls = [...config.gatewayUrls];
    } else if (config.gatewayUrl) {
      this.gatewayUrls = [config.gatewayUrl];
    } else {
      throw new Error('WitnessAdapter requires either gatewayUrl or gatewayUrls');
    }

    this.networkId = config.networkId ?? 'scarcity-network';
    this.powDifficulty = config.powDifficulty ?? 0; // Default: disabled
    const envFallback =
      typeof process !== 'undefined' &&
      !!process.env &&
      process.env.SCARCITY_ALLOW_INSECURE_FALLBACK === 'true';
    this.allowInsecureFallback = config.allowInsecureFallback ?? envFallback;
    this.proxy = config.proxy;

    // Default quorum: 2-of-3 (or majority if different number of gateways)
    this.quorumThreshold = config.quorumThreshold ?? Math.ceil(this.gatewayUrls.length / 2);

    console.log(`[Witness] Configured with ${this.gatewayUrls.length} gateway(s), quorum threshold: ${this.quorumThreshold}`);
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

  private signatureCount(signedAttestation: any): number {
    try {
      return signatureCount(normalizeSignedAttestation(signedAttestation));
    } catch {
      return 0;
    }
  }

  private parseSignedAttestation(data: any, fallbackHash: string): Attestation {
    const canonical = normalizeSignedAttestation(data);

    return {
      hash: canonical.attestation.hash ?? fallbackHash,
      timestamp: timestampMilliseconds(canonical.attestation.timestamp),
      signatures: signatureStrings(canonical),
      witnessIds: signerIds(canonical),
      canonical,
      raw: canonical,
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Effective network id used for local signing/verification.
   * After init, prefer the server-provided config.id over the
   * adapter's constructor default (Fix 2).
   */
  private get effectiveNetworkId(): string {
    return this.config?.id || this.networkId;
  }

  /**
   * Compute the sleep delay before the next attestation poll.
   * Uses the server's next_attempt_at hint when present, otherwise
   * a fixed base delay, both bounded by jobPollMaxDelayMs.
   */
  private computePollDelay(job: any): number {
    if (job?.next_attempt_at) {
      const next = new Date(job.next_attempt_at).getTime();
      const delay = next - Date.now();
      if (Number.isFinite(delay) && delay > 0) {
        return Math.min(delay, this.jobPollMaxDelayMs);
      }
    }
    return this.jobPollBaseDelayMs;
  }

  /**
   * Submit an attestation job to a single gateway and poll it to
   * completion (Fix 1).
   *
   * POST /v1/attestations is idempotent create-or-get. Returns 202 while
   * pending/retryable and 200 when confirmed/failed. Polling is pinned to
   * the gateway that accepted the job (jobs are gateway-local).
   *
   * Throws WitnessJobFailedError on a definitive server-side failure.
   * Returns null on network/transient errors (caller may fall back).
   */
  private async submitAndPollAttestation(gatewayUrl: string, hash: string): Promise<Attestation | null> {
    const response = await this.fetch(`${gatewayUrl}/v1/attestations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // freebird_token is optional and not currently supplied by callers.
      body: JSON.stringify({ hash })
    });

    if (!response.ok) {
      return null;
    }

    let job = await response.json();
    let status: string | undefined = job?.status;

    const deadline = Date.now() + this.jobPollTimeoutMs;
    while (status === 'pending' || status === 'retryable') {
      if (Date.now() > deadline) {
        throw new Error(`[Witness] Timestamp job for ${hash} timed out after ${this.jobPollTimeoutMs}ms`);
      }
      await this.sleep(this.computePollDelay(job));
      const pollResponse = await this.fetch(`${gatewayUrl}/v1/attestations/${hash}`);
      if (!pollResponse.ok) {
        // Transient poll failure — keep polling until the deadline.
        continue;
      }
      job = await pollResponse.json();
      status = job?.status;
    }

    if (status === 'failed') {
      throw new WitnessJobFailedError(
        `[Witness] Timestamp job for ${hash} failed: ${job?.last_error ?? 'unknown error'}`
      );
    }

    if (status === 'confirmed' && job?.signed_attestation) {
      return this.parseSignedAttestation(job.signed_attestation, hash);
    }

    return null;
  }

  /**
   * Initialize by fetching network configuration
   * Tries all gateways and succeeds if at least one responds
   */
  private async init(): Promise<void> {
    if (this.config) return;

    // Try all gateways in parallel
    const configPromises = this.gatewayUrls.map(async (url) => {
      try {
        // Fix 2: full config (witnesses[].{id,pubkey,endpoint}) moved to /v1/network
        const response = await this.fetch(`${url}/v1/network`);
        if (response.ok) {
          return await response.json();
        }
        return null;
      } catch (error) {
        this.warningOnce(
          `init:${url}`,
          `[Witness] Gateway ${url} not available (${this.summarizeError(error)})`
        );
        return null;
      }
    });

    const configs = await Promise.all(configPromises);
    const validConfig = configs.find(c => c !== null);

    if (validConfig) {
      this.config = validConfig;
      // Pin the signature scheme to BLS if the server did not specify one.
      // The Rust serde default is `ed25519`; an `Aggregated × ed25519` dispatch
      // would reject valid BLS attestations (see @witness/sdk verify).
      if (!this.config.signature_scheme) {
        this.config.signature_scheme = 'bls';
      }
      console.log('[Witness] Connected to network:', this.config.id || 'unknown');
      this.noGatewayWarningLogged = false;

      // Build the local WASM verifier pinned to this network config. On any
      // failure (config shape, WASM load) leave it null so verification falls
      // through to the gateway / insecure-fallback paths as before.
      try {
        this.verifier = await WitnessVerifier.create(this.config);
      } catch (error) {
        this.warningOnce(
          'init:verifier',
          `[Witness] Local WASM verifier unavailable (${this.summarizeError(error)})`
        );
        this.verifier = null;
      }
    } else {
      if (!this.noGatewayWarningLogged) {
        console.warn('[Witness] No gateways available, using fallback mode');
        this.noGatewayWarningLogged = true;
      }
    }
  }

  /**
   * Timestamp a hash with Witness federation
   *
   * Submits hash to gateway, which collects threshold signatures
   * from witness nodes and returns signed attestation.
   *
   * LAYER 2: PROOF-OF-WORK - If powDifficulty > 0, solves a computational
   * puzzle before submitting, imposing a "computation cost" on the requester.
   *
   * Multi-gateway: Tries all gateways and returns first successful response
   */
  async timestamp(hash: string): Promise<Attestation> {
    await this.init();

    // Attempt real timestamping if gateway is available
    if (this.config) {
      // Try all gateways in parallel, use first successful response.
      // Each gateway is polled independently (jobs are gateway-local).
      const timestampPromises = this.gatewayUrls.map(async (gatewayUrl) => {
        try {
          return await this.submitAndPollAttestation(gatewayUrl, hash);
        } catch (error) {
          // A definitive server-side job failure must NOT fall back.
          if (error instanceof WitnessJobFailedError) {
            throw error;
          }
          this.warningOnce(
            `timestamp:${gatewayUrl}`,
            `[Witness] Timestamping failed for gateway ${gatewayUrl} (${this.summarizeError(error)})`
          );
          return null;
        }
      });

      // Wait for first successful response
      const results = await Promise.all(timestampPromises);
      const successfulResult = results.find(r => r !== null);

      if (successfulResult) {
        console.log('[Witness] Successfully timestamped via gateway');
        return successfulResult;
      }
    }

    if (!this.allowInsecureFallback) {
      throw new Error(
        'Timestamping failed: no Witness gateway available. ' +
        'Set SCARCITY_ALLOW_INSECURE_FALLBACK=true (or allowInsecureFallback) for local/dev fallback mode.'
      );
    }

    // Fallback mode for local/offline development and tests.
    // Produces a structurally valid attestation without remote guarantees.
    this.warningOnce('timestamp:fallback', '[Witness] ⚠ No gateway available — using INSECURE fallback timestamp. DO NOT USE IN PRODUCTION.');
    const fallbackTimestamp = Date.now();
    const fallbackSignatures = this.fallbackWitnessIds.map((id) =>
      Crypto.hashString(`fallback-sig:${id}:${hash}:${fallbackTimestamp}`)
    );

    return {
      hash,
      timestamp: fallbackTimestamp,
      signatures: fallbackSignatures,
      witnessIds: [...this.fallbackWitnessIds]
    };
  }

  /**
   * Verify a Witness attestation
   *
   * Validates threshold signatures from witness nodes.
   * Supports both Ed25519 multi-sig and BLS12-381 aggregated signatures.
   *
   * IMPORTANT: This method requires actual cryptographic verification.
   * It will throw if no gateway is available and local BLS verification fails.
   */
  async verify(attestation: Attestation): Promise<boolean> {
    await this.init();

    // Basic structural validation first
    if (!attestation.hash || !attestation.timestamp) {
      return false;
    }

    if (!attestation.signatures || attestation.signatures.length === 0) {
      return false;
    }

    if (!attestation.witnessIds || attestation.witnessIds.length !== attestation.signatures.length) {
      return false;
    }

    if (this.config) {
      let canonical: SophiaWitnessSignedAttestation;
      try {
        canonical = this.toCanonicalSignedAttestation(attestation);
      } catch {
        return false;
      }
      const witnessAttestation = toWireSignedAttestation(canonical);

      // Try each gateway sequentially until one succeeds
      for (const gatewayUrl of this.gatewayUrls) {
        try {
          const response = await this.fetch(`${gatewayUrl}/v1/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attestation: witnessAttestation })
          });

          if (response.ok) {
            const data = await response.json();
            return data.valid === true;
          }
        } catch (error) {
          this.warningOnce(
            `verify:${gatewayUrl}`,
            `[Witness] Gateway ${gatewayUrl} verification failed (${this.summarizeError(error)})`
          );
          continue;
        }
      }

      // All gateways failed - try local verification via the pinned WASM verifier.
      // This covers both BLS aggregated and Ed25519 multisig, matching gateway
      // semantics (threshold, duplicate-signer, unknown-witness enforcement).
      if (this.verifier) {
        try {
          const validSigners = this.verifier.verifyAttestation(witnessAttestation);
          console.log(`[Witness] Verified attestation locally (${validSigners} valid signers)`);
          return true;
        } catch (error) {
          // A definitive rejection (bad-signature, sub-threshold, unknown-witness,
          // duplicate-signer) — never falls through to insecure fallback.
          console.log(`[Witness] Local verification rejected attestation: ${this.summarizeError(error)}`);
          return false;
        }
      }
    }

    if (!this.allowInsecureFallback) {
      throw new Error(
        'Attestation verification failed: no Witness gateway available. ' +
        'Set SCARCITY_ALLOW_INSECURE_FALLBACK=true (or allowInsecureFallback) for local/dev fallback mode.'
      );
    }

    // Fallback mode for local/offline development and tests.
    this.warningOnce('verify:fallback', '[Witness] ⚠ No gateway available — using INSECURE fallback verification. DO NOT USE IN PRODUCTION.');
    return (
      attestation.signatures.length >= 2 &&
      attestation.witnessIds.length === attestation.signatures.length
    );
  }

  private toCanonicalSignedAttestation(attestation: Attestation): SophiaWitnessSignedAttestation {
    if (attestation.canonical) {
      return normalizeSignedAttestation(attestation.canonical);
    }

    if (attestation.raw) {
      return normalizeSignedAttestation(attestation.raw);
    }

    return {
      contract_version: CONTRACT_VERSION,
      artifact_type: 'witness.signed_attestation',
      attestation: {
        hash: sha256Hex(attestation.hash, 'attestation.hash'),
        timestamp: timestampSeconds(attestation.timestamp),
        network_id: this.effectiveNetworkId,
        sequence: 0,
      },
      signatures: {
        kind: 'multisig',
        signatures: attestation.signatures.map((sig, idx) => ({
          witness_id: attestation.witnessIds[idx],
          signature: sig,
        })),
      },
    };
  }

  /**
   * Check if nullifier has been seen by Witness network
   *
   * Queries for existing timestamp to detect double-spends.
   *
   * ANTI-CENSORSHIP: Uses quorum voting across multiple gateways.
   * A malicious gateway cannot hide a nullifier - we need quorum agreement.
   *
   * Returns:
   * - 1.0: Quorum agrees nullifier exists (double-spend detected)
   * - 0.0: Quorum agrees nullifier doesn't exist (safe to accept)
   * - 0.5: Split vote or insufficient responses (treat as suspicious)
   */
  async checkNullifier(nullifier: Uint8Array): Promise<number> {
    await this.init();

    const hash = Crypto.toHex(nullifier);

    // Attempt real lookup if gateway is available
    if (this.config) {
      // Query all gateways in parallel
      const checkPromises = this.gatewayUrls.map(async (gatewayUrl) => {
        try {
          const response = await this.fetch(`${gatewayUrl}/v1/attestations/${hash}`);

          if (response.status === 404) {
            return { seen: false, gateway: gatewayUrl };
          }

          if (response.ok) {
            const data = await response.json();
            const status = data?.status;
            if (status === 'confirmed') {
              // Fix 5: count signatures from the signed_attestation, NOT the
              // unsigned plain attestation (data.attestation).
              const sigCount = this.signatureCount(data.signed_attestation);
              const threshold = this.config.threshold || 2;
              return {
                seen: sigCount >= threshold,
                gateway: gatewayUrl
              };
            }
            if (status === 'pending' || status === 'retryable') {
              // Job exists but not yet confirmed — treat as suspicious (0.5),
              // NOT "not seen". Avoids a race where two concurrent spends both
              // pass while the first is still being signed.
              return { seen: false, suspicious: true, gateway: gatewayUrl };
            }
            // failed or unknown status -> not seen
            return { seen: false, gateway: gatewayUrl };
          }

          return null; // Gateway error
        } catch (error) {
          this.warningOnce(
            `nullifier:${gatewayUrl}`,
            `[Witness] Gateway ${gatewayUrl} failed for nullifier check (${this.summarizeError(error)})`
          );
          return null; // Network error
        }
      });

      const results = await Promise.all(checkPromises);
      const validResults = results.filter(r => r !== null);

      if (validResults.length === 0) {
        // All gateways failed — cannot determine safety.
        // Return suspicious (0.5) not safe (0), matching split-vote semantics.
        if (!this.allowInsecureFallback) {
          throw new Error('Nullifier check failed: all Witness gateways unreachable');
        }
        this.warningOnce('checkNullifier:fallback', '[Witness] ⚠ All gateways failed — returning suspicious (0.5). DO NOT USE IN PRODUCTION.');
        return 0.5;
      }

      // Count votes
      const seenCount = validResults.filter(r => r.seen).length;
      const suspiciousCount = validResults.filter(r => r.suspicious).length;
      const notSeenCount = validResults.filter(r => !r.seen && !r.suspicious).length;

      console.log(`[Witness] Nullifier check: ${seenCount}/${validResults.length} gateways report seen (quorum: ${this.quorumThreshold})`);

      // Quorum logic
      if (seenCount >= this.quorumThreshold) {
        // Quorum agrees: nullifier has been seen (DOUBLE-SPEND!)
        return 1.0;
      } else if (notSeenCount >= this.quorumThreshold && suspiciousCount === 0) {
        // Quorum agrees: nullifier has NOT been seen (SAFE)
        return 0.0;
      } else {
        // Split vote, insufficient responses, or a pending job — suspicious!
        // This could indicate a censorship attack or an in-flight spend.
        console.warn('[Witness] Split vote on nullifier check - possible censorship attack');
        return 0.5;
      }
    }

    // No gateway config — cannot check.
    if (!this.allowInsecureFallback) {
      throw new Error('Nullifier check failed: no Witness gateway available');
    }
    return 0.5;
  }

  /**
   * Retrieve attestation for a specific hash
   *
   * Multi-gateway: Tries all gateways and returns first valid attestation
   */
  async getAttestation(hash: string): Promise<Attestation | null> {
    await this.init();

    if (this.config) {
      // Try all gateways in parallel
      const attestationPromises = this.gatewayUrls.map(async (gatewayUrl) => {
        try {
          const response = await this.fetch(`${gatewayUrl}/v1/attestations/${hash}`);

          if (response.status === 404) {
            return null;
          }

          if (response.ok) {
            const data = await response.json();
            // Job wrapper — only a confirmed job carries a signed_attestation.
            if (data?.status === 'confirmed' && data?.signed_attestation) {
              return this.parseSignedAttestation(data.signed_attestation, hash);
            }
            return null;
          }
          return null;
        } catch (error) {
          this.warningOnce(
            `attestation:${gatewayUrl}`,
            `[Witness] Failed to retrieve attestation from ${gatewayUrl} (${this.summarizeError(error)})`
          );
          return null;
        }
      });

      const results = await Promise.all(attestationPromises);
      const validAttestation = results.find(a => a !== null);

      if (validAttestation) {
        return validAttestation;
      }
    }

    return null;
  }

  /**
   * Get Witness network configuration
   */
  async getConfig() {
    await this.init();

    // Return cached config if available
    if (this.config) {
      return this.config;
    }

    // Fallback config
    return {
      network_id: this.networkId,
      threshold: 2,
      witnesses: [
        { id: 'witness-1', endpoint: 'http://localhost:3001' },
        { id: 'witness-2', endpoint: 'http://localhost:3002' },
        { id: 'witness-3', endpoint: 'http://localhost:3003' }
      ]
    };
  }
}
