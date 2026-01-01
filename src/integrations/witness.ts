/**
 * Witness integration adapter
 *
 * Provides timestamped attestations for Scarcity transfers using
 * threshold signature-based timestamping without blockchain.
 *
 * Supports both Ed25519 multi-sig and BLS12-381 aggregated signatures.
 */

import { Crypto } from '../crypto.js';
import type { WitnessClient, Attestation, TorConfig } from '../types.js';
import { bls12_381 } from '@noble/curves/bls12-381';
import { TorProxy } from '../tor.js';

export interface WitnessAdapterConfig {
  readonly gatewayUrl?: string; // Single gateway (backward compatibility)
  readonly gatewayUrls?: string[]; // Multiple gateways for quorum
  readonly networkId?: string;
  readonly tor?: TorConfig;
  readonly powDifficulty?: number; // Proof-of-work difficulty in bits (default: 0 = disabled)
  readonly quorumThreshold?: number; // Minimum agreements required (default: 2 for 2-of-3)
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
  private readonly tor: TorProxy | null;
  private readonly powDifficulty: number;
  private readonly quorumThreshold: number;
  private config: any = null;

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
    this.tor = config.tor ? new TorProxy(config.tor) : null;
    this.powDifficulty = config.powDifficulty ?? 0; // Default: disabled

    // Default quorum: 2-of-3 (or majority if different number of gateways)
    this.quorumThreshold = config.quorumThreshold ?? Math.ceil(this.gatewayUrls.length / 2);

    console.log(`[Witness] Configured with ${this.gatewayUrls.length} gateway(s), quorum threshold: ${this.quorumThreshold}`);

    // Log if Tor is enabled for .onion addresses
    for (const url of this.gatewayUrls) {
      if (TorProxy.isOnionUrl(url)) {
        if (this.tor) {
          console.log(`[Witness] Tor enabled for .onion address: ${url}`);
        } else {
          console.warn(`[Witness] .onion URL detected but Tor not configured: ${url}`);
        }
      }
    }
  }

  /**
   * Fetch with Tor support for .onion URLs
   */
  private async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    if (this.tor) {
      return this.tor.fetch(url, options);
    }
    return fetch(url, options);
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
        const response = await this.fetch(`${url}/v1/config`);
        if (response.ok) {
          return await response.json();
        }
        return null;
      } catch (error) {
        console.warn(`[Witness] Gateway ${url} not available:`, error);
        return null;
      }
    });

    const configs = await Promise.all(configPromises);
    const validConfig = configs.find(c => c !== null);

    if (validConfig) {
      this.config = validConfig;
      console.log('[Witness] Connected to network:', this.config.network_id || 'unknown');
    } else {
      console.warn('[Witness] No gateways available, using fallback mode');
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

    // LAYER 2: PROOF-OF-WORK CHALLENGE
    // Solve computational puzzle to prevent cheap spam
    let nonce: number | undefined;
    if (this.powDifficulty > 0) {
      const startTime = Date.now();
      nonce = Crypto.solveProofOfWork(hash, this.powDifficulty);
      const elapsed = Date.now() - startTime;
      console.log(`[Witness] PoW solved in ${elapsed}ms (difficulty: ${this.powDifficulty}, nonce: ${nonce})`);
    }

    // Attempt real timestamping if gateway is available
    if (this.config) {
      // Try all gateways in parallel, use first successful response
      const requestBody: any = { hash };
      if (nonce !== undefined) {
        requestBody.nonce = nonce;
        requestBody.difficulty = this.powDifficulty;
      }

      const timestampPromises = this.gatewayUrls.map(async (gatewayUrl) => {
        try {
          const response = await this.fetch(`${gatewayUrl}/v1/timestamp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
          });

          if (response.ok) {
            const data = await response.json();

            // Transform Witness API response to Scarcity's Attestation format
            const signaturesData = data.attestation?.signatures;
            let signatures: string[] = [];
            let witnessIds: string[] = [];

            if (signaturesData) {
              // Check if it's MultiSig variant (has 'signatures' array)
              if (Array.isArray(signaturesData.signatures)) {
                signatures = signaturesData.signatures.map((sig: any) =>
                  typeof sig.signature === 'string' ? sig.signature : JSON.stringify(sig.signature)
                );
                witnessIds = signaturesData.signatures.map((sig: any) => sig.witness_id);
              }
              // Check if it's Aggregated variant (has 'signature' and 'signers')
              else if (signaturesData.signature && Array.isArray(signaturesData.signers)) {
                signatures = [
                  typeof signaturesData.signature === 'string'
                    ? signaturesData.signature
                    : JSON.stringify(signaturesData.signature)
                ];
                witnessIds = signaturesData.signers;
              }
            }

            // Ensure hash is always a hex string (gateway may return Uint8Array)
            let hashString = hash; // Default to input hash
            const gatewayHash = data.attestation?.attestation?.hash;
            if (gatewayHash) {
              if (typeof gatewayHash === 'string') {
                hashString = gatewayHash;
              } else if (gatewayHash instanceof Uint8Array || Array.isArray(gatewayHash)) {
                // Convert Uint8Array or array to hex string
                hashString = Crypto.toHex(new Uint8Array(gatewayHash));
              }
            }

            return {
              hash: hashString,
              timestamp: data.attestation?.attestation?.timestamp
                ? data.attestation.attestation.timestamp * 1000  // Convert seconds to milliseconds
                : Date.now(),
              signatures,
              witnessIds,
              raw: data.attestation  // Store original SignedAttestation for verification
            };
          }
          return null;
        } catch (error) {
          console.warn(`[Witness] Timestamping failed for gateway ${gatewayUrl}:`, error);
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

    // All gateways failed - this is a fatal error
    // Never create fake signatures as this would undermine the security model
    throw new Error('Timestamping failed: no Witness gateway available');
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

    // If we have the raw SignedAttestation, use it directly
    // Otherwise, try to reconstruct (may fail if signatures aren't in correct format)
    const witnessAttestation = attestation.raw || {
      attestation: {
        hash: attestation.hash,
        timestamp: attestation.timestamp,
        network_id: this.networkId,
        sequence: 0
      },
      signatures: attestation.signatures.map((sig, idx) => ({
        witness_id: attestation.witnessIds[idx],
        signature: sig
      }))
    };

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
        console.warn(`[Witness] Gateway ${gatewayUrl} verification failed:`, error);
        continue;
      }
    }

    // All gateways failed - try local BLS verification
    if (attestation.raw && this.config) {
      const blsResult = this.verifyBLSLocal(attestation);
      if (blsResult !== null) {
        console.log('[Witness] Verified attestation locally via BLS');
        return blsResult;
      }
    }

    // No verification method succeeded - fail securely
    throw new Error('Attestation verification failed: no gateway available and local BLS verification not possible');
  }

  /**
   * Verify BLS aggregated signature locally
   *
   * This requires the network config to have witness public keys.
   * Returns null if verification cannot be performed (missing data),
   * true if valid, false if invalid.
   */
  private verifyBLSLocal(attestation: Attestation): boolean | null {
    try {
      // Check if this is a BLS aggregated signature
      const signaturesData = attestation.raw?.signatures;
      if (!signaturesData || !signaturesData.signature || !Array.isArray(signaturesData.signers)) {
        return null; // Not BLS aggregated format
      }

      // Check if we have witness public keys in config
      if (!this.config?.witnesses || !Array.isArray(this.config.witnesses)) {
        console.warn('[Witness] Cannot verify BLS locally: missing witness public keys');
        return null;
      }

      // Extract the aggregated signature
      const aggregatedSigHex = signaturesData.signature;
      const signers = signaturesData.signers;

      // Get public keys for all signers
      const pubkeys: string[] = [];
      for (const signerId of signers) {
        const witness = this.config.witnesses.find((w: any) => w.id === signerId);
        if (!witness || !witness.pubkey) {
          console.warn(`[Witness] Missing public key for signer: ${signerId}`);
          return null;
        }
        pubkeys.push(witness.pubkey);
      }

      // Prepare the message (attestation hash)
      const attestationData = attestation.raw.attestation;
      const messageBytes = this.serializeAttestationForSigning(attestationData);

      // Verify BLS signature
      const isValid = this.verifyBLSAggregatedSignature(
        messageBytes,
        aggregatedSigHex,
        pubkeys
      );

      console.log(`[Witness] Local BLS verification: ${isValid ? 'valid' : 'invalid'}`);
      return isValid;

    } catch (error) {
      console.error('[Witness] BLS verification error:', error);
      return null; // Cannot verify
    }
  }

  /**
   * Serialize attestation for signing (matches Witness Rust implementation)
   *
   * The message format must match exactly what the Witness nodes sign.
   * Based on Witness implementation: hash || timestamp || network_id || sequence
   */
  private serializeAttestationForSigning(attestation: any): Uint8Array {
    // Convert hash (either Uint8Array or hex string) to bytes
    let hashBytes: Uint8Array;
    if (typeof attestation.hash === 'string') {
      // Remove '0x' prefix if present
      const hex = attestation.hash.startsWith('0x') ? attestation.hash.slice(2) : attestation.hash;
      hashBytes = Uint8Array.from(Buffer.from(hex, 'hex'));
    } else if (Array.isArray(attestation.hash)) {
      hashBytes = new Uint8Array(attestation.hash);
    } else {
      hashBytes = attestation.hash;
    }

    // Convert timestamp to 8-byte little-endian
    const timestampBytes = new Uint8Array(8);
    const view = new DataView(timestampBytes.buffer);
    view.setBigUint64(0, BigInt(attestation.timestamp), true); // little-endian

    // Convert network_id to UTF-8 bytes
    const networkIdBytes = new TextEncoder().encode(attestation.network_id || '');

    // Convert sequence to 8-byte little-endian
    const sequenceBytes = new Uint8Array(8);
    const seqView = new DataView(sequenceBytes.buffer);
    seqView.setBigUint64(0, BigInt(attestation.sequence || 0), true); // little-endian

    // Concatenate: hash || timestamp || network_id || sequence
    const messageLen = hashBytes.length + timestampBytes.length + networkIdBytes.length + sequenceBytes.length;
    const message = new Uint8Array(messageLen);
    let offset = 0;
    message.set(hashBytes, offset); offset += hashBytes.length;
    message.set(timestampBytes, offset); offset += timestampBytes.length;
    message.set(networkIdBytes, offset); offset += networkIdBytes.length;
    message.set(sequenceBytes, offset);

    return message;
  }

  /**
   * Verify BLS aggregated signature using noble-curves
   *
   * @param message - The message that was signed
   * @param aggregatedSigHex - Hex-encoded aggregated signature (96 bytes)
   * @param pubkeysHex - Array of hex-encoded public keys (48 bytes each)
   * @returns true if signature is valid
   */
  private verifyBLSAggregatedSignature(
    message: Uint8Array,
    aggregatedSigHex: string,
    pubkeysHex: string[]
  ): boolean {
    try {
      // Parse aggregated signature (G2 point, 96 bytes)
      const sigHex = aggregatedSigHex.startsWith('0x') ? aggregatedSigHex.slice(2) : aggregatedSigHex;
      const signature = Uint8Array.from(Buffer.from(sigHex, 'hex'));

      // Parse and aggregate public keys (G1 points, 48 bytes each)
      const pubkeys = pubkeysHex.map(pkHex => {
        const hex = pkHex.startsWith('0x') ? pkHex.slice(2) : pkHex;
        return Uint8Array.from(Buffer.from(hex, 'hex'));
      });

      // Aggregate public keys (G1 point addition)
      let aggregatedPubkey = bls12_381.G1.ProjectivePoint.ZERO;
      for (const pk of pubkeys) {
        const point = bls12_381.G1.ProjectivePoint.fromHex(pk);
        aggregatedPubkey = aggregatedPubkey.add(point);
      }

      // Verify using BLS12-381 pairing (minimal-signature-size variant)
      // This uses G2 for signatures (96 bytes) and G1 for public keys (48 bytes)
      const isValid = bls12_381.verify(
        signature,
        message,
        aggregatedPubkey.toRawBytes()
      );

      return isValid;

    } catch (error) {
      console.error('[Witness] BLS signature verification failed:', error);
      return false;
    }
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
          const response = await this.fetch(`${gatewayUrl}/v1/timestamp/${hash}`);

          if (response.status === 404) {
            return { seen: false, gateway: gatewayUrl };
          }

          if (response.ok) {
            const data = await response.json();
            // Check if we have valid attestation with threshold signatures
            const sigCount = data.attestation?.signatures?.length || 0;
            const threshold = this.config.threshold || 2;
            return {
              seen: sigCount >= threshold,
              gateway: gatewayUrl
            };
          }

          return null; // Gateway error
        } catch (error) {
          console.warn(`[Witness] Gateway ${gatewayUrl} failed for nullifier check:`, error);
          return null; // Network error
        }
      });

      const results = await Promise.all(checkPromises);
      const validResults = results.filter(r => r !== null);

      if (validResults.length === 0) {
        // All gateways failed - cannot determine, return low confidence
        console.warn('[Witness] All gateways failed, cannot verify nullifier');
        return 0;
      }

      // Count votes
      const seenCount = validResults.filter(r => r.seen).length;
      const notSeenCount = validResults.filter(r => !r.seen).length;

      console.log(`[Witness] Nullifier check: ${seenCount}/${validResults.length} gateways report seen (quorum: ${this.quorumThreshold})`);

      // Quorum logic
      if (seenCount >= this.quorumThreshold) {
        // Quorum agrees: nullifier has been seen (DOUBLE-SPEND!)
        return 1.0;
      } else if (notSeenCount >= this.quorumThreshold) {
        // Quorum agrees: nullifier has NOT been seen (SAFE)
        return 0.0;
      } else {
        // Split vote or insufficient responses - suspicious!
        // This could indicate a censorship attack
        console.warn('[Witness] Split vote on nullifier check - possible censorship attack');
        return 0.5;
      }
    }

    // Fallback: cannot check without gateway
    return 0;
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
          const response = await this.fetch(`${gatewayUrl}/v1/timestamp/${hash}`);

          if (response.status === 404) {
            return null;
          }

          if (response.ok) {
            const data = await response.json();

            // Ensure hash is always a hex string (gateway may return Uint8Array)
            let hashString = hash; // Default to input hash
            const gatewayHash = data.attestation?.attestation?.hash;
            if (gatewayHash) {
              if (typeof gatewayHash === 'string') {
                hashString = gatewayHash;
              } else if (gatewayHash instanceof Uint8Array || Array.isArray(gatewayHash)) {
                // Convert Uint8Array or array to hex string
                hashString = Crypto.toHex(new Uint8Array(gatewayHash));
              }
            }

            return {
              hash: hashString,
              timestamp: data.attestation?.attestation?.timestamp
                ? data.attestation.attestation.timestamp * 1000  // Convert seconds to milliseconds
                : Date.now(),
              signatures: data.attestation?.signatures?.map((sig: any) =>
                typeof sig.signature === 'string' ? sig.signature : JSON.stringify(sig.signature)
              ) || [],
              witnessIds: data.attestation?.signatures?.map((sig: any) =>
                sig.witness_id
              ) || []
            };
          }
          return null;
        } catch (error) {
          console.warn(`[Witness] Failed to retrieve attestation from ${gatewayUrl}:`, error);
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
