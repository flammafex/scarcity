/**
 * TransferValidator: Probabilistic double-spend detection
 *
 * Validates transfers using a tiered approach:
 * 1. Fast gossip check (probabilistic)
 * 2. Witness federation check (deterministic)
 * 3. Tunable wait period for propagation
 * 4. Confidence scoring
 */

import { DEFAULT_TOKEN_VALIDITY_MS } from './constants.js';
import type {
  TransferPackage,
  ValidationResult,
  ConfidenceParams,
  WitnessClient,
  GossipNetwork
} from './types.js';

export interface ValidatorConfig {
  readonly gossip: GossipNetwork;
  readonly witness: WitnessClient;
  readonly waitTime?: number; // milliseconds
  readonly minConfidence?: number; // 0-1
  readonly maxTokenAge?: number; // Maximum allowed age of a transfer proof
}

export class TransferValidator {
  private readonly gossip: GossipNetwork;
  private readonly witness: WitnessClient;
  private readonly waitTime: number;
  private readonly minConfidence: number;
  private readonly maxTokenAge: number;
  
  constructor(config: ValidatorConfig) {
    this.gossip = config.gossip;
    this.witness = config.witness;
    this.waitTime = config.waitTime ?? 5000; // 5 seconds default
    this.minConfidence = config.minConfidence ?? 0.7; // 70% confidence required
    // Default to ~576 days (~1.58 years). See constants.ts for details.
    // Must match or be shorter than NullifierGossip's maxNullifierAge.
    this.maxTokenAge = config.maxTokenAge ?? DEFAULT_TOKEN_VALIDITY_MS;
  }

  /**
   * Validate a transfer package
   *
   * Returns validation result with confidence score.
   * Higher confidence = lower risk of double-spend.
   *
   * @param pkg - Transfer package to validate
   * @returns Validation result with confidence score
   */
  async validateTransfer(pkg: TransferPackage): Promise<ValidationResult> {
  	// Step 1: Enforce Rolling Validity Window
  	const age = Date.now() - pkg.proof.timestamp;
    if (age > this.maxTokenAge) {
      return {
        valid: false,
        confidence: 0,
        reason: `Token expired. Proof age (${(age/3600000).toFixed(1)}h) exceeds limit.`
      };
    }
    
    // Step 2: Fast gossip check (instant, probabilistic)
    const gossipConfidence = await this.gossip.checkNullifier(pkg.nullifier);

    // For a legitimate transfer, the nullifier will be seen once (confidence ~0.1-0.4).
    // For a double-spend, it will be seen multiple times (confidence > 0.5).
    // We use a threshold of 0.5 to distinguish between the two cases.
    const DOUBLE_SPEND_THRESHOLD = 0.5;

    if (gossipConfidence > DOUBLE_SPEND_THRESHOLD) {
      // Nullifier seen multiple times = likely double-spend
      return {
        valid: false,
        confidence: 0,
        reason: `Double-spend detected in gossip network (confidence: ${gossipConfidence.toFixed(2)})`
      };
    }
    

    // Step 3: Witness federation check (slower, deterministic)
    const witnessConfidence = await this.witness.checkNullifier(pkg.nullifier);

    if (witnessConfidence > 0) {
      // Nullifier in Witness = proven double-spend
      return {
        valid: false,
        confidence: 0,
        reason: 'Double-spend proven by Witness federation'
      };
    }

    // Step 4: Verify the Witness attestation itself
    const proofValid = await this.witness.verify(pkg.proof);
    if (!proofValid) {
      return {
        valid: false,
        confidence: 0,
        reason: 'Invalid Witness attestation'
      };
    }

    // Step 5: Wait for gossip propagation (tunable delay)
    if (this.waitTime > 0) {
      await this.sleep(this.waitTime);

      // Check again after waiting - use same threshold as initial check
      const finalCheck = await this.gossip.checkNullifier(pkg.nullifier);

      if (finalCheck > DOUBLE_SPEND_THRESHOLD) {
        return {
          valid: false,
          confidence: 0,
          reason: `Double-spend detected during propagation wait (confidence: ${finalCheck.toFixed(2)})`
        };
      }
    }

    // Step 6: Compute confidence score
    const confidence = this.computeConfidence({
      gossipPeers: this.gossip.peers.length,
      witnessDepth: this.getWitnessFederationDepth(),
      waitTime: this.waitTime
    });

    // Step 7: Accept or reject based on confidence threshold
    if (confidence < this.minConfidence) {
      return {
        valid: false,
        confidence,
        reason: `Confidence ${confidence.toFixed(2)} below threshold ${this.minConfidence}`
      };
    }

    return {
      valid: true,
      confidence,
      reason: 'Transfer validated successfully'
    };
  }

  /**
   * Compute confidence score based on network conditions
   *
   * Factors:
   * - More gossip peers = higher confidence (up to 50%)
   *   - OUTBOUND peers weighted 3x higher (Eclipse attack mitigation)
   * - Deeper Witness federation = higher confidence (up to 30%)
   * - Longer wait time = higher confidence (up to 20%)
   *
   * @param params - Network parameters
   * @returns Confidence score (0-1)
   */
  computeConfidence(params: ConfidenceParams): number {
    // ANTI-ECLIPSE: Weight outbound peers 3x higher than inbound
    // Rationale: Attackers can connect TO you (inbound), but can't force you
    // to connect TO them (outbound). Outbound peers are inherently more trustworthy.
    const outboundPeers = this.gossip.peers.filter(p => p.direction === 'outbound').length;
    const inboundPeers = this.gossip.peers.filter(p => p.direction === 'inbound').length;
    const unknownPeers = this.gossip.peers.filter(p => !p.direction).length;

    // Effective peers: outbound * 3 + inbound * 1 + unknown * 1
    // Unknown direction treated as inbound for safety
    const effectivePeers = (outboundPeers * 3) + inboundPeers + unknownPeers;

    // Peer score: asymptotic to 0.5 as effective peers approach 10
    const peerScore = Math.min(effectivePeers / 10, 0.5);

    // Witness score: asymptotic to 0.3 as federation depth approaches 3
    const witnessScore = Math.min(params.witnessDepth / 3, 0.3);

    // Time score: asymptotic to 0.2 as wait time approaches 10 seconds
    const timeScore = Math.min(params.waitTime / 10_000, 0.2);

    // Combined score (max: 1.0, min: 0.0)
    return peerScore + witnessScore + timeScore;
  }

  /**
   * Fast validation without waiting
   *
   * Useful for preliminary checks before accepting a transfer.
   * Lower confidence, but instant.
   *
   * @param pkg - Transfer package
   * @returns Validation result
   */
  async fastValidate(pkg: TransferPackage): Promise<ValidationResult> {
    const gossipConfidence = await this.gossip.checkNullifier(pkg.nullifier);

    if (gossipConfidence > 0) {
      return {
        valid: false,
        confidence: 0,
        reason: 'Double-spend detected in gossip'
      };
    }

    const proofValid = await this.witness.verify(pkg.proof);
    if (!proofValid) {
      return {
        valid: false,
        confidence: 0,
        reason: 'Invalid Witness attestation'
      };
    }

    const confidence = this.computeConfidence({
      gossipPeers: this.gossip.peers.length,
      witnessDepth: this.getWitnessFederationDepth(),
      waitTime: 0
    });

    return {
      valid: confidence >= this.minConfidence,
      confidence,
      reason: confidence >= this.minConfidence
        ? 'Fast validation passed'
        : 'Insufficient confidence without wait period'
    };
  }

  /**
   * Deep validation with extended waiting
   *
   * For high-value transfers where maximum certainty is needed.
   *
   * @param pkg - Transfer package
   * @param extendedWaitTime - Additional wait time in ms
   * @returns Validation result
   */
  async deepValidate(
    pkg: TransferPackage,
    extendedWaitTime = 30_000
  ): Promise<ValidationResult> {
    const originalWaitTime = this.waitTime;

    try {
      // Temporarily extend wait time
      (this as any).waitTime = extendedWaitTime;

      return await this.validateTransfer(pkg);
    } finally {
      // Restore original wait time
      (this as any).waitTime = originalWaitTime;
    }
  }

  /**
   * Get Witness federation depth
   *
   * In production, this would query the actual Witness network.
   * For now, we return a default value.
   */
  private getWitnessFederationDepth(): number {
    // TODO: Query actual Witness federation
    // For now, assume a 3-of-5 threshold (depth = 3)
    return 3;
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Update minimum confidence threshold
   */
  setMinConfidence(confidence: number): void {
    if (confidence < 0 || confidence > 1) {
      throw new Error('Confidence must be between 0 and 1');
    }
    (this as any).minConfidence = confidence;
  }

  /**
   * Get current configuration
   */
  getConfig() {
    return {
      waitTime: this.waitTime,
      minConfidence: this.minConfidence,
      gossipPeers: this.gossip.peers.length
    };
  }
}
