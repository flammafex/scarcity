/**
 * Cross-Federation Bridge
 *
 * Enables token transfers between different Witness federations.
 * This allows tokens to move between different networks while maintaining
 * the double-spend prevention guarantees.
 */

import { Crypto } from './crypto.js';
import { ScarbuckToken } from './token.js';
import type {
  PublicKey,
  BridgePackage,
  FreebirdClient,
  WitnessClient,
  GossipNetwork
} from './types.js';

export interface BridgeConfig {
  readonly sourceFederation: string;
  readonly targetFederation: string;
  readonly sourceWitness: WitnessClient;
  readonly targetWitness: WitnessClient;
  readonly sourceGossip: GossipNetwork;
  readonly targetGossip: GossipNetwork;
  /** Freebird for the source federation (ownership proofs, locking) */
  readonly sourceFreebird?: FreebirdClient;
  /** Freebird for the target federation (commitments, auth tokens for recipient) */
  readonly targetFreebird?: FreebirdClient;
  /** @deprecated Use sourceFreebird/targetFreebird instead. When provided alone, used for both federations. */
  readonly freebird?: FreebirdClient;
}

export class FederationBridge {
  private readonly sourceFederation: string;
  private readonly targetFederation: string;
  private readonly sourceWitness: WitnessClient;
  private readonly targetWitness: WitnessClient;
  private readonly sourceGossip: GossipNetwork;
  private readonly targetGossip: GossipNetwork;
  private readonly sourceFreebird: FreebirdClient;
  private readonly targetFreebird: FreebirdClient;

  constructor(config: BridgeConfig) {
    this.sourceFederation = config.sourceFederation;
    this.targetFederation = config.targetFederation;
    this.sourceWitness = config.sourceWitness;
    this.targetWitness = config.targetWitness;
    this.sourceGossip = config.sourceGossip;
    this.targetGossip = config.targetGossip;
    // Support both new (sourceFreebird/targetFreebird) and legacy (freebird) config
    this.sourceFreebird = config.sourceFreebird ?? config.freebird!;
    this.targetFreebird = config.targetFreebird ?? config.freebird!;
  }

  /**
   * Bridge a token from source to target federation
   *
   * This is a two-phase process:
   * 1. Lock the token in the source federation (via nullifier)
   * 2. Mint equivalent token in target federation (with proof from source)
   *
   * @param token - Token to bridge
   * @param recipientKey - Recipient's public key in target federation
   * @returns Bridge package containing both source and target proofs
   */
  async bridgeToken(
    token: ScarbuckToken,
    recipientKey: PublicKey
  ): Promise<BridgePackage> {
    const tokenState = token.getPersistentState();

    // Phase 1: Lock token in source federation
    const nullifier = Crypto.hash(
      tokenState.secret,
      tokenState.id
    );

    // Create commitment and auth token for recipient via TARGET federation's Freebird
    const commitment = await this.targetFreebird.blind(recipientKey);
    const authToken = await this.targetFreebird.issueToken(commitment);

    // Create ownership proof bound to nullifier via SOURCE federation's Freebird
    const ownershipProof = await this.sourceFreebird.createOwnershipProof(
      tokenState.secret,
      nullifier
    );

    // Package bridge data for source federation
    const lockPackage = {
      sourceTokenId: tokenState.id,
      sourceFederation: this.sourceFederation,
      targetFederation: this.targetFederation,
      amount: tokenState.amount,
      commitment,
      authToken,
      nullifier
    };

    // Hash lock package
    const lockHash = Crypto.hashString(JSON.stringify(lockPackage));

    // Timestamp lock in source federation
    const sourceProof = await this.sourceWitness.timestamp(lockHash);

    // Broadcast nullifier in source federation (locks the token)
    await this.sourceGossip.publish(nullifier, sourceProof);

    // Mark source token as spent
    token.markSpent();

    // Phase 2: Mint equivalent token in target federation
    // Package mint data for target federation
    const mintPackage = {
      ...lockPackage,
      sourceProof
    };

    // Hash mint package
    const mintHash = Crypto.hashString(JSON.stringify(mintPackage));

    // Timestamp mint in target federation
    const targetProof = await this.targetWitness.timestamp(mintHash);

    // Broadcast to target gossip (registers the new token)
    // Note: We don't publish a nullifier here, as this is a mint operation
    // The nullifier will be published when this token is spent in the target federation

    return {
      sourceTokenId: tokenState.id,
      sourceFederation: this.sourceFederation,
      targetFederation: this.targetFederation,
      amount: tokenState.amount,
      commitment,
      authToken,
      nullifier,
      sourceProof,
      targetProof,
      ownershipProof
    };
  }

  /**
   * Receive a bridged token in the target federation
   *
   * @param pkg - Bridge package from bridgeToken
   * @param recipientSecret - Recipient's secret key
   * @returns New ScarbuckToken instance in target federation
   */
  async receiveBridged(
    pkg: BridgePackage,
    recipientSecret: Uint8Array
  ): Promise<ScarbuckToken> {
    // Verify source proof
    const sourceValid = await this.sourceWitness.verify(pkg.sourceProof);
    if (!sourceValid) {
      throw new Error('Invalid source federation proof');
    }

    // Verify target proof if present
    if (pkg.targetProof) {
      const targetValid = await this.targetWitness.verify(pkg.targetProof);
      if (!targetValid) {
        throw new Error('Invalid target federation proof');
      }
    }

    // Verify Freebird authorization token is present (V3 tokens are single-use;
    // actual verification happens before receiveBridged is called).
    if (!pkg.authToken || pkg.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token for bridge');
    }

    // Verify ownership proof
    if (!pkg.ownershipProof) {
      throw new Error('Missing required ownership proof for bridge');
    }
    // Ownership proof was created by source federation's Freebird
    const ownershipValid = await this.sourceFreebird.verifyOwnershipProof(pkg.ownershipProof, pkg.nullifier);
    if (!ownershipValid) {
      throw new Error('Invalid ownership proof');
    }

    // Verify this is the correct target federation
    if (pkg.targetFederation !== this.targetFederation) {
      throw new Error(
        `Bridge package is for federation ${pkg.targetFederation}, ` +
        `not ${this.targetFederation}`
      );
    }

    // Replay protection: check if this bridge nullifier was already used
    // in the target federation. Without this, the same BridgePackage could
    // be submitted multiple times to mint duplicate tokens.
    const alreadyBridged = await this.targetGossip.checkNullifier(pkg.nullifier);
    if (alreadyBridged > 0) {
      throw new Error('Bridge replay detected: nullifier already exists in target federation');
    }

    // Create new token in target federation with unique ID
    // Derive a new ID to prevent nullifier collision across federations
    const targetTokenId = Crypto.toHex(
      Crypto.hash(pkg.sourceTokenId, this.targetFederation, 'bridge-v1')
    );

    // Publish nullifier in target federation to prevent replay.
    // Use targetProof (attested by the target witness) so the target gossip
    // network can verify it. Fall back to sourceProof if targetProof is absent.
    const replayProof = pkg.targetProof ?? pkg.sourceProof;
    await this.targetGossip.publish(pkg.nullifier, replayProof);

    return new ScarbuckToken({
      id: targetTokenId,
      amount: pkg.amount,
      secret: recipientSecret,
      freebird: this.targetFreebird,
      witness: this.targetWitness,
      gossip: this.targetGossip
    });
  }

  /**
   * Verify a bridge operation completed successfully
   *
   * Checks that:
   * 1. Token is locked in source federation (nullifier published)
   * 2. Token is minted in target federation (proofs valid)
   *
   * @param pkg - Bridge package to verify
   * @returns true if bridge is valid, false otherwise
   */
  async verifyBridge(pkg: BridgePackage): Promise<boolean> {
    // Check source federation lock
    const sourceLocked = await this.sourceWitness.checkNullifier(pkg.nullifier);
    if (sourceLocked === 0) {
      // Nullifier not found in source federation
      return false;
    }

    // Verify source proof
    const sourceValid = await this.sourceWitness.verify(pkg.sourceProof);
    if (!sourceValid) {
      return false;
    }

    // Verify target proof if present
    if (pkg.targetProof) {
      const targetValid = await this.targetWitness.verify(pkg.targetProof);
      if (!targetValid) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get bridge status
   */
  getStatus() {
    return {
      sourceFederation: this.sourceFederation,
      targetFederation: this.targetFederation,
      sourceGossipPeers: this.sourceGossip.peers.length,
      targetGossipPeers: this.targetGossip.peers.length
    };
  }
}
