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
  readonly freebird: FreebirdClient;
}

export class FederationBridge {
  private readonly sourceFederation: string;
  private readonly targetFederation: string;
  private readonly sourceWitness: WitnessClient;
  private readonly targetWitness: WitnessClient;
  private readonly sourceGossip: GossipNetwork;
  private readonly targetGossip: GossipNetwork;
  private readonly freebird: FreebirdClient;

  constructor(config: BridgeConfig) {
    this.sourceFederation = config.sourceFederation;
    this.targetFederation = config.targetFederation;
    this.sourceWitness = config.sourceWitness;
    this.targetWitness = config.targetWitness;
    this.sourceGossip = config.sourceGossip;
    this.targetGossip = config.targetGossip;
    this.freebird = config.freebird;
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
    // Phase 1: Lock token in source federation
    const nullifier = Crypto.hash(
      (token as any).secret,
      (token as any).id
    );

    // Create commitment for recipient in target federation
    const commitment = await this.freebird.blind(recipientKey);

    // Create ownership proof bound to nullifier
    const ownershipProof = await this.freebird.createOwnershipProof(
      (token as any).secret,
      nullifier
    );

    // Package bridge data for source federation
    const lockPackage = {
      sourceTokenId: (token as any).id,
      sourceFederation: this.sourceFederation,
      targetFederation: this.targetFederation,
      amount: (token as any).amount,
      commitment,
      nullifier
    };

    // Hash lock package
    const lockHash = Crypto.hashString(JSON.stringify(lockPackage));

    // Timestamp lock in source federation
    const sourceProof = await this.sourceWitness.timestamp(lockHash);

    // Broadcast nullifier in source federation (locks the token)
    await this.sourceGossip.publish(nullifier, sourceProof);

    // Mark source token as spent
    (token as any).spent = true;

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
      sourceTokenId: (token as any).id,
      sourceFederation: this.sourceFederation,
      targetFederation: this.targetFederation,
      amount: (token as any).amount,
      commitment,
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

    // Verify ownership proof
    if (pkg.ownershipProof) {
      const ownershipValid = await this.freebird.verifyToken(pkg.ownershipProof);
      if (!ownershipValid) {
        throw new Error('Invalid ownership proof');
      }
    }

    // Verify this is the correct target federation
    if (pkg.targetFederation !== this.targetFederation) {
      throw new Error(
        `Bridge package is for federation ${pkg.targetFederation}, ` +
        `not ${this.targetFederation}`
      );
    }

    // Create new token in target federation with unique ID
    // Derive a new ID to prevent nullifier collision across federations
    const targetTokenId = Crypto.toHex(
      Crypto.hash(pkg.sourceTokenId, this.targetFederation, 'bridge-v1')
    );

    return new ScarbuckToken({
      id: targetTokenId,
      amount: pkg.amount,
      secret: recipientSecret,
      freebird: this.freebird,
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
