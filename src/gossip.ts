/**
 * NullifierGossip: P2P nullifier set propagation
 *
 * Implements fast, probabilistic double-spend detection through
 * gossip-based broadcast of spent token nullifiers.
 */

import { Crypto } from './crypto.js';
import { DEFAULT_TOKEN_VALIDITY_MS } from './constants.js';
import type {
  PeerConnection,
  GossipMessage,
  Attestation,
  WitnessClient,
  FreebirdClient
} from './types.js';

export interface GossipConfig {
  readonly witness: WitnessClient;
  readonly freebird?: FreebirdClient; // Required if requireOwnershipProof is true
  readonly maxNullifiers?: number;
  readonly pruneInterval?: number;
  readonly maxNullifierAge?: number; // Must match Validator's maxTokenAge
  readonly peerScoreThreshold?: number; // Minimum score before disconnect (default: -50)
  readonly maxTimestampFuture?: number; // Max seconds in future (default: 5)
  readonly requireOwnershipProof?: boolean; // Require Freebird ownership proof (default: false)
}

interface PeerScore {
  score: number;
  invalidProofs: number;
  duplicates: number;
  validMessages: number;
  lastSeen: number;
}

export class NullifierGossip {
  private readonly seenNullifiers = new Map<string, NullifierRecord>();
  private readonly peerConnections: PeerConnection[] = [];
  private readonly peerScores = new Map<string, PeerScore>();
  private readonly witness: WitnessClient;
  private readonly freebird?: FreebirdClient;
  private readonly maxNullifiers: number;
  private readonly pruneInterval: number;
  private receiveHandler?: (data: GossipMessage) => Promise<void>;
  private pruneTimer?: NodeJS.Timeout;
  private readonly maxNullifierAge: number;
  private readonly peerScoreThreshold: number;
  private readonly maxTimestampFuture: number;
  private readonly requireOwnershipProof: boolean;

  constructor(config: GossipConfig) {
    this.witness = config.witness;
    this.freebird = config.freebird;
    this.maxNullifiers = config.maxNullifiers ?? 100_000;
    this.pruneInterval = config.pruneInterval ?? 3600_000; // 1 hour
    // Default to ~576 days (~1.58 years). See constants.ts for details.
    // Should match or exceed TransferValidator's maxTokenAge.
    this.maxNullifierAge = config.maxNullifierAge ?? DEFAULT_TOKEN_VALIDITY_MS;
    this.peerScoreThreshold = config.peerScoreThreshold ?? -50;
    this.maxTimestampFuture = (config.maxTimestampFuture ?? 5) * 1000; // Convert to ms
    this.requireOwnershipProof = config.requireOwnershipProof ?? false;

    // Validate config: if ownership proof is required, freebird must be provided
    if (this.requireOwnershipProof && !this.freebird) {
      throw new Error('GossipConfig: freebird client required when requireOwnershipProof is true');
    }

    // Start pruning old nullifiers periodically
    this.startPruning();
  }

  /**
   * Publish a nullifier to the gossip network
   *
   * @param nullifier - Unique spend identifier
   * @param proof - Witness attestation
   */
  async publish(nullifier: Uint8Array, proof: Attestation): Promise<void> {
    const key = Crypto.toHex(nullifier);

    // Check if already spent
    if (this.seenNullifiers.has(key)) {
      throw new Error('Double-spend detected! Nullifier already published.');
    }

    // Add to local set with metadata
    this.seenNullifiers.set(key, {
      nullifier,
      proof,
      firstSeen: Date.now(),
      peerCount: 1
    });

    // Broadcast to all peers
    const message: GossipMessage = {
      type: 'nullifier',
      nullifier,
      proof,
      timestamp: Date.now()
    };

    await this.broadcast(message);

    // Notify local receiveHandler (so collectors in same process can see it)
    if (this.receiveHandler) {
      await this.receiveHandler(message);
    }
  }

  /**
   * Check if nullifier has been seen
   *
   * @param nullifier - Nullifier to check
   * @returns Confidence score (0-1), where 0 = never seen, 1 = widely propagated
   */
  async checkNullifier(nullifier: Uint8Array): Promise<number> {
    const key = Crypto.toHex(nullifier);
    const record = this.seenNullifiers.get(key);

    if (!record) {
      return 0; // Never seen
    }

    // For double-spend detection, only peer count matters.
    // Age is irrelevant - a legitimate transfer gets older over time,
    // but that doesn't make it a double-spend.
    //
    // peerCount = 1: Seen once (legitimate first use)
    // peerCount > 1: Seen multiple times (likely double-spend)
    //
    // We return a confidence score based on how many peers reported it
    // relative to total peers. This helps distinguish:
    // - Low confidence (1 peer): Legitimate transfer
    // - High confidence (many peers): Likely double-spend

    const peerConfidence = Math.min(
      record.peerCount / Math.max(this.peerConnections.length, 1),
      1.0
    );

    return peerConfidence;
  }

  /**
   * Receive nullifier from peer
   *
   * @param data - Gossip message from peer
   * @param peerId - Optional peer ID for reputation tracking
   */
  async onReceive(data: GossipMessage, peerId?: string): Promise<void> {
    if (data.type !== 'nullifier' || !data.nullifier || !data.proof) {
      return;
    }

    // Initialize peer score if tracking
    let peerScore: PeerScore | undefined;
    if (peerId) {
      peerScore = this.getOrCreatePeerScore(peerId);
      peerScore.lastSeen = Date.now();
    }

    // LAYER 2: WITNESS TIMESTAMP VALIDATION
    // Strict timestamp window checks (saves CPU by rejecting obviously invalid nullifiers early)
    const now = Date.now();
    const timestampAge = now - data.proof.timestamp;

    // Reject nullifiers with timestamps too far in the future (prevents pre-mining spam)
    if (data.proof.timestamp > now + this.maxTimestampFuture) {
      console.warn(`[Gossip] Rejecting nullifier from future (${data.proof.timestamp - now}ms ahead)`);
      if (peerScore) {
        this.penalizePeer(peerId!, -5, 'future timestamp');
      }
      return;
    }

    // Reject nullifiers older than maxNullifierAge immediately (saves CPU, prevents replay attacks)
    if (timestampAge > this.maxNullifierAge) {
      console.warn(`[Gossip] Rejecting expired nullifier (${timestampAge}ms old)`);
      if (peerScore) {
        this.penalizePeer(peerId!, -2, 'expired nullifier');
      }
      return;
    }

    const key = Crypto.toHex(data.nullifier);
    const existing = this.seenNullifiers.get(key);

    // Check for duplicate spam (before expensive verification)
    if (existing) {
      // Increment peer count (saw from another source)
      existing.peerCount++;

      // LAYER 1: PEER SCORING - Penalize duplicate spam
      if (peerScore) {
        this.penalizePeer(peerId!, -1, 'duplicate nullifier');
      }
      return;
    }

    // LAYER 2: WITNESS PROOF VERIFICATION
    // Verify timestamp proof (CPU-intensive operation)
    const valid = await this.witness.verify(data.proof);
    if (!valid) {
      console.warn('[Gossip] Received invalid nullifier proof, ignoring');

      // LAYER 1: PEER SCORING - Heavy penalty for invalid proofs
      if (peerScore) {
        this.penalizePeer(peerId!, -10, 'invalid witness proof');
      }
      return;
    }

    // LAYER 3: FREEBIRD OWNERSHIP PROOF (optional, for maximum spam resistance)
    // This forces attackers to perform expensive VOPRF operations for each spam message
    if (this.requireOwnershipProof && this.freebird) {
      if (!data.ownershipProof) {
        console.warn('[Gossip] Missing required ownership proof');
        if (peerScore) {
          this.penalizePeer(peerId!, -5, 'missing ownership proof');
        }
        return;
      }

      // Verify Schnorr ownership proof with nullifier as binding
      const proofValid = await this.freebird.verifyOwnershipProof(
        data.ownershipProof,
        data.nullifier!
      );

      if (!proofValid) {
        console.warn('[Gossip] Invalid ownership proof');
        if (peerScore) {
          this.penalizePeer(peerId!, -8, 'invalid ownership proof');
        }
        return;
      }
    }

    // Valid message - reward peer
    if (peerScore) {
      peerScore.validMessages++;
      peerScore.score = Math.min(peerScore.score + 1, 100); // Cap at 100
    }

    // First time seeing this nullifier
    this.seenNullifiers.set(key, {
      nullifier: data.nullifier,
      proof: data.proof,
      firstSeen: Date.now(),
      peerCount: 1
    });

    // Propagate to other peers (epidemic broadcast)
    await this.broadcast(data, true);

    // Call user handler if registered
    if (this.receiveHandler) {
      await this.receiveHandler(data);
    }
  }

  /**
   * Register handler for received messages
   */
  setReceiveHandler(handler: (data: GossipMessage) => Promise<void>): void {
    this.receiveHandler = handler;
  }

  /**
   * Add peer connection
   *
   * ANTI-SYBIL: Checks IP subnet diversity to prevent attacks from single network
   */
  addPeer(peer: PeerConnection): void {
    // Check subnet diversity if we have the remote address
    if (peer.remoteAddress) {
      const subnet = this.getSubnet(peer.remoteAddress);
      const sameSubnetPeers = this.peerConnections.filter(p =>
        p.remoteAddress && this.getSubnet(p.remoteAddress) === subnet
      );

      // Warn if too many peers from same subnet (potential Sybil attack)
      const MAX_PEERS_PER_SUBNET = 3;
      if (sameSubnetPeers.length >= MAX_PEERS_PER_SUBNET) {
        console.warn(
          `[Gossip] Warning: ${sameSubnetPeers.length + 1} peers from subnet ${subnet}. ` +
          `Possible Sybil attack. Consider limiting connections from same subnet.`
        );
        // Still add the peer, but log the warning
        // In production, you might want to reject or deprioritize
      }
    }

    // Set up message handler for this peer (if supported)
    if (peer.setMessageHandler) {
      peer.setMessageHandler(async (data: GossipMessage) => {
        await this.onReceive(data, peer.id);
      });
    }

    this.peerConnections.push(peer);
    console.log(`[Gossip] Added peer ${peer.id} (total: ${this.peerConnections.length})`);
  }

  /**
   * Remove peer connection
   */
  removePeer(peerId: string): void {
    const index = this.peerConnections.findIndex(p => p.id === peerId);
    if (index !== -1) {
      this.peerConnections.splice(index, 1);
    }
  }

  /**
   * Get current peer list
   */
  get peers(): PeerConnection[] {
    return [...this.peerConnections];
  }

  /**
   * Get gossip network statistics
   */
  getStats() {
    return {
      nullifierCount: this.seenNullifiers.size,
      peerCount: this.peerConnections.length,
      activePeers: this.peerConnections.filter(p => p.isConnected()).length
    };
  }

  /**
   * Broadcast message to all peers
   */
  private async broadcast(message: GossipMessage, skipFailed = false): Promise<void> {
    const promises = this.peerConnections
      .filter(peer => peer.isConnected())
      .map(async (peer) => {
        try {
          await peer.send(message);
        } catch (error) {
          if (!skipFailed) {
            throw error;
          }
          console.warn(`Failed to send to peer ${peer.id}:`, error);
        }
      });

    await Promise.all(promises);
  }

  /**
   * Prune old nullifiers to prevent unbounded growth
   */
  private startPruning(): void {
    this.pruneTimer = setInterval(() => {
      const now = Date.now();
      const cutoff = now - this.maxNullifierAge;

      // Remove nullifiers older than cutoff
      for (const [key, record] of this.seenNullifiers.entries()) {
        // We rely on 'firstSeen' as the approximation of the token's timestamp
        if (record.firstSeen < cutoff) {
          this.seenNullifiers.delete(key);
        }
      }

      // Safety Valve: If still over maxNullifiers limit (e.g. DDoS), 
      // we must enforce the hard cap to prevent crashing.
      // NOTE: This creates a theoretical double-spend risk if the network is flooded,
      // but preventing a crash is the priority.
      if (this.seenNullifiers.size > this.maxNullifiers) {
        console.warn(`[Gossip] Nullifier set size (${this.seenNullifiers.size}) exceeded limit. Forcing prune.`);
        
        const entries = Array.from(this.seenNullifiers.entries())
          .sort((a, b) => a[1].firstSeen - b[1].firstSeen);

        const toRemove = entries.slice(0, this.seenNullifiers.size - this.maxNullifiers);
        for (const [key] of toRemove) {
          this.seenNullifiers.delete(key);
        }
      }
    }, this.pruneInterval);
	}

  /**
   * Get or create peer score record
   */
  private getOrCreatePeerScore(peerId: string): PeerScore {
    let score = this.peerScores.get(peerId);
    if (!score) {
      score = {
        score: 0,
        invalidProofs: 0,
        duplicates: 0,
        validMessages: 0,
        lastSeen: Date.now()
      };
      this.peerScores.set(peerId, score);
    }
    return score;
  }

  /**
   * Penalize a peer and potentially disconnect them
   */
  private penalizePeer(peerId: string, penalty: number, reason: string): void {
    const score = this.getOrCreatePeerScore(peerId);
    score.score += penalty; // Penalty is negative

    if (reason === 'invalid witness proof') {
      score.invalidProofs++;
    } else if (reason === 'duplicate nullifier') {
      score.duplicates++;
    }

    console.log(`[Gossip] Peer ${peerId} penalized ${penalty} for ${reason} (score: ${score.score})`);

    // Disconnect if score falls below threshold
    if (score.score < this.peerScoreThreshold) {
      console.warn(`[Gossip] Disconnecting peer ${peerId} due to low score (${score.score})`);
      this.disconnectPeer(peerId);
    }
  }

  /**
   * Disconnect a peer by ID
   */
  private disconnectPeer(peerId: string): void {
    const peerIndex = this.peerConnections.findIndex(p => p.id === peerId);
    if (peerIndex !== -1) {
      const peer = this.peerConnections[peerIndex];

      // If peer has disconnect method, call it
      if ('disconnect' in peer && typeof (peer as any).disconnect === 'function') {
        (peer as any).disconnect();
      }

      // Remove from connections
      this.peerConnections.splice(peerIndex, 1);
      this.peerScores.delete(peerId);

      console.log(`[Gossip] Peer ${peerId} disconnected and removed`);
    }
  }

  /**
   * Get peer reputation statistics
   */
  getPeerStats(peerId: string): PeerScore | null {
    return this.peerScores.get(peerId) ?? null;
  }

  /**
   * Get all peer scores
   */
  getAllPeerScores(): Map<string, PeerScore> {
    return new Map(this.peerScores);
  }

  /**
   * Extract /24 subnet from IP address
   *
   * Used for detecting Sybil attacks from the same network.
   * IPv4: Returns first 3 octets (e.g., "192.168.1" from "192.168.1.100")
   * IPv6: Returns first 48 bits (simplified implementation)
   */
  private getSubnet(ip: string): string {
    // IPv4
    if (ip.includes('.')) {
      const octets = ip.split('.');
      if (octets.length >= 3) {
        return octets.slice(0, 3).join('.');
      }
    }

    // IPv6 (simplified - use first 4 groups for /48)
    if (ip.includes(':')) {
      const groups = ip.split(':');
      if (groups.length >= 3) {
        return groups.slice(0, 3).join(':');
      }
    }

    // Unknown format, return as-is
    return ip;
  }

  /**
   * Get subnet diversity statistics
   */
  getSubnetStats(): Map<string, number> {
    const subnetCounts = new Map<string, number>();

    for (const peer of this.peerConnections) {
      if (peer.remoteAddress) {
        const subnet = this.getSubnet(peer.remoteAddress);
        subnetCounts.set(subnet, (subnetCounts.get(subnet) || 0) + 1);
      }
    }

    return subnetCounts;
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
    }
  }
}

interface NullifierRecord {
  nullifier: Uint8Array;
  proof: Attestation;
  firstSeen: number;
  peerCount: number;
}
