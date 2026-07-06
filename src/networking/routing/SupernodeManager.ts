/*
 * network/routing/SupernodeManager.ts
 * Supernode architecture for hierarchical gossip scaling
 *
 * Implements a two-tier network topology:
 * - Supernodes: Well-connected, stable nodes that form a mesh
 * - Leaf nodes: Regular nodes that connect to a few supernodes
 *
 * Benefits:
 * - O(sqrt(N)) connections per peer (supernodes manage O(sqrt(N)) leaves each)
 * - Reduced bandwidth for leaf nodes
 * - Fast propagation through supernode mesh
 *
 * Supernode Selection Criteria:
 * - Uptime (stability)
 * - Bandwidth capacity
 * - Connection count
 * - Geographic diversity (optional)
 */

import {
  Router,
  RoutedPeer,
  RoutedMessage,
  RoutingResult,
  RoutingConfig,
  PeerId,
  ConnectionState,
  peerIdToString,
  DEFAULT_ROUTING_CONFIG
} from "./types.js";

/**
 * Node roles in the supernode hierarchy
 */
export enum NodeRole {
  /** Regular leaf node connected to supernodes */
  Leaf = 'leaf',
  /** Candidate being evaluated for supernode promotion */
  Candidate = 'candidate',
  /** Active supernode managing leaves and mesh */
  Supernode = 'supernode'
}

/**
 * Statistics for supernode evaluation
 */
export interface NodeStats {
  /** Continuous uptime in milliseconds */
  uptime: number;
  /** Inbound bandwidth in KB/s */
  bandwidthIn: number;
  /** Outbound bandwidth in KB/s */
  bandwidthOut: number;
  /** Total messages relayed */
  messagesRelayed: number;
  /** Message delivery failure rate (0-1) */
  failureRate: number;
  /** Current connection count */
  connectionCount: number;
  /** Geographic region (optional) */
  region?: string;
}

/**
 * Supernode-specific configuration
 */
export interface SupernodeConfig extends RoutingConfig {
  /** Minimum uptime to become supernode (ms) */
  minUptime: number;
  /** Minimum outbound bandwidth (KB/s) */
  minBandwidth: number;
  /** Minimum connection count for supernode */
  minConnections: number;
  /** Maximum leaves per supernode */
  maxLeavesPerSupernode: number;
  /** Target supernodes for leaf to connect to */
  targetSupernodeCount: number;
  /** Gossip fanout among supernodes */
  supernodeGossipFanout: number;
  /** Evaluation interval for promotion/demotion */
  evaluationInterval: number;
  /** Minimum score to become supernode */
  minSupernodeScore: number;
  /** Grace period before demotion (ms) */
  demotionGracePeriod: number;
}

/**
 * Default supernode configuration
 */
export const DEFAULT_SUPERNODE_CONFIG: SupernodeConfig = {
  ...DEFAULT_ROUTING_CONFIG,
  minUptime: 3600000, // 1 hour
  minBandwidth: 500, // 500 KB/s
  minConnections: 10,
  maxLeavesPerSupernode: 100,
  targetSupernodeCount: 3,
  supernodeGossipFanout: 5,
  evaluationInterval: 60000, // 1 minute
  minSupernodeScore: 0.7,
  demotionGracePeriod: 300000 // 5 minutes
};

/**
 * Extended peer info for supernode topology
 */
export interface SupernodePeer extends RoutedPeer {
  /** Role in the network */
  role: NodeRole;
  /** Performance statistics */
  stats?: NodeStats;
  /** Supernode score (0-1) */
  score?: number;
  /** Leaves managed (if supernode) */
  leafCount?: number;
}

/**
 * SupernodeManager implements hierarchical gossip routing
 *
 * Events emitted:
 * - 'router:message' - Application message received
 * - 'router:peer:added' - Peer added
 * - 'router:peer:removed' - Peer removed
 * - 'role:promoted' - This node promoted to supernode
 * - 'role:demoted' - This node demoted to leaf
 * - 'supernode:discovered' - New supernode discovered
 * - 'supernode:lost' - Supernode disconnected
 */
export class SupernodeManager extends Router {
  private supernodeConfig: SupernodeConfig;
  private role: NodeRole = NodeRole.Leaf;
  private startTime: number = Date.now();
  private localStats: NodeStats;

  /** Connected supernodes (if we're a leaf) */
  private supernodes: Map<string, SupernodePeer> = new Map();

  /** Connected leaves (if we're a supernode) */
  private leaves: Map<string, SupernodePeer> = new Map();

  /** Other supernodes in the mesh (if we're a supernode) */
  private supernodeMesh: Map<string, SupernodePeer> = new Map();

  /** All known supernodes for discovery */
  private knownSupernodes: Map<string, SupernodePeer> = new Map();

  private evaluationTimer: ReturnType<typeof setInterval> | null = null;
  private lastEvaluationScore: number = 0;
  private scoreBelowThresholdSince: number | null = null;

  constructor(localId: PeerId, config: Partial<SupernodeConfig> = {}) {
    super(localId, config);
    this.supernodeConfig = { ...DEFAULT_SUPERNODE_CONFIG, ...config };

    this.localStats = {
      uptime: 0,
      bandwidthIn: 0,
      bandwidthOut: 0,
      messagesRelayed: 0,
      failureRate: 0,
      connectionCount: 0
    };

    this.startEvaluationTimer();
  }

  /**
   * Get current node role
   */
  getRole(): NodeRole {
    return this.role;
  }

  /**
   * Check if this node is a supernode
   */
  isSupernode(): boolean {
    return this.role === NodeRole.Supernode;
  }

  /**
   * Get local node statistics
   */
  getLocalStats(): NodeStats {
    return {
      ...this.localStats,
      uptime: Date.now() - this.startTime,
      connectionCount: this.getPeerCount()
    };
  }

  /**
   * Calculate supernode score for a node
   */
  calculateScore(stats: NodeStats): number {
    const { minUptime, minBandwidth, minConnections } = this.supernodeConfig;

    // Normalize each metric (0-1)
    const uptimeScore = Math.min(stats.uptime / (minUptime * 2), 1.0);
    const bandwidthScore = Math.min(stats.bandwidthOut / (minBandwidth * 2), 1.0);
    const reliabilityScore = 1.0 - Math.min(stats.failureRate, 1.0);
    const connectionScore = Math.min(stats.connectionCount / (minConnections * 2), 1.0);

    // Weighted average
    return (
      uptimeScore * 0.25 +
      bandwidthScore * 0.30 +
      reliabilityScore * 0.30 +
      connectionScore * 0.15
    );
  }

  /**
   * Evaluate if this node should be promoted/demoted
   */
  private evaluateRole(): void {
    const stats = this.getLocalStats();
    const score = this.calculateScore(stats);
    this.lastEvaluationScore = score;

    const { minSupernodeScore, demotionGracePeriod } = this.supernodeConfig;

    if (this.role === NodeRole.Leaf) {
      // Check for promotion
      if (score >= minSupernodeScore && this.meetsMinimumRequirements(stats)) {
        this.role = NodeRole.Candidate;
        this.debug(`Promoted to candidate with score ${score.toFixed(2)}`);
        // Will promote to supernode after confirming with network
        this.requestPromotion();
      }
    } else if (this.role === NodeRole.Candidate) {
      if (score >= minSupernodeScore) {
        this.promoteToSupernode();
      } else {
        this.role = NodeRole.Leaf;
        this.debug(`Candidate demoted, score dropped to ${score.toFixed(2)}`);
      }
    } else if (this.role === NodeRole.Supernode) {
      // Check for demotion
      if (score < minSupernodeScore) {
        if (this.scoreBelowThresholdSince === null) {
          this.scoreBelowThresholdSince = Date.now();
        } else if (Date.now() - this.scoreBelowThresholdSince > demotionGracePeriod) {
          this.demoteToLeaf();
        }
      } else {
        this.scoreBelowThresholdSince = null;
      }
    }
  }

  /**
   * Check if node meets minimum requirements for supernode
   */
  private meetsMinimumRequirements(stats: NodeStats): boolean {
    const { minUptime, minBandwidth, minConnections } = this.supernodeConfig;
    return (
      stats.uptime >= minUptime &&
      stats.bandwidthOut >= minBandwidth &&
      stats.connectionCount >= minConnections
    );
  }

  /**
   * Request promotion to supernode (announce to network)
   */
  private async requestPromotion(): Promise<void> {
    // Announce candidacy to known supernodes
    const announcement = {
      type: 'supernode:candidate',
      peerId: peerIdToString(this.localId),
      stats: this.getLocalStats(),
      score: this.lastEvaluationScore
    };

    for (const supernode of this.supernodes.values()) {
      await supernode.send(announcement);
    }
  }

  /**
   * Promote this node to supernode
   */
  private promoteToSupernode(): void {
    this.role = NodeRole.Supernode;

    // Convert current supernodes to mesh peers
    for (const [id, peer] of this.supernodes) {
      peer.role = NodeRole.Supernode;
      this.supernodeMesh.set(id, peer);
    }
    this.supernodes.clear();

    // Announce promotion
    this.announceRole();

    this.emit('role:promoted', {
      role: NodeRole.Supernode,
      score: this.lastEvaluationScore
    });

    this.debug(`Promoted to supernode with score ${this.lastEvaluationScore.toFixed(2)}`);
  }

  /**
   * Demote this node to leaf
   */
  private demoteToLeaf(): void {
    const previousRole = this.role;
    this.role = NodeRole.Leaf;
    this.scoreBelowThresholdSince = null;

    // Notify leaves to find new supernodes
    for (const leaf of this.leaves.values()) {
      leaf.send({
        type: 'supernode:demoted',
        peerId: peerIdToString(this.localId)
      });
    }

    // Move mesh peers back to supernode list
    for (const [id, peer] of this.supernodeMesh) {
      this.supernodes.set(id, peer);
    }
    this.supernodeMesh.clear();
    this.leaves.clear();

    this.emit('role:demoted', {
      previousRole,
      role: NodeRole.Leaf,
      score: this.lastEvaluationScore
    });

    this.debug(`Demoted to leaf, score dropped to ${this.lastEvaluationScore.toFixed(2)}`);
  }

  /**
   * Announce current role to the network
   */
  private async announceRole(): Promise<void> {
    const announcement = {
      type: 'supernode:announce',
      peerId: peerIdToString(this.localId),
      role: this.role,
      leafCount: this.leaves.size,
      stats: this.getLocalStats()
    };

    // Broadcast to all connected peers
    const allPeers = [
      ...this.supernodes.values(),
      ...this.supernodeMesh.values(),
      ...this.leaves.values()
    ];

    for (const peer of allPeers) {
      await peer.send(announcement);
    }
  }

  /**
   * Start periodic role evaluation
   */
  private startEvaluationTimer(): void {
    if (this.evaluationTimer) return;

    this.evaluationTimer = setInterval(
      () => this.evaluateRole(),
      this.supernodeConfig.evaluationInterval
    );
  }

  /**
   * Stop evaluation timer
   */
  stopEvaluationTimer(): void {
    if (this.evaluationTimer) {
      clearInterval(this.evaluationTimer);
      this.evaluationTimer = null;
    }
  }

  /**
   * Add a peer to the appropriate collection based on role
   */
  addPeer(peer: RoutedPeer): boolean {
    const supernodePeer = peer as SupernodePeer;
    const idString = peerIdToString(peer.id);

    // Don't add ourselves
    if (idString === peerIdToString(this.localId)) {
      return false;
    }

    supernodePeer.idString = idString;
    supernodePeer.role = supernodePeer.role || NodeRole.Leaf;

    if (supernodePeer.role === NodeRole.Supernode) {
      if (this.role === NodeRole.Supernode) {
        // Add to mesh
        this.supernodeMesh.set(idString, supernodePeer);
      } else {
        // Add to our supernode list
        if (this.supernodes.size < this.supernodeConfig.targetSupernodeCount) {
          this.supernodes.set(idString, supernodePeer);
        }
      }
      this.knownSupernodes.set(idString, supernodePeer);
      this.emit('supernode:discovered', { peer: supernodePeer });
    } else if (this.role === NodeRole.Supernode) {
      // Accept as leaf if we have capacity
      if (this.leaves.size < this.supernodeConfig.maxLeavesPerSupernode) {
        this.leaves.set(idString, supernodePeer);
      } else {
        return false; // At capacity
      }
    }

    this.stats.connectionCount++;
    this.stats.peakConnections = Math.max(
      this.stats.peakConnections,
      this.stats.connectionCount
    );
    this.emit('router:peer:added', { peer: supernodePeer });
    return true;
  }

  /**
   * Remove a peer from all collections
   */
  removePeer(peerId: PeerId): boolean {
    const idString = peerIdToString(peerId);
    let removed = false;

    if (this.supernodes.delete(idString)) {
      removed = true;
      this.emit('supernode:lost', { peerId: idString });
    }
    if (this.supernodeMesh.delete(idString)) {
      removed = true;
      this.emit('supernode:lost', { peerId: idString });
    }
    if (this.leaves.delete(idString)) {
      removed = true;
    }
    this.knownSupernodes.delete(idString);

    if (removed) {
      this.stats.connectionCount--;
      this.emit('router:peer:removed', { peerId: idString });
    }

    return removed;
  }

  /**
   * Get a peer by ID from any collection
   */
  getPeer(peerId: PeerId): SupernodePeer | undefined {
    const idString = peerIdToString(peerId);
    return (
      this.supernodes.get(idString) ||
      this.supernodeMesh.get(idString) ||
      this.leaves.get(idString)
    );
  }

  /**
   * Get all connected peers
   */
  getPeers(): SupernodePeer[] {
    return [
      ...this.supernodes.values(),
      ...this.supernodeMesh.values(),
      ...this.leaves.values()
    ];
  }

  /**
   * Get peer count
   */
  getPeerCount(): number {
    return this.supernodes.size + this.supernodeMesh.size + this.leaves.size;
  }

  /**
   * Get all known supernodes
   */
  getKnownSupernodes(): SupernodePeer[] {
    return Array.from(this.knownSupernodes.values());
  }

  /**
   * Get connected leaves (if supernode)
   */
  getLeaves(): SupernodePeer[] {
    return Array.from(this.leaves.values());
  }

  /**
   * Broadcast a message using hierarchical gossip
   */
  async broadcast(message: RoutedMessage): Promise<RoutingResult> {
    const startTime = Date.now();

    // Check if already seen
    if (this.hasSeen(message.id)) {
      return {
        success: true,
        forwardCount: 0,
        latencyMs: 0,
        recipients: []
      };
    }
    this.markSeen(message.id);

    // Check TTL
    if (message.ttl <= 0) {
      return {
        success: true,
        forwardCount: 0,
        latencyMs: 0,
        recipients: []
      };
    }

    let forwardCount = 0;
    const recipients: PeerId[] = [];
    const forwardMessage: RoutedMessage = {
      ...message,
      ttl: message.ttl - 1
    };

    if (this.role === NodeRole.Supernode) {
      // Forward to other supernodes in mesh
      const meshTargets = this.selectSupernodeTargets(
        this.supernodeConfig.supernodeGossipFanout
      );
      for (const peer of meshTargets) {
        const success = await peer.send(forwardMessage);
        if (success) {
          forwardCount++;
          recipients.push(peer.id);
        }
      }

      // Forward to all leaves
      for (const leaf of this.leaves.values()) {
        const success = await leaf.send(forwardMessage);
        if (success) {
          forwardCount++;
          recipients.push(leaf.id);
        }
      }
    } else {
      // Leaf: forward to supernodes only
      for (const supernode of this.supernodes.values()) {
        const success = await supernode.send(forwardMessage);
        if (success) {
          forwardCount++;
          recipients.push(supernode.id);
        }
      }
    }

    this.stats.messagesRouted++;
    this.localStats.messagesRelayed++;

    return {
      success: forwardCount > 0,
      forwardCount,
      latencyMs: Date.now() - startTime,
      recipients
    };
  }

  /**
   * Select supernodes for gossip (with diversity)
   */
  private selectSupernodeTargets(count: number): SupernodePeer[] {
    const supernodes = Array.from(this.supernodeMesh.values());
    if (supernodes.length <= count) {
      return supernodes;
    }

    // Shuffle and take first N
    const shuffled = [...supernodes];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled.slice(0, count);
  }

  /**
   * Send a message to a specific peer
   */
  async sendTo(target: PeerId, message: RoutedMessage): Promise<RoutingResult> {
    const startTime = Date.now();
    const targetString = peerIdToString(target);

    // Check if we have direct connection
    const directPeer = this.getPeer(target);
    if (directPeer) {
      const success = await directPeer.send(message);
      return {
        success,
        forwardCount: 1,
        latencyMs: Date.now() - startTime,
        recipients: success ? [target] : []
      };
    }

    // Route through supernodes
    const routedMessage: RoutedMessage = {
      ...message,
      target
    };

    if (this.role === NodeRole.Supernode) {
      // Check if target is one of our leaves
      const leaf = this.leaves.get(targetString);
      if (leaf) {
        const success = await leaf.send(routedMessage);
        return {
          success,
          forwardCount: 1,
          latencyMs: Date.now() - startTime,
          recipients: success ? [target] : []
        };
      }

      // Forward to other supernodes
      for (const supernode of this.supernodeMesh.values()) {
        const success = await supernode.send(routedMessage);
        if (success) {
          return {
            success: true,
            forwardCount: 1,
            latencyMs: Date.now() - startTime,
            recipients: [supernode.id]
          };
        }
      }
    } else {
      // Leaf: route through supernodes
      for (const supernode of this.supernodes.values()) {
        const success = await supernode.send(routedMessage);
        if (success) {
          return {
            success: true,
            forwardCount: 1,
            latencyMs: Date.now() - startTime,
            recipients: [supernode.id]
          };
        }
      }
    }

    return {
      success: false,
      forwardCount: 0,
      latencyMs: Date.now() - startTime,
      recipients: [],
      error: 'No route to target'
    };
  }

  /**
   * Handle an incoming message
   */
  async handleMessage(message: RoutedMessage, from: RoutedPeer): Promise<void> {
    const supernodeFrom = from as SupernodePeer;

    // Update sender info
    this.addPeer(supernodeFrom);
    supernodeFrom.lastSeen = Date.now();

    // Track stats
    this.stats.messagesReceived++;

    // Handle supernode protocol messages
    if (message.type.startsWith('supernode:')) {
      await this.handleSupernodeMessage(message, supernodeFrom);
      return;
    }

    // Check if already seen
    if (this.hasSeen(message.id)) {
      return;
    }
    this.markSeen(message.id);

    // Emit for application handling
    this.emit('router:message', { message, from: supernodeFrom });

    // Handle routing
    if (message.target) {
      const targetString = peerIdToString(message.target);
      const localString = peerIdToString(this.localId);

      if (targetString !== localString) {
        // Forward towards target
        await this.sendTo(message.target, message);
      }
    } else if (message.ttl > 0) {
      // Broadcast message
      await this.broadcast(message);
    }
  }

  /**
   * Handle supernode protocol messages
   */
  private async handleSupernodeMessage(
    message: RoutedMessage,
    from: SupernodePeer
  ): Promise<void> {
    const payload = message.payload;

    switch (message.type) {
      case 'supernode:announce':
        // Update peer role
        from.role = payload.role as NodeRole;
        from.stats = payload.stats;
        from.score = this.calculateScore(payload.stats);
        from.leafCount = payload.leafCount;

        if (payload.role === NodeRole.Supernode) {
          this.knownSupernodes.set(from.idString, from);
          this.emit('supernode:discovered', { peer: from });
        }
        break;

      case 'supernode:candidate':
        // Another node wants to become supernode
        // Could implement voting/approval here
        this.debug(`Candidate announcement from ${from.idString.slice(0, 16)}...`);
        break;

      case 'supernode:demoted':
        // A supernode is stepping down
        this.supernodes.delete(payload.peerId);
        this.supernodeMesh.delete(payload.peerId);
        this.knownSupernodes.delete(payload.peerId);
        this.emit('supernode:lost', { peerId: payload.peerId });

        // Find replacement supernode if we're a leaf
        if (this.role === NodeRole.Leaf) {
          await this.findReplacementSupernode();
        }
        break;

      case 'supernode:register':
        // Leaf wants to register with us (if we're a supernode)
        if (this.role === NodeRole.Supernode) {
          if (this.leaves.size < this.supernodeConfig.maxLeavesPerSupernode) {
            from.role = NodeRole.Leaf;
            this.leaves.set(from.idString, from);
            await from.send({
              type: 'supernode:registered',
              peerId: peerIdToString(this.localId),
              success: true
            });
          } else {
            // At capacity, suggest other supernodes
            await from.send({
              type: 'supernode:registered',
              success: false,
              alternatives: this.getAlternativeSupernodes()
            });
          }
        }
        break;

      case 'supernode:registered':
        if (payload.success) {
          this.debug(`Registered with supernode ${from.idString.slice(0, 16)}...`);
        } else if (payload.alternatives) {
          // Try alternative supernodes
          for (const alt of payload.alternatives) {
            const peer = this.knownSupernodes.get(alt);
            if (peer) {
              await peer.send({
                type: 'supernode:register',
                peerId: peerIdToString(this.localId),
                stats: this.getLocalStats()
              });
              break;
            }
          }
        }
        break;

      case 'supernode:discover':
        // Share known supernodes
        await from.send({
          type: 'supernode:discovered',
          supernodes: Array.from(this.knownSupernodes.values()).map(sn => ({
            id: sn.idString,
            leafCount: sn.leafCount,
            score: sn.score
          }))
        });
        break;
    }
  }

  /**
   * Get alternative supernodes when at capacity
   */
  private getAlternativeSupernodes(): string[] {
    return Array.from(this.knownSupernodes.values())
      .filter(sn =>
        sn.idString !== peerIdToString(this.localId) &&
        (sn.leafCount || 0) < this.supernodeConfig.maxLeavesPerSupernode
      )
      .sort((a, b) => (a.leafCount || 0) - (b.leafCount || 0))
      .slice(0, 3)
      .map(sn => sn.idString);
  }

  /**
   * Find a replacement supernode when one is lost
   */
  private async findReplacementSupernode(): Promise<void> {
    const needed = this.supernodeConfig.targetSupernodeCount - this.supernodes.size;
    if (needed <= 0) return;

    // Try known supernodes we're not connected to
    for (const [id, supernode] of this.knownSupernodes) {
      if (!this.supernodes.has(id)) {
        await supernode.send({
          type: 'supernode:register',
          peerId: peerIdToString(this.localId),
          stats: this.getLocalStats()
        });
        if (this.supernodes.size >= this.supernodeConfig.targetSupernodeCount) {
          break;
        }
      }
    }
  }

  /**
   * Bootstrap as a leaf node
   */
  async bootstrapAsLeaf(bootstrapPeers: SupernodePeer[]): Promise<void> {
    this.debug(`Bootstrapping as leaf with ${bootstrapPeers.length} potential supernodes`);

    for (const peer of bootstrapPeers) {
      if (this.supernodes.size >= this.supernodeConfig.targetSupernodeCount) {
        break;
      }

      // Try to register with this supernode
      peer.role = NodeRole.Supernode;
      this.knownSupernodes.set(peer.idString, peer);

      await peer.send({
        type: 'supernode:register',
        peerId: peerIdToString(this.localId),
        stats: this.getLocalStats()
      });

      // Wait a bit for response
      await new Promise(resolve => setTimeout(resolve, 100));

      if (peer.state === ConnectionState.Connected) {
        this.supernodes.set(peer.idString, peer);
      }
    }

    this.debug(`Bootstrap complete, connected to ${this.supernodes.size} supernodes`);
  }

  /**
   * Bootstrap as a supernode
   */
  async bootstrapAsSupernode(meshPeers: SupernodePeer[]): Promise<void> {
    this.role = NodeRole.Supernode;
    this.debug(`Bootstrapping as supernode with ${meshPeers.length} mesh peers`);

    for (const peer of meshPeers) {
      peer.role = NodeRole.Supernode;
      this.supernodeMesh.set(peer.idString, peer);
      this.knownSupernodes.set(peer.idString, peer);

      // Announce ourselves
      await peer.send({
        type: 'supernode:announce',
        peerId: peerIdToString(this.localId),
        role: NodeRole.Supernode,
        leafCount: 0,
        stats: this.getLocalStats()
      });
    }

    this.debug(`Supernode bootstrap complete, mesh size: ${this.supernodeMesh.size}`);
  }

  /**
   * Get supernode statistics
   */
  getSupernodeStats(): {
    role: NodeRole;
    score: number;
    supernodeCount: number;
    leafCount: number;
    meshSize: number;
    knownSupernodes: number;
  } {
    return {
      role: this.role,
      score: this.lastEvaluationScore,
      supernodeCount: this.supernodes.size,
      leafCount: this.leaves.size,
      meshSize: this.supernodeMesh.size,
      knownSupernodes: this.knownSupernodes.size
    };
  }

  /**
   * Shutdown the manager
   */
  shutdown(): void {
    this.stopEvaluationTimer();
    this.seen.clear();
    this.supernodes.clear();
    this.leaves.clear();
    this.supernodeMesh.clear();
    this.knownSupernodes.clear();
  }
}
