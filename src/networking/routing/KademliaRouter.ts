/*
 * network/routing/KademliaRouter.ts
 * Kademlia DHT implementation for O(log N) peer routing
 *
 * Implements the Kademlia distributed hash table protocol:
 * - 256-bit peer IDs with XOR distance metric
 * - k-buckets organized by distance prefix
 * - Iterative parallel lookups with alpha concurrency
 * - Automatic bucket refresh and peer eviction
 *
 * References:
 * - Maymounkov & Mazières (2002): "Kademlia: A Peer-to-peer Information System"
 * - libp2p Kademlia: https://github.com/libp2p/specs/tree/master/kad-dht
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
  createMessageId,
  DEFAULT_ROUTING_CONFIG
} from "./types.js";

/**
 * Kademlia-specific configuration
 */
export interface KademliaConfig extends RoutingConfig {
  /** Replication factor (peers per k-bucket) */
  k: number;
  /** Parallel lookup concurrency */
  alpha: number;
  /** Number of bits in peer ID (256 for SHA-256) */
  idBits: number;
  /** Bucket refresh interval (ms) */
  bucketRefreshInterval: number;
  /** Maximum bucket size before considering eviction */
  maxBucketSize: number;
  /** Size of replacement cache per bucket */
  replacementCacheSize: number;
}

/**
 * Default Kademlia configuration
 */
export const DEFAULT_KADEMLIA_CONFIG: KademliaConfig = {
  ...DEFAULT_ROUTING_CONFIG,
  k: 20,
  alpha: 3,
  idBits: 256,
  bucketRefreshInterval: 3600000, // 1 hour
  maxBucketSize: 20,
  replacementCacheSize: 8
};

/**
 * K-bucket: stores peers at a specific distance range
 */
interface KBucket {
  /** Bucket index (0-255 for 256-bit IDs) */
  index: number;
  /** Minimum XOR distance (2^index) */
  minDistance: bigint;
  /** Maximum XOR distance (2^(index+1) - 1) */
  maxDistance: bigint;
  /** Active peers in this bucket */
  peers: RoutedPeer[];
  /** Replacement cache for when bucket is full */
  replacementCache: RoutedPeer[];
  /** Last time this bucket was refreshed */
  lastRefresh: number;
}

/**
 * RPC types for Kademlia protocol
 */
export enum KademliaRpcType {
  Ping = 'kad:ping',
  Pong = 'kad:pong',
  FindNode = 'kad:find_node',
  FindNodeResponse = 'kad:find_node_response',
  Store = 'kad:store',
  FindValue = 'kad:find_value',
  FindValueResponse = 'kad:find_value_response'
}

/**
 * Serializable peer info for RPC responses
 */
export interface PeerInfo {
  id: string;
  rtt: number;
  metadata?: Record<string, any>;
}

/**
 * KademliaRouter implements Kademlia DHT for O(log N) routing
 *
 * Events emitted:
 * - 'router:message' - Application message received
 * - 'router:peer:added' - Peer added to routing table
 * - 'router:peer:removed' - Peer removed from routing table
 * - 'router:lookup:complete' - Node lookup completed
 * - 'router:bucket:refresh' - Bucket refresh triggered
 */
export class KademliaRouter extends Router {
  private kademliaConfig: KademliaConfig;
  private buckets: KBucket[];
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private pendingLookups: Map<string, Promise<RoutedPeer[]>> = new Map();

  constructor(localId: PeerId, config: Partial<KademliaConfig> = {}) {
    super(localId, config);
    this.kademliaConfig = { ...DEFAULT_KADEMLIA_CONFIG, ...config };

    // Initialize k-buckets (one per bit position)
    this.buckets = this.initializeBuckets();

    // Start bucket refresh timer
    this.startRefreshTimer();
  }

  /**
   * Initialize empty k-buckets
   */
  private initializeBuckets(): KBucket[] {
    const buckets: KBucket[] = [];

    for (let i = 0; i < this.kademliaConfig.idBits; i++) {
      buckets.push({
        index: i,
        minDistance: 1n << BigInt(i),
        maxDistance: (1n << BigInt(i + 1)) - 1n,
        peers: [],
        replacementCache: [],
        lastRefresh: Date.now()
      });
    }

    return buckets;
  }

  /**
   * Start periodic bucket refresh
   */
  private startRefreshTimer(): void {
    if (this.refreshTimer) return;

    this.refreshTimer = setInterval(
      () => this.refreshBuckets(),
      this.kademliaConfig.bucketRefreshInterval / 10 // Check more frequently, refresh selectively
    );
  }

  /**
   * Stop refresh timer
   */
  stopRefreshTimer(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  /**
   * Calculate XOR distance between two peer IDs as bigint
   */
  distance(a: PeerId, b: PeerId): bigint {
    let result = 0n;
    const len = Math.min(a.length, b.length);

    for (let i = 0; i < len; i++) {
      result = (result << 8n) | BigInt(a[i] ^ b[i]);
    }

    return result;
  }

  /**
   * Find the bucket index for a given peer ID
   * Based on the position of the highest differing bit
   */
  bucketIndex(peerId: PeerId): number {
    const dist = this.distance(this.localId, peerId);
    if (dist === 0n) return 0;

    // Find position of highest set bit
    return this.kademliaConfig.idBits - 1 - this.clzBigInt(dist);
  }

  /**
   * Count leading zeros in a bigint (up to 256 bits)
   */
  private clzBigInt(n: bigint): number {
    if (n === 0n) return this.kademliaConfig.idBits;

    let count = 0;
    let mask = 1n << BigInt(this.kademliaConfig.idBits - 1);

    while ((n & mask) === 0n && count < this.kademliaConfig.idBits) {
      count++;
      mask >>= 1n;
    }

    return count;
  }

  /**
   * Add a peer to the routing table
   */
  addPeer(peer: RoutedPeer): boolean {
    // Don't add ourselves
    if (peerIdToString(peer.id) === peerIdToString(this.localId)) {
      return false;
    }

    const bucketIdx = this.bucketIndex(peer.id);
    const bucket = this.buckets[bucketIdx];

    // Check if peer already exists
    const existingIdx = bucket.peers.findIndex(
      p => peerIdToString(p.id) === peerIdToString(peer.id)
    );

    if (existingIdx >= 0) {
      // Move to end (most recently seen)
      const existing = bucket.peers.splice(existingIdx, 1)[0];
      existing.lastSeen = Date.now();
      existing.rtt = peer.rtt;
      existing.state = ConnectionState.Connected;
      existing.failureCount = 0;
      bucket.peers.push(existing);
      return true;
    }

    // Bucket not full: add directly
    if (bucket.peers.length < this.kademliaConfig.k) {
      peer.idString = peerIdToString(peer.id);
      bucket.peers.push(peer);
      this.stats.connectionCount++;
      this.stats.peakConnections = Math.max(
        this.stats.peakConnections,
        this.stats.connectionCount
      );
      this.emit('router:peer:added', { peer, bucket: bucketIdx });
      return true;
    }

    // Bucket full: add to replacement cache
    if (this.kademliaConfig.replacementCacheSize > 0) {
      // Remove oldest from cache if full
      if (bucket.replacementCache.length >= this.kademliaConfig.replacementCacheSize) {
        bucket.replacementCache.shift();
      }
      peer.idString = peerIdToString(peer.id);
      bucket.replacementCache.push(peer);
    }

    return false;
  }

  /**
   * Remove a peer from the routing table
   */
  removePeer(peerId: PeerId): boolean {
    const bucketIdx = this.bucketIndex(peerId);
    const bucket = this.buckets[bucketIdx];
    const idString = peerIdToString(peerId);

    const peerIdx = bucket.peers.findIndex(p => peerIdToString(p.id) === idString);

    if (peerIdx >= 0) {
      const peer = bucket.peers.splice(peerIdx, 1)[0];
      this.stats.connectionCount--;
      this.emit('router:peer:removed', { peer, bucket: bucketIdx });

      // Promote from replacement cache if available
      if (bucket.replacementCache.length > 0) {
        const replacement = bucket.replacementCache.pop()!;
        bucket.peers.push(replacement);
        this.stats.connectionCount++;
        this.emit('router:peer:added', { peer: replacement, bucket: bucketIdx, fromCache: true });
      }

      return true;
    }

    // Also check replacement cache
    const cacheIdx = bucket.replacementCache.findIndex(p => peerIdToString(p.id) === idString);
    if (cacheIdx >= 0) {
      bucket.replacementCache.splice(cacheIdx, 1);
    }

    return false;
  }

  /**
   * Get a peer by ID
   */
  getPeer(peerId: PeerId): RoutedPeer | undefined {
    const bucketIdx = this.bucketIndex(peerId);
    const bucket = this.buckets[bucketIdx];
    const idString = peerIdToString(peerId);

    return bucket.peers.find(p => peerIdToString(p.id) === idString);
  }

  /**
   * Get all connected peers
   */
  getPeers(): RoutedPeer[] {
    return this.buckets.flatMap(b => b.peers);
  }

  /**
   * Get peer count
   */
  getPeerCount(): number {
    return this.buckets.reduce((sum, b) => sum + b.peers.length, 0);
  }

  /**
   * Find the k closest peers to a target ID from local table
   */
  closestPeers(target: PeerId, count: number = this.kademliaConfig.k): RoutedPeer[] {
    const allPeers = this.getPeers();

    return allPeers
      .map(peer => ({
        peer,
        dist: this.distance(peer.id, target)
      }))
      .sort((a, b) => {
        if (a.dist < b.dist) return -1;
        if (a.dist > b.dist) return 1;
        return 0;
      })
      .slice(0, count)
      .map(x => x.peer);
  }

  /**
   * Select diverse peers from different buckets for broadcast
   */
  selectDiversePeers(count: number): RoutedPeer[] {
    const selected: RoutedPeer[] = [];
    const bucketsCopy = [...this.buckets].filter(b => b.peers.length > 0);

    // Shuffle buckets
    for (let i = bucketsCopy.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [bucketsCopy[i], bucketsCopy[j]] = [bucketsCopy[j], bucketsCopy[i]];
    }

    // Take one peer from each bucket until we have enough
    while (selected.length < count && bucketsCopy.length > 0) {
      for (let i = 0; i < bucketsCopy.length && selected.length < count; i++) {
        const bucket = bucketsCopy[i];
        if (bucket.peers.length > 0) {
          // Random peer from bucket
          const idx = Math.floor(Math.random() * bucket.peers.length);
          const peer = bucket.peers[idx];
          if (!selected.includes(peer)) {
            selected.push(peer);
          }
        }
      }
      // Remove empty buckets
      bucketsCopy.splice(0, bucketsCopy.length, ...bucketsCopy.filter(b => b.peers.length > 0));
    }

    return selected;
  }

  /**
   * Iterative node lookup: find k closest peers to target across network
   */
  async findNode(target: PeerId): Promise<RoutedPeer[]> {
    const targetString = peerIdToString(target);

    // Check for in-progress lookup
    const pending = this.pendingLookups.get(targetString);
    if (pending) {
      return pending;
    }

    const lookupPromise = this.performFindNode(target);
    this.pendingLookups.set(targetString, lookupPromise);

    try {
      const result = await lookupPromise;
      return result;
    } finally {
      this.pendingLookups.delete(targetString);
    }
  }

  /**
   * Perform the actual iterative lookup
   */
  private async performFindNode(target: PeerId): Promise<RoutedPeer[]> {
    const { k, alpha } = this.kademliaConfig;
    const queried = new Set<string>();
    let closest = this.closestPeers(target, k);

    this.debug(`Starting FIND_NODE for ${peerIdToString(target).slice(0, 16)}...`);

    let iterations = 0;
    const maxIterations = 20; // Prevent infinite loops

    while (iterations++ < maxIterations) {
      // Get alpha closest unqueried peers
      const toQuery = closest
        .filter(p => !queried.has(peerIdToString(p.id)))
        .slice(0, alpha);

      if (toQuery.length === 0) {
        this.debug(`FIND_NODE complete after ${iterations} iterations`);
        break;
      }

      // Query in parallel
      const results = await Promise.allSettled(
        toQuery.map(async peer => {
          queried.add(peerIdToString(peer.id));
          return this.sendFindNode(peer, target);
        })
      );

      // Collect successful responses
      const newPeers: RoutedPeer[] = [];
      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          newPeers.push(...result.value);
        }
      }

      // Merge and keep k closest
      const merged = this.mergeClosest(target, [...closest, ...newPeers], k);

      // Check if we've converged (no new closer peers)
      const prevClosest = closest[0] ? this.distance(closest[0].id, target) : null;
      const newClosest = merged[0] ? this.distance(merged[0].id, target) : null;

      if (prevClosest !== null && newClosest !== null && newClosest >= prevClosest) {
        // No improvement, we're done
        this.debug(`FIND_NODE converged after ${iterations} iterations`);
        break;
      }

      closest = merged;
    }

    this.emit('router:lookup:complete', {
      target: peerIdToString(target),
      found: closest.length,
      iterations
    });

    return closest;
  }

  /**
   * Merge peer lists and return k closest to target
   */
  private mergeClosest(target: PeerId, peers: RoutedPeer[], k: number): RoutedPeer[] {
    // Deduplicate by peer ID
    const seen = new Map<string, RoutedPeer>();
    for (const peer of peers) {
      const id = peerIdToString(peer.id);
      if (!seen.has(id)) {
        seen.set(id, peer);
      }
    }

    // Sort by distance and take k
    return Array.from(seen.values())
      .map(peer => ({
        peer,
        dist: this.distance(peer.id, target)
      }))
      .sort((a, b) => {
        if (a.dist < b.dist) return -1;
        if (a.dist > b.dist) return 1;
        return 0;
      })
      .slice(0, k)
      .map(x => x.peer);
  }

  /**
   * Send FIND_NODE RPC to a peer
   */
  private async sendFindNode(peer: RoutedPeer, target: PeerId): Promise<RoutedPeer[]> {
    const startTime = Date.now();

    try {
      const response = await this.sendRpc(peer, {
        type: KademliaRpcType.FindNode,
        target: peerIdToString(target)
      });

      const rtt = Date.now() - startTime;
      peer.lastSeen = Date.now();
      peer.rtt = peer.rtt === 0 ? rtt : peer.rtt * 0.8 + rtt * 0.2;

      if (response && response.peers) {
        return this.deserializePeers(response.peers, peer);
      }
      return [];
    } catch (err) {
      peer.failureCount++;
      this.debug(`FIND_NODE to ${peerIdToString(peer.id).slice(0, 16)}... failed:`, err);
      return [];
    }
  }

  /**
   * Send an RPC message to a peer and wait for response
   */
  private async sendRpc(peer: RoutedPeer, message: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('RPC timeout'));
      }, this.config.routeTimeout);

      // Create response handler
      const responseHandler = (evt: any) => {
        const payload = evt.payload;
        if (payload.rpcId === message.rpcId) {
          clearTimeout(timeout);
          this.off(`rpc:response:${message.rpcId}`, responseHandler);
          resolve(payload);
        }
      };

      // Generate RPC ID
      message.rpcId = Math.random().toString(36).slice(2);

      // Listen for response
      this.on(`rpc:response:${message.rpcId}`, responseHandler);

      // Send message
      peer.send(message).catch(err => {
        clearTimeout(timeout);
        this.off(`rpc:response:${message.rpcId}`, responseHandler);
        reject(err);
      });
    });
  }

  /**
   * Convert serialized peer info back to RoutedPeer objects
   */
  private deserializePeers(peerInfos: PeerInfo[], via: RoutedPeer): RoutedPeer[] {
    return peerInfos.map(info => ({
      id: this.hexToBytes(info.id),
      idString: info.id,
      state: ConnectionState.Disconnected, // We don't have a connection yet
      lastSeen: Date.now(),
      rtt: info.rtt || 0,
      failureCount: 0,
      send: async (data: any) => {
        // Route through the peer that gave us this info
        return via.send({
          type: 'route',
          target: info.id,
          payload: data
        });
      },
      metadata: info.metadata
    }));
  }

  /**
   * Convert hex string to bytes
   */
  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  /**
   * Broadcast a message to the network using epidemic gossip
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

    // Select diverse peers for forwarding
    const targets = this.selectDiversePeers(this.kademliaConfig.k);

    // Forward to selected peers
    const forwardMessage: RoutedMessage = {
      ...message,
      ttl: message.ttl - 1
    };

    const results = await Promise.allSettled(
      targets.map(peer => peer.send(forwardMessage))
    );

    const successCount = results.filter(r => r.status === 'fulfilled' && r.value).length;
    const recipients = targets
      .filter((_, i) => results[i].status === 'fulfilled')
      .map(p => p.id);

    this.stats.messagesRouted++;
    this.stats.bytesSent += JSON.stringify(forwardMessage).length * successCount;

    return {
      success: successCount > 0,
      forwardCount: successCount,
      latencyMs: Date.now() - startTime,
      recipients
    };
  }

  /**
   * Send a message to a specific peer (routed through network)
   */
  async sendTo(target: PeerId, message: RoutedMessage): Promise<RoutingResult> {
    const startTime = Date.now();

    // Check if we have direct connection
    const directPeer = this.getPeer(target);
    if (directPeer && directPeer.state === ConnectionState.Connected) {
      const success = await directPeer.send(message);
      return {
        success,
        forwardCount: 1,
        latencyMs: Date.now() - startTime,
        recipients: success ? [target] : []
      };
    }

    // Find closest peers and route through them
    const closest = this.closestPeers(target, this.kademliaConfig.alpha);

    if (closest.length === 0) {
      return {
        success: false,
        forwardCount: 0,
        latencyMs: Date.now() - startTime,
        recipients: [],
        error: 'No peers available for routing'
      };
    }

    // Send through closest peers
    const routedMessage: RoutedMessage = {
      ...message,
      target
    };

    const results = await Promise.allSettled(
      closest.map(peer => peer.send(routedMessage))
    );

    const successCount = results.filter(r => r.status === 'fulfilled' && r.value).length;

    return {
      success: successCount > 0,
      forwardCount: successCount,
      latencyMs: Date.now() - startTime,
      recipients: closest.filter((_, i) => results[i].status === 'fulfilled').map(p => p.id)
    };
  }

  /**
   * Handle an incoming message
   */
  async handleMessage(message: RoutedMessage, from: RoutedPeer): Promise<void> {
    // Update peer info
    this.addPeer(from);
    from.lastSeen = Date.now();

    // Track stats
    this.stats.messagesReceived++;
    this.stats.bytesReceived += JSON.stringify(message).length;

    // Check if already seen
    if (this.hasSeen(message.id)) {
      return;
    }
    this.markSeen(message.id);

    // Handle Kademlia RPC messages
    if (message.type.startsWith('kad:')) {
      await this.handleRpcMessage(message, from);
      return;
    }

    // Emit for application handling
    this.emit('router:message', { message, from });

    // Forward if TTL allows and this is a broadcast
    if (!message.target && message.ttl > 0) {
      await this.broadcast({
        ...message,
        ttl: message.ttl - 1
      });
    }

    // Handle targeted message routing
    if (message.target) {
      const targetString = peerIdToString(message.target);
      const localString = peerIdToString(this.localId);

      if (targetString === localString) {
        // Message is for us
        this.emit('router:message', { message, from });
      } else {
        // Forward towards target
        await this.sendTo(message.target, message);
      }
    }
  }

  /**
   * Handle Kademlia RPC messages
   */
  private async handleRpcMessage(message: RoutedMessage, from: RoutedPeer): Promise<void> {
    const payload = message.payload;

    switch (message.type) {
      case KademliaRpcType.Ping:
        await from.send({
          type: KademliaRpcType.Pong,
          rpcId: payload.rpcId
        });
        break;

      case KademliaRpcType.Pong:
        this.emit(`rpc:response:${payload.rpcId}`, { payload });
        break;

      case KademliaRpcType.FindNode:
        const closest = this.closestPeers(
          this.hexToBytes(payload.target),
          this.kademliaConfig.k
        );
        await from.send({
          type: KademliaRpcType.FindNodeResponse,
          rpcId: payload.rpcId,
          peers: closest.map(p => ({
            id: peerIdToString(p.id),
            rtt: p.rtt,
            metadata: p.metadata
          }))
        });
        break;

      case KademliaRpcType.FindNodeResponse:
        this.emit(`rpc:response:${payload.rpcId}`, { payload });
        break;

      default:
        this.debug(`Unknown RPC type: ${message.type}`);
    }
  }

  /**
   * Refresh buckets that haven't been used recently
   */
  private async refreshBuckets(): Promise<void> {
    const now = Date.now();
    const refreshInterval = this.kademliaConfig.bucketRefreshInterval;

    for (const bucket of this.buckets) {
      if (now - bucket.lastRefresh > refreshInterval) {
        // Generate random ID in this bucket's range
        const randomId = this.generateRandomIdInBucket(bucket.index);

        this.debug(`Refreshing bucket ${bucket.index}`);
        bucket.lastRefresh = now;

        // Perform lookup to refresh bucket
        this.findNode(randomId).catch(err => {
          this.debug(`Bucket ${bucket.index} refresh failed:`, err);
        });

        this.emit('router:bucket:refresh', { bucket: bucket.index });
      }
    }
  }

  /**
   * Generate a random peer ID that would fall into the given bucket
   */
  private generateRandomIdInBucket(bucketIndex: number): PeerId {
    const id = new Uint8Array(32);

    // Copy local ID
    id.set(this.localId);

    // Flip bit at bucketIndex from MSB
    const byteIndex = Math.floor((255 - bucketIndex) / 8);
    const bitIndex = 7 - ((255 - bucketIndex) % 8);

    id[byteIndex] ^= (1 << bitIndex);

    // Randomize remaining bits
    for (let i = byteIndex + 1; i < 32; i++) {
      id[i] = Math.floor(Math.random() * 256);
    }

    return id;
  }

  /**
   * Bootstrap into the network using known peers
   */
  async bootstrap(bootstrapPeers: RoutedPeer[]): Promise<void> {
    this.debug(`Bootstrapping with ${bootstrapPeers.length} peers`);

    // Add bootstrap peers
    for (const peer of bootstrapPeers) {
      this.addPeer(peer);
    }

    // Lookup ourselves to populate routing table
    await this.findNode(this.localId);

    this.debug(`Bootstrap complete, ${this.getPeerCount()} peers in table`);
  }

  /**
   * Get bucket statistics
   */
  getBucketStats(): { index: number; peers: number; cache: number }[] {
    return this.buckets.map(b => ({
      index: b.index,
      peers: b.peers.length,
      cache: b.replacementCache.length
    }));
  }

  /**
   * Get non-empty buckets
   */
  getNonEmptyBuckets(): KBucket[] {
    return this.buckets.filter(b => b.peers.length > 0);
  }

  /**
   * Shutdown the router
   */
  shutdown(): void {
    this.stopRefreshTimer();
    this.pendingLookups.clear();
    this.seen.clear();
  }
}
