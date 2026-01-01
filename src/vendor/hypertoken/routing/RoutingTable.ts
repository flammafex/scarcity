/*
 * network/routing/RoutingTable.ts
 * Abstract routing table with common operations for peer management
 *
 * Provides base functionality shared by both Kademlia and Supernode topologies:
 * - Peer state management
 * - Connection health monitoring
 * - Automatic eviction of unresponsive peers
 */

import { Emitter } from "../events.js";
import {
  PeerId,
  RoutedPeer,
  ConnectionState,
  peerIdToString
} from "./types.js";

/**
 * Configuration for routing table behavior
 */
export interface RoutingTableConfig {
  /** Maximum peers to maintain */
  maxPeers: number;
  /** Time before considering peer stale (ms) */
  staleTimeout: number;
  /** Number of failures before evicting peer */
  maxFailures: number;
  /** Interval for health checks (ms) */
  healthCheckInterval: number;
  /** Enable replacement cache for full buckets */
  useReplacementCache: boolean;
  /** Size of replacement cache per bucket */
  replacementCacheSize: number;
}

/**
 * Default routing table configuration
 */
export const DEFAULT_TABLE_CONFIG: RoutingTableConfig = {
  maxPeers: 256,
  staleTimeout: 60000, // 1 minute
  maxFailures: 3,
  healthCheckInterval: 30000, // 30 seconds
  useReplacementCache: true,
  replacementCacheSize: 8
};

/**
 * Events emitted by RoutingTable:
 * - 'peer:added' - Peer added to table
 * - 'peer:updated' - Peer info updated
 * - 'peer:removed' - Peer removed from table
 * - 'peer:stale' - Peer became stale
 * - 'peer:evicted' - Peer evicted due to failures
 */
export abstract class RoutingTable extends Emitter {
  protected config: RoutingTableConfig;
  protected localId: PeerId;
  protected peers: Map<string, RoutedPeer> = new Map();
  protected healthCheckTimer: ReturnType<typeof setInterval> | null = null;

  constructor(localId: PeerId, config: Partial<RoutingTableConfig> = {}) {
    super();
    this.localId = localId;
    this.config = { ...DEFAULT_TABLE_CONFIG, ...config };
  }

  /**
   * Start periodic health checks
   */
  startHealthChecks(): void {
    if (this.healthCheckTimer) return;

    this.healthCheckTimer = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckInterval
    );
  }

  /**
   * Stop periodic health checks
   */
  stopHealthChecks(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  /**
   * Add or update a peer in the table
   */
  addOrUpdate(peer: RoutedPeer): boolean {
    const idString = peerIdToString(peer.id);
    const existing = this.peers.get(idString);

    if (existing) {
      // Update existing peer
      existing.lastSeen = peer.lastSeen;
      existing.rtt = peer.rtt;
      existing.state = peer.state;
      existing.failureCount = 0; // Reset failures on successful contact
      if (peer.metadata) {
        existing.metadata = { ...existing.metadata, ...peer.metadata };
      }
      this.emit('peer:updated', { peer: existing });
      return true;
    }

    // Check if we can add new peer
    if (this.peers.size >= this.config.maxPeers) {
      // Try to evict a stale peer
      if (!this.evictStalePeer()) {
        return false; // Table is full
      }
    }

    // Add new peer
    peer.idString = idString;
    this.peers.set(idString, peer);
    this.emit('peer:added', { peer });
    return true;
  }

  /**
   * Remove a peer from the table
   */
  remove(peerId: PeerId): boolean {
    const idString = peerIdToString(peerId);
    const peer = this.peers.get(idString);

    if (peer) {
      this.peers.delete(idString);
      this.emit('peer:removed', { peer });
      return true;
    }
    return false;
  }

  /**
   * Get a peer by ID
   */
  get(peerId: PeerId): RoutedPeer | undefined {
    return this.peers.get(peerIdToString(peerId));
  }

  /**
   * Get peer by string ID
   */
  getByString(idString: string): RoutedPeer | undefined {
    return this.peers.get(idString);
  }

  /**
   * Check if peer exists
   */
  has(peerId: PeerId): boolean {
    return this.peers.has(peerIdToString(peerId));
  }

  /**
   * Get all peers
   */
  getAll(): RoutedPeer[] {
    return Array.from(this.peers.values());
  }

  /**
   * Get connected peers only
   */
  getConnected(): RoutedPeer[] {
    return this.getAll().filter(p => p.state === ConnectionState.Connected);
  }

  /**
   * Get peer count
   */
  size(): number {
    return this.peers.size;
  }

  /**
   * Record a successful contact with a peer
   */
  recordSuccess(peerId: PeerId, rtt?: number): void {
    const peer = this.get(peerId);
    if (peer) {
      peer.lastSeen = Date.now();
      peer.failureCount = 0;
      peer.state = ConnectionState.Connected;
      if (rtt !== undefined) {
        // Exponential moving average for RTT
        peer.rtt = peer.rtt === 0 ? rtt : peer.rtt * 0.8 + rtt * 0.2;
      }
    }
  }

  /**
   * Record a failed contact attempt with a peer
   */
  recordFailure(peerId: PeerId): void {
    const peer = this.get(peerId);
    if (peer) {
      peer.failureCount++;
      if (peer.failureCount >= this.config.maxFailures) {
        peer.state = ConnectionState.Failed;
        this.emit('peer:evicted', { peer, reason: 'max_failures' });
        this.remove(peerId);
      }
    }
  }

  /**
   * Get stale peers (not contacted recently)
   */
  getStalePeers(): RoutedPeer[] {
    const now = Date.now();
    return this.getAll().filter(
      p => now - p.lastSeen > this.config.staleTimeout
    );
  }

  /**
   * Evict the stalest peer to make room
   */
  protected evictStalePeer(): boolean {
    const stalePeers = this.getStalePeers();
    if (stalePeers.length === 0) return false;

    // Evict the peer that was last seen longest ago
    const oldest = stalePeers.reduce((a, b) =>
      a.lastSeen < b.lastSeen ? a : b
    );

    this.emit('peer:evicted', { peer: oldest, reason: 'stale' });
    return this.remove(oldest.id);
  }

  /**
   * Perform health check on all peers
   */
  protected performHealthCheck(): void {
    const now = Date.now();
    const stalePeers: RoutedPeer[] = [];

    for (const peer of this.peers.values()) {
      if (now - peer.lastSeen > this.config.staleTimeout) {
        if (peer.state === ConnectionState.Connected) {
          peer.state = ConnectionState.Disconnected;
          stalePeers.push(peer);
        }
      }
    }

    if (stalePeers.length > 0) {
      this.emit('peer:stale', { peers: stalePeers });
    }
  }

  /**
   * Clear all peers
   */
  clear(): void {
    const peers = this.getAll();
    this.peers.clear();
    for (const peer of peers) {
      this.emit('peer:removed', { peer });
    }
  }

  /**
   * Get table statistics
   */
  getTableStats(): {
    total: number;
    connected: number;
    stale: number;
    avgRtt: number;
  } {
    const all = this.getAll();
    const connected = all.filter(p => p.state === ConnectionState.Connected);
    const stale = this.getStalePeers();
    const avgRtt = connected.length > 0
      ? connected.reduce((sum, p) => sum + p.rtt, 0) / connected.length
      : 0;

    return {
      total: all.length,
      connected: connected.length,
      stale: stale.length,
      avgRtt
    };
  }
}

/**
 * Simple flat routing table (for basic use cases)
 */
export class FlatRoutingTable extends RoutingTable {
  constructor(localId: PeerId, config: Partial<RoutingTableConfig> = {}) {
    super(localId, config);
  }

  /**
   * Get N random connected peers
   */
  getRandomPeers(count: number): RoutedPeer[] {
    const connected = this.getConnected();
    if (connected.length <= count) {
      return connected;
    }

    // Fisher-Yates shuffle and take first N
    const shuffled = [...connected];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled.slice(0, count);
  }

  /**
   * Get N peers with lowest RTT
   */
  getFastestPeers(count: number): RoutedPeer[] {
    return this.getConnected()
      .sort((a, b) => a.rtt - b.rtt)
      .slice(0, count);
  }
}
