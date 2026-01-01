/*
 * network/routing/types.ts
 * Shared types and interfaces for structured overlay routing
 *
 * Supports both Kademlia DHT and Supernode topologies with common abstractions
 * for message routing, peer management, and broadcast operations.
 */

import { Emitter } from "../events.js";

/**
 * 256-bit peer identifier (SHA-256 hash of public key)
 */
export type PeerId = Uint8Array;

/**
 * Connection state for a routed peer
 */
export enum ConnectionState {
  Connecting = 'connecting',
  Connected = 'connected',
  Disconnected = 'disconnected',
  Failed = 'failed'
}

/**
 * Peer information with routing metadata
 */
export interface RoutedPeer {
  /** 256-bit peer identifier */
  id: PeerId;
  /** String representation of peer ID for Map keys */
  idString: string;
  /** Current connection state */
  state: ConnectionState;
  /** Last successful contact timestamp */
  lastSeen: number;
  /** Round-trip time estimate in milliseconds */
  rtt: number;
  /** Number of failed contact attempts */
  failureCount: number;
  /** Send function to this peer */
  send: (data: any) => Promise<boolean>;
  /** Optional metadata (e.g., geographic location, bandwidth) */
  metadata?: PeerMetadata;
}

/**
 * Optional peer metadata for routing decisions
 */
export interface PeerMetadata {
  /** Geographic region for locality-aware routing */
  region?: string;
  /** Estimated bandwidth in KB/s */
  bandwidth?: number;
  /** Continuous uptime in hours */
  uptime?: number;
  /** User agent / client version */
  userAgent?: string;
}

/**
 * Message envelope for routed messages
 */
export interface RoutedMessage {
  /** Unique message identifier (hash of content) */
  id: string;
  /** Message type for application-level routing */
  type: string;
  /** Message payload */
  payload: any;
  /** Time-to-live (hop count remaining) */
  ttl: number;
  /** Origin peer ID */
  origin: PeerId;
  /** Timestamp when message was created */
  timestamp: number;
  /** Optional: target peer for point-to-point routing */
  target?: PeerId;
}

/**
 * Result of a routing operation
 */
export interface RoutingResult {
  /** Whether the message was successfully routed */
  success: boolean;
  /** Number of peers the message was forwarded to */
  forwardCount: number;
  /** Time taken in milliseconds */
  latencyMs: number;
  /** Peers that received the message */
  recipients: PeerId[];
  /** Error message if failed */
  error?: string;
}

/**
 * Statistics for routing performance monitoring
 */
export interface RoutingStats {
  /** Total messages routed */
  messagesRouted: number;
  /** Total messages received */
  messagesReceived: number;
  /** Total bytes sent */
  bytesSent: number;
  /** Total bytes received */
  bytesReceived: number;
  /** Average message propagation latency */
  avgLatencyMs: number;
  /** Message delivery success rate (0-1) */
  deliveryRate: number;
  /** Current connection count */
  connectionCount: number;
  /** Peak connection count */
  peakConnections: number;
}

/**
 * Configuration for routing behavior
 */
export interface RoutingConfig {
  /** Maximum time-to-live for broadcast messages */
  maxTtl: number;
  /** How long to remember seen message IDs (ms) */
  seenMessageExpiry: number;
  /** Maximum concurrent routing operations */
  maxConcurrentRoutes: number;
  /** Timeout for routing operations (ms) */
  routeTimeout: number;
  /** Enable debug logging */
  debug: boolean;
}

/**
 * Default routing configuration
 */
export const DEFAULT_ROUTING_CONFIG: RoutingConfig = {
  maxTtl: 10,
  seenMessageExpiry: 60000, // 1 minute
  maxConcurrentRoutes: 100,
  routeTimeout: 5000,
  debug: false
};

/**
 * Abstract router interface that both Kademlia and Supernode implement
 *
 * Events emitted:
 * - 'router:message' - Message received from network
 * - 'router:peer:added' - Peer added to routing table
 * - 'router:peer:removed' - Peer removed from routing table
 * - 'router:stats:updated' - Routing statistics updated
 */
export abstract class Router extends Emitter {
  protected config: RoutingConfig;
  protected localId: PeerId;
  protected seen: Map<string, number> = new Map();
  protected stats: RoutingStats;

  constructor(localId: PeerId, config: Partial<RoutingConfig> = {}) {
    super();
    this.localId = localId;
    this.config = { ...DEFAULT_ROUTING_CONFIG, ...config };
    this.stats = {
      messagesRouted: 0,
      messagesReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      avgLatencyMs: 0,
      deliveryRate: 1.0,
      connectionCount: 0,
      peakConnections: 0
    };

    // Periodically clean up seen message cache
    setInterval(() => this.cleanupSeenCache(), this.config.seenMessageExpiry / 2);
  }

  /**
   * Get the local peer ID
   */
  getLocalId(): PeerId {
    return this.localId;
  }

  /**
   * Get current routing statistics
   */
  getStats(): RoutingStats {
    return { ...this.stats };
  }

  /**
   * Add a peer to the routing table
   */
  abstract addPeer(peer: RoutedPeer): boolean;

  /**
   * Remove a peer from the routing table
   */
  abstract removePeer(peerId: PeerId): boolean;

  /**
   * Get a peer by ID
   */
  abstract getPeer(peerId: PeerId): RoutedPeer | undefined;

  /**
   * Get all connected peers
   */
  abstract getPeers(): RoutedPeer[];

  /**
   * Get the count of connected peers
   */
  abstract getPeerCount(): number;

  /**
   * Broadcast a message to the network
   */
  abstract broadcast(message: RoutedMessage): Promise<RoutingResult>;

  /**
   * Send a message to a specific peer (may route through intermediaries)
   */
  abstract sendTo(target: PeerId, message: RoutedMessage): Promise<RoutingResult>;

  /**
   * Handle an incoming message
   */
  abstract handleMessage(message: RoutedMessage, from: RoutedPeer): Promise<void>;

  /**
   * Check if we've already seen this message
   */
  protected hasSeen(messageId: string): boolean {
    return this.seen.has(messageId);
  }

  /**
   * Mark a message as seen
   */
  protected markSeen(messageId: string): void {
    this.seen.set(messageId, Date.now());
  }

  /**
   * Clean up expired seen message entries
   */
  protected cleanupSeenCache(): void {
    const now = Date.now();
    const expiry = this.config.seenMessageExpiry;

    for (const [id, timestamp] of this.seen) {
      if (now - timestamp > expiry) {
        this.seen.delete(id);
      }
    }
  }

  /**
   * Log debug message if debug mode is enabled
   */
  protected debug(message: string, ...args: any[]): void {
    if (this.config.debug) {
      console.log(`[Router] ${message}`, ...args);
    }
  }
}

/**
 * Utility: Convert PeerId to hex string
 */
export function peerIdToString(id: PeerId): string {
  return Array.from(id)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Utility: Convert hex string to PeerId
 */
export function stringToPeerId(hex: string): PeerId {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Utility: Generate a random 256-bit peer ID
 */
export function generateRandomPeerId(): PeerId {
  const id = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(id);
  } else {
    // Fallback for Node.js
    for (let i = 0; i < 32; i++) {
      id[i] = Math.floor(Math.random() * 256);
    }
  }
  return id;
}

/**
 * Utility: Compute SHA-256 hash (for message IDs)
 */
export async function sha256(data: Uint8Array | string): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = typeof data === 'string' ? encoder.encode(data) : data;

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', new Uint8Array(buffer));
    return peerIdToString(new Uint8Array(hashBuffer));
  } else {
    // Fallback: use Node.js crypto
    const nodeCrypto = await import('crypto');
    return nodeCrypto.createHash('sha256').update(buffer).digest('hex');
  }
}

/**
 * Utility: Create message ID from payload
 */
export async function createMessageId(payload: any): Promise<string> {
  const json = JSON.stringify(payload);
  return sha256(json);
}
