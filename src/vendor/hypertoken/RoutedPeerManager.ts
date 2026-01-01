/*
 * network/RoutedPeerManager.ts
 * Unified peer management with pluggable routing strategies
 *
 * Wraps HybridPeerManager to provide:
 * - Naive gossip (backward compatible)
 * - Kademlia DHT routing
 * - Supernode hierarchical routing
 *
 * Automatically selects routing strategy based on network size
 * or explicit configuration.
 */

import { Emitter } from "./events.js";
import { HybridPeerManager, HybridPeerManagerOptions } from "./HybridPeerManager.js";
import {
  Router,
  RoutedPeer,
  RoutedMessage,
  RoutingResult,
  PeerId,
  ConnectionState,
  peerIdToString,
  generateRandomPeerId,
  createMessageId
} from "./routing/types.js";
import { KademliaRouter, KademliaConfig } from "./routing/KademliaRouter.js";
import { SupernodeManager, SupernodeConfig, NodeRole } from "./routing/SupernodeManager.js";

/**
 * Routing strategy selection
 */
export enum RoutingStrategy {
  /** Direct broadcast to all peers (O(N)) */
  Naive = 'naive',
  /** Kademlia DHT (O(log N)) */
  Kademlia = 'kademlia',
  /** Supernode hierarchy (O(sqrt N)) */
  Supernode = 'supernode',
  /** Automatic selection based on peer count */
  Auto = 'auto'
}

/**
 * Thresholds for automatic routing strategy selection
 */
export interface AutoRoutingThresholds {
  /** Use Kademlia above this peer count */
  kademliaThreshold: number;
  /** Use Supernode above this peer count (if not using Kademlia) */
  supernodeThreshold: number;
}

/**
 * Configuration for RoutedPeerManager
 */
export interface RoutedPeerManagerOptions extends HybridPeerManagerOptions {
  /** Routing strategy to use */
  routingStrategy?: RoutingStrategy;
  /** Kademlia-specific configuration */
  kademliaConfig?: Partial<KademliaConfig>;
  /** Supernode-specific configuration */
  supernodeConfig?: Partial<SupernodeConfig>;
  /** Thresholds for auto strategy selection */
  autoThresholds?: AutoRoutingThresholds;
  /** Local peer ID (generated if not provided) */
  localPeerId?: PeerId;
  /** Enable routing debug logging */
  routingDebug?: boolean;
}

/**
 * Default auto-routing thresholds
 */
export const DEFAULT_AUTO_THRESHOLDS: AutoRoutingThresholds = {
  kademliaThreshold: 100,
  supernodeThreshold: 50
};

/**
 * RoutedPeerManager extends HybridPeerManager with structured routing
 *
 * Events emitted (in addition to HybridPeerManager events):
 * - 'routing:strategy:changed' - Routing strategy switched
 * - 'routing:message' - Message received via routing layer
 * - 'routing:broadcast' - Broadcast completed
 */
export class RoutedPeerManager extends Emitter {
  private hybridManager: HybridPeerManager;
  private router: Router | null = null;
  private strategy: RoutingStrategy;
  private activeStrategy: RoutingStrategy;
  private localId: PeerId;
  private options: RoutedPeerManagerOptions;
  private peerMap: Map<string, RoutedPeer> = new Map();
  private strategyCheckInterval: ReturnType<typeof setInterval> | null = null;

  constructor(options: RoutedPeerManagerOptions) {
    super();
    this.options = options;
    this.strategy = options.routingStrategy || RoutingStrategy.Auto;
    this.activeStrategy = RoutingStrategy.Naive; // Start with naive
    this.localId = options.localPeerId || generateRandomPeerId();

    // Create underlying hybrid manager
    this.hybridManager = new HybridPeerManager(options);
    this.setupHybridHandlers();

    // Initialize router if not using naive/auto
    if (this.strategy !== RoutingStrategy.Naive && this.strategy !== RoutingStrategy.Auto) {
      this.initializeRouter(this.strategy);
    }

    // Start strategy check for auto mode
    if (this.strategy === RoutingStrategy.Auto) {
      this.startStrategyCheck();
    }
  }

  /**
   * Get the local peer ID
   */
  getLocalId(): PeerId {
    return this.localId;
  }

  /**
   * Get current active routing strategy
   */
  getActiveStrategy(): RoutingStrategy {
    return this.activeStrategy;
  }

  /**
   * Get the underlying router (if using structured routing)
   */
  getRouter(): Router | null {
    return this.router;
  }

  /**
   * Connect to the network
   */
  connect(): void {
    this.hybridManager.connect();
  }

  /**
   * Disconnect from the network
   */
  disconnect(): void {
    this.stopStrategyCheck();
    if (this.router instanceof KademliaRouter) {
      this.router.shutdown();
    } else if (this.router instanceof SupernodeManager) {
      this.router.shutdown();
    }
    this.hybridManager.disconnect();
    this.peerMap.clear();
  }

  /**
   * Broadcast a message to the network
   */
  async broadcast(type: string, payload: any = {}): Promise<RoutingResult | void> {
    if (this.activeStrategy === RoutingStrategy.Naive || !this.router) {
      // Use naive broadcast via HybridPeerManager
      this.hybridManager.broadcast(type, payload);
      return;
    }

    // Use structured routing
    const messageId = await createMessageId({ type, payload, timestamp: Date.now() });
    const message: RoutedMessage = {
      id: messageId,
      type,
      payload,
      ttl: 10,
      origin: this.localId,
      timestamp: Date.now()
    };

    const result = await this.router.broadcast(message);
    this.emit('routing:broadcast', { message, result });
    return result;
  }

  /**
   * Send a message to a specific peer
   */
  async sendToPeer(targetPeerId: string, payload: any): Promise<boolean> {
    if (this.activeStrategy === RoutingStrategy.Naive || !this.router) {
      this.hybridManager.sendToPeer(targetPeerId, payload);
      return true;
    }

    // Use routed delivery
    const targetPeer = this.peerMap.get(targetPeerId);
    if (!targetPeer) {
      // Fall back to direct send
      this.hybridManager.sendToPeer(targetPeerId, payload);
      return true;
    }

    const messageId = await createMessageId({ payload, target: targetPeerId, timestamp: Date.now() });
    const message: RoutedMessage = {
      id: messageId,
      type: 'p2p',
      payload,
      ttl: 10,
      origin: this.localId,
      timestamp: Date.now(),
      target: targetPeer.id
    };

    const result = await this.router.sendTo(targetPeer.id, message);
    return result.success;
  }

  /**
   * Get the peer ID from underlying connection
   */
  getPeerId(): string | null {
    return this.hybridManager.getPeerId();
  }

  /**
   * Get connected peers
   */
  getPeers(): Set<string> {
    return this.hybridManager.getPeers();
  }

  /**
   * Get peer count
   */
  getPeerCount(): number {
    if (this.router) {
      return this.router.getPeerCount();
    }
    return this.hybridManager.getPeers().size;
  }

  /**
   * Check if using WebRTC for a peer
   */
  isWebRTCConnected(peerId: string): boolean {
    return this.hybridManager.isWebRTCConnected(peerId);
  }

  /**
   * Get underlying HybridPeerManager
   */
  getHybridManager(): HybridPeerManager {
    return this.hybridManager;
  }

  /**
   * Force switch to a specific routing strategy
   */
  switchStrategy(strategy: RoutingStrategy): void {
    if (strategy === RoutingStrategy.Auto) {
      this.strategy = RoutingStrategy.Auto;
      this.startStrategyCheck();
      return;
    }

    this.strategy = strategy;
    this.stopStrategyCheck();

    if (strategy === RoutingStrategy.Naive) {
      this.activeStrategy = RoutingStrategy.Naive;
      this.router = null;
    } else {
      this.initializeRouter(strategy);
    }

    this.emit('routing:strategy:changed', {
      strategy: this.activeStrategy,
      peerCount: this.getPeerCount()
    });
  }

  /**
   * Get routing statistics
   */
  getRoutingStats(): {
    strategy: RoutingStrategy;
    peerCount: number;
    routerStats?: any;
  } {
    return {
      strategy: this.activeStrategy,
      peerCount: this.getPeerCount(),
      routerStats: this.router?.getStats()
    };
  }

  /**
   * Initialize a router for the given strategy
   */
  private initializeRouter(strategy: RoutingStrategy): void {
    // Clean up existing router
    if (this.router instanceof KademliaRouter) {
      this.router.shutdown();
    } else if (this.router instanceof SupernodeManager) {
      this.router.shutdown();
    }

    const debug = this.options.routingDebug || false;

    if (strategy === RoutingStrategy.Kademlia) {
      this.router = new KademliaRouter(this.localId, {
        ...this.options.kademliaConfig,
        debug
      });
      this.activeStrategy = RoutingStrategy.Kademlia;
    } else if (strategy === RoutingStrategy.Supernode) {
      this.router = new SupernodeManager(this.localId, {
        ...this.options.supernodeConfig,
        debug
      });
      this.activeStrategy = RoutingStrategy.Supernode;
    }

    // Add existing peers to router
    if (this.router) {
      for (const peer of this.peerMap.values()) {
        this.router.addPeer(peer);
      }

      // Setup router message handler
      this.router.on('router:message', (evt) => {
        this.emit('routing:message', evt.payload);
        // Also emit as standard net:message for compatibility
        this.emit('net:message', {
          payload: evt.payload.message.payload,
          fromPeerId: peerIdToString(evt.payload.from.id)
        });
      });
    }
  }

  /**
   * Setup handlers for HybridPeerManager events
   */
  private setupHybridHandlers(): void {
    // Forward connection events
    this.hybridManager.on('net:connected', (evt) => this.emit('net:connected', evt));
    this.hybridManager.on('net:ready', (evt) => this.emit('net:ready', evt));
    this.hybridManager.on('net:disconnected', (evt) => this.emit('net:disconnected', evt));
    this.hybridManager.on('net:error', (evt) => this.emit('net:error', evt));

    // Handle peer connections
    this.hybridManager.on('net:peer:connected', (evt) => {
      const { peerId } = evt.payload;
      this.onPeerConnected(peerId);
      this.emit('net:peer:connected', evt);
    });

    this.hybridManager.on('net:peer:disconnected', (evt) => {
      const { peerId } = evt.payload;
      this.onPeerDisconnected(peerId);
      this.emit('net:peer:disconnected', evt);
    });

    // Handle messages
    this.hybridManager.on('net:message', (evt) => {
      if (this.activeStrategy === RoutingStrategy.Naive || !this.router) {
        // Direct pass-through in naive mode
        this.emit('net:message', evt);
      } else {
        // Route through structured overlay
        this.handleRoutedMessage(evt.payload);
      }
    });

    // Forward WebRTC events
    this.hybridManager.on('rtc:upgraded', (evt) => this.emit('rtc:upgraded', evt));
    this.hybridManager.on('rtc:downgraded', (evt) => this.emit('rtc:downgraded', evt));
    this.hybridManager.on('rtc:connection-failed', (evt) => this.emit('rtc:connection-failed', evt));
    this.hybridManager.on('rtc:retrying', (evt) => this.emit('rtc:retrying', evt));
  }

  /**
   * Handle a new peer connection
   */
  private onPeerConnected(peerId: string): void {
    // Create RoutedPeer wrapper
    const routedPeer: RoutedPeer = {
      id: this.stringToBytes(peerId),
      idString: peerId,
      state: ConnectionState.Connected,
      lastSeen: Date.now(),
      rtt: 0,
      failureCount: 0,
      send: async (data: any) => {
        this.hybridManager.sendToPeer(peerId, data);
        return true;
      }
    };

    this.peerMap.set(peerId, routedPeer);

    // Add to router if active
    if (this.router) {
      this.router.addPeer(routedPeer);
    }

    // Check if we should switch strategies
    if (this.strategy === RoutingStrategy.Auto) {
      this.checkAutoStrategy();
    }
  }

  /**
   * Handle peer disconnection
   */
  private onPeerDisconnected(peerId: string): void {
    const peer = this.peerMap.get(peerId);
    if (peer && this.router) {
      this.router.removePeer(peer.id);
    }
    this.peerMap.delete(peerId);

    // Check if we should switch strategies
    if (this.strategy === RoutingStrategy.Auto) {
      this.checkAutoStrategy();
    }
  }

  /**
   * Handle a routed message
   */
  private handleRoutedMessage(payload: any): void {
    if (!this.router) return;

    // Check if this is a routing protocol message
    if (payload.type?.startsWith('kad:') || payload.type?.startsWith('supernode:')) {
      const fromPeer = this.peerMap.get(payload.fromPeerId);
      if (fromPeer) {
        const message: RoutedMessage = {
          id: payload.id || `${payload.fromPeerId}-${Date.now()}`,
          type: payload.type,
          payload: payload,
          ttl: payload.ttl || 10,
          origin: fromPeer.id,
          timestamp: payload.timestamp || Date.now()
        };
        this.router.handleMessage(message, fromPeer);
      }
      return;
    }

    // Regular message - emit for application
    this.emit('net:message', { payload });
  }

  /**
   * Start periodic strategy check for auto mode
   */
  private startStrategyCheck(): void {
    if (this.strategyCheckInterval) return;

    this.strategyCheckInterval = setInterval(() => {
      this.checkAutoStrategy();
    }, 30000); // Check every 30 seconds
  }

  /**
   * Stop strategy check
   */
  private stopStrategyCheck(): void {
    if (this.strategyCheckInterval) {
      clearInterval(this.strategyCheckInterval);
      this.strategyCheckInterval = null;
    }
  }

  /**
   * Check and potentially switch strategy in auto mode
   */
  private checkAutoStrategy(): void {
    const thresholds = this.options.autoThresholds || DEFAULT_AUTO_THRESHOLDS;
    const peerCount = this.getPeerCount();
    let targetStrategy = RoutingStrategy.Naive;

    if (peerCount >= thresholds.kademliaThreshold) {
      targetStrategy = RoutingStrategy.Kademlia;
    } else if (peerCount >= thresholds.supernodeThreshold) {
      targetStrategy = RoutingStrategy.Supernode;
    }

    if (targetStrategy !== this.activeStrategy) {
      console.log(`[RoutedPeerManager] Switching from ${this.activeStrategy} to ${targetStrategy} (${peerCount} peers)`);
      this.initializeRouter(targetStrategy);
      this.emit('routing:strategy:changed', {
        strategy: this.activeStrategy,
        peerCount
      });
    }
  }

  /**
   * Convert string peer ID to bytes
   */
  private stringToBytes(str: string): PeerId {
    // If it looks like a hex string, decode it
    if (/^[0-9a-f]+$/i.test(str) && str.length === 64) {
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(str.substr(i * 2, 2), 16);
      }
      return bytes;
    }

    // Otherwise, hash the string to get a consistent ID
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hash = new Uint8Array(32);
    for (let i = 0; i < data.length; i++) {
      hash[i % 32] ^= data[i];
    }
    return hash;
  }
}
