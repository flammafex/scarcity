/**
 * HyperToken integration adapter
 *
 * Provides P2P network connectivity for gossip protocol using HyperToken's
 * advanced networking features:
 *
 * - RoutedPeerManager: Kademlia/Supernode routing for O(log N) scalability
 * - E2EEncryption: ECDH + AES-GCM encryption for privacy from relay servers
 * - StateSyncManager: Delta-based catch-up for reconnecting peers
 */

import { RoutedPeerManager, RoutingStrategy } from '../vendor/hypertoken/RoutedPeerManager.js';
import { E2EEncryption, EncryptedMessage, KeyExchangeMessage } from '../vendor/hypertoken/E2EEncryption.js';
import { StateSyncManager, StateDelta, CatchupRequest, CatchupResponse } from '../vendor/hypertoken/StateSyncManager.js';
import type { PeerConnection, GossipMessage } from '../types.js';
import { Crypto } from '../crypto.js';

export interface HyperTokenAdapterConfig {
  readonly relayUrl?: string;
  readonly rateLimitPerSecond?: number;
  readonly rateLimitBurst?: number;
  /** Routing strategy (default: Auto) */
  readonly routingStrategy?: RoutingStrategy;
  /** Thresholds for auto routing strategy selection */
  readonly autoThresholds?: {
    kademliaThreshold: number;
    supernodeThreshold: number;
  };
  /** Enable routing debug logging */
  readonly routingDebug?: boolean;
}

/**
 * Serializable version of GossipMessage for JSON transmission
 */
interface SerializedGossipMessage {
  readonly type: 'nullifier' | 'ping' | 'pong';
  readonly nullifier?: string;
  readonly proof?: any;
  readonly timestamp: number;
  readonly ownershipProof?: string;
}

/**
 * Protocol message types for internal communication
 */
interface ProtocolMessage {
  readonly _protocol: 'scarcity';
  readonly _type: 'gossip' | 'key-exchange' | 'catchup-request' | 'catchup-response';
  readonly payload: any;
  readonly encrypted?: EncryptedMessage;
}

function serializeGossipMessage(msg: GossipMessage): SerializedGossipMessage {
  return {
    type: msg.type,
    nullifier: msg.nullifier ? Crypto.toHex(msg.nullifier) : undefined,
    proof: msg.proof,
    timestamp: msg.timestamp,
    ownershipProof: msg.ownershipProof ? Crypto.toHex(msg.ownershipProof) : undefined
  };
}

function deserializeGossipMessage(serialized: SerializedGossipMessage): GossipMessage {
  return {
    type: serialized.type,
    nullifier: serialized.nullifier ? Crypto.fromHex(serialized.nullifier) : undefined,
    proof: serialized.proof,
    timestamp: serialized.timestamp,
    ownershipProof: serialized.ownershipProof ? Crypto.fromHex(serialized.ownershipProof) : undefined
  };
}

/**
 * Leaky bucket rate limiter for peer message throttling
 */
class LeakyBucket {
  private tokens: number;
  private lastRefill: number;
  private readonly capacity: number;
  private readonly refillRate: number;

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  tryConsume(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    const tokensToAdd = elapsed * this.refillRate;
    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  getTokens(): number {
    this.refill();
    return this.tokens;
  }
}

/**
 * Wrapper that adapts HyperToken's RoutedPeerManager to Scarcity's PeerConnection interface
 */
class HyperTokenPeerWrapper implements PeerConnection {
  readonly id: string;
  private adapter: HyperTokenAdapter;
  private messageHandler?: (data: GossipMessage) => void;
  private rateLimiter: LeakyBucket;
  private droppedMessages: number = 0;

  constructor(adapter: HyperTokenAdapter, peerId: string, rateLimitPerSecond: number, rateLimitBurst: number) {
    this.adapter = adapter;
    this.id = peerId;
    this.rateLimiter = new LeakyBucket(rateLimitBurst, rateLimitPerSecond);
  }

  async send(data: GossipMessage): Promise<void> {
    if (!this.isConnected()) {
      throw new Error(`Peer ${this.id} is not connected`);
    }
    await this.adapter.sendToPeer(this.id, data);
  }

  isConnected(): boolean {
    return this.adapter.isPeerConnected(this.id);
  }

  setMessageHandler(handler: (data: GossipMessage) => void): void {
    this.messageHandler = handler;
  }

  _handleIncomingMessage(data: GossipMessage): void {
    if (!this.rateLimiter.tryConsume()) {
      this.droppedMessages++;
      console.warn(`[HyperToken] Rate limit exceeded for peer ${this.id}, dropping message (${this.droppedMessages} total dropped)`);
      return;
    }

    if (this.messageHandler) {
      this.messageHandler(data);
    }
  }

  getRateLimitStats() {
    return {
      droppedMessages: this.droppedMessages,
      currentTokens: this.rateLimiter.getTokens()
    };
  }

  disconnect(): void {
    console.log(`[HyperToken] Disconnecting peer ${this.id}`);
  }
}

/**
 * HyperToken adapter with routing, encryption, and state sync
 */
export class HyperTokenAdapter {
  private readonly relayUrl: string;
  private readonly rateLimitPerSecond: number;
  private readonly rateLimitBurst: number;

  private routedManager: RoutedPeerManager | null = null;
  private encryption: E2EEncryption = new E2EEncryption({ curve: 'P-256' });
  private stateSync: StateSyncManager;

  private peerWrappers = new Map<string, HyperTokenPeerWrapper>();
  private isReady = false;
  private readyPromise: Promise<void>;
  private readyResolve?: () => void;
  private readyReject?: (error: Error) => void;
  private peerDiscoveryHandler?: (peer: PeerConnection) => void;
  private stateDeltaHandler?: (delta: StateDelta) => void;
  private config: HyperTokenAdapterConfig;

  constructor(config: HyperTokenAdapterConfig = {}) {
    this.config = config;
    this.relayUrl = config.relayUrl ?? 'ws://localhost:8080';
    this.rateLimitPerSecond = config.rateLimitPerSecond ?? 10;
    this.rateLimitBurst = config.rateLimitBurst ?? 20;

    this.stateSync = new StateSyncManager({
      maxHistory: 10000,
      maxAge: 5 * 60 * 1000,
      getSnapshot: () => this.getStateSnapshot(),
      applySnapshot: (snapshot) => this.applyStateSnapshot(snapshot)
    });

    this.stateSync.on('sync:apply:delta', (evt: any) => {
      if (this.stateDeltaHandler) {
        this.stateDeltaHandler(evt.payload.delta);
      }
    });

    this.readyPromise = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
  }

  /**
   * Set handler for when new peers are discovered
   */
  setPeerDiscoveryHandler(handler: (peer: PeerConnection) => void): void {
    this.peerDiscoveryHandler = handler;
  }

  /**
   * Set handler for state sync deltas (for NullifierGossip integration)
   */
  setStateDeltaHandler(handler: (delta: StateDelta) => void): void {
    this.stateDeltaHandler = handler;
  }

  /**
   * Connect to relay server
   */
  async connect(): Promise<void> {
    this.routedManager = new RoutedPeerManager({
      url: this.relayUrl,
      autoUpgrade: true,
      upgradeDelay: 1000,
      routingStrategy: this.config.routingStrategy ?? RoutingStrategy.Auto,
      autoThresholds: this.config.autoThresholds ?? {
        kademliaThreshold: 100,
        supernodeThreshold: 50
      },
      routingDebug: this.config.routingDebug ?? false
    });

    this.routedManager.on('net:ready', async (evt: any) => {
      this.isReady = true;
      const peerId = evt.payload.peerId;
      console.log(`[HyperToken] Connected: ${peerId}`);

      await this.encryption.initialize(peerId);
      console.log('[HyperToken] E2E encryption initialized');

      if (this.readyResolve) {
        this.readyResolve();
      }
    });

    this.routedManager.on('net:peer:connected', async (evt: any) => {
      const peerId = evt.payload.peerId;
      console.log(`[HyperToken] Peer joined: ${peerId}`);

      const peer = this.ensurePeerWrapper(peerId);

      // Initiate key exchange
      const keyExchange = this.encryption.createKeyExchangeMessage();
      if (keyExchange) {
        this.sendProtocolMessage(peerId, 'key-exchange', keyExchange);
      }

      // Request state catch-up
      const request = this.stateSync.createCatchupRequest(1000);
      this.sendProtocolMessage(peerId, 'catchup-request', request);

      if (this.peerDiscoveryHandler) {
        this.peerDiscoveryHandler(peer);
      }
    });

    this.routedManager.on('net:peer:disconnected', (evt: any) => {
      const peerId = evt.payload.peerId;
      console.log(`[HyperToken] Peer left: ${peerId}`);
      this.encryption.removeSession(peerId);
      this.peerWrappers.delete(peerId);
    });

    this.routedManager.on('net:message', async (evt: any) => {
      await this.handleIncomingMessage(evt.payload);
    });

    this.routedManager.on('net:error', (evt: any) => {
      const error = evt.payload?.error || new Error('Unknown network error');
      console.error(`[HyperToken] Network error:`, error);
      if (this.readyReject && !this.isReady) {
        this.readyReject(error);
      }
    });

    this.routedManager.on('routing:strategy:changed', (evt: any) => {
      console.log(`[HyperToken] Routing strategy changed to ${evt.payload.strategy} (${evt.payload.peerCount} peers)`);
    });

    this.routedManager.on('rtc:upgraded', (evt: any) => {
      const { peerId, usingTurn } = evt.payload;
      const turnInfo = usingTurn ? ' (via TURN)' : '';
      console.log(`[HyperToken] ✅ WebRTC connection established with ${peerId}${turnInfo}`);
    });

    this.routedManager.on('rtc:downgraded', (evt: any) => {
      console.log(`[HyperToken] WebRTC connection lost with ${evt.payload.peerId}, using WebSocket fallback`);
    });

    // Initiate connection
    this.routedManager.connect();

    const timeout = setTimeout(() => {
      if (!this.isReady && this.readyReject) {
        this.readyReject(new Error('Connection timeout'));
      }
    }, 10000);

    try {
      await this.readyPromise;
      clearTimeout(timeout);
    } catch (error) {
      clearTimeout(timeout);
      throw error;
    }
  }

  /**
   * Handle incoming messages (protocol + gossip)
   */
  private async handleIncomingMessage(payload: any): Promise<void> {
    const fromPeerId = payload?.fromPeerId || payload?.payload?.fromPeerId;
    if (!fromPeerId) return;

    const wrapper = this.ensurePeerWrapper(fromPeerId);
    const message = payload?.payload || payload?.data || payload;

    // Protocol messages (key exchange, catchup) are unencrypted
    if (message?._protocol === 'scarcity') {
      await this.handleProtocolMessage(fromPeerId, message as ProtocolMessage);
      return;
    }

    // All gossip messages must be encrypted
    if (!message?.encrypted) {
      console.warn(`[HyperToken] Dropping unencrypted message from ${fromPeerId}`);
      return;
    }

    const decrypted = await this.encryption.decryptJSON<SerializedGossipMessage>(fromPeerId, message.encrypted);
    if (decrypted) {
      wrapper._handleIncomingMessage(deserializeGossipMessage(decrypted));
    }
  }

  /**
   * Handle protocol messages (key exchange, catchup)
   */
  private async handleProtocolMessage(fromPeerId: string, message: ProtocolMessage): Promise<void> {
    switch (message._type) {
      case 'key-exchange': {
        const keyExchange = message.payload as KeyExchangeMessage;
        const success = await this.encryption.handleKeyExchange(keyExchange);
        if (success) {
          console.log(`[HyperToken] 🔐 E2E session established with ${fromPeerId}`);
        }
        break;
      }

      case 'catchup-request': {
        const request = message.payload as CatchupRequest;
        const response = this.stateSync.handleCatchupRequest(request);
        this.sendProtocolMessage(fromPeerId, 'catchup-response', response);
        break;
      }

      case 'catchup-response': {
        const response = message.payload as CatchupResponse;
        console.log(`[HyperToken] Received ${response.deltas.length} catch-up deltas from ${fromPeerId}`);
        this.stateSync.applyCatchupResponse(response);
        break;
      }
    }
  }

  /**
   * Send a protocol message to a peer
   */
  private sendProtocolMessage(peerId: string, type: ProtocolMessage['_type'], payload: any): void {
    const message: ProtocolMessage = {
      _protocol: 'scarcity',
      _type: type,
      payload
    };

    this.routedManager?.sendToPeer(peerId, message);
  }

  /**
   * Send a gossip message to a specific peer (encrypted)
   */
  async sendToPeer(peerId: string, data: GossipMessage): Promise<void> {
    if (!this.encryption.hasSession(peerId)) {
      throw new Error(`No E2E session with ${peerId} - cannot send unencrypted`);
    }

    const serialized = serializeGossipMessage(data);
    const encrypted = await this.encryption.encryptJSON(peerId, serialized);
    if (!encrypted) {
      throw new Error(`Encryption failed for ${peerId}`);
    }

    this.routedManager?.sendToPeer(peerId, { encrypted });
  }

  /**
   * Record a state delta for sync (called by NullifierGossip)
   */
  recordStateDelta(type: string, payload: any): void {
    this.stateSync.recordDelta(type, payload, this.getMyPeerId() ?? undefined);
  }

  /**
   * Get state snapshot for catch-up (override in NullifierGossip)
   */
  private getStateSnapshot(): any {
    // This will be overridden by setStateSnapshotProvider
    return { nullifiers: [] };
  }

  /**
   * Apply state snapshot from catch-up
   */
  private applyStateSnapshot(_snapshot: any): void {
    // Handled via stateDeltaHandler for each delta
  }

  /**
   * Check if a peer is connected
   */
  isPeerConnected(peerId: string): boolean {
    if (!this.routedManager) return false;
    return this.routedManager.getPeers().has(peerId);
  }

  private ensurePeerWrapper(peerId: string): HyperTokenPeerWrapper {
    let wrapper = this.peerWrappers.get(peerId);
    if (!wrapper) {
      wrapper = new HyperTokenPeerWrapper(this, peerId, this.rateLimitPerSecond, this.rateLimitBurst);
      this.peerWrappers.set(peerId, wrapper);
    }
    return wrapper;
  }

  createPeer(peerId?: string): PeerConnection {
    const targetPeerId = peerId ?? this.generatePeerId();

    if (!this.routedManager) {
      return {
        id: targetPeerId,
        async send(_data: GossipMessage): Promise<void> {},
        isConnected(): boolean { return false; }
      };
    }

    return this.ensurePeerWrapper(targetPeerId);
  }

  getPeers(): PeerConnection[] {
    return Array.from(this.peerWrappers.values());
  }

  getMyPeerId(): string | null {
    return this.routedManager?.getPeerId() ?? null;
  }

  getConnectedPeerIds(): string[] {
    if (!this.routedManager) return [];
    return Array.from(this.routedManager.getPeers());
  }

  /**
   * Get current routing strategy
   */
  getRoutingStrategy(): RoutingStrategy | null {
    return this.routedManager?.getActiveStrategy() ?? null;
  }

  /**
   * Get routing, encryption, and state sync statistics
   */
  getStats() {
    return {
      routing: this.routedManager?.getRoutingStats() ?? null,
      encryption: this.encryption.getStats(),
      stateSync: this.stateSync.getStats()
    };
  }

  /**
   * Get peers with E2E encryption established
   */
  getEncryptedPeers(): string[] {
    return this.encryption.getEstablishedPeers();
  }

  disconnect(): void {
    this.routedManager?.disconnect();
    this.encryption.clearSessions();
    this.stateSync.destroy();
    this.peerWrappers.clear();
    this.isReady = false;
  }

  private generatePeerId(): string {
    return `peer-${Math.random().toString(36).substring(2, 11)}`;
  }
}

// Re-export types for convenience
export { RoutingStrategy } from '../vendor/hypertoken/RoutedPeerManager.js';
export type { StateDelta } from '../vendor/hypertoken/StateSyncManager.js';
