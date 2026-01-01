/*
 * network/HybridPeerManager.ts
 * Unified peer management with automatic WebRTC upgrade and WebSocket fallback
 *
 * Provides a seamless interface that:
 * 1. Starts with WebSocket for initial connection and signaling
 * 2. Automatically upgrades to WebRTC for lower latency
 * 3. Gracefully falls back to WebSocket if WebRTC fails
 *
 * Vendored from hypertoken-monorepo for Scarcity integration.
 */
import { Emitter } from "./events.js";
import {
  PeerConnection,
  PeerConnectionOptions,
  ReconnectConfig,
  ConnectionState
} from "./PeerConnection.js";
import { WebRTCConnection, WebRTCConfig, DEFAULT_RTC_CONFIG } from "./WebRTCConnection.js";
import { SignalingService } from "./SignalingService.js";

export interface HybridPeerManagerOptions {
  url: string;
  rtcConfig?: WebRTCConfig;
  autoUpgrade?: boolean; // Automatically attempt WebRTC upgrade
  upgradeDelay?: number;  // Delay before attempting upgrade (ms)
  /** Reconnection configuration for WebSocket */
  reconnect?: Partial<ReconnectConfig> | false;
  /** Options for PeerConnection */
  peerConnectionOptions?: PeerConnectionOptions;
}

/**
 * HybridPeerManager manages both WebSocket and WebRTC connections
 *
 * Events emitted (forwards from PeerConnection and WebRTCConnection):
 * - 'net:connected' - WebSocket connected
 * - 'net:ready' - Assigned peerId from server
 * - 'net:disconnected' - WebSocket disconnected
 * - 'net:reconnecting' - WebSocket reconnection attempt starting
 * - 'net:reconnected' - WebSocket successfully reconnected
 * - 'net:peer:connected' - New peer joined (via WebSocket)
 * - 'net:peer:disconnected' - Peer left
 * - 'net:message' - Data received (from either WebSocket or WebRTC)
 * - 'net:error' - Connection error
 * - 'rtc:upgraded' - WebRTC connection established for a peer
 * - 'rtc:downgraded' - Fell back to WebSocket for a peer
 * - 'rtc:connection-failed' - WebRTC connection attempt failed
 * - 'rtc:retrying' - Retrying WebRTC with TURN servers
 */
export class HybridPeerManager extends Emitter {
  private wsConnection: PeerConnection;
  private signalingService: SignalingService;
  private rtcConnections: Map<string, WebRTCConnection>;
  private rtcConfig: WebRTCConfig;
  private autoUpgrade: boolean;
  private upgradeDelay: number;

  // Track which peers we've initiated WebRTC with to avoid duplicates
  private initiatedRTC: Set<string>;

  constructor(options: HybridPeerManagerOptions) {
    super();

    this.rtcConfig = options.rtcConfig || DEFAULT_RTC_CONFIG;
    this.autoUpgrade = options.autoUpgrade !== false; // Default true
    this.upgradeDelay = options.upgradeDelay || 500;

    this.rtcConnections = new Map();
    this.initiatedRTC = new Set();

    // Create WebSocket connection with reconnection options
    const peerOptions: PeerConnectionOptions = {
      ...options.peerConnectionOptions,
      reconnect: options.reconnect,
    };
    this.wsConnection = new PeerConnection(options.url, null, peerOptions);
    this.signalingService = new SignalingService(this.wsConnection);

    this.setupWebSocketHandlers();
    this.setupSignalingHandlers();
  }

  /**
   * Get the WebSocket connection state
   */
  getConnectionState(): ConnectionState {
    return this.wsConnection.getConnectionState();
  }

  /**
   * Get the number of reconnection attempts
   */
  getReconnectAttempts(): number {
    return this.wsConnection.getReconnectAttempts();
  }

  /**
   * Connect to the server via WebSocket
   */
  connect(): void {
    this.wsConnection.connect();
  }

  /**
   * Disconnect from all peers
   */
  disconnect(): void {
    // Close all WebRTC connections
    for (const [peerId, rtcConn] of this.rtcConnections) {
      rtcConn.close();
    }
    this.rtcConnections.clear();
    this.initiatedRTC.clear();

    // Close WebSocket
    this.wsConnection.disconnect();
  }

  /**
   * Send data to a specific peer
   * Prefers WebRTC if available, falls back to WebSocket
   */
  sendToPeer(targetPeerId: string, payload: any): void {
    const rtcConn = this.rtcConnections.get(targetPeerId);

    if (rtcConn && rtcConn.isConnected()) {
      // Fast path: Send via WebRTC DataChannel
      const success = rtcConn.send(payload);
      if (success) {
        return;
      }
      // If WebRTC send failed, fall through to WebSocket
      console.warn(`[Hybrid] WebRTC send failed to ${targetPeerId}, using WebSocket fallback`);
    }

    // Fallback: Send via WebSocket relay
    this.wsConnection.sendToPeer(targetPeerId, payload);
  }

  /**
   * Broadcast data to all connected peers
   */
  broadcast(type: string, payload: any = {}): void {
    // Send to all WebRTC-connected peers
    for (const [peerId, rtcConn] of this.rtcConnections) {
      if (rtcConn.isConnected()) {
        rtcConn.send({ type, payload });
      }
    }

    // Also broadcast via WebSocket for peers without WebRTC
    this.wsConnection.broadcast(type, payload);
  }

  /**
   * Get the local peer ID
   */
  getPeerId(): string | null {
    return this.wsConnection.peerId;
  }

  /**
   * Get list of connected peers (via WebSocket)
   */
  getPeers(): Set<string> {
    return this.wsConnection.peers;
  }

  /**
   * Check if a peer is connected via WebRTC
   */
  isWebRTCConnected(peerId: string): boolean {
    const rtcConn = this.rtcConnections.get(peerId);
    return rtcConn ? rtcConn.isConnected() : false;
  }

  /**
   * Get WebSocket connection (for advanced use)
   */
  getWebSocketConnection(): PeerConnection {
    return this.wsConnection;
  }

  /**
   * Manually initiate WebRTC connection to a peer
   */
  async upgradeToWebRTC(peerId: string): Promise<void> {
    if (this.rtcConnections.has(peerId)) {
      console.warn(`[Hybrid] WebRTC connection to ${peerId} already exists`);
      return;
    }

    if (this.initiatedRTC.has(peerId)) {
      console.log(`[Hybrid] WebRTC connection to ${peerId} already initiated`);
      return;
    }

    this.initiatedRTC.add(peerId);

    console.log(`[Hybrid] Initiating WebRTC connection to ${peerId}`);

    const rtcConn = new WebRTCConnection(peerId, this.rtcConfig);
    this.rtcConnections.set(peerId, rtcConn);

    this.setupWebRTCHandlers(rtcConn, peerId);

    // Create and send offer
    const offer = await rtcConn.createOffer();
    this.signalingService.sendOffer(peerId, offer);
  }

  /**
   * Setup handlers for WebSocket events
   */
  private setupWebSocketHandlers(): void {
    // Forward WebSocket events
    this.wsConnection.on('net:connected', (evt) => {
      this.emit('net:connected', evt);
    });

    this.wsConnection.on('net:ready', (evt) => {
      this.emit('net:ready', evt);
    });

    this.wsConnection.on('net:peer:connected', (evt) => {
      const { peerId } = evt.payload;
      this.emit('net:peer:connected', evt);

      // Auto-upgrade to WebRTC after delay
      if (this.autoUpgrade && peerId) {
        setTimeout(() => {
          this.upgradeToWebRTC(peerId).catch(err => {
            console.error(`[Hybrid] Failed to upgrade to WebRTC for ${peerId}:`, err);
          });
        }, this.upgradeDelay);
      }
    });

    this.wsConnection.on('net:peer:disconnected', (evt) => {
      const { peerId } = evt.payload;

      // Clean up WebRTC connection if exists
      const rtcConn = this.rtcConnections.get(peerId);
      if (rtcConn) {
        rtcConn.close();
        this.rtcConnections.delete(peerId);
      }
      this.initiatedRTC.delete(peerId);

      this.emit('net:peer:disconnected', evt);
    });

    this.wsConnection.on('net:message', (evt) => {
      // Forward non-signaling messages
      const payload = evt.payload;
      if (!payload || !['webrtc-offer', 'webrtc-answer', 'webrtc-ice-candidate'].includes(payload.type)) {
        this.emit('net:message', evt);
      }
    });

    this.wsConnection.on('net:error', (evt) => {
      this.emit('net:error', evt);
    });

    this.wsConnection.on('net:disconnected', (evt) => {
      // Clean up all WebRTC connections on disconnect
      for (const rtcConn of this.rtcConnections.values()) {
        rtcConn.close();
      }
      this.rtcConnections.clear();
      this.initiatedRTC.clear();

      this.emit('net:disconnected', evt);
    });

    // Forward reconnection events
    this.wsConnection.on('net:reconnecting', (evt) => {
      this.emit('net:reconnecting', evt);
    });

    this.wsConnection.on('net:reconnected', (evt) => {
      this.emit('net:reconnected', evt);
    });
  }

  /**
   * Setup handlers for WebRTC signaling
   */
  private setupSignalingHandlers(): void {
    // Handle incoming offers (we are the receiver)
    this.signalingService.on('signal:offer', async (evt) => {
      const { fromPeerId, offer } = evt.payload;

      console.log(`[Hybrid] Received WebRTC offer from ${fromPeerId}`);

      // Create WebRTC connection if it doesn't exist
      let rtcConn = this.rtcConnections.get(fromPeerId);
      if (!rtcConn) {
        rtcConn = new WebRTCConnection(fromPeerId, this.rtcConfig);
        this.rtcConnections.set(fromPeerId, rtcConn);
        this.setupWebRTCHandlers(rtcConn, fromPeerId);
      }

      // Handle offer and send answer
      const answer = await rtcConn.handleOffer(offer);
      this.signalingService.sendAnswer(fromPeerId, answer);
    });

    // Handle incoming answers (we are the caller)
    this.signalingService.on('signal:answer', async (evt) => {
      const { fromPeerId, answer } = evt.payload;

      console.log(`[Hybrid] Received WebRTC answer from ${fromPeerId}`);

      const rtcConn = this.rtcConnections.get(fromPeerId);
      if (rtcConn) {
        await rtcConn.handleAnswer(answer);
      } else {
        console.warn(`[Hybrid] Received answer from ${fromPeerId} but no connection exists`);
      }
    });

    // Handle incoming ICE candidates
    this.signalingService.on('signal:ice-candidate', async (evt) => {
      const { fromPeerId, candidate } = evt.payload;

      const rtcConn = this.rtcConnections.get(fromPeerId);
      if (rtcConn) {
        await rtcConn.addIceCandidate(candidate);
      } else {
        console.warn(`[Hybrid] Received ICE candidate from ${fromPeerId} but no connection exists`);
      }
    });
  }

  /**
   * Setup handlers for a specific WebRTC connection
   */
  private setupWebRTCHandlers(rtcConn: WebRTCConnection, peerId: string): void {
    // Forward ICE candidates to remote peer
    rtcConn.on('rtc:ice-candidate', (evt) => {
      this.signalingService.sendIceCandidate(peerId, evt.payload.candidate);
    });

    // WebRTC connection established
    rtcConn.on('rtc:connected', (evt) => {
      const { usingTurn, retryCount } = evt.payload;
      const turnInfo = usingTurn ? ' (via TURN relay)' : '';
      const retryInfo = retryCount > 0 ? ` after ${retryCount} retries` : '';

      console.log(`[Hybrid] ✅ WebRTC connection established with ${peerId}${turnInfo}${retryInfo}`);
      this.emit('rtc:upgraded', {
        peerId,
        usingTurn,
        retryCount
      });
    });

    // WebRTC connection closed
    rtcConn.on('rtc:disconnected', () => {
      console.log(`[Hybrid] WebRTC connection closed with ${peerId}, falling back to WebSocket`);
      this.rtcConnections.delete(peerId);
      this.initiatedRTC.delete(peerId);
      this.emit('rtc:downgraded', { peerId });
    });

    // WebRTC connection failed (before retry)
    rtcConn.on('rtc:connection-failed', (evt) => {
      const { retryCount, willRetry } = evt.payload;
      console.warn(`[Hybrid] WebRTC connection failed with ${peerId} (attempt ${retryCount})`);

      if (!willRetry) {
        console.log(`[Hybrid] No more retries, using WebSocket fallback for ${peerId}`);
      }

      this.emit('rtc:connection-failed', evt.payload);
    });

    // WebRTC retrying with TURN
    rtcConn.on('rtc:retrying', (evt) => {
      const { retryCount, usingTurn } = evt.payload;
      console.log(`[Hybrid] 🔄 Retrying WebRTC connection with ${peerId} (attempt ${retryCount}, TURN: ${usingTurn})`);
      this.emit('rtc:retrying', evt.payload);
    });

    // Forward data from WebRTC to application
    rtcConn.on('rtc:data', (evt) => {
      this.emit('net:message', {
        payload: evt.payload.payload,
        fromPeerId: peerId
      });
    });

    // Forward errors
    rtcConn.on('rtc:error', (evt) => {
      console.error(`[Hybrid] WebRTC error with ${peerId}:`, evt.payload.error);
      this.emit('net:error', evt);
    });
  }
}
