/*
 * network/WebRTCConnection.ts
 * WebRTC DataChannel wrapper for direct peer-to-peer connections
 *
 * Provides a high-level abstraction over RTCPeerConnection and RTCDataChannel
 * for reliable, low-latency P2P communication.
 *
 * Vendored from hypertoken-monorepo for Scarcity integration.
 */
import { Emitter } from "./events.js";
import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate } from "./webrtc-polyfill.js";
import { MessageCodec, defaultCodec } from "./MessageCodec.js";

export interface WebRTCConfig {
  iceServers: RTCIceServer[];
  // Optional: Configure DataChannel behavior
  ordered?: boolean;
  maxRetransmits?: number;
  // Connection retry configuration
  enableTurnFallback?: boolean;
  connectionTimeout?: number; // ms to wait before considering connection failed
  maxRetries?: number;
  // Message codec (default: msgpack with compression)
  codec?: MessageCodec;
}

export const DEFAULT_RTC_CONFIG: WebRTCConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
  ],
  ordered: true,
  maxRetransmits: 3,
  enableTurnFallback: true,
  connectionTimeout: 15000, // 15 seconds
  maxRetries: 1
};

// Public TURN servers (for fallback)
// Note: For production, use your own TURN servers with authentication
export const DEFAULT_TURN_SERVERS: RTCIceServer[] = [
  {
    urls: 'turn:openrelay.metered.ca:80',
    username: 'openrelayproject',
    credential: 'openrelayproject'
  },
  {
    urls: 'turn:openrelay.metered.ca:443',
    username: 'openrelayproject',
    credential: 'openrelayproject'
  }
];

/**
 * WebRTCConnection manages a single peer-to-peer WebRTC connection
 *
 * Events emitted:
 * - 'rtc:ice-candidate' - Local ICE candidate generated
 * - 'rtc:connected' - DataChannel opened and ready
 * - 'rtc:disconnected' - Connection closed
 * - 'rtc:data' - Data received from peer
 * - 'rtc:error' - Connection error occurred
 * - 'rtc:connection-failed' - Connection attempt failed (before retry)
 * - 'rtc:retrying' - Attempting to reconnect with TURN
 */
export class WebRTCConnection extends Emitter {
  private peerConnection!: RTCPeerConnection; // Initialized in initializePeerConnection()
  private dataChannel: RTCDataChannel | null = null;
  private remotePeerId: string;
  private config: WebRTCConfig;
  private connectionState: RTCPeerConnectionState = 'new';
  private connectionTimeout: ReturnType<typeof setTimeout> | null = null;
  private retryCount: number = 0;
  private usingTurn: boolean = false;
  private codec: MessageCodec;

  constructor(remotePeerId: string, config: WebRTCConfig = DEFAULT_RTC_CONFIG) {
    super();
    this.remotePeerId = remotePeerId;
    this.config = config;
    this.codec = config.codec ?? defaultCodec;

    this.initializePeerConnection();
  }

  /**
   * Get the current message codec
   */
  getCodec(): MessageCodec {
    return this.codec;
  }

  /**
   * Set a new message codec
   */
  setCodec(codec: MessageCodec): void {
    this.codec = codec;
  }

  /**
   * Initialize or re-initialize the peer connection
   */
  private initializePeerConnection(): void {
    // Clean up existing connection if any
    if (this.peerConnection) {
      this.peerConnection.close();
    }

    // Create peer connection with ICE servers for NAT traversal
    this.peerConnection = new RTCPeerConnection({
      iceServers: this.config.iceServers
    });

    this.setupConnectionHandlers();
    this.startConnectionTimeout();
  }

  /**
   * Get the remote peer ID
   */
  getRemotePeerId(): string {
    return this.remotePeerId;
  }

  /**
   * Check if the connection is established and ready
   */
  isConnected(): boolean {
    return this.dataChannel?.readyState === 'open';
  }

  /**
   * Get current connection state
   */
  getConnectionState(): RTCPeerConnectionState {
    return this.connectionState;
  }

  /**
   * Create an offer to initiate connection (caller side)
   */
  async createOffer(): Promise<RTCSessionDescriptionInit> {
    // Create data channel (only caller creates it)
    this.dataChannel = this.peerConnection.createDataChannel('hypertoken', {
      ordered: this.config.ordered ?? true,
      maxRetransmits: this.config.maxRetransmits ?? 3
    });

    this.setupDataChannelHandlers();

    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);

    return offer;
  }

  /**
   * Handle an incoming offer and create an answer (receiver side)
   */
  async handleOffer(offer: RTCSessionDescriptionInit): Promise<RTCSessionDescriptionInit> {
    await this.peerConnection.setRemoteDescription(new RTCSessionDescription(offer));

    const answer = await this.peerConnection.createAnswer();
    await this.peerConnection.setLocalDescription(answer);

    return answer;
  }

  /**
   * Handle an incoming answer (caller side)
   */
  async handleAnswer(answer: RTCSessionDescriptionInit): Promise<void> {
    await this.peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
  }

  /**
   * Add an ICE candidate received from the remote peer
   */
  async addIceCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    try {
      await this.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (err) {
      console.error('[WebRTC] Error adding ICE candidate:', err);
    }
  }

  /**
   * Send data to the remote peer via DataChannel
   */
  send(data: any): boolean {
    if (!this.isConnected()) {
      console.warn('[WebRTC] Cannot send: DataChannel not open');
      return false;
    }

    try {
      const encoded = this.codec.encode(data);
      // DataChannel.send() accepts string, ArrayBuffer, or ArrayBufferView
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      this.dataChannel!.send(encoded as any);
      return true;
    } catch (err) {
      console.error('[WebRTC] Send error:', err);
      this.emit('rtc:error', { error: err });
      return false;
    }
  }

  /**
   * Close the connection
   */
  close(): void {
    this.clearConnectionTimeout();

    if (this.dataChannel) {
      this.dataChannel.close();
      this.dataChannel = null;
    }

    this.peerConnection.close();
    this.emit('rtc:disconnected', { peerId: this.remotePeerId });
  }

  /**
   * Check if currently using TURN servers
   */
  isUsingTurn(): boolean {
    return this.usingTurn;
  }

  /**
   * Get current retry count
   */
  getRetryCount(): number {
    return this.retryCount;
  }

  /**
   * Start connection timeout
   */
  private startConnectionTimeout(): void {
    this.clearConnectionTimeout();

    const timeout = this.config.connectionTimeout || 15000;
    this.connectionTimeout = setTimeout(() => {
      if (!this.isConnected()) {
        console.warn(`[WebRTC] Connection timeout after ${timeout}ms with ${this.remotePeerId}`);
        this.handleConnectionFailure();
      }
    }, timeout);
  }

  /**
   * Clear connection timeout
   */
  private clearConnectionTimeout(): void {
    if (this.connectionTimeout) {
      clearTimeout(this.connectionTimeout);
      this.connectionTimeout = null;
    }
  }

  /**
   * Handle connection failure and retry with TURN if enabled
   */
  private handleConnectionFailure(): void {
    const maxRetries = this.config.maxRetries || 1;
    const enableTurnFallback = this.config.enableTurnFallback !== false;

    // Emit failure event
    this.emit('rtc:connection-failed', {
      peerId: this.remotePeerId,
      retryCount: this.retryCount,
      willRetry: enableTurnFallback && this.retryCount < maxRetries
    });

    // Retry with TURN if enabled and within retry limit
    if (enableTurnFallback && this.retryCount < maxRetries && !this.usingTurn) {
      this.retryCount++;
      this.retryWithTurn();
    } else {
      console.error(`[WebRTC] Connection failed permanently with ${this.remotePeerId}`);
      this.emit('rtc:error', {
        error: 'Connection failed after retries',
        peerId: this.remotePeerId
      });
    }
  }

  /**
   * Retry connection with TURN servers
   */
  private retryWithTurn(): void {
    console.log(`[WebRTC] Retrying connection with TURN servers (attempt ${this.retryCount}/${this.config.maxRetries})`);

    this.usingTurn = true;

    // Add TURN servers to existing STUN servers
    const turnConfig = [...this.config.iceServers, ...DEFAULT_TURN_SERVERS];
    this.config = {
      ...this.config,
      iceServers: turnConfig
    };

    this.emit('rtc:retrying', {
      peerId: this.remotePeerId,
      retryCount: this.retryCount,
      usingTurn: true
    });

    // Reinitialize connection with TURN servers
    this.initializePeerConnection();
  }

  /**
   * Setup handlers for peer connection events
   */
  private setupConnectionHandlers(): void {
    // ICE candidate generation
    this.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.emit('rtc:ice-candidate', {
          peerId: this.remotePeerId,
          candidate: event.candidate.toJSON()
        });
      }
    };

    // Connection state changes
    this.peerConnection.onconnectionstatechange = () => {
      this.connectionState = this.peerConnection.connectionState;

      console.log(`[WebRTC] Connection state with ${this.remotePeerId}: ${this.connectionState}`);

      if (this.connectionState === 'connected') {
        // Connection succeeded, clear timeout
        this.clearConnectionTimeout();
      } else if (this.connectionState === 'failed') {
        // Connection failed, trigger failure handler
        this.handleConnectionFailure();
      } else if (this.connectionState === 'closed') {
        this.emit('rtc:disconnected', { peerId: this.remotePeerId });
      }
    };

    // ICE connection state changes
    this.peerConnection.oniceconnectionstatechange = () => {
      const iceState = this.peerConnection.iceConnectionState;
      console.log(`[WebRTC] ICE state with ${this.remotePeerId}: ${iceState}`);

      if (iceState === 'connected' || iceState === 'completed') {
        // ICE connection successful
        this.clearConnectionTimeout();
      } else if (iceState === 'failed') {
        // ICE connection failed, trigger failure handler
        console.warn(`[WebRTC] ICE connection failed with ${this.remotePeerId}`);
        this.handleConnectionFailure();
      }
    };

    // Handle incoming data channels (receiver side)
    this.peerConnection.ondatachannel = (event) => {
      console.log(`[WebRTC] Received data channel from ${this.remotePeerId}`);
      this.dataChannel = event.channel;
      this.setupDataChannelHandlers();
    };
  }

  /**
   * Setup handlers for data channel events
   */
  private setupDataChannelHandlers(): void {
    if (!this.dataChannel) return;

    // Set binary type for efficient message handling
    this.dataChannel.binaryType = 'arraybuffer';

    this.dataChannel.onopen = () => {
      console.log(`[WebRTC] DataChannel opened with ${this.remotePeerId}`);
      this.clearConnectionTimeout(); // Connection successful

      const turnStatus = this.usingTurn ? ' (via TURN)' : '';
      console.log(`[WebRTC] ✅ Connection established${turnStatus}`);

      this.emit('rtc:connected', {
        peerId: this.remotePeerId,
        usingTurn: this.usingTurn,
        retryCount: this.retryCount
      });
    };

    this.dataChannel.onclose = () => {
      console.log(`[WebRTC] DataChannel closed with ${this.remotePeerId}`);
      this.emit('rtc:disconnected', { peerId: this.remotePeerId });
    };

    this.dataChannel.onerror = (error) => {
      console.error(`[WebRTC] DataChannel error with ${this.remotePeerId}:`, error);
      this.emit('rtc:error', { error, peerId: this.remotePeerId });
    };

    this.dataChannel.onmessage = (event) => {
      try {
        const data = this.codec.decode(event.data);
        this.emit('rtc:data', {
          payload: data,
          fromPeerId: this.remotePeerId
        });
      } catch (err) {
        console.error('[WebRTC] Error parsing message:', err);
      }
    };
  }

  /**
   * Get connection statistics (useful for debugging)
   */
  async getStats(): Promise<RTCStatsReport> {
    return await this.peerConnection.getStats();
  }
}
