/*
 * network/PeerConnection.ts
 * Robust handling for both Node (ws) and Browser (WebSocket) environments.
 *
 * This is network transport infrastructure for P2P engine synchronization.
 * Includes automatic reconnection with exponential backoff.
 *
 * Vendored from hypertoken-monorepo for Scarcity integration.
 */
import { Emitter } from "./events.js";
import { MessageCodec, CodecConfig, jsonCodec } from "./MessageCodec.js";
import * as Ws from "ws";

// Message Types
export interface NetworkMessage {
  type: string;
  payload?: any;
  targetPeerId?: string;
  fromPeerId?: string;
}

/**
 * Connection state machine
 */
export enum ConnectionState {
  Disconnected = "disconnected",
  Connecting = "connecting",
  Connected = "connected",
  Reconnecting = "reconnecting",
}

/**
 * Reconnection configuration
 */
export interface ReconnectConfig {
  /** Enable auto-reconnect (default: true) */
  enabled: boolean;
  /** Initial delay in ms (default: 1000) */
  initialDelay: number;
  /** Maximum delay in ms (default: 30000) */
  maxDelay: number;
  /** Backoff multiplier (default: 2) */
  multiplier: number;
  /** Maximum reconnection attempts (default: Infinity) */
  maxAttempts: number;
  /** Add random jitter to delays (default: true) */
  jitter: boolean;
}

export const DEFAULT_RECONNECT_CONFIG: ReconnectConfig = {
  enabled: true,
  initialDelay: 1000,
  maxDelay: 30000,
  multiplier: 2,
  maxAttempts: Infinity,
  jitter: true,
};

export interface PeerConnectionOptions {
  /** Message codec configuration (default: JSON for compatibility) */
  codec?: MessageCodec | Partial<CodecConfig>;
  /** Use binary WebSocket mode when codec supports it */
  binaryMode?: boolean;
  /** Reconnection configuration */
  reconnect?: Partial<ReconnectConfig> | false;
  /** Maximum messages to buffer during reconnection (default: 100) */
  messageBufferSize?: number;
}

/**
 * PeerConnection manages a WebSocket connection with automatic reconnection
 *
 * Events emitted:
 * - 'net:connected' - Initial connection established
 * - 'net:ready' - Received peerId from server
 * - 'net:disconnected' - Connection lost (may reconnect)
 * - 'net:reconnecting' - Starting reconnection attempt
 * - 'net:reconnected' - Successfully reconnected
 * - 'net:error' - Connection error
 * - 'net:peer:connected' - A peer joined
 * - 'net:peer:disconnected' - A peer left
 * - 'net:message' - Received a message
 */
export class PeerConnection extends Emitter {
  url: string;
  engine: any | null;
  socket: WebSocket | null;
  connected: boolean;

  peerId: string | null = null;
  peers: Set<string> = new Set();

  private codec: MessageCodec;
  private binaryMode: boolean;

  // Reconnection state
  private reconnectConfig: ReconnectConfig;
  private connectionState: ConnectionState = ConnectionState.Disconnected;
  private reconnectAttempts: number = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose: boolean = false;
  private messageBuffer: Array<Partial<NetworkMessage>> = [];
  private messageBufferSize: number;

  constructor(
    url: string,
    engine: any | null = null,
    options: PeerConnectionOptions = {}
  ) {
    super();
    this.url = url;
    this.engine = engine;
    this.socket = null;
    this.connected = false;

    // Setup codec (default to JSON for backward compatibility)
    if (options.codec instanceof MessageCodec) {
      this.codec = options.codec;
    } else if (options.codec) {
      this.codec = new MessageCodec(options.codec);
    } else {
      this.codec = jsonCodec;
    }

    this.binaryMode = options.binaryMode ?? this.codec.getConfig().format === "msgpack";

    // Setup reconnection config
    if (options.reconnect === false) {
      this.reconnectConfig = { ...DEFAULT_RECONNECT_CONFIG, enabled: false };
    } else {
      this.reconnectConfig = { ...DEFAULT_RECONNECT_CONFIG, ...options.reconnect };
    }

    this.messageBufferSize = options.messageBufferSize ?? 100;
  }

  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  /**
   * Get number of reconnection attempts
   */
  getReconnectAttempts(): number {
    return this.reconnectAttempts;
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
    this.binaryMode = codec.getConfig().format === "msgpack";
  }

  connect(): void {
    this.intentionalClose = false;
    this._connect();
  }

  /**
   * Internal connect implementation
   */
  private _connect(): void {
    // Cancel any pending reconnection
    this._cancelReconnect();

    this.connectionState = this.reconnectAttempts > 0
      ? ConnectionState.Reconnecting
      : ConnectionState.Connecting;

    // Check for Node's 'ws' constructor (Ws.WebSocket) first, otherwise fall back to browser global
    const WS = typeof Ws.WebSocket !== "undefined" ? Ws.WebSocket : (global as any).WebSocket;

    try {
      this.socket = new WS(this.url);
    } catch (err) {
      console.error("[PeerConnection] Failed to create WebSocket:", err);
      this._scheduleReconnect();
      return;
    }

    if (!this.socket) return;

    // Set binary type for ArrayBuffer handling
    if (this.binaryMode && this.socket.binaryType !== undefined) {
      this.socket.binaryType = "arraybuffer";
    }

    // Use standard 'on' pattern if available (Node/ws), fall back to addEventListener (Browser)
    if (typeof (this.socket as any).on === "function") {
      (this.socket as any).on("open", () => this._onOpen());
      (this.socket as any).on("message", (data: any) => this._handleMessageData(data));
      (this.socket as any).on("close", (code: number, reason: string) => this._onClose(code, reason));
      (this.socket as any).on("error", (err: any) => this._onError(err));
    } else {
      this.socket.addEventListener("open", () => this._onOpen());
      this.socket.addEventListener("message", (ev: any) => this._handleMessageEvent(ev));
      this.socket.addEventListener("close", (ev: CloseEvent) => this._onClose(ev.code, ev.reason));
      this.socket.addEventListener("error", (err: any) => this._onError(err));
    }
  }

  /**
   * Disconnect and don't reconnect
   */
  disconnect(): void {
    this.intentionalClose = true;
    this._cancelReconnect();
    if (this.socket) {
      this.socket.close(1000, "Client disconnect");
    }
    this.connectionState = ConnectionState.Disconnected;
  }

  /**
   * Reset reconnection state (call before re-connecting after intentional disconnect)
   */
  resetReconnection(): void {
    this.reconnectAttempts = 0;
    this.intentionalClose = false;
  }

  sendToPeer(targetPeerId: string, payload: any): void {
    this._send({ type: "p2p", targetPeerId, payload });
  }

  broadcast(type: string, payload: any = {}): void {
    this._send({ type, payload });
  }

  private _send(msg: Partial<NetworkMessage>): void {
    // Buffer messages during reconnection
    if (this.connectionState === ConnectionState.Reconnecting) {
      if (this.messageBuffer.length < this.messageBufferSize) {
        this.messageBuffer.push(msg);
      }
      return;
    }

    if (!this.socket || this.socket.readyState !== 1) return;

    const encoded = this.codec.encode(msg);
    this.socket.send(encoded);
  }

  /**
   * Flush buffered messages after reconnection
   */
  private _flushMessageBuffer(): void {
    const buffered = this.messageBuffer.splice(0);
    for (const msg of buffered) {
      this._send(msg);
    }
  }

  // --- Event Handlers ---

  private _onOpen() {
    const wasReconnecting = this.connectionState === ConnectionState.Reconnecting;

    this.connected = true;
    this.connectionState = ConnectionState.Connected;

    if (wasReconnecting) {
      console.log(`[PeerConnection] Reconnected after ${this.reconnectAttempts} attempts`);
      this.emit("net:reconnected", { attempts: this.reconnectAttempts });
      this._flushMessageBuffer();
    } else {
      this.emit("net:connected");
    }

    // Reset reconnection state on successful connection
    this.reconnectAttempts = 0;
  }

  private _onClose(code?: number, reason?: string) {
    this.connected = false;
    this.socket = null;

    // Normal closure codes: 1000 (normal), 1001 (going away)
    const isNormalClosure = code === 1000 || code === 1001;

    if (this.intentionalClose || isNormalClosure) {
      // Intentional disconnect - clear state and don't reconnect
      this.peers.clear();
      this.connectionState = ConnectionState.Disconnected;
      this.emit("net:disconnected", { code, reason, intentional: true });
      return;
    }

    // Unexpected disconnect - try to reconnect
    this.connectionState = ConnectionState.Reconnecting;
    this.emit("net:disconnected", { code, reason, intentional: false });

    this._scheduleReconnect();
  }

  private _onError(err: any) {
    this.emit("net:error", { payload: { error: err } });

    // If not connected, the close handler will trigger reconnection
    // If connected, just emit the error (socket may recover)
  }

  // --- Reconnection Logic ---

  /**
   * Schedule a reconnection attempt with exponential backoff
   */
  private _scheduleReconnect(): void {
    if (!this.reconnectConfig.enabled) {
      console.log("[PeerConnection] Reconnection disabled");
      return;
    }

    if (this.reconnectAttempts >= this.reconnectConfig.maxAttempts) {
      console.error(`[PeerConnection] Max reconnection attempts (${this.reconnectConfig.maxAttempts}) exceeded`);
      this.connectionState = ConnectionState.Disconnected;
      this.emit("net:error", {
        payload: { error: new Error("Max reconnection attempts exceeded") }
      });
      return;
    }

    // Calculate delay with exponential backoff
    let delay = this.reconnectConfig.initialDelay *
      Math.pow(this.reconnectConfig.multiplier, this.reconnectAttempts);

    // Cap at max delay
    delay = Math.min(delay, this.reconnectConfig.maxDelay);

    // Add jitter if enabled (±25%)
    if (this.reconnectConfig.jitter) {
      const jitter = delay * 0.25 * (Math.random() * 2 - 1);
      delay = Math.round(delay + jitter);
    }

    this.reconnectAttempts++;

    console.log(`[PeerConnection] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.reconnectConfig.maxAttempts === Infinity ? '∞' : this.reconnectConfig.maxAttempts})`);

    this.emit("net:reconnecting", {
      attempt: this.reconnectAttempts,
      delay,
      maxAttempts: this.reconnectConfig.maxAttempts
    });

    this.reconnectTimer = setTimeout(() => {
      this._connect();
    }, delay);
  }

  /**
   * Cancel pending reconnection
   */
  private _cancelReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  // Browser-style event wrapper
  private _handleMessageEvent(ev: any) {
    this._handleMessageData(ev.data);
  }

  // Core logic handling raw data string/buffer
  private _handleMessageData(data: any) {
    try {
      // Decode using codec (handles both binary and JSON)
      const msg = this.codec.decode(data) as NetworkMessage;

      switch (msg.type) {
        case "welcome":
          this.peerId = (msg as any).peerId;
          this.emit("net:ready", { peerId: this.peerId });
          break;

        case "peer:joined":
          if ((msg as any).peerId !== this.peerId) {
            this.peers.add((msg as any).peerId);
            this.emit("net:peer:connected", { peerId: (msg as any).peerId });
          }
          break;

        case "peer:left":
          this.peers.delete((msg as any).peerId);
          this.emit("net:peer:disconnected", { peerId: (msg as any).peerId });
          break;

        case "p2p":
          this.emit("net:message", {
            ...msg.payload,
            fromPeerId: msg.fromPeerId,
          });
          break;

        case "error":
          this.emit("net:error", msg);
          break;

        default:
          this.emit("net:message", msg);
          break;
      }
    } catch (err) {
      console.error("Network parse error", err);
    }
  }
}
