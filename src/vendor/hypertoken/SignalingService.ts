/*
 * network/SignalingService.ts
 * WebRTC signaling over WebSocket
 *
 * Uses the existing WebSocket PeerConnection infrastructure to exchange
 * WebRTC session descriptions (SDP) and ICE candidates between peers.
 */
import { Emitter } from "./events.js";
import { PeerConnection } from "./PeerConnection.js";

export interface SignalingMessage {
  type: 'webrtc-offer' | 'webrtc-answer' | 'webrtc-ice-candidate';
  fromPeerId?: string;
  targetPeerId?: string;
  offer?: RTCSessionDescriptionInit;
  answer?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
}

/**
 * SignalingService handles WebRTC signaling over existing WebSocket connection
 *
 * Events emitted:
 * - 'signal:offer' - Received offer from remote peer
 * - 'signal:answer' - Received answer from remote peer
 * - 'signal:ice-candidate' - Received ICE candidate from remote peer
 */
export class SignalingService extends Emitter {
  private wsConnection: PeerConnection;

  constructor(wsConnection: PeerConnection) {
    super();
    this.wsConnection = wsConnection;
    this.setupSignalingHandlers();
  }

  /**
   * Send a WebRTC offer to a remote peer
   */
  sendOffer(targetPeerId: string, offer: RTCSessionDescriptionInit): void {
    this.wsConnection.sendToPeer(targetPeerId, {
      type: 'webrtc-offer',
      offer
    });
    console.log(`[Signaling] Sent offer to ${targetPeerId}`);
  }

  /**
   * Send a WebRTC answer to a remote peer
   */
  sendAnswer(targetPeerId: string, answer: RTCSessionDescriptionInit): void {
    this.wsConnection.sendToPeer(targetPeerId, {
      type: 'webrtc-answer',
      answer
    });
    console.log(`[Signaling] Sent answer to ${targetPeerId}`);
  }

  /**
   * Send an ICE candidate to a remote peer
   */
  sendIceCandidate(targetPeerId: string, candidate: RTCIceCandidateInit): void {
    this.wsConnection.sendToPeer(targetPeerId, {
      type: 'webrtc-ice-candidate',
      candidate
    });
    // ICE candidates can be frequent, so verbose logging is optional
    // console.log(`[Signaling] Sent ICE candidate to ${targetPeerId}`);
  }

  /**
   * Setup handlers for incoming signaling messages
   */
  private setupSignalingHandlers(): void {
    this.wsConnection.on('net:message', (evt) => {
      const msg = evt.payload;

      if (!msg || !msg.type) return;

      switch (msg.type) {
        case 'webrtc-offer':
          this.handleOffer(msg);
          break;

        case 'webrtc-answer':
          this.handleAnswer(msg);
          break;

        case 'webrtc-ice-candidate':
          this.handleIceCandidate(msg);
          break;
      }
    });
  }

  /**
   * Handle incoming offer
   */
  private handleOffer(msg: SignalingMessage): void {
    if (!msg.offer || !msg.fromPeerId) {
      console.warn('[Signaling] Received malformed offer:', msg);
      return;
    }

    console.log(`[Signaling] Received offer from ${msg.fromPeerId}`);
    this.emit('signal:offer', {
      fromPeerId: msg.fromPeerId,
      offer: msg.offer
    });
  }

  /**
   * Handle incoming answer
   */
  private handleAnswer(msg: SignalingMessage): void {
    if (!msg.answer || !msg.fromPeerId) {
      console.warn('[Signaling] Received malformed answer:', msg);
      return;
    }

    console.log(`[Signaling] Received answer from ${msg.fromPeerId}`);
    this.emit('signal:answer', {
      fromPeerId: msg.fromPeerId,
      answer: msg.answer
    });
  }

  /**
   * Handle incoming ICE candidate
   */
  private handleIceCandidate(msg: SignalingMessage): void {
    if (!msg.candidate || !msg.fromPeerId) {
      console.warn('[Signaling] Received malformed ICE candidate:', msg);
      return;
    }

    // console.log(`[Signaling] Received ICE candidate from ${msg.fromPeerId}`);
    this.emit('signal:ice-candidate', {
      fromPeerId: msg.fromPeerId,
      candidate: msg.candidate
    });
  }

  /**
   * Get the underlying WebSocket connection
   */
  getWebSocketConnection(): PeerConnection {
    return this.wsConnection;
  }

  /**
   * Check if the WebSocket connection is ready
   */
  isReady(): boolean {
    return this.wsConnection.connected && this.wsConnection.peerId !== null;
  }
}
