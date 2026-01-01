/*
 * network/StateSyncManager.ts
 *
 * Manages state synchronization for reconnecting peers.
 * Tracks state deltas with sequence numbers and provides
 * catch-up functionality for peers that missed updates.
 */

import { Emitter } from "./events.js";

/**
 * A tracked state delta
 */
export interface StateDelta {
  /** Unique sequence number */
  seq: number;
  /** Timestamp when the delta was created */
  timestamp: number;
  /** Type of operation */
  type: string;
  /** Delta payload */
  payload: unknown;
  /** Origin peer ID */
  origin?: string;
}

/**
 * Catch-up request from a reconnecting peer
 */
export interface CatchupRequest {
  /** Last sequence number the peer has */
  lastSeq: number;
  /** Peer's unique session ID (to detect reconnections) */
  sessionId: string;
  /** Maximum number of deltas to receive */
  maxDeltas?: number;
}

/**
 * Catch-up response with missed deltas
 */
export interface CatchupResponse {
  /** Deltas since the requested sequence number */
  deltas: StateDelta[];
  /** Current sequence number */
  currentSeq: number;
  /** Whether there are more deltas available */
  hasMore: boolean;
  /** Full state snapshot if delta history is unavailable */
  snapshot?: unknown;
}

/**
 * Configuration for StateSyncManager
 */
export interface StateSyncConfig {
  /** Maximum number of deltas to keep in history (default: 1000) */
  maxHistory: number;
  /** Maximum age of deltas to keep in ms (default: 5 minutes) */
  maxAge: number;
  /** Enable compression for snapshots (default: true) */
  compressSnapshots: boolean;
  /** Function to get current full state snapshot */
  getSnapshot?: () => unknown;
  /** Function to apply a snapshot to restore state */
  applySnapshot?: (snapshot: unknown) => void;
}

export const DEFAULT_STATE_SYNC_CONFIG: StateSyncConfig = {
  maxHistory: 1000,
  maxAge: 5 * 60 * 1000, // 5 minutes
  compressSnapshots: true,
};

/**
 * StateSyncManager tracks state deltas and provides catch-up for reconnecting peers
 *
 * Events emitted:
 * - 'sync:delta' - New delta recorded
 * - 'sync:catchup:request' - Received catchup request
 * - 'sync:catchup:response' - Received catchup response
 * - 'sync:catchup:complete' - Catchup process completed
 */
export class StateSyncManager extends Emitter {
  private config: StateSyncConfig;
  private deltas: StateDelta[] = [];
  private currentSeq: number = 0;
  private sessionId: string;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: Partial<StateSyncConfig> = {}) {
    super();
    this.config = { ...DEFAULT_STATE_SYNC_CONFIG, ...config };
    this.sessionId = this.generateSessionId();

    // Start periodic cleanup
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  /**
   * Generate a unique session ID
   */
  private generateSessionId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 10)}`;
  }

  /**
   * Get the current session ID
   */
  getSessionId(): string {
    return this.sessionId;
  }

  /**
   * Get the current sequence number
   */
  getCurrentSeq(): number {
    return this.currentSeq;
  }

  /**
   * Record a new state delta
   */
  recordDelta(type: string, payload: unknown, origin?: string): StateDelta {
    this.currentSeq++;

    const delta: StateDelta = {
      seq: this.currentSeq,
      timestamp: Date.now(),
      type,
      payload,
      origin,
    };

    this.deltas.push(delta);

    // Trim if over max history
    if (this.deltas.length > this.config.maxHistory) {
      this.deltas.shift();
    }

    this.emit("sync:delta", { delta });

    return delta;
  }

  /**
   * Get deltas since a given sequence number
   */
  getDeltasSince(seq: number, maxDeltas?: number): { deltas: StateDelta[]; hasMore: boolean } {
    const matchingDeltas = this.deltas.filter((d) => d.seq > seq);

    // Apply limit if specified
    if (maxDeltas && matchingDeltas.length > maxDeltas) {
      return {
        deltas: matchingDeltas.slice(0, maxDeltas),
        hasMore: true,
      };
    }

    return {
      deltas: matchingDeltas,
      hasMore: false,
    };
  }

  /**
   * Check if we can provide deltas since the given sequence
   */
  canProvideDeltasSince(seq: number): boolean {
    if (seq >= this.currentSeq) {
      return true; // Already up to date
    }

    if (this.deltas.length === 0) {
      return seq >= this.currentSeq;
    }

    const oldestSeq = this.deltas[0].seq;
    return seq >= oldestSeq - 1;
  }

  /**
   * Handle a catch-up request from a reconnecting peer
   */
  handleCatchupRequest(request: CatchupRequest): CatchupResponse {
    const { lastSeq, maxDeltas } = request;

    this.emit("sync:catchup:request", { request });

    // Check if we can provide deltas
    if (this.canProvideDeltasSince(lastSeq)) {
      const { deltas, hasMore } = this.getDeltasSince(lastSeq, maxDeltas);

      return {
        deltas,
        currentSeq: this.currentSeq,
        hasMore,
      };
    }

    // Can't provide deltas - need full snapshot
    const snapshot = this.config.getSnapshot?.();

    return {
      deltas: [],
      currentSeq: this.currentSeq,
      hasMore: false,
      snapshot,
    };
  }

  /**
   * Apply a catch-up response
   */
  applyCatchupResponse(response: CatchupResponse): void {
    this.emit("sync:catchup:response", { response });

    if (response.snapshot !== undefined) {
      // Apply full snapshot
      this.config.applySnapshot?.(response.snapshot);
      this.currentSeq = response.currentSeq;
      this.deltas = []; // Clear local deltas after snapshot
    } else {
      // Apply deltas
      for (const delta of response.deltas) {
        this.emit("sync:apply:delta", { delta });
      }
      this.currentSeq = response.currentSeq;
    }

    this.emit("sync:catchup:complete", {
      deltasApplied: response.deltas.length,
      hadSnapshot: response.snapshot !== undefined,
      currentSeq: this.currentSeq,
    });
  }

  /**
   * Create a catch-up request
   */
  createCatchupRequest(maxDeltas?: number): CatchupRequest {
    return {
      lastSeq: this.currentSeq,
      sessionId: this.sessionId,
      maxDeltas,
    };
  }

  /**
   * Reset the session (call after intentional disconnect)
   */
  resetSession(): void {
    this.sessionId = this.generateSessionId();
    this.currentSeq = 0;
    this.deltas = [];
  }

  /**
   * Cleanup old deltas
   */
  private cleanup(): void {
    const now = Date.now();
    const cutoff = now - this.config.maxAge;

    // Remove deltas older than maxAge
    const initialLength = this.deltas.length;
    this.deltas = this.deltas.filter((d) => d.timestamp > cutoff);

    if (this.deltas.length !== initialLength) {
      console.log(
        `[StateSyncManager] Cleaned up ${initialLength - this.deltas.length} old deltas`
      );
    }
  }

  /**
   * Destroy the manager
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Get statistics
   */
  getStats(): {
    deltaCount: number;
    currentSeq: number;
    oldestSeq: number | null;
    sessionId: string;
  } {
    return {
      deltaCount: this.deltas.length,
      currentSeq: this.currentSeq,
      oldestSeq: this.deltas.length > 0 ? this.deltas[0].seq : null,
      sessionId: this.sessionId,
    };
  }
}

export default StateSyncManager;
