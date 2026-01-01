/**
 * Nullifier Collector
 *
 * Background service that subscribes to the gossip network
 * and stores nullifier records in persistent storage
 */

import { NullifierDatabase, type NullifierRecord } from './database.js';
import { NullifierGossip } from '../gossip.js';
import { Crypto } from '../crypto.js';
import type { GossipMessage, WitnessClient } from '../types.js';

export interface CollectorConfig {
  database: NullifierDatabase;
  gossip: NullifierGossip;
  witness: WitnessClient;
  federation?: string;
  // Add callback for realtime updates
  onNullifier?: (message: GossipMessage) => void;
}

export class NullifierCollector {
  private db: NullifierDatabase;
  private gossip: NullifierGossip;
  private witness: WitnessClient;
  private federation: string;
  private running = false;
  private onNullifier?: (message: GossipMessage) => void;
  private stats = {
    received: 0,
    stored: 0,
    errors: 0
  };

  constructor(config: CollectorConfig) {
    this.db = config.database;
    this.gossip = config.gossip;
    this.witness = config.witness;
    this.federation = config.federation || 'default';
    this.onNullifier = config.onNullifier;
  }

  /**
   * Start collecting nullifiers from gossip network
   */
  start(): void {
    if (this.running) {
      console.warn('Collector already running');
      return;
    }

    this.running = true;
    console.log('🔍 Nullifier collector started');
    console.log(`   Federation: ${this.federation}`);
    console.log(`   Gossip peers: ${this.gossip.peers.length}`);

    // Subscribe to gossip messages
    this.gossip.setReceiveHandler(async (message: GossipMessage) => {
      await this.handleGossipMessage(message);
    });
  }

  /**
   * Stop collecting
   */
  stop(): void {
    this.running = false;
    console.log('🛑 Nullifier collector stopped');
    console.log(`   Stats: ${this.stats.stored} stored, ${this.stats.errors} errors`);
  }

  /**
   * Handle incoming gossip message
   */
  private async handleGossipMessage(message: GossipMessage): Promise<void> {
    if (message.type !== 'nullifier' || !message.nullifier || !message.proof) {
      return;
    }

    // Call the realtime hook FIRST so UI updates instantly
    if (this.onNullifier) {
      try {
        this.onNullifier(message);
      } catch (err) {
        console.error('Error in onNullifier callback:', err);
      }
    }

    this.stats.received++;

    try {
      const nullifierHex = Crypto.toHex(message.nullifier);

      // Check if we already have this nullifier
      const existing = this.db.getNullifier(nullifierHex);
      if (existing) {
        // Update peer count if we got more confirmations
        const peerCount = await this.gossip.checkNullifier(message.nullifier);
        if (peerCount > existing.peerCount) {
          this.db.insertNullifier({
            ...existing,
            peerCount
          });
        }
        return;
      }

      // Get witness depth (number of signatures)
      const witnessDepth = message.proof.signatures?.length || 0;

      // Get peer count from gossip network
      const peerCount = await this.gossip.checkNullifier(message.nullifier);

      // Extract token ID from proof if available
      let tokenId: string | undefined;
      try {
        if (message.proof.hash) {
          // Token ID is embedded in the proof hash for transfers
          tokenId = message.proof.hash.substring(0, 64);
        }
      } catch (error) {
        // Token ID not available
      }

      // Create record
      const record: NullifierRecord = {
        nullifierHex,
        tokenId,
        timestamp: message.proof.timestamp,
        firstSeen: message.timestamp,
        peerCount,
        witnessDepth,
        federation: this.federation,
        proof: JSON.stringify(message.proof)
      };

      // Store in database
      this.db.insertNullifier(record);
      this.stats.stored++;

      if (this.stats.stored % 10 === 0) {
        console.log(`   Collected ${this.stats.stored} nullifiers (${this.stats.received} received)`);
      }
    } catch (error) {
      this.stats.errors++;
      console.error('Error processing nullifier:', error);
    }
  }

  /**
   * Get collector statistics
   */
  getStats() {
    const gossipStats = this.gossip.getStats();
    return {
      ...this.stats,
      running: this.running,
      dbCount: this.db.getCount(),
      gossip: gossipStats
    };
  }

  /**
   * Check if collector is running
   */
  isRunning(): boolean {
    return this.running;
  }
}