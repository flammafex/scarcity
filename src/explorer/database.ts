/**
 * Nullifier Database
 *
 * Persistent storage for nullifier records from the gossip network
 */

import Database from 'better-sqlite3';
import { join } from 'path';
import { homedir } from 'os';
import { existsSync, mkdirSync } from 'fs';
import type { Attestation } from '../types.js';

export interface NullifierRecord {
  id?: number;
  nullifierHex: string;
  tokenId?: string;
  timestamp: number;
  firstSeen: number;
  peerCount: number;
  witnessDepth: number;
  federation?: string;
  proof: string; // JSON serialized Attestation
}

export interface NetworkStats {
  totalNullifiers: number;
  last24h: number;
  lastHour: number;
  activeFederations: number;
  avgPeerCount: number;
  avgWitnessDepth: number;
}

export class NullifierDatabase {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const defaultPath = join(homedir(), '.scarcity', 'explorer.db');
    const path = dbPath || defaultPath;

    // Ensure directory exists
    const dir = join(path, '..');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(path);
    this.initialize();
  }

  /**
   * Initialize database schema
   */
  private initialize(): void {
    // Create nullifiers table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS nullifiers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nullifierHex TEXT UNIQUE NOT NULL,
        tokenId TEXT,
        timestamp INTEGER NOT NULL,
        firstSeen INTEGER NOT NULL,
        peerCount INTEGER NOT NULL,
        witnessDepth INTEGER NOT NULL,
        federation TEXT,
        proof TEXT NOT NULL
      );
    `);

    // Create indices for common queries
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_nullifiers_timestamp ON nullifiers(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_nullifiers_firstSeen ON nullifiers(firstSeen DESC);
      CREATE INDEX IF NOT EXISTS idx_nullifiers_federation ON nullifiers(federation);
      CREATE INDEX IF NOT EXISTS idx_nullifiers_tokenId ON nullifiers(tokenId);
    `);

    console.log('✓ Nullifier database initialized');
  }

  /**
   * Insert or update a nullifier record
   */
  insertNullifier(record: NullifierRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO nullifiers (nullifierHex, tokenId, timestamp, firstSeen, peerCount, witnessDepth, federation, proof)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(nullifierHex) DO UPDATE SET
        peerCount = MAX(peerCount, excluded.peerCount),
        witnessDepth = MAX(witnessDepth, excluded.witnessDepth)
    `);

    stmt.run(
      record.nullifierHex,
      record.tokenId || null,
      record.timestamp,
      record.firstSeen,
      record.peerCount,
      record.witnessDepth,
      record.federation || null,
      record.proof
    );
  }

  /**
   * Get nullifier by hex
   */
  getNullifier(nullifierHex: string): NullifierRecord | undefined {
    const stmt = this.db.prepare('SELECT * FROM nullifiers WHERE nullifierHex = ?');
    return stmt.get(nullifierHex) as NullifierRecord | undefined;
  }

  /**
   * Get recent nullifiers with pagination
   */
  getRecentNullifiers(limit = 50, offset = 0): NullifierRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM nullifiers
      ORDER BY firstSeen DESC
      LIMIT ? OFFSET ?
    `);
    return stmt.all(limit, offset) as NullifierRecord[];
  }

  /**
   * Search nullifiers by partial hex
   */
  searchNullifiers(searchHex: string, limit = 50): NullifierRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM nullifiers
      WHERE nullifierHex LIKE ?
      ORDER BY firstSeen DESC
      LIMIT ?
    `);
    return stmt.all(`%${searchHex}%`, limit) as NullifierRecord[];
  }

  /**
   * Get nullifiers by token ID
   */
  getNullifiersByToken(tokenId: string): NullifierRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM nullifiers
      WHERE tokenId = ?
      ORDER BY firstSeen DESC
    `);
    return stmt.all(tokenId) as NullifierRecord[];
  }

  /**
   * Get nullifiers by federation
   */
  getNullifiersByFederation(federation: string, limit = 50, offset = 0): NullifierRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM nullifiers
      WHERE federation = ?
      ORDER BY firstSeen DESC
      LIMIT ? OFFSET ?
    `);
    return stmt.all(federation, limit, offset) as NullifierRecord[];
  }

  /**
   * Get nullifiers in time range
   */
  getNullifiersInRange(startTime: number, endTime: number): NullifierRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM nullifiers
      WHERE firstSeen BETWEEN ? AND ?
      ORDER BY firstSeen DESC
    `);
    return stmt.all(startTime, endTime) as NullifierRecord[];
  }

  /**
   * Get network statistics
   */
  getStats(): NetworkStats {
    const now = Date.now();
    const hour = 60 * 60 * 1000;
    const day = 24 * hour;

    const total = this.db.prepare('SELECT COUNT(*) as count FROM nullifiers').get() as { count: number };
    const last24h = this.db.prepare('SELECT COUNT(*) as count FROM nullifiers WHERE firstSeen > ?').get(now - day) as { count: number };
    const lastHour = this.db.prepare('SELECT COUNT(*) as count FROM nullifiers WHERE firstSeen > ?').get(now - hour) as { count: number };
    const federations = this.db.prepare('SELECT COUNT(DISTINCT federation) as count FROM nullifiers WHERE federation IS NOT NULL').get() as { count: number };
    const avgPeers = this.db.prepare('SELECT AVG(peerCount) as avg FROM nullifiers').get() as { avg: number };
    const avgDepth = this.db.prepare('SELECT AVG(witnessDepth) as avg FROM nullifiers').get() as { avg: number };

    return {
      totalNullifiers: total.count,
      last24h: last24h.count,
      lastHour: lastHour.count,
      activeFederations: federations.count,
      avgPeerCount: Math.round(avgPeers.avg || 0),
      avgWitnessDepth: Math.round(avgDepth.avg || 0)
    };
  }

  /**
   * Get hourly activity for the last 24 hours
   */
  getHourlyActivity(): Array<{ hour: string; count: number }> {
    const stmt = this.db.prepare(`
      SELECT
        strftime('%Y-%m-%d %H:00', datetime(firstSeen / 1000, 'unixepoch')) as hour,
        COUNT(*) as count
      FROM nullifiers
      WHERE firstSeen > ?
      GROUP BY hour
      ORDER BY hour DESC
    `);

    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;
    return stmt.all(now - day) as Array<{ hour: string; count: number }>;
  }

  /**
   * Get federation activity
   */
  getFederationStats(): Array<{ federation: string; count: number; avgPeerCount: number }> {
    const stmt = this.db.prepare(`
      SELECT
        federation,
        COUNT(*) as count,
        AVG(peerCount) as avgPeerCount
      FROM nullifiers
      WHERE federation IS NOT NULL
      GROUP BY federation
      ORDER BY count DESC
    `);

    return stmt.all() as Array<{ federation: string; count: number; avgPeerCount: number }>;
  }

  /**
   * Get total count
   */
  getCount(): number {
    const result = this.db.prepare('SELECT COUNT(*) as count FROM nullifiers').get() as { count: number };
    return result.count;
  }

  /**
   * Close database connection
   */
  close(): void {
    this.db.close();
  }
}
