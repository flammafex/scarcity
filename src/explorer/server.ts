/**
 * Nullscape Explorer Server
 *
 * HTTP API and WebSocket server for viewing nullifier feed
 */

import express, { Request, Response } from 'express';
import cors from 'cors';
import { WebSocketServer, WebSocket } from 'ws';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { NullifierDatabase } from './database.js';
import { NullifierCollector } from './collector.js';
import { InfrastructureManager } from '../cli/infrastructure.js';
import { Crypto } from '../crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export class ExplorerServer {
  private app: express.Application;
  private db: NullifierDatabase;
  private collector?: NullifierCollector;
  private infraManager: InfrastructureManager;
  private wss?: WebSocketServer;
  private wsClients: Set<WebSocket> = new Set();

  constructor() {
    this.app = express();
    this.db = new NullifierDatabase();
    this.infraManager = new InfrastructureManager();

    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup Express middleware
   */
  private setupMiddleware(): void {
    this.app.use(cors());
    this.app.use(express.json());
    this.app.use(express.static(join(__dirname, 'public')));
  }

  /**
   * Setup API routes
   */
  private setupRoutes(): void {
    // Health check
    this.app.get('/api/health', (req, res) => {
      res.json({
        success: true,
        data: {
          collecting: this.collector?.isRunning() || false,
          dbRecords: this.db.getCount(),
          wsClients: this.wsClients.size
        }
      });
    });

    // Start collector
    this.app.post('/api/start', async (req, res) => {
      try {
        if (this.collector?.isRunning()) {
          return res.json({
            success: false,
            error: 'Collector already running'
          });
        }

        const { federation } = req.body;

        // Initialize infrastructure
        const infra = await this.infraManager.initialize();

        // Create and start collector with WebSocket broadcast hook
        this.collector = new NullifierCollector({
          database: this.db,
          gossip: infra.gossip,
          witness: infra.witness,
          federation: federation || 'default',
          // Hook into the collector stream to broadcast to UI
          onNullifier: (message) => {
            if (message.type === 'nullifier' && message.nullifier) {
              this.broadcastNullifier({
                nullifierHex: Crypto.toHex(message.nullifier),
                timestamp: message.timestamp,
                proof: message.proof
              });
            }
          }
        });

        this.collector.start();

        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Stop collector
    this.app.post('/api/stop', (req, res) => {
      if (this.collector) {
        this.collector.stop();
      }
      res.json({ success: true });
    });

    // Get collector stats
    this.app.get('/api/stats', (req, res) => {
      const collectorStats = this.collector?.getStats() || null;
      const dbStats = this.db.getStats();

      res.json({
        success: true,
        data: {
          collector: collectorStats,
          network: dbStats
        }
      });
    });

    // Get recent nullifiers
    this.app.get('/api/nullifiers', (req, res) => {
      try {
        const limit = parseInt(req.query.limit as string) || 50;
        const offset = parseInt(req.query.offset as string) || 0;
        const nullifiers = this.db.getRecentNullifiers(limit, offset);

        res.json({
          success: true,
          data: {
            nullifiers: nullifiers.map(n => ({
              ...n,
              proof: JSON.parse(n.proof)
            })),
            total: this.db.getCount(),
            limit,
            offset
          }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Search nullifiers
    this.app.get('/api/nullifiers/search', (req, res) => {
      try {
        const query = req.query.q as string;
        if (!query) {
          return res.status(400).json({
            success: false,
            error: 'Query parameter required'
          });
        }

        const nullifiers = this.db.searchNullifiers(query);

        res.json({
          success: true,
          data: {
            nullifiers: nullifiers.map(n => ({
              ...n,
              proof: JSON.parse(n.proof)
            })),
            query
          }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Get nullifier by hex
    this.app.get('/api/nullifiers/:hex', (req, res) => {
      try {
        const nullifier = this.db.getNullifier(req.params.hex);

        if (!nullifier) {
          return res.status(404).json({
            success: false,
            error: 'Nullifier not found'
          });
        }

        res.json({
          success: true,
          data: {
            ...nullifier,
            proof: JSON.parse(nullifier.proof)
          }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Get nullifiers by token ID
    this.app.get('/api/tokens/:tokenId/nullifiers', (req, res) => {
      try {
        const nullifiers = this.db.getNullifiersByToken(req.params.tokenId);

        res.json({
          success: true,
          data: {
            nullifiers: nullifiers.map(n => ({
              ...n,
              proof: JSON.parse(n.proof)
            })),
            tokenId: req.params.tokenId
          }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Get nullifiers by federation
    this.app.get('/api/federations/:federation/nullifiers', (req, res) => {
      try {
        const limit = parseInt(req.query.limit as string) || 50;
        const offset = parseInt(req.query.offset as string) || 0;
        const nullifiers = this.db.getNullifiersByFederation(
          req.params.federation,
          limit,
          offset
        );

        res.json({
          success: true,
          data: {
            nullifiers: nullifiers.map(n => ({
              ...n,
              proof: JSON.parse(n.proof)
            })),
            federation: req.params.federation,
            limit,
            offset
          }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Get hourly activity
    this.app.get('/api/activity/hourly', (req, res) => {
      try {
        const activity = this.db.getHourlyActivity();

        res.json({
          success: true,
          data: { activity }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Get federation stats
    this.app.get('/api/federations/stats', (req, res) => {
      try {
        const stats = this.db.getFederationStats();

        res.json({
          success: true,
          data: { federations: stats }
        });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });
  }

  /**
   * Broadcast nullifier to WebSocket clients
   */
  private broadcastNullifier(data: any): void {
    const message = JSON.stringify({
      type: 'nullifier',
      data
    });

    this.wsClients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  /**
   * Start the server
   */
  async start(port = 3001): Promise<void> {
    return new Promise((resolve) => {
      const server = this.app.listen(port, () => {
        console.log(`\n🔍 Nullscape Explorer`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`Server running at http://localhost:${port}`);
        console.log(`\nAPI Endpoints:`);
        console.log(`  Health:     GET  /api/health`);
        console.log(`  Start:      POST /api/start`);
        console.log(`  Stats:      GET  /api/stats`);
        console.log(`  Nullifiers: GET  /api/nullifiers`);
        console.log(`  Search:     GET  /api/nullifiers/search?q=<hex>`);
        console.log(`\nWebSocket: ws://localhost:${port}`);
        console.log(`\nOpen http://localhost:${port} in your browser`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

        // Setup WebSocket server
        this.wss = new WebSocketServer({ server });

        this.wss.on('connection', (ws: WebSocket) => {
          console.log('🔌 WebSocket client connected');
          this.wsClients.add(ws);

          ws.on('close', () => {
            console.log('🔌 WebSocket client disconnected');
            this.wsClients.delete(ws);
          });

          // Send current stats on connection
          const stats = this.db.getStats();
          ws.send(JSON.stringify({
            type: 'stats',
            data: stats
          }));
        });

        resolve();
      });
    });
  }

  /**
   * Cleanup
   */
  async cleanup(): Promise<void> {
    if (this.collector) {
      this.collector.stop();
    }
    this.db.close();
    if (this.wss) {
      this.wss.close();
    }
  }
}

// CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3001', 10);
  const server = new ExplorerServer();

  server.start(port).catch(console.error);

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n\nShutting down...');
    await server.cleanup();
    process.exit(0);
  });
}