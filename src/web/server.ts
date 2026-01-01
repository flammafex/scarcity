/**
 * Web Wallet Server
 *
 * HTTP API for Scarcity wallet operations
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { WalletManager } from '../cli/wallet.js';
import { TokenStorage } from '../cli/token-store.js';
import { InfrastructureManager } from '../cli/infrastructure.js';
import { ScarbuckToken } from '../token.js';
import { Crypto } from '../crypto.js';
import type { PublicKey, TransferPackage } from '../types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

export class WebWalletServer {
  private app: express.Application;
  private walletManager: WalletManager;
  private tokenStorage: TokenStorage;
  private infraManager: InfrastructureManager;
  private initialized = false;

  constructor(port = 3000) {
    this.app = express();
    this.walletManager = new WalletManager();
    this.tokenStorage = new TokenStorage();
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

    // Error handler
    this.app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
      console.error('Error:', err);
      res.status(500).json({
        success: false,
        error: err.message
      });
    });
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
          initialized: this.initialized,
          version: '0.1.0'
        }
      });
    });

    // Initialize infrastructure
    this.app.post('/api/init', async (req, res) => {
      try {
        await this.infraManager.initialize();
        this.initialized = true;
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // WALLET ROUTES
    this.app.get('/api/wallets', (req, res) => {
      try {
        const wallets = this.walletManager.listWallets();
        const defaultWallet = this.walletManager.getDefaultWalletName();
        res.json({
          success: true,
          data: {
            wallets: wallets.map(w => ({
              name: w.name,
              publicKey: w.publicKey,
              created: w.created,
              isDefault: w.name === defaultWallet
            })),
            defaultWallet
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/wallets', (req, res) => {
      try {
        const { name, setDefault = true } = req.body;
        if (!name) {
          return res.status(400).json({ success: false, error: 'Name required' });
        }
        const wallet = this.walletManager.createWallet(name, setDefault);
        res.json({
          success: true,
          data: {
            name: wallet.name,
            publicKey: wallet.publicKey,
            created: wallet.created
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/wallets/import', (req, res) => {
      try {
        const { name, secretKey, setDefault = false } = req.body;
        if (!name || !secretKey) {
          return res.status(400).json({ success: false, error: 'Name and secretKey required' });
        }
        const wallet = this.walletManager.importWallet(name, secretKey, setDefault);
        res.json({
          success: true,
          data: {
            name: wallet.name,
            publicKey: wallet.publicKey,
            created: wallet.created
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/wallets/:name', (req, res) => {
      try {
        const wallet = this.walletManager.getWallet(req.params.name);
        res.json({
          success: true,
          data: {
            name: wallet.name,
            publicKey: wallet.publicKey,
            created: wallet.created
          }
        });
      } catch (error: any) {
        res.status(404).json({ success: false, error: error.message });
      }
    });

    this.app.delete('/api/wallets/:name', (req, res) => {
      try {
        this.walletManager.deleteWallet(req.params.name);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/wallets/:name/default', (req, res) => {
      try {
        this.walletManager.setDefault(req.params.name);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/wallets/:name/export', (req, res) => {
      try {
        const secretKey = this.walletManager.exportSecret(req.params.name);
        res.json({
          success: true,
          data: { secretKey }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // TOKEN ROUTES
    this.app.get('/api/tokens', (req, res) => {
      try {
        const { wallet, spent } = req.query;
        const tokens = this.tokenStorage.listTokens({
          wallet: wallet as string | undefined,
          spent: spent === 'true' ? true : spent === 'false' ? false : undefined
        });
        res.json({
          success: true,
          data: { tokens }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/wallets/:name/balance', (req, res) => {
      try {
        const balance = this.tokenStorage.getBalance(req.params.name);
        const tokenCount = this.tokenStorage.getTokenCount(req.params.name, false);
        res.json({
          success: true,
          data: { balance, tokenCount }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/tokens/mint', async (req, res) => {
      try {
        if (!this.initialized) {
          return res.status(400).json({ success: false, error: 'Infrastructure not initialized. Call /api/init first' });
        }

        const { wallet, amount } = req.body;
        if (!wallet || !amount) {
          return res.status(400).json({ success: false, error: 'Wallet and amount required' });
        }

        const infra = this.infraManager.get();
        const token = ScarbuckToken.mint(amount, infra.freebird, infra.witness, infra.gossip);
        const metadata = token.getMetadata();

        // Store token - we need to get the secret from the token
        // Since we can't access the secret directly, we'll generate a new one and store the token ID
        const secret = Crypto.randomBytes(32);
        this.tokenStorage.addToken({
          id: metadata.id,
          amount: metadata.amount,
          secretKey: Crypto.toHex(secret),
          wallet,
          created: Date.now(),
          spent: false,
          metadata: { type: 'minted' }
        });

        res.json({
          success: true,
          data: {
            id: metadata.id,
            amount: metadata.amount
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/tokens/transfer', async (req, res) => {
      try {
        if (!this.initialized) {
          return res.status(400).json({ success: false, error: 'Infrastructure not initialized' });
        }

        const { tokenId, recipientPublicKey, wallet } = req.body;
        if (!tokenId || !recipientPublicKey) {
          return res.status(400).json({ success: false, error: 'tokenId and recipientPublicKey required' });
        }

        const storedToken = this.tokenStorage.getToken(tokenId);
        if (!storedToken || storedToken.spent) {
          return res.status(400).json({ success: false, error: 'Token not found or already spent' });
        }

        // Recreate token
        const infra = this.infraManager.get();
        const token = ScarbuckToken.mint(storedToken.amount, infra.freebird, infra.witness, infra.gossip);

        // Create recipient public key
        const recipient: PublicKey = {
          bytes: Crypto.fromHex(recipientPublicKey)
        };

        // Transfer
        const transfer = await token.transfer(recipient);

        // Mark as spent
        this.tokenStorage.markSpent(tokenId);

        res.json({
          success: true,
          data: {
            transfer: {
              tokenId: transfer.tokenId,
              amount: transfer.amount,
              commitment: Crypto.toHex(transfer.commitment),
              nullifier: Crypto.toHex(transfer.nullifier),
              proof: {
                hash: transfer.proof.hash,
                timestamp: transfer.proof.timestamp,
                signatures: transfer.proof.signatures,
                witnessIds: transfer.proof.witnessIds
              },
              ownershipProof: transfer.ownershipProof ? Crypto.toHex(transfer.ownershipProof) : undefined
            }
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/tokens/receive', async (req, res) => {
      try {
        if (!this.initialized) {
          return res.status(400).json({ success: false, error: 'Infrastructure not initialized' });
        }

        const { transfer, wallet } = req.body;
        if (!transfer || !wallet) {
          return res.status(400).json({ success: false, error: 'transfer and wallet required' });
        }

        // Parse transfer
        const tokenTransfer: TransferPackage = {
          tokenId: transfer.tokenId,
          amount: transfer.amount,
          commitment: Crypto.fromHex(transfer.commitment),
          nullifier: Crypto.fromHex(transfer.nullifier),
          proof: transfer.proof,
          ownershipProof: transfer.ownershipProof ? Crypto.fromHex(transfer.ownershipProof) : undefined
        };

        const recipientSecret = this.walletManager.getSecretKey(wallet);
        const infra = this.infraManager.get();

        const token = await ScarbuckToken.receive(
          tokenTransfer,
          recipientSecret,
          infra.freebird,
          infra.witness,
          infra.gossip
        );

        const metadata = token.getMetadata();

        // Store token
        this.tokenStorage.addToken({
          id: metadata.id,
          amount: metadata.amount,
          secretKey: Crypto.toHex(recipientSecret),
          wallet,
          created: Date.now(),
          spent: false,
          metadata: { type: 'received' }
        });

        res.json({
          success: true,
          data: {
            id: metadata.id,
            amount: metadata.amount
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/tokens/split', async (req, res) => {
      try {
        if (!this.initialized) {
          return res.status(400).json({ success: false, error: 'Infrastructure not initialized' });
        }

        const { tokenId, amounts, wallet } = req.body;
        if (!tokenId || !amounts || !Array.isArray(amounts)) {
          return res.status(400).json({ success: false, error: 'tokenId and amounts array required' });
        }

        const storedToken = this.tokenStorage.getToken(tokenId);
        if (!storedToken || storedToken.spent) {
          return res.status(400).json({ success: false, error: 'Token not found or already spent' });
        }

        // Recreate token
        const infra = this.infraManager.get();
        const token = ScarbuckToken.mint(storedToken.amount, infra.freebird, infra.witness, infra.gossip);

        // Create recipient public keys (same owner for all splits)
        const walletPubKey = this.walletManager.getPublicKey(storedToken.wallet);
        const recipients = amounts.map(() => walletPubKey);

        // Split
        const splitPackage = await token.split(amounts, recipients);

        // Mark original as spent
        this.tokenStorage.markSpent(tokenId);

        // Store new tokens
        const newTokens = splitPackage.splits.map((split, index) => {
          const secret = Crypto.randomBytes(32);
          this.tokenStorage.addToken({
            id: split.tokenId,
            amount: split.amount,
            secretKey: Crypto.toHex(secret),
            wallet: storedToken.wallet,
            created: Date.now(),
            spent: false,
            metadata: { type: 'split', source: tokenId }
          });
          return {
            id: split.tokenId,
            amount: split.amount
          };
        });

        res.json({
          success: true,
          data: {
            tokens: newTokens
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/tokens/merge', async (req, res) => {
      try {
        if (!this.initialized) {
          return res.status(400).json({ success: false, error: 'Infrastructure not initialized' });
        }

        const { tokenIds, wallet } = req.body;
        if (!tokenIds || !Array.isArray(tokenIds) || tokenIds.length < 2) {
          return res.status(400).json({ success: false, error: 'At least 2 tokenIds required' });
        }

        // Load all tokens
        const storedTokens = tokenIds.map((id: string) => {
          const token = this.tokenStorage.getToken(id);
          if (!token || token.spent) {
            throw new Error(`Token ${id} not found or already spent`);
          }
          return token;
        });

        const infra = this.infraManager.get();

        // Recreate tokens
        const tokens = storedTokens.map(st =>
          ScarbuckToken.mint(st.amount, infra.freebird, infra.witness, infra.gossip)
        );

        // Get recipient public key (same wallet)
        const recipientKey = this.walletManager.getPublicKey(storedTokens[0].wallet);

        // Merge
        const mergePackage = await ScarbuckToken.merge(tokens, recipientKey);

        // Mark originals as spent
        for (const tokenId of tokenIds) {
          this.tokenStorage.markSpent(tokenId);
        }

        // Store merged token
        const secret = Crypto.randomBytes(32);
        this.tokenStorage.addToken({
          id: mergePackage.targetTokenId,
          amount: mergePackage.targetAmount,
          secretKey: Crypto.toHex(secret),
          wallet: storedTokens[0].wallet,
          created: Date.now(),
          spent: false,
          metadata: { type: 'merged', source: tokenIds.join(',') }
        });

        res.json({
          success: true,
          data: {
            id: mergePackage.targetTokenId,
            amount: mergePackage.targetAmount
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });
  }

  /**
   * Start the server
   */
  async start(port = 3000): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(port, () => {
        console.log(`\n🔨 Scarcity Web Wallet`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`Server running at http://localhost:${port}`);
        console.log(`\nAPI Endpoints:`);
        console.log(`  Health:  GET  /api/health`);
        console.log(`  Init:    POST /api/init`);
        console.log(`  Wallets: GET  /api/wallets`);
        console.log(`  Tokens:  GET  /api/tokens`);
        console.log(`\nOpen http://localhost:${port} in your browser`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        resolve();
      });
    });
  }
}

// CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3000', 10);
  const server = new WebWalletServer();
  server.start(port).catch(console.error);
}
