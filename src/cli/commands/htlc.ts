/**
 * HTLC command - Hash Time-Locked Contract operations
 */

import { Command } from '../command.js';
import { InfrastructureManager } from '../infrastructure.js';
import { TokenStorage } from '../token-store.js';
import { ScarbuckToken } from '../../token.js';
import { Crypto } from '../../crypto.js';

export class HTLCCommand extends Command {
  constructor() {
    super('htlc', 'Hash Time-Locked Contract operations');
  }

  async execute(args: string[]): Promise<void> {
    const { positional, options } = this.parseArgs(args);

    if (options.help || options.h) {
      this.showHelp();
      return;
    }

    const subcommand = positional[0];

    if (!subcommand) {
      this.showHelp();
      return;
    }

    switch (subcommand) {
      case 'create':
        await this.create(positional, options);
        break;

      case 'claim':
        await this.claim(positional, options);
        break;

      case 'refund':
        await this.refund(positional, options);
        break;

      default:
        console.error(`Unknown subcommand: ${subcommand}`);
        this.showHelp();
        process.exit(1);
    }
  }

  /**
   * Create an HTLC
   */
  private async create(positional: string[], options: any): Promise<void> {
    const tokenId = this.requireArg(positional, 1, 'token-id');
    const recipient = this.requireArg(positional, 2, 'recipient-pubkey');
    const hashLock = options['hash-lock'] || options.H;
    const timeLock = options['time-lock'] || options.T;

    if (!hashLock && !timeLock) {
      console.error('Error: Either --hash-lock or --time-lock (or both) must be specified');
      process.exit(1);
    }

    // Parse time lock
    let timeLockValue: number | undefined;
    if (timeLock) {
      timeLockValue = parseInt(timeLock as string, 10);
      if (isNaN(timeLockValue) || timeLockValue < 0) {
        console.error(`Error: Invalid time-lock value: ${timeLock}`);
        process.exit(1);
      }
    }

    // Load infrastructure and storage
    const infraMgr = new InfrastructureManager();
    const storage = new TokenStorage();

    try {
      console.log('');
      console.log('🔐 Creating HTLC...');
      console.log('');

      await infraMgr.initialize();
      const { witness, gossip, freebird } = infraMgr.get();

      // Load token
      const storedToken = storage.getToken(tokenId as string);
      if (!storedToken) {
        console.error(`Error: Token not found: ${tokenId}`);
        process.exit(1);
      }

      if (storedToken.spent) {
        console.error(`Error: Token already spent`);
        process.exit(1);
      }

      // Recreate token
      const token = new ScarbuckToken({
        id: storedToken.id,
        amount: storedToken.amount,
        secret: Crypto.fromHex(storedToken.secretKey),
        freebird,
        witness,
        gossip
      });

      // Create HTLC condition
      const condition: any = {
        type: hashLock ? 'hash' : 'time'
      };
      if (hashLock) {
        condition.hashlock = hashLock as string;
      }
      if (timeLockValue !== undefined) {
        condition.timelock = timeLockValue;
      }

      // Create HTLC
      const recipientKey = { bytes: Crypto.fromHex(recipient as string) };
      const htlcPkg = await token.transferHTLC(recipientKey, condition);

      // Mark token as spent
      storage.markSpent(storedToken.id);

      console.log('✅ HTLC created successfully!');
      console.log('');
      console.log('HTLC Details:');
      console.log(`  Token ID:   ${storedToken.id}`);
      console.log(`  Amount:     ${storedToken.amount}`);
      console.log(`  Recipient:  ${recipient}`);
      if (hashLock) {
        console.log(`  Hash Lock:  ${hashLock}`);
      }
      if (timeLockValue !== undefined) {
        console.log(`  Time Lock:  ${timeLockValue} seconds`);
      }
      console.log('');
      console.log('Send this package to the recipient:');
      console.log('');
      console.log(JSON.stringify({
        type: 'htlc',
        tokenId: htlcPkg.tokenId,
        amount: htlcPkg.amount,
        commitment: Crypto.toHex(htlcPkg.commitment),
        condition: htlcPkg.condition,
        nullifier: Crypto.toHex(htlcPkg.nullifier),
        proof: htlcPkg.proof,
        ownershipProof: htlcPkg.ownershipProof ? Crypto.toHex(htlcPkg.ownershipProof) : undefined
      }, null, 2));
      console.log('');

      if (hashLock) {
        console.log('⚠️  IMPORTANT: Store the hash preimage securely!');
        console.log('   The recipient will need it to claim this HTLC.');
        console.log('');
      }

      await infraMgr.cleanup();

    } catch (error: any) {
      console.error(`Failed to create HTLC: ${error.message}`);
      await infraMgr.cleanup();
      process.exit(1);
    }
  }

  /**
   * Claim an HTLC
   */
  private async claim(positional: string[], options: any): Promise<void> {
    const packagePath = this.requireArg(positional, 1, 'package-file');
    const wallet = this.requireArg(positional, 2, 'wallet-name');
    const preimage = options.preimage || options.p;

    // Load package
    const pkg = await this.loadPackage(packagePath as string);

    if (pkg.type !== 'htlc') {
      console.error('Error: Package is not an HTLC');
      process.exit(1);
    }

    if (!pkg.condition) {
      console.error('Error: Package missing HTLC condition');
      process.exit(1);
    }

    // Check if hash lock exists and preimage is provided
    if (pkg.condition.hashlock && !preimage) {
      console.error('Error: This HTLC has a hash lock. Provide --preimage to claim.');
      process.exit(1);
    }

    // Verify preimage if provided
    if (preimage && pkg.condition.hashlock) {
      const preimageHash = Crypto.hashString(preimage as string);
      if (preimageHash !== pkg.condition.hashlock) {
        console.error('Error: Invalid preimage for hash lock');
        process.exit(1);
      }
    }

    // Check time lock
    if (pkg.condition.timelock !== undefined) {
      const currentTime = Math.floor(Date.now() / 1000);
      if (currentTime >= pkg.condition.timelock) {
        console.error('Error: HTLC has expired. Use "htlc refund" instead.');
        process.exit(1);
      }
    }

    // Load infrastructure and storage
    const infraMgr = new InfrastructureManager();
    const storage = new TokenStorage();

    try {
      console.log('');
      console.log('🔓 Claiming HTLC...');
      console.log('');

      await infraMgr.initialize();
      const { witness, gossip, freebird } = infraMgr.get();

      // Import wallet
      const wallets = await import('../wallet.js');
      const walletMgr = new wallets.WalletManager();
      const walletData = walletMgr.getWallet(wallet as string);

      if (!walletData) {
        console.error(`Error: Wallet not found: ${wallet}`);
        process.exit(1);
      }

      // Receive HTLC
      const token = await ScarbuckToken.receiveHTLC(
        {
          tokenId: pkg.tokenId,
          amount: pkg.amount,
          commitment: Crypto.fromHex(pkg.commitment),
          condition: pkg.condition,
          nullifier: Crypto.fromHex(pkg.nullifier),
          proof: pkg.proof,
          ownershipProof: pkg.ownershipProof ? Crypto.fromHex(pkg.ownershipProof) : undefined
        },
        Crypto.fromHex(walletData.secretKey),
        preimage ? Crypto.fromHex(preimage as string) : undefined,
        freebird,
        witness,
        gossip
      );

      // Store received token
      const metadata = token.getMetadata();
      storage.addToken({
        id: metadata.id,
        amount: metadata.amount,
        secretKey: Crypto.toHex((token as any).secret),
        wallet: wallet as string,
        created: Date.now(),
        spent: false,
        metadata: {
          type: 'received',
          source: 'htlc',
          notes: preimage ? `Claimed with preimage` : `Claimed (time-locked)`
        }
      });

      console.log('✅ HTLC claimed successfully!');
      console.log('');
      console.log('Token Details:');
      console.log(`  Token ID: ${metadata.id}`);
      console.log(`  Amount:   ${metadata.amount}`);
      console.log(`  Wallet:   ${wallet}`);
      console.log('');

      await infraMgr.cleanup();

    } catch (error: any) {
      console.error(`Failed to claim HTLC: ${error.message}`);
      await infraMgr.cleanup();
      process.exit(1);
    }
  }

  /**
   * Refund an expired HTLC
   */
  private async refund(positional: string[], options: any): Promise<void> {
    const packagePath = this.requireArg(positional, 1, 'package-file');
    const wallet = this.requireArg(positional, 2, 'wallet-name');

    // Load package
    const pkg = await this.loadPackage(packagePath as string);

    if (pkg.type !== 'htlc') {
      console.error('Error: Package is not an HTLC');
      process.exit(1);
    }

    if (!pkg.condition || pkg.condition.timelock === undefined) {
      console.error('Error: This HTLC does not have a time lock and cannot be refunded');
      process.exit(1);
    }

    // Check if time lock has expired
    const currentTime = Math.floor(Date.now() / 1000);
    if (currentTime < pkg.condition.timelock) {
      const remaining = pkg.condition.timelock - currentTime;
      console.error(`Error: HTLC has not expired yet. ${remaining} seconds remaining.`);
      process.exit(1);
    }

    // Load infrastructure and storage
    const infraMgr = new InfrastructureManager();
    const storage = new TokenStorage();

    try {
      console.log('');
      console.log('💸 Refunding expired HTLC...');
      console.log('');

      await infraMgr.initialize();
      const { witness, gossip, freebird } = infraMgr.get();

      // Import wallet
      const wallets = await import('../wallet.js');
      const walletMgr = new wallets.WalletManager();
      const walletData = walletMgr.getWallet(wallet as string);

      if (!walletData) {
        console.error(`Error: Wallet not found: ${wallet}`);
        process.exit(1);
      }

      // Refund HTLC
      const token = await ScarbuckToken.refundHTLC(
        {
          tokenId: pkg.tokenId,
          amount: pkg.amount,
          commitment: Crypto.fromHex(pkg.commitment),
          condition: pkg.condition,
          nullifier: Crypto.fromHex(pkg.nullifier),
          proof: pkg.proof,
          ownershipProof: pkg.ownershipProof ? Crypto.fromHex(pkg.ownershipProof) : undefined
        },
        Crypto.fromHex(walletData.secretKey),
        freebird,
        witness,
        gossip
      );

      // Store refunded token
      const metadata = token.getMetadata();
      storage.addToken({
        id: metadata.id,
        amount: metadata.amount,
        secretKey: Crypto.toHex((token as any).secret),
        wallet: wallet as string,
        created: Date.now(),
        spent: false,
        metadata: {
          type: 'received',
          source: 'htlc-refund',
          notes: 'Refunded from expired HTLC'
        }
      });

      console.log('✅ HTLC refunded successfully!');
      console.log('');
      console.log('Token Details:');
      console.log(`  Token ID: ${metadata.id}`);
      console.log(`  Amount:   ${metadata.amount}`);
      console.log(`  Wallet:   ${wallet}`);
      console.log('');

      await infraMgr.cleanup();

    } catch (error: any) {
      console.error(`Failed to refund HTLC: ${error.message}`);
      await infraMgr.cleanup();
      process.exit(1);
    }
  }

  /**
   * Load package from file
   */
  private async loadPackage(path: string): Promise<any> {
    const fs = await import('fs/promises');
    try {
      const data = await fs.readFile(path, 'utf-8');
      return JSON.parse(data);
    } catch (error: any) {
      console.error(`Failed to load package: ${error.message}`);
      process.exit(1);
    }
  }

  showHelp(): void {
    console.log(`
USAGE:
  scar htlc <subcommand> [options]

SUBCOMMANDS:
  create <token-id> <recipient-pubkey>    Create an HTLC
  claim <package-file> <wallet-name>      Claim an HTLC
  refund <package-file> <wallet-name>     Refund an expired HTLC

OPTIONS (create):
  -H, --hash-lock <hash>     Hash lock (SHA-256 hex)
  -T, --time-lock <seconds>  Time lock (Unix timestamp)
  -h, --help                 Show this help message

OPTIONS (claim):
  -p, --preimage <string>    Hash preimage for hash-locked HTLC
  -h, --help                 Show this help message

NOTES:
  - HTLCs require at least one lock (hash or time)
  - Hash lock requires SHA-256 hash of a secret preimage
  - Time lock is a Unix timestamp (seconds since epoch)
  - Recipient can claim before timeout with valid preimage
  - Sender can refund after timeout expires

EXAMPLES:
  # Create hash-locked HTLC
  scar htlc create abc123 deadbeef... --hash-lock 9f86d081...

  # Create time-locked HTLC (expires in 1 hour)
  scar htlc create abc123 deadbeef... --time-lock $(date -d '+1 hour' +%s)

  # Create dual-locked HTLC
  scar htlc create abc123 deadbeef... -H 9f86d081... -T 1735689600

  # Claim HTLC with preimage
  scar htlc claim htlc-package.json my-wallet --preimage "secret"

  # Refund expired HTLC
  scar htlc refund htlc-package.json my-wallet
`);
  }
}
