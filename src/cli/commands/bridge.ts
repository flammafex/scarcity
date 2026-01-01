/**
 * Bridge command - Cross-federation bridge operations
 */

import { Command } from '../command.js';
import { ConfigManager } from '../config.js';
import { TokenStorage } from '../token-store.js';
import { ScarbuckToken } from '../../token.js';
import { FederationBridge } from '../../bridge.js';
import { FreebirdAdapter, WitnessAdapter, NullifierGossip } from '../../index.js';
import { Crypto } from '../../crypto.js';

export class BridgeCommand extends Command {
  constructor() {
    super('bridge', 'Cross-federation bridge operations');
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
      case 'transfer':
        await this.transfer(positional, options);
        break;

      case 'claim':
        await this.claim(positional, options);
        break;

      default:
        console.error(`Unknown subcommand: ${subcommand}`);
        this.showHelp();
        process.exit(1);
    }
  }

  /**
   * Bridge a token to target federation
   */
  private async transfer(positional: string[], options: any): Promise<void> {
    const tokenId = this.requireArg(positional, 1, 'token-id');
    const recipient = this.requireArg(positional, 2, 'recipient-pubkey');
    const targetGateway = options['target-gateway'] || options.g;
    const targetNetwork = options['target-network'] || options.n;

    if (!targetGateway) {
      console.error('Error: Target federation gateway URL required (--target-gateway)');
      process.exit(1);
    }

    if (!targetNetwork) {
      console.error('Error: Target federation network ID required (--target-network)');
      process.exit(1);
    }

    const config = new ConfigManager();
    const storage = new TokenStorage();

    try {
      console.log('');
      console.log('🌉 Bridging token to target federation...');
      console.log('');

      // Load token from storage
      const storedToken = storage.getToken(tokenId as string);
      if (!storedToken) {
        console.error(`Error: Token not found: ${tokenId}`);
        process.exit(1);
      }

      if (storedToken.spent) {
        console.error(`Error: Token already spent`);
        process.exit(1);
      }

      // Setup source federation infrastructure
      const sourceWitness = new WitnessAdapter(config.getWitnessConfig());
      const sourceFreebird = new FreebirdAdapter(config.getFreebirdConfig());
      const sourceGossip = new NullifierGossip({ witness: sourceWitness });

      // Setup target federation infrastructure
      const targetWitness = new WitnessAdapter({
        gatewayUrl: targetGateway as string,
        networkId: targetNetwork as string
      });
      const targetFreebird = new FreebirdAdapter(config.getFreebirdConfig());
      const targetGossip = new NullifierGossip({ witness: targetWitness });

      // Recreate token
      const token = new ScarbuckToken({
        id: storedToken.id,
        amount: storedToken.amount,
        secret: Crypto.fromHex(storedToken.secretKey),
        freebird: sourceFreebird,
        witness: sourceWitness,
        gossip: sourceGossip
      });

      // Create bridge
      const bridge = new FederationBridge({
        sourceFederation: config.get('witness.networkId'),
        targetFederation: targetNetwork as string,
        sourceWitness,
        targetWitness,
        sourceGossip,
        targetGossip,
        freebird: sourceFreebird
      });

      // Bridge the token
      const recipientKey = { bytes: Crypto.fromHex(recipient as string) };
      const bridgePkg = await bridge.bridgeToken(token, recipientKey);

      // Mark token as spent
      storage.markSpent(storedToken.id);

      console.log('✅ Token bridged successfully!');
      console.log('');
      console.log('Bridge Details:');
      console.log(`  Token ID:          ${storedToken.id}`);
      console.log(`  Amount:            ${storedToken.amount}`);
      console.log(`  Source Federation: ${config.get('witness.networkId')}`);
      console.log(`  Target Federation: ${targetNetwork}`);
      console.log(`  Recipient:         ${recipient}`);
      console.log('');
      console.log('Send this package to the recipient:');
      console.log('');
      console.log(JSON.stringify({
        type: 'bridge',
        sourceTokenId: bridgePkg.sourceTokenId,
        sourceFederation: bridgePkg.sourceFederation,
        targetFederation: bridgePkg.targetFederation,
        amount: bridgePkg.amount,
        commitment: Crypto.toHex(bridgePkg.commitment),
        nullifier: Crypto.toHex(bridgePkg.nullifier),
        sourceProof: bridgePkg.sourceProof,
        targetProof: bridgePkg.targetProof,
        ownershipProof: bridgePkg.ownershipProof ? Crypto.toHex(bridgePkg.ownershipProof) : undefined
      }, null, 2));
      console.log('');

    } catch (error: any) {
      console.error(`Failed to bridge token: ${error.message}`);
      process.exit(1);
    }
  }

  /**
   * Claim a bridged token
   */
  private async claim(positional: string[], options: any): Promise<void> {
    const packagePath = this.requireArg(positional, 1, 'package-file');
    const wallet = this.requireArg(positional, 2, 'wallet-name');

    // Load package
    const pkg = await this.loadPackage(packagePath as string);

    if (pkg.type !== 'bridge') {
      console.error('Error: Package is not a bridge transfer');
      process.exit(1);
    }

    const config = new ConfigManager();
    const storage = new TokenStorage();

    try {
      console.log('');
      console.log('🎁 Claiming bridged token...');
      console.log('');

      // Verify current config matches target federation
      const currentNetwork = config.get('witness.networkId');
      if (currentNetwork !== pkg.targetFederation) {
        console.error(`Error: This bridge is for federation "${pkg.targetFederation}"`);
        console.error(`       but your config is set to "${currentNetwork}"`);
        console.error('');
        console.error(`Switch to the target federation with:`);
        console.error(`  scar config set witness.networkId ${pkg.targetFederation}`);
        process.exit(1);
      }

      // Import wallet
      const wallets = await import('../wallet.js');
      const walletMgr = new wallets.WalletManager();
      const walletData = walletMgr.getWallet(wallet as string);

      if (!walletData) {
        console.error(`Error: Wallet not found: ${wallet}`);
        process.exit(1);
      }

      // Setup source federation infrastructure
      const sourceFreebird = new FreebirdAdapter(config.getFreebirdConfig());

      // For source, we need the original federation's gateway
      // This should be provided in the bridge package or known ahead of time
      // For now, we'll require the user to specify it
      const sourceGateway = options['source-gateway'] || options.s;
      if (!sourceGateway) {
        console.error('Error: Source federation gateway URL required (--source-gateway)');
        console.error(`       This is the Witness gateway for "${pkg.sourceFederation}"`);
        process.exit(1);
      }

      const sourceWitness = new WitnessAdapter({
        gatewayUrl: sourceGateway as string,
        networkId: pkg.sourceFederation
      });
      const sourceGossip = new NullifierGossip({ witness: sourceWitness });

      // Setup target federation infrastructure (current config)
      const targetWitness = new WitnessAdapter(config.getWitnessConfig());
      const targetFreebird = new FreebirdAdapter(config.getFreebirdConfig());
      const targetGossip = new NullifierGossip({ witness: targetWitness });

      // Create bridge
      const bridge = new FederationBridge({
        sourceFederation: pkg.sourceFederation,
        targetFederation: pkg.targetFederation,
        sourceWitness,
        targetWitness,
        sourceGossip,
        targetGossip,
        freebird: sourceFreebird
      });

      // Receive bridged token
      const token = await bridge.receiveBridged(
        {
          sourceTokenId: pkg.sourceTokenId,
          sourceFederation: pkg.sourceFederation,
          targetFederation: pkg.targetFederation,
          amount: pkg.amount,
          commitment: Crypto.fromHex(pkg.commitment),
          nullifier: Crypto.fromHex(pkg.nullifier),
          sourceProof: pkg.sourceProof,
          targetProof: pkg.targetProof,
          ownershipProof: pkg.ownershipProof ? Crypto.fromHex(pkg.ownershipProof) : undefined
        },
        Crypto.fromHex(walletData.secretKey)
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
          source: 'bridge',
          notes: `Bridged from ${pkg.sourceFederation}`
        }
      });

      console.log('✅ Bridged token claimed successfully!');
      console.log('');
      console.log('Token Details:');
      console.log(`  Token ID:          ${metadata.id}`);
      console.log(`  Amount:            ${metadata.amount}`);
      console.log(`  Wallet:            ${wallet}`);
      console.log(`  Source Federation: ${pkg.sourceFederation}`);
      console.log(`  Target Federation: ${pkg.targetFederation}`);
      console.log('');

    } catch (error: any) {
      console.error(`Failed to claim bridged token: ${error.message}`);
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
  scar bridge <subcommand> [options]

SUBCOMMANDS:
  transfer <token-id> <recipient-pubkey>    Bridge token to target federation
  claim <package-file> <wallet-name>        Claim bridged token

OPTIONS (transfer):
  -g, --target-gateway <url>     Target federation Witness gateway URL
  -n, --target-network <id>      Target federation network ID
  -h, --help                     Show this help message

OPTIONS (claim):
  -s, --source-gateway <url>     Source federation Witness gateway URL
  -h, --help                     Show this help message

NOTES:
  - Bridge transfers lock tokens in source federation
  - Equivalent tokens are minted in target federation
  - Recipient must be on target federation to claim
  - Both federations must be accessible for bridge to work

EXAMPLES:
  # Bridge a token to another federation
  scar bridge transfer abc123 deadbeef... \\
    --target-gateway http://fed2.example.com:8080 \\
    --target-network scarcity-federation-2

  # Claim a bridged token (from target federation)
  scar bridge claim bridge-package.json my-wallet \\
    --source-gateway http://fed1.example.com:8080
`);
  }
}
