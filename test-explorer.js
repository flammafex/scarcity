#!/usr/bin/env node
/**
 * Test script to generate nullifiers in the same process as the explorer
 * This allows the explorer to collect them without needing a relay server
 */

import { NullifierDatabase } from './dist/src/explorer/database.js';
import { NullifierCollector } from './dist/src/explorer/collector.js';
import { InfrastructureManager } from './dist/src/cli/infrastructure.js';
import { WalletManager } from './dist/src/cli/wallet.js';
import { ScarbuckToken } from './dist/src/token.js';
import { Crypto } from './dist/src/crypto.js';

async function main() {
  console.log('🧪 Nullscape Explorer Test - Generating nullifiers...\n');

  // Create shared infrastructure
  const infraManager = new InfrastructureManager();
  const infra = await infraManager.initialize();

  // Create database and collector
  const db = new NullifierDatabase();
  const collector = new NullifierCollector({
    database: db,
    gossip: infra.gossip,
    witness: infra.witness,
    federation: 'test'
  });

  // Start collector
  collector.start();

  // Create wallets
  const walletManager = new WalletManager();

  console.log('Creating wallets...');
  const alice = walletManager.createWallet('test-alice');
  const bob = walletManager.createWallet('test-bob');

  // Mint token
  console.log('Minting token for alice...');
  const token = ScarbuckToken.mint(100, infra.freebird, infra.witness, infra.gossip);

  // Transfer token (this generates a nullifier!)
  console.log('Transferring token from alice to bob...');
  const transfer = await token.transfer({
    bytes: Crypto.fromHex(bob.publicKey)
  });

  console.log('✅ Transfer complete! Nullifier published to gossip network.\n');
  console.log(`Nullifier: ${Crypto.toHex(transfer.nullifier)}`);

  // Wait a bit for collector to process
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Check database
  const stats = collector.getStats();
  const dbCount = db.getCount();

  console.log('\n📊 Collector Stats:');
  console.log(`  Received: ${stats.received}`);
  console.log(`  Stored:   ${stats.stored}`);
  console.log(`  Errors:   ${stats.errors}`);
  console.log(`  DB Count: ${dbCount}`);

  if (dbCount > 0) {
    console.log('\n✅ SUCCESS! Nullifiers collected in database.');
    console.log('You can now view them in Nullscape Explorer.');
  } else {
    console.log('\n❌ No nullifiers in database. Check collector logs.');
  }

  // Cleanup
  collector.stop();
  await infraManager.cleanup();
  db.close();

  // Force exit
  setTimeout(() => process.exit(0), 500);
}

main().catch((error) => {
  console.error('Error:', error);
  process.exit(1);
});
