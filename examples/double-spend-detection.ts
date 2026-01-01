/**
 * Double-Spend Detection Example
 *
 * Demonstrates how the gossip network prevents double-spending
 */

import {
  ScarceToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter,
  Crypto
} from '../src/index.js';

async function doubleSpendDetection() {
  console.log('=== Scarce Double-Spend Detection Example ===\n');

  // Setup infrastructure
  const freebird = new FreebirdAdapter({
    issuerUrl: 'https://issuer.example.com',
    verifierUrl: 'https://verifier.example.com'
  });

  const witness = new WitnessAdapter({
    gatewayUrl: 'https://witness.example.com'
  });

  const hypertoken = new HyperTokenAdapter();
  const gossip = new NullifierGossip({ witness });

  // Add peers
  for (let i = 0; i < 10; i++) {
    gossip.addPeer(hypertoken.createPeer(`peer-${i}`));
  }

  const validator = new TransferValidator({
    gossip,
    witness,
    waitTime: 2000,      // Faster for demo
    minConfidence: 0.6
  });

  console.log('Setup complete. Network has', gossip.peers.length, 'peers\n');

  // Mint a token
  console.log('1. Minting token worth 500 units...');
  const token = ScarceToken.mint(500, freebird, witness, gossip);
  console.log(`   Token ID: ${token.getMetadata().id}\n`);

  // Create two recipients (attacker tries to double-spend)
  const recipient1Secret = Crypto.randomBytes(32);
  const recipient1PublicKey = {
    bytes: Crypto.hash(recipient1Secret, 'PUBLIC_KEY')
  };

  const recipient2Secret = Crypto.randomBytes(32);
  const recipient2PublicKey = {
    bytes: Crypto.hash(recipient2Secret, 'PUBLIC_KEY')
  };

  console.log('2. Attempting first transfer to Recipient A...');

  const transfer1 = await token.transfer(recipient1PublicKey);

  console.log(`   ✅ Transfer created`);
  console.log(`   Nullifier: ${Crypto.toHex(transfer1.nullifier).substring(0, 16)}...`);
  console.log(`   Broadcasted to gossip network\n`);

  // Validate first transfer (should succeed)
  console.log('3. Recipient A validates transfer...');

  const result1 = await validator.validateTransfer(transfer1);

  console.log(`   Valid: ${result1.valid}`);
  console.log(`   Confidence: ${(result1.confidence * 100).toFixed(1)}%`);
  console.log(`   ${result1.reason}\n`);

  // Try to spend the SAME token again (double-spend attempt)
  console.log('4. 🚨 ATTACKER: Attempting double-spend to Recipient B...');
  console.log('   (Trying to transfer already-spent token)\n');

  try {
    // This should fail because token is already marked as spent
    const transfer2 = await token.transfer(recipient2PublicKey);

    console.log('   ⚠️  Transfer package created (token allowed it)');
    console.log(`   Nullifier: ${Crypto.toHex(transfer2.nullifier).substring(0, 16)}...`);

    // But validation should catch it
    console.log('\n5. Recipient B validates transfer...');

    const result2 = await validator.validateTransfer(transfer2);

    console.log(`   Valid: ${result2.valid}`);
    console.log(`   Confidence: ${(result2.confidence * 100).toFixed(1)}%`);
    console.log(`   ${result2.reason}\n`);

    if (!result2.valid) {
      console.log('✅ Double-spend PREVENTED by gossip network!\n');
    } else {
      console.log('❌ Double-spend NOT prevented (this should not happen)\n');
    }
  } catch (error: any) {
    console.log(`   ❌ Transfer failed: ${error.message}`);
    console.log('\n✅ Double-spend PREVENTED by token itself!\n');
  }

  // Show gossip stats
  const stats = gossip.getStats();
  console.log('Final Gossip Network Stats:');
  console.log(`   Nullifiers tracked: ${stats.nullifierCount}`);
  console.log(`   Total peers: ${stats.peerCount}`);

  // Check nullifier confidence
  const nullifierConfidence = await gossip.checkNullifier(transfer1.nullifier);
  console.log(`   Nullifier confidence: ${(nullifierConfidence * 100).toFixed(1)}%`);

  // Cleanup
  gossip.destroy();
}

// Run the example
doubleSpendDetection().catch(console.error);
