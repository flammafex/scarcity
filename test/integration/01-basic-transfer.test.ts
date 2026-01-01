/**
 * Integration Test: Basic Token Transfer
 *
 * Tests the complete flow of minting, transferring, and receiving a token
 * across all three integration layers (HyperToken, Freebird, Witness).
 */

import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter
} from '../../src/index.js';

import { TestRunner, createTestKeyPair, sleep, TestConfig } from '../helpers/test-utils.js';

export async function runBasicTransferTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Basic Token Transfer');
  console.log('='.repeat(60) + '\n');

  // Setup infrastructure
  const freebird = new FreebirdAdapter({
    issuerEndpoints: [TestConfig.freebird.issuer],
    verifierUrl: TestConfig.freebird.verifier
  });

  const witness = new WitnessAdapter({
    gatewayUrl: TestConfig.witness.gateway,
    networkId: 'test-network'
  });

  const hypertoken = new HyperTokenAdapter({
    relayUrl: TestConfig.hypertoken.relay
  });

  await runner.run('HyperToken connection', async () => {
    await hypertoken.connect();
    runner.assert(true, 'Connected to HyperToken');
  });

  // Create gossip network
  const gossip = new NullifierGossip({ witness });

  await runner.run('Gossip network setup', async () => {
    // Add test peers
    for (let i = 0; i < 3; i++) {
      const peer = hypertoken.createPeer(`test-peer-${i}`);
      gossip.addPeer(peer);
    }

    const stats = gossip.getStats();
    runner.assertEquals(stats.peerCount, 3, 'Should have 3 peers');
  });

  // Create validator
  const validator = new TransferValidator({
    gossip,
    witness,
    waitTime: 2000,      // 2 second wait for testing
    minConfidence: 0.5   // Lower threshold for testing
  });

  await runner.run('Validator configuration', async () => {
    const config = validator.getConfig();
    runner.assertEquals(config.waitTime, 2000, 'Wait time should be 2000ms');
    runner.assertEquals(config.minConfidence, 0.5, 'Min confidence should be 0.5');
  });

  // Test 1: Mint a token
  let token: ScarbuckToken;

  await runner.run('Token minting', async () => {
    token = ScarbuckToken.mint(100, freebird, witness, gossip);

    const metadata = token.getMetadata();
    runner.assert(metadata.id.length > 0, 'Token should have ID');
    runner.assertEquals(metadata.amount, 100, 'Amount should be 100');
    runner.assertEquals(metadata.spent, false, 'Token should not be spent');
  });

  // Test 2: Generate recipient
  const { publicKey: recipientPublicKey, secret: recipientSecret } = createTestKeyPair();

  await runner.run('Recipient key generation', async () => {
    runner.assert(recipientPublicKey.bytes.length === 32, 'Public key should be 32 bytes');
    runner.assert(recipientSecret.length === 32, 'Secret should be 32 bytes');
  });

  // Test 3: Transfer token
  let transferPkg: any;

  await runner.run('Token transfer', async () => {
    transferPkg = await token!.transfer(recipientPublicKey);

    runner.assert(transferPkg.tokenId.length > 0, 'Package should have token ID');
    runner.assertEquals(transferPkg.amount, 100, 'Amount should be 100');
    runner.assert(transferPkg.nullifier.length === 32, 'Nullifier should be 32 bytes');

    // Commitment can be 32 bytes (fallback hash) or 33 bytes (VOPRF compressed P-256 point)
    const commitmentSize = transferPkg.commitment.length;
    const isVoprfMode = commitmentSize === 33;
    const isFallbackMode = commitmentSize === 32;

    runner.assert(
      isVoprfMode || isFallbackMode,
      `Commitment should be 32 bytes (fallback) or 33 bytes (VOPRF), got ${commitmentSize} bytes. ` +
      `Mode: ${isVoprfMode ? 'VOPRF (Freebird connected)' : isFallbackMode ? 'Fallback (Freebird unavailable)' : 'Unknown'}`
    );

    console.log(`  ℹ️  Freebird mode: ${isVoprfMode ? 'VOPRF (33-byte compressed P-256 point)' : 'Fallback (32-byte hash)'}`);

    runner.assert(transferPkg.proof, 'Package should have proof');

    // Check token is marked as spent
    const metadata = token!.getMetadata();
    runner.assertEquals(metadata.spent, true, 'Token should be marked spent');
  });

  // Test 4: Wait for gossip propagation
  await runner.run('Gossip propagation', async () => {
    await sleep(2500); // Wait longer than validator wait time

    const stats = gossip.getStats();
    runner.assertGreaterThan(stats.nullifierCount, 0, 'Gossip should have nullifiers');
  });

  // Test 5: Validate transfer
  await runner.run('Transfer validation', async () => {
    const result = await validator.validateTransfer(transferPkg);

    console.log('Validation result:', {
      valid: result.valid,
      confidence: result.confidence,
      reason: result.reason
    });

    runner.assertEquals(result.valid, true, 'Transfer should be valid');
    runner.assertBetween(result.confidence, 0, 1, 'Confidence should be 0-1');

    if (!result.valid) {
      console.log('Validation failed:', result.reason);
    }
  });

  // Test 6: Receive token
  await runner.run('Token reception', async () => {
    const receivedToken = await ScarbuckToken.receive(
      transferPkg,
      recipientSecret,
      freebird,
      witness,
      gossip
    );

    const metadata = receivedToken.getMetadata();
    runner.assertEquals(metadata.amount, 100, 'Received amount should be 100');
    runner.assertEquals(metadata.spent, false, 'Received token should not be spent');
  });

  // Cleanup
  gossip.destroy();
  hypertoken.disconnect();

  runner.printSummary();

  const summary = runner.getSummary();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} test(s) failed`);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runBasicTransferTest()
    .then(() => {
      console.log('\n✅ All tests passed!\n');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Test suite failed:', error.message);
      process.exit(1);
    });
}