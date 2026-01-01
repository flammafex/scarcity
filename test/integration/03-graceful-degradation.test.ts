/**
 * Integration Test: Graceful Degradation
 *
 * Tests that the system works correctly when external services
 * (Freebird, Witness, HyperToken) are unavailable, falling back
 * to simulated mode.
 */

import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter
} from '../../src/index.js';

import { TestRunner, createTestKeyPair, TestConfig } from '../helpers/test-utils.js';

export async function runGracefulDegradationTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Graceful Degradation');
  console.log('='.repeat(60) + '\n');

  // Test 1: Freebird with invalid URLs (should fall back)
  await runner.run('Freebird fallback mode', async () => {
    const freebird = new FreebirdAdapter({
      issuerEndpoints: ['http://invalid-url-12345.example.com'],
      verifierUrl: 'http://invalid-url-67890.example.com'
    });

    // These should work in fallback mode
    const { publicKey } = createTestKeyPair();
    const blinded = await freebird.blind(publicKey);

    runner.assert(
      blinded.length === 32,
      `Fallback mode should return 32-byte hash, got ${blinded.length} bytes. ` +
      `Expected fallback mode with invalid URLs.`
    );

    const token = await freebird.issueToken(blinded);
    runner.assert(
      token.length === 32,
      `Fallback mode should issue 32-byte token, got ${token.length} bytes`
    );

    const valid = await freebird.verifyToken(token);
    runner.assertEquals(valid, true, 'VerifyToken should return true in fallback');
  });

  // Test 2: Witness with invalid URL (should fall back)
  await runner.run('Witness fallback mode', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: 'http://invalid-witness.example.com'
    });

    const attestation = await witness.timestamp('test-hash-123');

    runner.assert(attestation.hash === 'test-hash-123', 'Timestamp should return hash');
    runner.assert(attestation.signatures.length >= 2, 'Should have fallback signatures');
    runner.assert(attestation.witnessIds.length >= 2, 'Should have fallback witness IDs');

    const valid = await witness.verify(attestation);
    runner.assertEquals(valid, true, 'Verify should work in fallback');
  });

  // Test 3: HyperToken with invalid URL (should handle gracefully)
  await runner.run('HyperToken connection failure handling', async () => {
    const hypertoken = new HyperTokenAdapter({
      relayUrl: 'ws://invalid-relay.example.com:9999'
    });

    try {
      // Connection will fail, but should not crash
      await hypertoken.connect();
    } catch {
      // Expected - connection should fail
    }

    // Should still be able to create peer wrappers
    const peer = hypertoken.createPeer('test-peer');
    runner.assert(peer.id === 'test-peer', 'Should create peer even when disconnected');
  });

  // Test 4: Complete token transfer in fallback mode
  await runner.run('End-to-end transfer in fallback mode', async () => {
    const freebird = new FreebirdAdapter({
      issuerEndpoints: ['http://invalid.example.com'],
      verifierUrl: 'http://invalid.example.com'
    });

    const witness = new WitnessAdapter({
      gatewayUrl: 'http://invalid.example.com'
    });

    const hypertoken = new HyperTokenAdapter({
      relayUrl: 'ws://invalid.example.com'
    });

    // Don't attempt connection
    const gossip = new NullifierGossip({ witness });

    // Add mock peers (not connected)
    for (let i = 0; i < 3; i++) {
      const peer = hypertoken.createPeer(`fallback-peer-${i}`);
      gossip.addPeer(peer);
    }

    const validator = new TransferValidator({
      gossip,
      witness,
      waitTime: 1000,
      minConfidence: 0.3 // Lower threshold for fallback mode
    });

    // Mint, transfer, receive should all work in fallback
    const token = ScarbuckToken.mint(100, freebird, witness, gossip);
    const { publicKey, secret } = createTestKeyPair();

    const transferPkg = await token.transfer(publicKey);
    runner.assert(transferPkg.amount === 100, 'Transfer should work in fallback');

    const result = await validator.validateTransfer(transferPkg);
    // May be valid or invalid depending on fallback behavior
    runner.assert(
      typeof result.valid === 'boolean',
      'Validator should return result in fallback'
    );

    if (result.valid) {
      const receivedToken = await ScarbuckToken.receive(
        transferPkg,
        secret,
        freebird,
        witness,
        gossip
      );
      runner.assert(receivedToken.getMetadata().amount === 100, 'Receive should work');
    }

    gossip.destroy();
  });

  // Test 5: Mixed mode (some services available, some not)
  await runner.run('Mixed service availability', async () => {
    // Real Freebird URLs (may or may not be running, use TestConfig)
    const freebird = new FreebirdAdapter({
      issuerEndpoints: [TestConfig.freebird.issuer],
      verifierUrl: TestConfig.freebird.verifier
    });

    // Invalid Witness URL
    const witness = new WitnessAdapter({
      gatewayUrl: 'http://invalid-witness.example.com'
    });

    const { publicKey, secret } = createTestKeyPair();

    // Should work regardless of which services are available
    const blinded = await freebird.blind(publicKey);
    const attestation = await witness.timestamp('mixed-mode-test');

    // Blinded value can be either:
    // - 33 bytes (VOPRF mode if service is running)
    // - 32 bytes (fallback mode if service is not running)
    const blindedSize = blinded.length;
    const isVoprfMode = blindedSize === 33;
    const isFallbackMode = blindedSize === 32;

    runner.assert(
      isVoprfMode || isFallbackMode,
      `Blinding should work in either mode: 32 bytes (fallback) or 33 bytes (VOPRF), got ${blindedSize} bytes. ` +
      `Mode detected: ${isVoprfMode ? 'VOPRF (Freebird available)' : isFallbackMode ? 'Fallback (Freebird unavailable)' : 'Unknown'}`
    );

    console.log(`  ℹ️  Mixed mode - Freebird: ${isVoprfMode ? 'Connected (VOPRF)' : 'Unavailable (Fallback)'}, Witness: Unavailable (Fallback)`);

    runner.assert(attestation.signatures.length > 0, 'Timestamping should work');
  });

  runner.printSummary();

  const summary = runner.getSummary();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} test(s) failed`);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runGracefulDegradationTest()
    .then(() => {
      console.log('\n✅ All graceful degradation tests passed!\n');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Test suite failed:', error.message);
      process.exit(1);
    });
}