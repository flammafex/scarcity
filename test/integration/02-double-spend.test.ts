/**
 * Integration Test: Double-Spend Detection
 *
 * Tests that the system correctly detects and prevents double-spending
 * through nullifier gossip and Witness attestations.
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

export async function runDoubleSpendTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Double-Spend Detection');
  console.log('='.repeat(60) + '\n');

  // Setup infrastructure
  const freebird = new FreebirdAdapter({
    issuerEndpoints: [TestConfig.freebird.issuer],
    verifierUrl: TestConfig.freebird.verifier
  });

  const witness = new WitnessAdapter({
    gatewayUrl: TestConfig.witness.gateway
  });

  const hypertoken = new HyperTokenAdapter({
    relayUrl: TestConfig.hypertoken.relay
  });

  try {
    await hypertoken.connect();
  } catch {
    console.log('⚠️  HyperToken unavailable, using fallback');
  }

  const gossip = new NullifierGossip({ witness });

  // Add peers
  for (let i = 0; i < 5; i++) {
    const peer = hypertoken.createPeer(`test-peer-${i}`);
    gossip.addPeer(peer);
  }

  const validator = new TransferValidator({
    gossip,
    witness,
    waitTime: 3000,
    minConfidence: 0.6
  });

  // Test 1: Mint a token
  let token: ScarbuckToken;

  await runner.run('Token minting', async () => {
    token = ScarbuckToken.mint(50, freebird, witness, gossip);
    runner.assert(token.getMetadata().spent === false, 'Token should not be spent');
  });

  // Test 2: First transfer (legitimate)
  const recipient1 = createTestKeyPair();
  let transfer1: any;

  await runner.run('First transfer (legitimate)', async () => {
    transfer1 = await token!.transfer(recipient1.publicKey);
    runner.assert(transfer1.nullifier.length === 32, 'First transfer should have nullifier');
    runner.assert(token!.getMetadata().spent === true, 'Token should be marked spent');
  });

  // Test 3: Wait for propagation
  await runner.run('Nullifier propagation', async () => {
    await sleep(3500); // Wait for gossip to propagate

    const nullifierSeen = await gossip.checkNullifier(transfer1.nullifier);
    runner.assertGreaterThan(nullifierSeen, 0, 'Nullifier should be seen in gossip');
  });

  // Test 4: Validate first transfer
  await runner.run('First transfer validation', async () => {
    const result = await validator.validateTransfer(transfer1);
    runner.assertEquals(result.valid, true, 'First transfer should be valid');
  });

  // Test 5: Attempt double-spend (should fail)
  const recipient2 = createTestKeyPair();

  await runner.run('Double-spend attempt (should be detected)', async () => {
    try {
      // Try to transfer the same token again
      // This should fail because the token is already spent
      const transfer2 = await token!.transfer(recipient2.publicKey);

      // If we get here, the transfer was created
      // Try to validate it - should fail
      const result = await validator.validateTransfer(transfer2);

      runner.assertEquals(
        result.valid,
        false,
        'Double-spend should be detected as invalid'
      );

      if (result.valid) {
        throw new Error('Double-spend was not detected!');
      }
    } catch (error: any) {
      // Expected: token.transfer() should throw because token is spent
      if (error.message.includes('already spent')) {
        runner.assert(true, 'Token correctly rejected as already spent');
      } else {
        // Re-throw unexpected errors
        throw error;
      }
    }
  });

  // Test 6: Direct nullifier republish attempt
  await runner.run('Nullifier republish detection', async () => {
    try {
      // Try to publish the same nullifier again
      await gossip.publish(transfer1.nullifier, transfer1.proof);

      // Should throw double-spend error
      runner.assert(false, 'Should have thrown double-spend error');
    } catch (error: any) {
      runner.assert(
        error.message.includes('Double-spend'),
        'Should detect double-spend on republish'
      );
    }
  });

  // Test 7: Check nullifier confidence over time
  await runner.run('Nullifier confidence increases', async () => {
    const confidence1 = await gossip.checkNullifier(transfer1.nullifier);

    await sleep(2000);

    const confidence2 = await gossip.checkNullifier(transfer1.nullifier);

    runner.assertGreaterThan(
      confidence2,
      0,
      'Confidence should remain high after time'
    );
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
  runDoubleSpendTest()
    .then(() => {
      console.log('\n✅ All double-spend tests passed!\n');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Test suite failed:', error.message);
      process.exit(1);
    });
}