/**
 * Integration Test: Phase 3 Advanced Features
 *
 * Tests:
 * - Token splitting/merging
 * - Multi-party transfers
 * - HTLCs (Hash Time-Locked Contracts)
 * - Cross-federation bridging
 */

import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FederationBridge,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter,
  Crypto,
  type PublicKey,
  type HTLCCondition
} from '../../src/index.js';

import { TestRunner, createTestKeyPair, sleep, TestConfig } from '../helpers/test-utils.js';

export async function runPhase3Tests(): Promise<any> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Phase 3 Advanced Features');
  console.log('='.repeat(60) + '\n');

  // Setup infrastructure
  const freebird = new FreebirdAdapter({
    issuerEndpoints: [TestConfig.freebird.issuer],
    verifierUrl: TestConfig.freebird.verifier
  });

  const witness = new WitnessAdapter({
    gatewayUrl: TestConfig.witness.gateway,
    networkId: 'gateway1-network'
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
    waitTime: 2000,
    minConfidence: 0.5
  });

  // Test 1: Token Splitting
  await runner.run('Token splitting', async () => {
    const token = ScarbuckToken.mint(100, freebird, witness, gossip);

    const recipient1: PublicKey = { bytes: Crypto.randomBytes(32) };
    const recipient2: PublicKey = { bytes: Crypto.randomBytes(32) };
    const recipient3: PublicKey = { bytes: Crypto.randomBytes(32) };

    const splitPkg = await token.split(
      [30, 30, 40],
      [recipient1, recipient2, recipient3]
    );

    runner.assertEquals(splitPkg.splits.length, 3, 'Should have 3 splits');
    runner.assertEquals(splitPkg.sourceAmount, 100, 'Source amount should be 100');

    const totalSplit = splitPkg.splits.reduce((sum, s) => sum + s.amount, 0);
    runner.assertEquals(totalSplit, 100, 'Split amounts should sum to 100');
  });

  // Test 2: Token Split Validation
  await runner.run('Token split validation (wrong amounts)', async () => {
    const token = ScarbuckToken.mint(100, freebird, witness, gossip);

    const recipient1: PublicKey = { bytes: Crypto.randomBytes(32) };
    const recipient2: PublicKey = { bytes: Crypto.randomBytes(32) };

    try {
      await token.split([30, 40], [recipient1, recipient2]);
      throw new Error('Should have rejected invalid split amounts');
    } catch (err: any) {
      runner.assert(
        err.message.includes('must equal token amount'),
        'Should reject invalid amounts'
      );
    }
  });

  // Test 3: Token Merging
  await runner.run('Token merging', async () => {
    const token1 = ScarbuckToken.mint(30, freebird, witness, gossip);
    const token2 = ScarbuckToken.mint(40, freebird, witness, gossip);
    const token3 = ScarbuckToken.mint(30, freebird, witness, gossip);

    const recipientKey: PublicKey = { bytes: Crypto.randomBytes(32) };

    const mergePkg = await ScarbuckToken.merge(
      [token1, token2, token3],
      recipientKey
    );

    runner.assertEquals(mergePkg.targetAmount, 100, 'Merged amount should be 100');
    runner.assertEquals(mergePkg.sources.length, 3, 'Should have 3 sources');
  });

  // Test 4: Receive Split Tokens
  await runner.run('Receiving split tokens', async () => {
    const token = ScarbuckToken.mint(90, freebird, witness, gossip);

    const recipient1Secret = Crypto.randomBytes(32);
    const recipient2Secret = Crypto.randomBytes(32);
    const recipient3Secret = Crypto.randomBytes(32);

    const splitPkg = await token.split(
      [30, 30, 30],
      [
        { bytes: recipient1Secret },
        { bytes: recipient2Secret },
        { bytes: recipient3Secret }
      ]
    );

    const receivedToken1 = await ScarbuckToken.receiveSplit(
      splitPkg,
      recipient1Secret,
      0,
      freebird,
      witness,
      gossip
    );

    runner.assertEquals(receivedToken1.getMetadata().amount, 30, 'Should receive 30');
  });

  // Test 5: Receive Merged Token
  await runner.run('Receiving merged token', async () => {
    const token1 = ScarbuckToken.mint(25, freebird, witness, gossip);
    const token2 = ScarbuckToken.mint(25, freebird, witness, gossip);

    const recipientSecret = Crypto.randomBytes(32);
    const recipientKey: PublicKey = { bytes: recipientSecret };

    const mergePkg = await ScarbuckToken.merge(
      [token1, token2],
      recipientKey
    );

    const receivedToken = await ScarbuckToken.receiveMerge(
      mergePkg,
      recipientSecret,
      freebird,
      witness,
      gossip
    );

    runner.assertEquals(receivedToken.getMetadata().amount, 50, 'Should receive 50');
  });

  // Test 6: Multi-Party Transfer
  await runner.run('Multi-party transfer', async () => {
    const token = ScarbuckToken.mint(100, freebird, witness, gossip);

    const recipient1: PublicKey = { bytes: Crypto.randomBytes(32) };
    const recipient2: PublicKey = { bytes: Crypto.randomBytes(32) };
    const recipient3: PublicKey = { bytes: Crypto.randomBytes(32) };

    const multiPartyPkg = await token.transferMultiParty([
      { publicKey: recipient1, amount: 25 },
      { publicKey: recipient2, amount: 35 },
      { publicKey: recipient3, amount: 40 }
    ]);

    runner.assertEquals(multiPartyPkg.recipients.length, 3, 'Should have 3 recipients');

    const totalAmount = multiPartyPkg.recipients.reduce((sum, r) => sum + r.amount, 0);
    runner.assertEquals(totalAmount, 100, 'Amounts should sum to 100');
  });

  // Test 7: Receive Multi-Party Transfer
  await runner.run('Receiving from multi-party transfer', async () => {
    const token = ScarbuckToken.mint(60, freebird, witness, gossip);

    const recipient1Secret = Crypto.randomBytes(32);
    const recipient2Secret = Crypto.randomBytes(32);

    const multiPartyPkg = await token.transferMultiParty([
      { publicKey: { bytes: recipient1Secret }, amount: 20 },
      { publicKey: { bytes: recipient2Secret }, amount: 40 }
    ]);

    const receivedToken = await ScarbuckToken.receiveMultiParty(
      multiPartyPkg,
      recipient2Secret,
      1,
      freebird,
      witness,
      gossip
    );

    runner.assertEquals(receivedToken.getMetadata().amount, 40, 'Should receive 40');
  });

  // Test 8: Hash-Locked HTLC
  await runner.run('Hash-locked HTLC', async () => {
    const token = ScarbuckToken.mint(50, freebird, witness, gossip);

    const recipientSecret = Crypto.randomBytes(32);
    const recipientKey: PublicKey = { bytes: recipientSecret };

    const preimage = Crypto.randomBytes(32);
    const hashlock = Crypto.hashString(Crypto.toHex(preimage));

    const condition: HTLCCondition = {
      type: 'hash',
      hashlock
    };

    const htlcPkg = await token.transferHTLC(recipientKey, condition);

    runner.assertEquals(htlcPkg.condition.type, 'hash', 'Should be hash-locked');

    const receivedToken = await ScarbuckToken.receiveHTLC(
      htlcPkg,
      recipientSecret,
      preimage,
      freebird,
      witness,
      gossip
    );

    runner.assertEquals(receivedToken.getMetadata().amount, 50, 'Should receive 50');
  });

  // Test 9: HTLC with Wrong Preimage
  await runner.run('HTLC rejection with wrong preimage', async () => {
    const token = ScarbuckToken.mint(50, freebird, witness, gossip);

    const recipientSecret = Crypto.randomBytes(32);
    const recipientKey: PublicKey = { bytes: recipientSecret };

    const preimage = Crypto.randomBytes(32);
    const hashlock = Crypto.hashString(Crypto.toHex(preimage));

    const condition: HTLCCondition = {
      type: 'hash',
      hashlock
    };

    const htlcPkg = await token.transferHTLC(recipientKey, condition);

    const wrongPreimage = Crypto.randomBytes(32);

    try {
      await ScarbuckToken.receiveHTLC(
        htlcPkg,
        recipientSecret,
        wrongPreimage,
        freebird,
        witness,
        gossip
      );
      throw new Error('Should have rejected wrong preimage');
    } catch (err: any) {
      runner.assert(
        err.message.includes('Invalid preimage'),
        'Should reject wrong preimage'
      );
    }
  });

  // Test 10: Time-Locked HTLC
  await runner.run('Time-locked HTLC', async () => {
    const token = ScarbuckToken.mint(50, freebird, witness, gossip);

    const recipientSecret = Crypto.randomBytes(32);
    const recipientKey: PublicKey = { bytes: recipientSecret };

    const refundSecret = Crypto.randomBytes(32);
    const refundKey: PublicKey = { bytes: refundSecret };

    const timelock = Date.now() + 5000;

    const condition: HTLCCondition = {
      type: 'time',
      timelock
    };

    const htlcPkg = await token.transferHTLC(recipientKey, condition, refundKey);

    runner.assertEquals(htlcPkg.condition.type, 'time', 'Should be time-locked');

    const receivedToken = await ScarbuckToken.receiveHTLC(
      htlcPkg,
      recipientSecret,
      undefined,
      freebird,
      witness,
      gossip
    );

    runner.assertEquals(receivedToken.getMetadata().amount, 50, 'Should receive 50');
  });

  // Test 11: Cross-Federation Bridge
  await runner.run('Cross-federation bridge', async () => {
    const witness2 = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway2, // Use secondary witness gateway
      networkId: 'test-federation-2'
    });

    const gossip2 = new NullifierGossip({ witness: witness2 });

    const bridge = new FederationBridge({
      sourceFederation: 'test-federation-1',
      targetFederation: 'test-federation-2',
      sourceWitness: witness,
      targetWitness: witness2,
      sourceGossip: gossip,
      targetGossip: gossip2,
      freebird
    });

    const token = ScarbuckToken.mint(75, freebird, witness, gossip);

    const recipientSecret = Crypto.randomBytes(32);
    const recipientKey: PublicKey = { bytes: recipientSecret };

    const bridgePkg = await bridge.bridgeToken(token, recipientKey);

    runner.assertEquals(bridgePkg.sourceFederation, 'test-federation-1', 'Source federation should match');
    runner.assertEquals(bridgePkg.targetFederation, 'test-federation-2', 'Target federation should match');
    runner.assertEquals(bridgePkg.amount, 75, 'Amount should be 75');

    const receivedToken = await bridge.receiveBridged(bridgePkg, recipientSecret);

    runner.assertEquals(receivedToken.getMetadata().amount, 75, 'Should receive 75');
  });

  // Cleanup
  await hypertoken.disconnect();

  // Print summary
  runner.printSummary();

  const summary = runner.getSummary();
  return summary;
}

// Run tests if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runPhase3Tests()
    .then(summary => {
      process.exit(summary.failed > 0 ? 1 : 0);
    })
    .catch(err => {
      console.error('Fatal error:', err);
      process.exit(1);
    });
}