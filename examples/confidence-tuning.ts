/**
 * Confidence Tuning Example
 *
 * Demonstrates different validation strategies based on transfer value
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

async function confidenceTuning() {
  console.log('=== Scarce Confidence Tuning Example ===\n');

  // Setup
  const freebird = new FreebirdAdapter({
    issuerUrl: 'https://issuer.example.com',
    verifierUrl: 'https://verifier.example.com'
  });

  const witness = new WitnessAdapter({
    gatewayUrl: 'https://witness.example.com'
  });

  const hypertoken = new HyperTokenAdapter();
  const gossip = new NullifierGossip({ witness });

  // Simulate different network sizes
  const scenarios = [
    { peers: 5, description: 'Small network (coffee shop)' },
    { peers: 50, description: 'Medium network (community)' },
    { peers: 200, description: 'Large network (city)' }
  ];

  for (const scenario of scenarios) {
    console.log(`\n📊 Scenario: ${scenario.description}`);
    console.log(`   Peers: ${scenario.peers}\n`);

    // Reset gossip network
    gossip.peers.forEach(p => gossip.removePeer(p.id));

    for (let i = 0; i < scenario.peers; i++) {
      gossip.addPeer(hypertoken.createPeer(`peer-${i}`));
    }

    // Create validator
    const validator = new TransferValidator({
      gossip,
      witness,
      waitTime: 5000,
      minConfidence: 0.7
    });

    // Mint three tokens of different values
    const smallToken = ScarceToken.mint(10, freebird, witness, gossip);
    const mediumToken = ScarceToken.mint(1000, freebird, witness, gossip);
    const largeToken = ScarceToken.mint(100000, freebird, witness, gossip);

    const recipient = {
      bytes: Crypto.randomBytes(32)
    };

    // Small value: Fast validation
    console.log('   💵 Small transfer (10 units)');
    const smallTransfer = await smallToken.transfer(recipient);
    const startSmall = Date.now();
    const smallResult = await validator.fastValidate(smallTransfer);
    const smallTime = Date.now() - startSmall;

    console.log(`      Strategy: Fast validation`);
    console.log(`      Time: ${smallTime}ms`);
    console.log(`      Confidence: ${(smallResult.confidence * 100).toFixed(1)}%`);
    console.log(`      Valid: ${smallResult.valid}\n`);

    // Medium value: Standard validation
    console.log('   💰 Medium transfer (1,000 units)');
    const mediumTransfer = await mediumToken.transfer(recipient);
    const startMedium = Date.now();
    const mediumResult = await validator.validateTransfer(mediumTransfer);
    const mediumTime = Date.now() - startMedium;

    console.log(`      Strategy: Standard validation (5s wait)`);
    console.log(`      Time: ${mediumTime}ms`);
    console.log(`      Confidence: ${(mediumResult.confidence * 100).toFixed(1)}%`);
    console.log(`      Valid: ${mediumResult.valid}\n`);

    // Large value: Deep validation
    console.log('   💎 Large transfer (100,000 units)');
    const largeTransfer = await largeToken.transfer(recipient);
    const startLarge = Date.now();
    const largeResult = await validator.deepValidate(largeTransfer, 15000);
    const largeTime = Date.now() - startLarge;

    console.log(`      Strategy: Deep validation (15s wait)`);
    console.log(`      Time: ${largeTime}ms`);
    console.log(`      Confidence: ${(largeResult.confidence * 100).toFixed(1)}%`);
    console.log(`      Valid: ${largeResult.valid}`);
  }

  // Show confidence score breakdown
  console.log('\n\n📈 Confidence Score Breakdown:\n');

  const exampleParams = [
    { peers: 5, depth: 3, wait: 0, label: 'Fast (5 peers, instant)' },
    { peers: 50, depth: 3, wait: 5000, label: 'Standard (50 peers, 5s)' },
    { peers: 200, depth: 5, wait: 15000, label: 'Deep (200 peers, 15s)' }
  ];

  const validator = new TransferValidator({
    gossip,
    witness,
    waitTime: 5000,
    minConfidence: 0.7
  });

  for (const params of exampleParams) {
    const confidence = validator.computeConfidence({
      gossipPeers: params.peers,
      witnessDepth: params.depth,
      waitTime: params.wait
    });

    const peerScore = Math.min(params.peers / 100, 0.5);
    const witnessScore = Math.min(params.depth / 3, 0.3);
    const timeScore = Math.min(params.wait / 10_000, 0.2);

    console.log(`   ${params.label}:`);
    console.log(`      Peer score: ${(peerScore * 100).toFixed(1)}%`);
    console.log(`      Witness score: ${(witnessScore * 100).toFixed(1)}%`);
    console.log(`      Time score: ${(timeScore * 100).toFixed(1)}%`);
    console.log(`      Total: ${(confidence * 100).toFixed(1)}%\n`);
  }

  console.log('💡 Key Insight:');
  console.log('   - More peers = faster confidence');
  console.log('   - Longer wait = higher confidence');
  console.log('   - Tune based on transfer value\n');

  // Cleanup
  gossip.destroy();
}

// Run the example
confidenceTuning().catch(console.error);
