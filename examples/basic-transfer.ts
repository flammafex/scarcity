/**
 * Basic Transfer Example
 *
 * Demonstrates a simple token mint -> transfer -> receive flow
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

async function basicTransfer() {
  console.log('=== Scarce Basic Transfer Example ===\n');

  // Step 1: Initialize infrastructure
  console.log('1. Initializing infrastructure...');

  const freebird = new FreebirdAdapter({
    issuerUrl: 'https://issuer.example.com',
    verifierUrl: 'https://verifier.example.com'
  });

  const witness = new WitnessAdapter({
    gatewayUrl: 'https://witness.example.com'
  });

  const hypertoken = new HyperTokenAdapter({
    relayUrl: 'ws://relay.example.com:8080'
  });

  await hypertoken.connect();

  // Step 2: Create gossip network with peers
  console.log('2. Setting up gossip network...');

  const gossip = new NullifierGossip({ witness });

  // Add some peers for gossip
  for (let i = 0; i < 5; i++) {
    const peer = hypertoken.createPeer(`peer-${i}`);
    gossip.addPeer(peer);
  }

  console.log(`   Connected to ${gossip.peers.length} peers`);

  // Step 3: Create validator
  console.log('3. Creating transfer validator...');

  const validator = new TransferValidator({
    gossip,
    witness,
    waitTime: 5000,      // 5 second wait
    minConfidence: 0.7   // 70% confidence required
  });

  console.log(`   Wait time: ${validator.getConfig().waitTime}ms`);
  console.log(`   Min confidence: ${validator.getConfig().minConfidence}\n`);

  // Step 4: Mint a token (sender creates it)
  console.log('4. Minting token...');

  const token = ScarceToken.mint(100, freebird, witness, gossip);
  const metadata = token.getMetadata();

  console.log(`   Token ID: ${metadata.id}`);
  console.log(`   Amount: ${metadata.amount}`);
  console.log(`   Spent: ${metadata.spent}\n`);

  // Step 5: Generate recipient key pair
  console.log('5. Generating recipient keys...');

  const recipientSecret = Crypto.randomBytes(32);
  const recipientPublicKey = {
    bytes: Crypto.hash(recipientSecret, 'PUBLIC_KEY')
  };

  console.log(`   Public key: ${Crypto.toHex(recipientPublicKey.bytes).substring(0, 16)}...`);

  // Step 6: Transfer token
  console.log('\n6. Initiating transfer...');

  const transferPkg = await token.transfer(recipientPublicKey);

  console.log(`   Nullifier: ${Crypto.toHex(transferPkg.nullifier).substring(0, 16)}...`);
  console.log(`   Commitment: ${Crypto.toHex(transferPkg.commitment).substring(0, 16)}...`);
  console.log(`   Timestamp: ${transferPkg.proof.timestamp}`);
  console.log(`   Witnesses: ${transferPkg.proof.witnessIds.join(', ')}\n`);

  // Step 7: Recipient validates transfer
  console.log('7. Validating transfer...');

  const result = await validator.validateTransfer(transferPkg);

  console.log(`   Valid: ${result.valid}`);
  console.log(`   Confidence: ${(result.confidence * 100).toFixed(1)}%`);
  console.log(`   Reason: ${result.reason}\n`);

  if (result.valid) {
    // Step 8: Recipient receives token
    console.log('8. Receiving token...');

    const receivedToken = await ScarceToken.receive(
      transferPkg,
      recipientSecret,
      freebird,
      witness,
      gossip
    );

    const receivedMetadata = receivedToken.getMetadata();

    console.log(`   Token ID: ${receivedMetadata.id}`);
    console.log(`   Amount: ${receivedMetadata.amount}`);
    console.log(`   Spent: ${receivedMetadata.spent}\n`);

    console.log('✅ Transfer complete!\n');

    // Step 9: Show gossip network stats
    const stats = gossip.getStats();
    console.log('Gossip Network Stats:');
    console.log(`   Nullifiers tracked: ${stats.nullifierCount}`);
    console.log(`   Total peers: ${stats.peerCount}`);
    console.log(`   Active peers: ${stats.activePeers}`);
  } else {
    console.log('❌ Transfer rejected!\n');
  }

  // Cleanup
  gossip.destroy();
}

// Run the example
basicTransfer().catch(console.error);
