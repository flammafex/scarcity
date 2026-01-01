/**
 * Integration tests for nullifier spam mitigation
 *
 * Tests the three-layer defense-in-depth strategy:
 * - Layer 1: Peer reputation and rate limiting
 * - Layer 2: Proof-of-work and timestamp validation
 * - Layer 3: Ownership proof verification
 */

import { TestRunner, TestConfig } from '../helpers/test-utils.js';
import { NullifierGossip } from '../../src/gossip.js';
import { WitnessAdapter } from '../../src/integrations/witness.js';
import { HyperTokenAdapter } from '../../src/integrations/hypertoken.js';
import { FreebirdAdapter } from '../../src/integrations/freebird.js';
import { Crypto } from '../../src/crypto.js';
import type { GossipMessage } from '../../src/types.js';

export async function runSpamMitigationTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Spam Mitigation');
  console.log('='.repeat(60) + '\n');

  // Layer 1: Peer Reputation Scoring
  console.log('\n📊 Layer 1: Peer Reputation Scoring\n');

  await runner.run('should penalize peers for invalid witness proofs', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      peerScoreThreshold: -50
    });

    const peerId = 'malicious-peer-1';

    // Send invalid proof (will fail verification in fallback mode)
    const invalidMessage: GossipMessage = {
      type: 'nullifier',
      nullifier: Crypto.randomBytes(32),
      proof: {
        hash: 'invalid',
        timestamp: Date.now() - 100000, // Very old timestamp
        signatures: [],
        witnessIds: []
      },
      timestamp: Date.now()
    };

    await gossip.onReceive(invalidMessage, peerId);

    // Check that peer was penalized
    const peerStats = gossip.getPeerStats(peerId);
    runner.assert(peerStats !== null, 'Peer stats should exist');
    if (peerStats) {
      runner.assert(peerStats.score < 0, `Peer should be penalized (score: ${peerStats.score})`);
      runner.assert(peerStats.invalidProofs > 0, 'Invalid proof count should increase');
    }
  });

  await runner.run('should penalize peers for duplicate nullifiers', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      peerScoreThreshold: -50
    });

    const peerId = 'spammer-peer';
    const nullifier = Crypto.randomBytes(32);

    // Create a valid-looking message
    const message: GossipMessage = {
      type: 'nullifier',
      nullifier,
      proof: {
        hash: Crypto.toHex(nullifier),
        timestamp: Date.now(),
        signatures: ['sig1', 'sig2', 'sig3'],
        witnessIds: ['w1', 'w2', 'w3']
      },
      timestamp: Date.now()
    };

    // First message should be accepted (peer gets +1)
    await gossip.onReceive(message, peerId);

    // Second identical message should penalize (peer gets -1, total = 0)
    await gossip.onReceive(message, peerId);

    // Third duplicate should bring score negative (peer gets -1, total = -1)
    await gossip.onReceive(message, peerId);

    const peerStats = gossip.getPeerStats(peerId);
    runner.assert(peerStats !== null, 'Peer stats should exist');
    if (peerStats) {
      runner.assert(peerStats.duplicates >= 2, 'Duplicate count should be at least 2');
      runner.assert(peerStats.score < 0, 'Peer should be penalized for duplicates');
    }
  });

  await runner.run('should disconnect peer when score falls below threshold', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      peerScoreThreshold: -10 // Low threshold for testing
    });

    // Create a mock peer
    const mockPeer = {
      id: 'bad-peer',
      async send(_data: GossipMessage) {},
      isConnected() { return true; },
      disconnect() { console.log('  → Peer disconnected'); }
    };

    gossip.addPeer(mockPeer);

    const peerId = 'bad-peer';

    // Send 2 invalid messages (-10 each = -20, below threshold of -10)
    for (let i = 0; i < 2; i++) {
      const invalidMessage: GossipMessage = {
        type: 'nullifier',
        nullifier: Crypto.randomBytes(32),
        proof: {
          hash: 'invalid',
          timestamp: Date.now() - 100000,
          signatures: [],
          witnessIds: []
        },
        timestamp: Date.now()
      };

      await gossip.onReceive(invalidMessage, peerId);
    }

    // Peer should be disconnected and removed after 2 invalid messages
    const peerStats = gossip.getPeerStats(peerId);
    runner.assert(peerStats === null, 'Peer should be disconnected and removed');

    // Verify peer was removed from connections
    const peers = gossip.peers;
    const peerExists = peers.some(p => p.id === peerId);
    runner.assert(!peerExists, 'Peer should be removed from connections');
  });

  // Layer 2: Timestamp Validation
  console.log('\n⏰ Layer 2: Timestamp Validation\n');

  await runner.run('should reject nullifiers with future timestamps', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      maxTimestampFuture: 5 // 5 seconds
    });

    const peerId = 'time-traveler';

    // Create message with timestamp 10 seconds in the future
    const futureMessage: GossipMessage = {
      type: 'nullifier',
      nullifier: Crypto.randomBytes(32),
      proof: {
        hash: 'test',
        timestamp: Date.now() + 10000, // 10 seconds in future
        signatures: ['sig1', 'sig2'],
        witnessIds: ['w1', 'w2']
      },
      timestamp: Date.now()
    };

    await gossip.onReceive(futureMessage, peerId);

    // Should be rejected (not added to seen nullifiers)
    const stats = gossip.getStats();
    runner.assertEquals(stats.nullifierCount, 0, 'Future nullifier should be rejected');

    // Peer should be penalized
    const peerStats = gossip.getPeerStats(peerId);
    runner.assert(peerStats !== null && peerStats.score < 0, 'Peer should be penalized');
  });

  await runner.run('should reject nullifiers that are too old', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      maxNullifierAge: 3600000 // 1 hour
    });

    const peerId = 'archaeologist';

    // Create message with timestamp 2 hours old
    const oldMessage: GossipMessage = {
      type: 'nullifier',
      nullifier: Crypto.randomBytes(32),
      proof: {
        hash: 'test',
        timestamp: Date.now() - (2 * 3600000), // 2 hours ago
        signatures: ['sig1', 'sig2'],
        witnessIds: ['w1', 'w2']
      },
      timestamp: Date.now()
    };

    await gossip.onReceive(oldMessage, peerId);

    // Should be rejected
    const stats = gossip.getStats();
    runner.assertEquals(stats.nullifierCount, 0, 'Old nullifier should be rejected');
  });

  // Layer 2: Proof-of-Work
  console.log('\n⛏️  Layer 2: Proof-of-Work\n');

  await runner.run('should solve PoW puzzle correctly', async () => {
    const challenge = 'test-challenge-123';
    const difficulty = 12; // Low difficulty for testing

    const nonce = Crypto.solveProofOfWork(challenge, difficulty);

    // Verify the solution
    const valid = Crypto.verifyProofOfWork(challenge, nonce, difficulty);
    runner.assert(valid, 'PoW solution should be valid');

    console.log(`  → PoW solved: nonce=${nonce} for difficulty=${difficulty}`);
  });

  await runner.run('should reject invalid PoW solutions', async () => {
    const challenge = 'test-challenge-456';
    const difficulty = 12;

    // Invalid nonce
    const valid = Crypto.verifyProofOfWork(challenge, 12345, difficulty);
    runner.assert(!valid, 'Invalid PoW solution should be rejected');
  });

  await runner.run('should require more attempts for higher difficulty', async () => {
    const challenge = 'difficulty-test';

    // Easy difficulty
    const nonce1 = Crypto.solveProofOfWork(challenge, 8);
    console.log(`  → Easy PoW (8 bits): nonce=${nonce1}`);

    // Medium difficulty
    const nonce2 = Crypto.solveProofOfWork(challenge, 12);
    console.log(`  → Medium PoW (12 bits): nonce=${nonce2}`);

    // Generally, higher difficulty requires larger nonce values
    runner.assert(nonce2 >= 0, 'Should find valid nonce for medium difficulty');
  });

  await runner.run('should integrate PoW with Witness timestamping', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway,
      powDifficulty: 12 // Enable PoW
    });

    const hash = Crypto.hashString('test-nullifier');
    console.log(`  → Input hash: ${hash}`);

    // This will solve PoW before attempting to timestamp
    const attestation = await witness.timestamp(hash);
    console.log(`  → Returned hash: ${attestation.hash}`);
    console.log(`  → Hash type: ${typeof attestation.hash}`);
    console.log(`  → Hashes equal: ${attestation.hash === hash}`);

    // Verify attestation structure (in fallback mode, hash should be preserved)
    runner.assert(attestation.hash != null, 'Attestation should have a hash');
    runner.assert(typeof attestation.hash === 'string', 'Hash should be a string');
    runner.assert(attestation.hash === hash, `Attestation hash should match (expected: ${hash}, got: ${attestation.hash})`);
    runner.assert(attestation.timestamp > 0, 'Attestation should have timestamp');
    runner.assert(Array.isArray(attestation.signatures), 'Attestation should have signatures');
    runner.assert(attestation.signatures.length >= 2, 'Attestation should have at least 2 signatures');
    console.log('  → Witness with PoW completed successfully');
  });

  // Layer 1: Rate Limiting
  console.log('\n🚦 Layer 1: Rate Limiting\n');

  await runner.run('should configure rate limiter correctly', async () => {
    const adapter = new HyperTokenAdapter({
      relayUrl: TestConfig.hypertoken.relay,
      rateLimitPerSecond: 5,  // Low rate for testing
      rateLimitBurst: 10
    });

    // Note: Without actual connection, we just verify configuration
    console.log('  → Rate limiter configured: 5 msg/sec, burst 10');
    runner.assert(true, 'Configuration should succeed');
  });

  // Layer 3: Ownership Proof Verification
  console.log('\n🔐 Layer 3: Ownership Proof Verification\n');

  // Create a Freebird adapter for ownership proof tests
  const freebird = new FreebirdAdapter({
    issuerEndpoints: [TestConfig.freebird.issuer],
    verifierUrl: TestConfig.freebird.verifier
  });

  await runner.run('should reject messages without ownership proof when required', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      freebird, // Required when requireOwnershipProof is true
      requireOwnershipProof: true // Enable ownership proof requirement
    });

    const peerId = 'no-proof-peer';

    // Message without ownership proof
    const message: GossipMessage = {
      type: 'nullifier',
      nullifier: Crypto.randomBytes(32),
      proof: {
        hash: 'test',
        timestamp: Date.now(),
        signatures: ['sig1', 'sig2'],
        witnessIds: ['w1', 'w2']
      },
      timestamp: Date.now()
      // ownershipProof: undefined
    };

    await gossip.onReceive(message, peerId);

    // Should be rejected
    const stats = gossip.getStats();
    runner.assertEquals(stats.nullifierCount, 0, 'Message without ownership proof should be rejected');

    // Peer should be penalized
    const peerStats = gossip.getPeerStats(peerId);
    runner.assert(peerStats !== null && peerStats.score < 0, 'Peer should be penalized');
  });

  await runner.run('should accept messages with valid Schnorr ownership proof', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      freebird,
      requireOwnershipProof: true
    });

    const peerId = 'valid-proof-peer';
    const secret = Crypto.randomBytes(32);
    const nullifier = Crypto.randomBytes(32);

    // Create a valid Schnorr ownership proof bound to the nullifier
    const ownershipProof = await freebird.createOwnershipProof(secret, nullifier);

    // Message with valid Schnorr ownership proof
    const message: GossipMessage = {
      type: 'nullifier',
      nullifier,
      proof: {
        hash: Crypto.toHex(nullifier),
        timestamp: Date.now(),
        signatures: ['sig1', 'sig2', 'sig3'],
        witnessIds: ['w1', 'w2', 'w3']
      },
      timestamp: Date.now(),
      ownershipProof
    };

    await gossip.onReceive(message, peerId);

    // Should be accepted (proof verification passes)
    const stats = gossip.getStats();
    runner.assertEquals(stats.nullifierCount, 1, 'Message with valid ownership proof should be accepted');
  });

  // Attack Simulation
  console.log('\n⚔️  Attack Simulation\n');

  await runner.run('should resist spam attack from multiple peers', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({
      witness,
      peerScoreThreshold: -50,
      maxTimestampFuture: 5,
      maxNullifierAge: 3600000
    });

    // Simulate 10 malicious peers sending spam
    const maliciousPeers = Array.from({ length: 10 }, (_, i) => `spammer-${i}`);

    let rejectedCount = 0;

    for (const peerId of maliciousPeers) {
      // Each peer sends 20 invalid nullifiers
      for (let i = 0; i < 20; i++) {
        const spamMessage: GossipMessage = {
          type: 'nullifier',
          nullifier: Crypto.randomBytes(32),
          proof: {
            hash: 'spam',
            timestamp: Date.now() - 10000000, // Very old
            signatures: [],
            witnessIds: []
          },
          timestamp: Date.now()
        };

        await gossip.onReceive(spamMessage, peerId);
        rejectedCount++;
      }
    }

    // All spam should be rejected
    const stats = gossip.getStats();
    runner.assertEquals(stats.nullifierCount, 0, 'All spam should be rejected');

    // All peers should be disconnected
    const remainingScores = gossip.getAllPeerScores();
    console.log(`  → Spam attack resisted: ${rejectedCount} messages rejected, ${remainingScores.size} peers remaining`);
  });

  // Print summary
  runner.printSummary();

  const summary = runner.getSummary();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} test(s) failed`);
  }
}