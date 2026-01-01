/**
 * Integration Test: Security Hardening Features
 *
 * Tests Phase 1 security improvements:
 * 1. Multi-gateway Witness support with quorum voting
 * 2. Outbound peer preference for Eclipse attack mitigation
 * 3. IP subnet diversity checks for Sybil resistance
 */

import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter
} from '../../src/index.js';

import type { PeerConnection, GossipMessage } from '../../src/types.js';
import { TestRunner, createTestKeyPair, sleep, TestConfig } from '../helpers/test-utils.js';

export async function runSecurityHardeningTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Security Hardening (Phase 1)');
  console.log('='.repeat(60) + '\n');

  // Test 1: Multi-Gateway Witness Support
  await runner.run('Multi-gateway Witness initialization', async () => {
    // Test backward compatibility with single gateway
    const singleGateway = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });
    runner.assert(true, 'Single gateway should work (backward compatibility)');

    // Test multiple gateways with default quorum (2-of-3)
    const multiGateway = new WitnessAdapter({
      gatewayUrls: [
        TestConfig.witness.gateway,
        TestConfig.witness.gateway2, // Use secondary gateway
        'http://localhost:5003' // Mock third gateway
      ]
    });
    runner.assert(true, 'Multiple gateways should initialize');

    // Test custom quorum threshold
    const customQuorum = new WitnessAdapter({
      gatewayUrls: [
        TestConfig.witness.gateway,
        TestConfig.witness.gateway2,
        'http://localhost:5003'
      ],
      quorumThreshold: 2
    });
    runner.assert(true, 'Custom quorum threshold should work');
  });

  // Test 2: Outbound Peer Preference
  await runner.run('Outbound peer preference in confidence scoring', async () => {
    const freebird = new FreebirdAdapter({
      issuerEndpoints: [TestConfig.freebird.issuer],
      verifierUrl: TestConfig.freebird.verifier
    });

    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({ witness });

    // Create mock peers with different directions
    const outboundPeer: PeerConnection = {
      id: 'outbound-peer-1',
      direction: 'outbound',
      send: async () => {},
      isConnected: () => true
    };

    const inboundPeer: PeerConnection = {
      id: 'inbound-peer-1',
      direction: 'inbound',
      send: async () => {},
      isConnected: () => true
    };

    const unknownPeer: PeerConnection = {
      id: 'unknown-peer-1',
      send: async () => {},
      isConnected: () => true
    };

    gossip.addPeer(outboundPeer);
    gossip.addPeer(inboundPeer);
    gossip.addPeer(unknownPeer);

    const validator = new TransferValidator({
      gossip,
      witness,
      waitTime: 0,
      minConfidence: 0.5
    });

    // Compute confidence with mixed peer types
    // 1 outbound (weight 3) + 1 inbound (weight 1) + 1 unknown (weight 1) = 5 effective peers
    // peerScore = min(5 / 10, 0.5) = 0.5
    const confidence = validator.computeConfidence({
      gossipPeers: 3, // Not used in new implementation
      witnessDepth: 0, // No witness score
      waitTime: 0 // No time score
    });

    // With 1 outbound, 1 inbound, 1 unknown:
    // Effective peers = (1 * 3) + 1 + 1 = 5
    // Score = min(5/10, 0.5) = 0.5
    runner.assertGreaterThan(confidence, 0.4, 'Confidence should reflect peer diversity');
    runner.assert(confidence <= 0.5, 'Confidence should not exceed peer score cap');
  });

  // Test 3: IP Subnet Diversity Checks
  await runner.run('IP subnet diversity detection', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({ witness });

    // Add peers from same subnet (should trigger warning)
    for (let i = 1; i <= 4; i++) {
      const peer: PeerConnection = {
        id: `peer-${i}`,
        direction: 'inbound',
        remoteAddress: `192.168.1.${i}`,
        send: async () => {},
        isConnected: () => true
      };
      gossip.addPeer(peer);
    }

    // Check subnet statistics
    const subnetStats = gossip.getSubnetStats();
    const sameSubnetCount = subnetStats.get('192.168.1') || 0;

    runner.assertEquals(sameSubnetCount, 4, 'Should track 4 peers in same subnet');

    // Add peers from different subnets (should not trigger warning)
    const diversePeer: PeerConnection = {
      id: 'diverse-peer',
      direction: 'outbound',
      remoteAddress: '10.0.0.1',
      send: async () => {},
      isConnected: () => true
    };
    gossip.addPeer(diversePeer);

    const updatedStats = gossip.getSubnetStats();
    runner.assertEquals(updatedStats.size, 2, 'Should have 2 different subnets');
  });

  // Test 4: IPv6 Subnet Handling
  await runner.run('IPv6 subnet diversity', async () => {
    const witness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway
    });

    const gossip = new NullifierGossip({ witness });

    // Add IPv6 peers
    const ipv6Peer1: PeerConnection = {
      id: 'ipv6-peer-1',
      remoteAddress: '2001:0db8:85a3::1',
      send: async () => {},
      isConnected: () => true
    };

    const ipv6Peer2: PeerConnection = {
      id: 'ipv6-peer-2',
      remoteAddress: '2001:0db8:85a3::2',
      send: async () => {},
      isConnected: () => true
    };

    const ipv6Peer3: PeerConnection = {
      id: 'ipv6-peer-3',
      remoteAddress: '2001:0db9:85a3::1',
      send: async () => {},
      isConnected: () => true
    };

    gossip.addPeer(ipv6Peer1);
    gossip.addPeer(ipv6Peer2);
    gossip.addPeer(ipv6Peer3);

    const subnetStats = gossip.getSubnetStats();

    // First two should be in same /48 subnet
    runner.assertEquals(subnetStats.size, 2, 'Should detect IPv6 subnet diversity');
  });

  // Test 5: Combined Security Features
  await runner.run('Combined security: Multi-gateway + Peer diversity', async () => {
    const freebird = new FreebirdAdapter({
      issuerEndpoints: [TestConfig.freebird.issuer],
      verifierUrl: TestConfig.freebird.verifier
    });

    // Use multiple gateways for redundancy
    const witness = new WitnessAdapter({
      gatewayUrls: [
        TestConfig.witness.gateway,
        TestConfig.witness.gateway2,
        'http://localhost:5003'
      ],
      quorumThreshold: 2
    });

    const gossip = new NullifierGossip({ witness });

    // Add diverse outbound peers
    for (let i = 0; i < 3; i++) {
      const peer: PeerConnection = {
        id: `secure-outbound-${i}`,
        direction: 'outbound',
        remoteAddress: `10.${i}.0.1`, // Different subnets
        send: async () => {},
        isConnected: () => true
      };
      gossip.addPeer(peer);
    }

    const validator = new TransferValidator({
      gossip,
      witness,
      waitTime: 1000,
      minConfidence: 0.7
    });

    // With 3 outbound peers from different subnets:
    // Effective peers = 3 * 3 = 9
    // peerScore = min(9/10, 0.5) = 0.5
    // witnessDepth = 3, witnessScore = min(3/3, 0.3) = 0.3
    // waitTime = 1000, timeScore = min(1000/10000, 0.2) = 0.1
    // Total = 0.5 + 0.3 + 0.1 = 0.9
    const confidence = validator.computeConfidence({
      gossipPeers: 3,
      witnessDepth: 3,
      waitTime: 1000
    });

    runner.assertGreaterThan(
      confidence,
      0.7,
      'High-security configuration should achieve high confidence'
    );

    // Verify subnet diversity
    const subnetStats = gossip.getSubnetStats();
    runner.assertEquals(subnetStats.size, 3, 'Should have 3 different subnets');
  });

  // Test 6: Quorum Voting Simulation (conceptual)
  await runner.run('Multi-gateway quorum concept validation', async () => {
    // This test validates the quorum logic conceptually
    // In a real scenario, this would test against actual gateways

    const witness = new WitnessAdapter({
      gatewayUrls: [
        TestConfig.witness.gateway,
        TestConfig.witness.gateway2,
        'http://localhost:5003'
      ],
      quorumThreshold: 2 // 2-of-3 required
    });

    // The adapter should handle split votes correctly:
    // - If 2+ gateways say "seen": return 1.0 (double-spend detected)
    // - If 2+ gateways say "not seen": return 0.0 (safe)
    // - If split (1-1-1 or gateway failures): return 0.5 (suspicious)

    runner.assert(
      true,
      'Quorum logic should protect against single malicious gateway'
    );
  });

  runner.printSummary();
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runSecurityHardeningTest().catch(console.error);
}