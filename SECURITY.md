# Security Model

## Overview

Scarcity's security model protects against three categories of attacks:

1. **Double-spending** - Spending the same token twice
2. **Spam/DoS** - Flooding the network with garbage
3. **Censorship** - Hiding or refusing to process transactions

## Trust Assumptions

**You must trust:**

| Component | Trust Assumption | If Compromised |
|-----------|------------------|----------------|
| **Freebird Issuer** | Won't secretly mint tokens | Invisible inflation |
| **Witness Federation** | Threshold honest (e.g., 2-of-3) | Double-spend possible |
| **Your Peers** | At least some are honest | Eclipse attack possible |

**Important:** Scarcity has NO protection against a malicious Freebird issuer. A compromised issuer can mint unlimited tokens without detection. This is a fundamental limitation of the current architecture.

## Attack Vectors & Mitigations

### 1. Double-Spending

**Attack:** Spend the same token twice before the network detects it.

**Mitigations:**
- **Gossip propagation** - Nullifiers broadcast to all peers
- **Witness timestamping** - Authoritative ordering for disputes
- **Multi-gateway quorum** - Query multiple Witness gateways (2-of-3)
- **Wait time** - Higher confidence with longer wait

**Configuration:**
```typescript
const witness = new WitnessAdapter({
  gatewayUrls: ['https://w1.example.com', 'https://w2.example.com', 'https://w3.example.com'],
  quorumThreshold: 2  // Require 2-of-3 agreement
});

const validator = new TransferValidator({
  gossip,
  witness,
  waitTime: 5000,      // 5 second propagation wait
  minConfidence: 0.8   // Require 80% confidence
});
```

### 2. Nullifier Spam (DoS)

**Attack:** Flood the network with fake nullifiers to exhaust memory/CPU.

**Mitigations:**

| Layer | Mechanism | Effect |
|-------|-----------|--------|
| Network | Rate limiting (leaky bucket) | 10 msg/sec per peer |
| Network | Peer reputation scoring | Auto-disconnect bad peers |
| Validation | Timestamp windows | Reject future/expired nullifiers |
| Validation | Proof-of-work (optional) | Computational cost per message |
| Economic | Ownership proofs (optional) | Require valid Freebird token |

**Configuration:**
```typescript
const gossip = new NullifierGossip({
  witness,
  freebird,                      // Required if using ownership proofs
  peerScoreThreshold: -50,       // Disconnect below this score
  maxTimestampFuture: 5,         // Reject >5s in future
  maxNullifierAge: 86400000,     // Reject >24h old
  requireOwnershipProof: true    // Require Freebird ownership proof
});

const witness = new WitnessAdapter({
  gatewayUrl: 'https://witness.example.com',
  powDifficulty: 16              // 16-bit PoW (~50-200ms)
});
```

### 3. Eclipse Attack

**Attack:** Surround your node with malicious peers who lie about nullifier states.

**Mitigations:**
- **Outbound peer preference** - Connections YOU initiate weighted 3x higher
- **Subnet diversity warnings** - Alert when too many peers from same /24

**Configuration:**
```typescript
// Mark peer direction when adding
const peer: PeerConnection = {
  id: 'trusted-1',
  direction: 'outbound',        // YOU connected to them
  remoteAddress: '203.0.113.1',
  send: async (data) => { ... },
  isConnected: () => true
};

gossip.addPeer(peer);

// Monitor diversity
const subnetStats = gossip.getSubnetStats();
// Warns if >3 peers from same subnet
```

### 4. Gateway Censorship

**Attack:** Single Witness gateway hides double-spends or refuses timestamps.

**Mitigation:** Multi-gateway quorum queries multiple gateways in parallel.

```typescript
const witness = new WitnessAdapter({
  gatewayUrls: [
    'https://witness1.example.com',
    'https://witness2.example.com',
    'https://witness3.example.com'
  ],
  quorumThreshold: 2  // 2-of-3 must agree
});
```

**Behavior:**
- If 2+ say "seen" → Double-spend detected
- If 2+ say "not seen" → Safe to accept
- If split vote → Suspicious, possible attack (returns 0.5 confidence)

### 5. Inflation Attack

**Attack:** Compromised Freebird issuer mints unlimited tokens.

**Mitigation:** **NONE at Scarcity level.**

This is a fundamental limitation. The Freebird issuer holds the token issuance key. If compromised, they can mint tokens without detection.

**Potential future mitigations (not implemented):**
- Threshold issuance (split key across multiple servers)
- Auditable issuance logs
- Rate-limited issuance with public counters

For now, you must trust your Freebird issuer(s).

## Confidence Scoring

Transfer confidence is computed as:

```
confidence = peerScore + witnessScore + timeScore

peerScore   = min(effectivePeers / 10, 0.5)   // Up to 50%
witnessScore = min(witnessDepth / 3, 0.3)      // Up to 30%
timeScore   = min(waitTime / 10000, 0.2)       // Up to 20%

effectivePeers = (outbound × 3) + (inbound × 1)
```

**Example:**
- 3 outbound + 2 inbound peers = (3×3) + 2 = 11 effective
- peerScore = min(11/10, 0.5) = 0.5
- witnessDepth 2 = min(2/3, 0.3) = 0.2
- waitTime 5s = min(5000/10000, 0.2) = 0.1
- **Total: 0.8 confidence**

## Known Limitations

| Limitation | Impact | Status |
|------------|--------|--------|
| Freebird issuer trust | Inflation possible | No mitigation |
| Quantum computers | ECDLP broken | No mitigation |
| Traffic analysis | Timing correlation | Use Tor |
| Token theft | Bearer instrument | Secure your secrets |

## Peer Reputation Scoring

| Event | Score Change |
|-------|-------------|
| Valid message | +1 (max 100) |
| Invalid Witness proof | -10 |
| Duplicate nullifier | -1 |
| Expired timestamp | -2 |
| Future timestamp | -5 |
| Missing ownership proof | -5 |
| Invalid ownership proof | -8 |

Peers below `peerScoreThreshold` (default: -50) are disconnected.

## Security Contact

Report vulnerabilities: https://github.com/flammafex/scarcity/issues

Do not disclose publicly until addressed.
