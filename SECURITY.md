# Security Model: Nullifier Spam Mitigation

## Vulnerability Overview

**Attack Vector**: Generating random 32-byte strings (fake nullifiers) is computationally free, but storing them in RAM (`seenNullifiers`) costs resources. An attacker could flood the gossip network with invalid nullifiers to exhaust validator memory and CPU resources, causing denial of service.

**Impact**:
- Memory exhaustion (unbounded `seenNullifiers` map growth)
- CPU exhaustion (expensive Witness proof verification for spam)
- Network degradation (bandwidth consumed by invalid messages)

## Defense-in-Depth Strategy

Scarcity implements a **three-layer defense** against nullifier spam attacks, moving from the network layer up to the economic layer:

### Layer 1: HyperToken (Network Layer)

**Peer Reputation & Throttling** - First line of defense at the P2P connection layer.

#### 1.1 Peer Reputation Scoring

Located in: `src/gossip.ts`

Each peer is assigned a reputation score that tracks their behavior:

- **Starting score**: 0
- **Invalid Witness proof**: -10 points (heavy penalty)
- **Duplicate spam**: -1 point per duplicate
- **Expired nullifiers**: -2 points
- **Future timestamps**: -5 points
- **Valid messages**: +1 point (capped at 100)

When a peer's score drops below the threshold (default: -50), they are **automatically disconnected**.

```typescript
// Configuration
const gossip = new NullifierGossip({
  witness,
  peerScoreThreshold: -50,  // Disconnect threshold
  // ... other options
});

// Monitor peer reputation
const peerStats = gossip.getPeerStats(peerId);
console.log(peerStats); // { score, invalidProofs, duplicates, validMessages }
```

**Benefits**:
- Prevents malicious peers from continuously flooding the network
- Low-cost rejection of known bad actors
- Incentivizes honest behavior

#### 1.2 End-to-End Encryption

Located in: `src/vendor/hypertoken/E2EEncryption.ts`

All peer communication is encrypted using **ECDH key exchange + AES-256-GCM**:

- **Key Exchange**: ECDH with P-256 curve establishes shared secret
- **Encryption**: AES-256-GCM for authenticated encryption
- **Mandatory**: Messages cannot be sent without an established E2E session

```typescript
// E2E encryption is automatic and mandatory
// Messages are encrypted before sending, decrypted on receipt
// No configuration needed - enforced by HyperTokenAdapter
```

**Benefits**:
- Relay servers cannot read message content
- Protects against man-in-the-middle attacks
- Prevents traffic analysis of message payloads

#### 1.3 Rate Limiting (Leaky Bucket)

Located in: `src/integrations/hypertoken.ts`

Each peer connection has an independent **leaky bucket** rate limiter:

- **Default rate**: 10 messages/second per peer
- **Burst capacity**: 20 messages
- **Behavior**: Silently drops messages exceeding the limit

```typescript
const adapter = new HyperTokenAdapter({
  relayUrl: 'ws://localhost:8080',
  rateLimitPerSecond: 10,  // Refill rate
  rateLimitBurst: 20       // Bucket capacity
});

// Monitor rate limiting
const peer = adapter.createPeer(peerId);
const stats = peer.getRateLimitStats();
console.log(stats); // { droppedMessages, currentTokens }
```

**Benefits**:
- Prevents single malicious node from overwhelming CPU
- Graceful degradation under load
- No configuration required for honest peers

**How it works**:
1. Each peer starts with a full bucket (20 tokens)
2. Each message consumes 1 token
3. Tokens refill at 10/second
4. Messages received when bucket is empty are dropped

---

### Layer 2: Witness (Validation Layer)

**Proof-of-Work & Timestamp Validation** - Computational "tolls" and strict timestamp windows.

#### 2.1 Client Proof-of-Work Puzzles

Located in: `src/integrations/witness.ts`, `src/crypto.ts`

Before the Witness timestamps a nullifier, the client must solve a **computational puzzle**:

- Find a nonce such that `Hash(nullifier + nonce)` has N leading zero bits
- **Default difficulty**: 0 (disabled, for backward compatibility)
- **Recommended**: 16 bits = ~65,000 attempts (~50-200ms on modern hardware)
- **High security**: 20 bits = ~1,000,000 attempts (~5-10 seconds)

```typescript
const witness = new WitnessAdapter({
  gatewayUrl: 'https://witness.example.com',
  powDifficulty: 16  // 16 leading zero bits
});

// When you call timestamp(), it automatically solves the PoW
const proof = await witness.timestamp(nullifierHash);
// Output: [Witness] PoW solved in 87ms (difficulty: 16, nonce: 54321)
```

**Benefits**:
- Imposes computation cost on spammer (generating 1M fake nullifiers becomes expensive)
- Legitimate users barely notice the delay (< 100ms typical)
- Tunable difficulty based on threat level

**Implementation**: Uses SHA-256 mining algorithm similar to Bitcoin, but with much lower difficulty.

#### 2.2 Strict Timestamp Windows

Located in: `src/gossip.ts`

The gossip layer enforces **strict acceptance windows** for Witness timestamps:

- **Future timestamps**: Reject if > 5 seconds in the future (prevents pre-mining spam)
- **Old timestamps**: Reject if older than `maxNullifierAge` (default: ~1.5 years)
- **Early rejection**: Invalid timestamps are rejected **before** verifying the expensive Witness signature

```typescript
const gossip = new NullifierGossip({
  witness,
  maxTimestampFuture: 5,        // Max 5 seconds in future
  maxNullifierAge: 86400000     // Max age: 24 hours
});
```

**Benefits**:
- Saves CPU by rejecting obviously invalid nullifiers early
- Prevents attackers from pre-generating spam with future timestamps
- Prevents replay attacks with old nullifiers

---

### Layer 3: Freebird (Economic Layer)

**Sybil Resistance** - The root solution that makes spam economically infeasible.

#### 3.1 Token-Based Nullifier Generation

A valid nullifier is derived from a **valid Token ID and Secret**:

```
nullifier = Hash(secret || tokenId || timestamp)
```

To generate a valid nullifier that passes Witness verification, an attacker needs:
1. A valid token from Freebird (requires passing Sybil resistance)
2. Knowledge of the token's secret (obtained via VOPRF)

**Benefits**:
- Attacker cannot easily get 1 million tokens from Freebird
- Rate limiting or invitation-only issuance on Freebird server prevents mass token acquisition
- Economic cost scales linearly with spam volume

#### 3.2 Ownership Proof Verification (Optional)

Located in: `src/gossip.ts`

For **maximum spam resistance**, you can require every nullifier message to include a **Freebird Ownership Proof**:

```typescript
const gossip = new NullifierGossip({
  witness,
  requireOwnershipProof: true  // Enforce ownership proofs
});
```

**How it works**:
- Each gossip message must include `ownershipProof` (cryptographic proof of token ownership)
- Attacker must perform expensive VOPRF operation for each spam message
- Significantly slower than just generating random hashes

**Benefits**:
- Forces attacker to use valid Freebird tokens for spam
- Makes spam **as expensive as legitimate transfers**
- Reduces spam to economic denial-of-service (which is rate-limited by Freebird)

**Trade-off**: Increases bandwidth and verification overhead for all messages. Recommended only for high-security deployments.

#### 3.3 Combined Sybil Resistance (Recommended)

Freebird supports multiple Sybil resistance mechanisms that can be combined for defense-in-depth.

**Recommended configuration:**

```bash
# Docker environment variables for Freebird issuer
SYBIL_RESISTANCE=combined
SYBIL_COMBINED_MODE=and
SYBIL_COMBINED_MECHANISMS=progressive_trust,proof_of_diversity
```

**Mechanisms:**

| Mechanism | Description |
|-----------|-------------|
| `progressive_trust` | New users start with limited issuance, limits increase over time |
| `proof_of_diversity` | Requires proof of unique identity signals (device, network, behavior) |

**Combined mode `and`**: User must satisfy ALL mechanisms to receive tokens. This provides layered protection:

1. **Progressive trust** prevents burst attacks from new identities
2. **Proof of diversity** prevents Sybil attacks from single actors with many identities

**Why this matters for Scarcity:**
- Token issuance is the economic root of the system
- Unlimited issuance would enable spam attacks and inflation
- Combined resistance makes mass token acquisition prohibitively difficult

**Alternative modes:**
- `or`: User satisfies ANY mechanism (more permissive)
- `and`: User satisfies ALL mechanisms (more restrictive, recommended)

---

## Configuration Examples

### Minimal Protection (Low-threat environments)

```typescript
// Basic rate limiting only
const gossip = new NullifierGossip({
  witness: new WitnessAdapter({ gatewayUrl: '...' }),
  peerScoreThreshold: -50
});

const adapter = new HyperTokenAdapter({
  rateLimitPerSecond: 10,
  rateLimitBurst: 20
});
```

### Balanced Protection (Recommended)

```typescript
// All layers except ownership proofs
const gossip = new NullifierGossip({
  witness: new WitnessAdapter({
    gatewayUrl: '...',
    powDifficulty: 16  // ~65k attempts
  }),
  peerScoreThreshold: -50,
  maxTimestampFuture: 5,
  maxNullifierAge: 86400000  // 24 hours
});

const adapter = new HyperTokenAdapter({
  rateLimitPerSecond: 10,
  rateLimitBurst: 20
});
```

### Maximum Protection (High-security deployments)

```typescript
// All layers including ownership proofs
const gossip = new NullifierGossip({
  witness: new WitnessAdapter({
    gatewayUrl: '...',
    powDifficulty: 20  // ~1M attempts, ~5-10 seconds
  }),
  peerScoreThreshold: -30,      // Stricter threshold
  maxTimestampFuture: 2,        // Tighter window
  maxNullifierAge: 3600000,     // 1 hour max age
  requireOwnershipProof: true   // Mandatory ownership proofs
});

const adapter = new HyperTokenAdapter({
  rateLimitPerSecond: 5,   // Lower rate limit
  rateLimitBurst: 10       // Lower burst
});
```

---

## Attack Cost Analysis

### Without Mitigations
- **Cost to generate 1M fake nullifiers**: ~0 (just random bytes)
- **Validator impact**: Memory exhaustion, crash

### With Layer 1 (Network)
- **Cost**: Attacker needs to create multiple peer identities
- **Limit**: 10 msg/sec/peer × N peers
- **Result**: Significantly slows attack, but still possible with Sybil network

### With Layer 1 + 2 (Network + Validation)
- **Cost**: 1M nullifiers × 50ms PoW = ~14 hours of computation
- **Limit**: Rate limiting + computational cost
- **Result**: Attack becomes expensive and slow

### With All Layers (Network + Validation + Economic)
- **Cost**: Attacker needs 1M valid Freebird tokens + PoW computation
- **Limit**: Freebird Sybil resistance limits token acquisition
- **Result**: Attack becomes economically infeasible

---

## Monitoring & Metrics

### Track peer reputation:
```typescript
const allScores = gossip.getAllPeerScores();
for (const [peerId, score] of allScores) {
  console.log(`${peerId}: ${score.score} (invalid: ${score.invalidProofs}, dupes: ${score.duplicates})`);
}
```

### Monitor rate limiting:
```typescript
for (const peer of adapter.getPeers()) {
  const stats = peer.getRateLimitStats();
  console.log(`${peer.id}: dropped ${stats.droppedMessages}, tokens: ${stats.currentTokens}`);
}
```

### Track gossip health:
```typescript
const stats = gossip.getStats();
console.log(`Nullifiers: ${stats.nullifierCount}, Peers: ${stats.peerCount}, Active: ${stats.activePeers}`);
```

---

## Future Enhancements

1. **Adaptive PoW Difficulty**: Automatically increase difficulty during attack
2. **Peer Reputation Persistence**: Save scores across restarts
3. **Distributed Banlist**: Share malicious peer IDs across network
4. **Freebird Rate Limiting Integration**: Query Freebird for token issuance rate
5. **Machine Learning**: Detect spam patterns using ML

---

## References

- **Leaky Bucket Algorithm**: https://en.wikipedia.org/wiki/Leaky_bucket
- **Proof-of-Work**: https://en.wikipedia.org/wiki/Proof_of_work
- **Sybil Resistance**: Freebird whitepaper (see `README.md`)
- **P2P Reputation Systems**: https://dl.acm.org/doi/10.1145/1030194.1015504

---

# Phase 1 Security Hardening: Integrity & Trust

While the spam mitigation measures above protect against **Availability** attacks (DoS/crashes), the following features address **Integrity** and **Trust** vulnerabilities that could enable theft, double-spending, or undetected inflation.

## 1. Multi-Gateway Witness Support (Anti-Censorship)

**Vulnerability**: Single gateway operator could perform targeted censorship or split-view attacks by returning false 404 responses for nullifiers that exist.

**Solution**: Query multiple independent gateways with quorum voting.

### Configuration

```typescript
// Backward compatible: single gateway
const witness = new WitnessAdapter({
  gatewayUrl: 'https://witness1.example.com'
});

// Multi-gateway with 2-of-3 quorum (recommended)
const witness = new WitnessAdapter({
  gatewayUrls: [
    'https://witness1.example.com',
    'https://witness2.example.com',
    'https://witness3.example.com'
  ],
  quorumThreshold: 2  // Require 2 gateways to agree
});

// Custom quorum (e.g., 3-of-5)
const witness = new WitnessAdapter({
  gatewayUrls: [
    'https://witness1.example.com',
    'https://witness2.example.com',
    'https://witness3.example.com',
    'https://witness4.example.com',
    'https://witness5.example.com'
  ],
  quorumThreshold: 3
});
```

### How It Works

When checking if a nullifier has been seen:

1. **Query All Gateways**: Queries all configured gateways in parallel
2. **Quorum Voting**:
   - If ≥ quorum say "seen" → Return 1.0 (double-spend detected)
   - If ≥ quorum say "not seen" → Return 0.0 (safe to accept)
   - If split vote or insufficient responses → Return 0.5 (suspicious, possible censorship attack)

### Benefits

- **Censorship Resistance**: Single malicious gateway cannot hide double-spends
- **Availability**: Continues working if some gateways are down
- **Split-View Detection**: Warns when gateways disagree (possible attack)

### Example Output

```
[Witness] Configured with 3 gateway(s), quorum threshold: 2
[Witness] Nullifier check: 0/3 gateways report seen (quorum: 2)
✅ Safe: Quorum agrees nullifier has NOT been seen

[Witness] Nullifier check: 3/3 gateways report seen (quorum: 2)
❌ Double-spend: Quorum agrees nullifier HAS been seen

[Witness] Nullifier check: 1/3 gateways report seen (quorum: 2)
⚠️ Suspicious: Split vote on nullifier check - possible censorship attack
```

---

## 2. Outbound Peer Preference (Anti-Eclipse)

**Vulnerability**: Attackers can easily connect TO you (inbound connections) and surround your node with malicious peers, creating a "reality bubble" where they lie about nullifier states.

**Solution**: Weight outbound peers (connections YOU initiated) 3x higher in confidence scoring.

### Configuration

Peers now support optional `direction` and `remoteAddress` tracking:

```typescript
// When adding peers, specify connection direction
const outboundPeer: PeerConnection = {
  id: 'trusted-peer-1',
  direction: 'outbound',  // YOU initiated this connection
  remoteAddress: '203.0.113.1',
  send: async (data) => { /* ... */ },
  isConnected: () => true
};

const inboundPeer: PeerConnection = {
  id: 'unknown-peer-1',
  direction: 'inbound',  // They connected to YOU
  remoteAddress: '198.51.100.1',
  send: async (data) => { /* ... */ },
  isConnected: () => true
};

gossip.addPeer(outboundPeer);
gossip.addPeer(inboundPeer);
```

### How It Works

The validator's confidence scoring now uses **effective peer count**:

```
Effective Peers = (Outbound × 3) + (Inbound × 1) + (Unknown × 1)
```

**Example**:
- 2 outbound peers + 3 inbound peers = (2×3) + 3 = **9 effective peers**
- 0 outbound peers + 9 inbound peers = (0×3) + 9 = **9 effective peers**

But the first scenario is **more secure** because outbound peers are more trustworthy.

### Benefits

- **Eclipse Resistance**: Attackers cannot easily surround your node
- **Trust Asymmetry**: Recognizes that outbound connections are inherently more trustworthy
- **Backward Compatible**: Works with peers that don't specify direction (treated as inbound for safety)

### Confidence Scoring Impact

```typescript
const validator = new TransferValidator({ gossip, witness });

// Scenario 1: Mixed peers (3 outbound, 2 inbound)
// Effective = (3×3) + 2 = 11
// peerScore = min(11/10, 0.5) = 0.5 ✅

// Scenario 2: All inbound (0 outbound, 11 inbound)
// Effective = (0×3) + 11 = 11
// peerScore = min(11/10, 0.5) = 0.5 ⚠️ (but less trustworthy)

// Scenario 3: All outbound (4 outbound, 0 inbound)
// Effective = (4×3) + 0 = 12
// peerScore = min(12/10, 0.5) = 0.5 ✅✅ (high trust)
```

---

## 3. IP Subnet Diversity Checks (Anti-Sybil)

**Vulnerability**: Attacker controls 20 nodes on same /24 subnet (e.g., rented VPS instances). All report "never seen it" for a double-spent nullifier.

**Solution**: Track and warn about peers from the same IP subnet.

### How It Works

```typescript
const gossip = new NullifierGossip({ witness });

// Add peers from diverse subnets (good)
gossip.addPeer({ id: 'peer-1', remoteAddress: '203.0.113.1', ... });
gossip.addPeer({ id: 'peer-2', remoteAddress: '198.51.100.1', ... });
gossip.addPeer({ id: 'peer-3', remoteAddress: '192.0.2.1', ... });

// Add 4th peer from same subnet as peer-1 (triggers warning)
gossip.addPeer({ id: 'peer-4', remoteAddress: '203.0.113.5', ... });
// Output:
// ⚠️ [Gossip] Warning: 4 peers from subnet 203.0.113.
//    Possible Sybil attack. Consider limiting connections from same subnet.

// Check subnet diversity
const subnetStats = gossip.getSubnetStats();
console.log(subnetStats);
// Map { '203.0.113' => 2, '198.51.100' => 1, '192.0.2' => 1 }
```

### Configuration

The maximum peers per subnet is currently hardcoded to **3**, but can be adjusted in `src/gossip.ts`:

```typescript
// In addPeer method
const MAX_PEERS_PER_SUBNET = 3;  // Adjust as needed
```

### Subnet Detection

- **IPv4**: First 3 octets (e.g., `192.168.1.x` → subnet `192.168.1`)
- **IPv6**: First 3 groups (e.g., `2001:db8:85a3::x` → subnet `2001:db8:85a3`)

### Benefits

- **Sybil Detection**: Warns when too many peers come from same network
- **Operational Visibility**: Helps operators identify potential attacks
- **Non-Breaking**: Still accepts the peer, just logs a warning

### Monitoring

```typescript
// Get subnet diversity statistics
const stats = gossip.getSubnetStats();

for (const [subnet, count] of stats) {
  if (count > 3) {
    console.warn(`⚠️ ${count} peers from subnet ${subnet} - investigate`);
  }
}

// Example output:
// ⚠️ 5 peers from subnet 192.168.1 - investigate
// ✅ 2 peers from subnet 10.0.0
// ✅ 1 peer from subnet 203.0.113
```

---

## 4. MPC Threshold Issuance (Anti-Inflation)

**Vulnerability**: Without a public ledger, there's no way to audit total supply. A compromised Freebird issuer key could mint unlimited tokens, causing "invisible inflation" undetectable by users.

**Solution**: Multi-Party Computation (MPC) threshold issuance splits the issuer key across multiple servers. Clients aggregate partial signatures locally using Lagrange interpolation.

### Configuration

```typescript
// Single issuer (backward compatible, no MPC)
const freebird = new FreebirdAdapter({
  issuerEndpoints: ['https://issuer.example.com'],
  verifierUrl: 'https://verifier.example.com'
});

// Multi-issuer MPC with 3 servers (recommended)
const freebird = new FreebirdAdapter({
  issuerEndpoints: [
    'https://issuer1.example.com',
    'https://issuer2.example.com',
    'https://issuer3.example.com'
  ],
  verifierUrl: 'https://verifier.example.com'
});

// High-security: 5-of-5 threshold
const freebird = new FreebirdAdapter({
  issuerEndpoints: [
    'https://issuer1.example.com',
    'https://issuer2.example.com',
    'https://issuer3.example.com',
    'https://issuer4.example.com',
    'https://issuer5.example.com'
  ],
  verifierUrl: 'https://verifier.example.com'
});
```

### How It Works

**Trusted Dealer Setup** (Phase 1 implementation):
1. Key dealer splits issuer secret key k into shares: k₁, k₂, k₃
2. Each server receives one share
3. Shares satisfy: k = λ₁·k₁ + λ₂·k₂ + λ₃·k₃ (where λᵢ are Lagrange coefficients)

**Token Issuance Flow**:
1. **Client**: Blinds recipient public key → A = H(pubkey) · r
2. **Broadcast**: Sends blinded element to all issuers in parallel
3. **Issuers**: Each server i computes partial signature Bᵢ = A · kᵢ
4. **Verify**: Client verifies DLEQ proof for each partial signature
5. **Threshold**: Client waits for majority (⌈n/2⌉) valid responses
6. **Aggregate**: Client computes final signature using Lagrange interpolation:
   ```
   B = Σ(λᵢ · Bᵢ)  where λᵢ = ∏(j≠i) (xⱼ / (xⱼ - xᵢ)) mod N
   ```
7. **Finalize**: Client uses aggregated B as the final token

### Cryptographic Properties

**P-256 VOPRF with Threshold Cryptography**:
- Each issuer has key share kᵢ, public key Qᵢ = G · kᵢ
- Partial evaluation: Bᵢ = A · kᵢ (where A is blinded element)
- DLEQ proof proves: log_G(Qᵢ) = log_A(Bᵢ)
- Aggregation uses Lagrange interpolation in scalar field mod N
- Final point: B = A · k (where k = Σλᵢ·kᵢ)

**Security Guarantees**:
- **Byzantine Fault Tolerance**: Tolerates up to ⌊n/2⌋ malicious servers
- **No Single Point of Failure**: No single server can inflate supply alone
- **Immediate Verification**: Each partial signature verified with DLEQ proof
- **Privacy Preserved**: Client aggregates locally without revealing input
- **Backward Compatible**: Single issuer works as before (no aggregation)

### Benefits

✅ **Inflation Resistance**: Requires collusion of multiple servers to inflate supply
✅ **Fault Tolerance**: Continues working if some servers are offline
✅ **Proof Verification**: Invalid partial signatures detected immediately
✅ **Local Aggregation**: Client controls the final token construction
✅ **Graceful Degradation**: Warns when below threshold but proceeds with available responses

### Example Output

```
[Freebird] MPC threshold mode: 3 issuers
[Freebird] Connected to 3/3 issuers
[Freebird] Nullifier check: Broadcasting to 3 issuers...
[Freebird] ✅ VOPRF token issued and aggregated (3/3 issuers)
```

**Warning output when below threshold:**
```
[Freebird] MPC threshold mode: 3 issuers
[Freebird] Connected to 2/3 issuers
[Freebird] ⚠️ Only 2/3 valid responses, threshold is 2. Proceeding with available responses.
[Freebird] ✅ VOPRF token issued and aggregated (2/3 issuers)
```

### Server Response Format

Each issuer returns:
```json
{
  "token": "base64url_encoded_token",
  "index": 1  // Server's key share index (1-based)
}
```

The token format is: `[ A (33 bytes) | Bᵢ (33 bytes) | DLEQ Proof (64 bytes) ]`

---

## Combined Security: Best Practices

### High-Security Configuration

Combine all Phase 1 hardening features:

```typescript
// 1. Multi-gateway Witness with quorum
const witness = new WitnessAdapter({
  gatewayUrls: [
    'https://witness1.example.com',
    'https://witness2.example.com',
    'https://witness3.example.com'
  ],
  quorumThreshold: 2,
  powDifficulty: 16  // Also use PoW from spam mitigation
});

// 2. Gossip with peer diversity tracking
const gossip = new NullifierGossip({
  witness,
  peerScoreThreshold: -50,
  maxTimestampFuture: 5,
  maxNullifierAge: 86400000
});

// 3. Add diverse outbound peers
const outboundPeers = [
  { id: 'peer-1', direction: 'outbound', remoteAddress: '203.0.113.1' },
  { id: 'peer-2', direction: 'outbound', remoteAddress: '198.51.100.1' },
  { id: 'peer-3', direction: 'outbound', remoteAddress: '192.0.2.1' }
];

for (const peer of outboundPeers) {
  gossip.addPeer(createPeerConnection(peer));
}

// 4. Validator with high confidence threshold
const validator = new TransferValidator({
  gossip,
  witness,
  waitTime: 5000,
  minConfidence: 0.8  // High threshold for security
});

// Result: System resistant to:
// ✅ Gateway censorship (multi-gateway quorum)
// ✅ Eclipse attacks (outbound peer preference)
// ✅ Sybil attacks (subnet diversity + peer scoring)
// ✅ Spam attacks (PoW + rate limiting from previous layers)
// ✅ Invisible inflation (MPC threshold issuance)
```

### Security Monitoring

```typescript
// Monitor all security dimensions
setInterval(() => {
  // 1. Peer diversity
  const subnetStats = gossip.getSubnetStats();
  console.log('Subnet diversity:', subnetStats.size);

  // 2. Peer direction mix
  const peers = gossip.peers;
  const outbound = peers.filter(p => p.direction === 'outbound').length;
  const inbound = peers.filter(p => p.direction === 'inbound').length;
  console.log(`Peers: ${outbound} outbound, ${inbound} inbound`);

  // 3. Peer reputation
  const scores = gossip.getAllPeerScores();
  const lowScorePeers = Array.from(scores.entries())
    .filter(([_, score]) => score.score < -20);
  if (lowScorePeers.length > 0) {
    console.warn('Peers with low reputation:', lowScorePeers);
  }

  // 4. Gateway availability (conceptual - depends on monitoring implementation)
  // Check if all gateways are reachable
}, 60000);  // Every minute
```

---

## Known Limitations & Future Work

### Limitations Addressed

✅ **Single Point of Failure (Gateway)**: Solved with multi-gateway quorum
✅ **Eclipse Attack (Gossip Layer)**: Mitigated with outbound peer preference
✅ **Sybil Attack (Gossip Layer)**: Partially mitigated with subnet diversity checks
✅ **Invisible Inflation (Economic Layer)**: Solved with MPC threshold issuance

### Remaining Challenges

These require more complex solutions and are documented for future development:

#### 1. Traffic Analysis & Metadata Leakage

**Vulnerability**: While Tor hides IPs and VOPRF hides identity, transaction graph analysis could correlate transfers.

**Future Solutions**:
- Fixed Denominations: Force all tokens to standard values (1, 10, 100) like Monero
- Dandelion++ Routing: Privacy-preserving routing phase before epidemic broadcast
- Decoy Traffic: Send fake transactions to obfuscate real patterns

#### 2. Advanced Eclipse Attacks

**Current mitigation** (outbound peer preference) is not foolproof. An attacker with network-level access could still intercept outbound connections.

**Future Solutions**:
- Trusted Anchor Peers: Hardcoded set of known-good peers
- Kademlia DHT: Distributed hash table to enforce topology
- Proof-of-Stake Peer Selection: Weight peer trust by economic stake

---

## Security Contact

To report security vulnerabilities in Scarcity, please open an issue at:
https://github.com/flammafex/scarcity/issues

**Do not** disclose security vulnerabilities publicly until they have been addressed.
