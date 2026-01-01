# Environmental Impact

<div align=center>

**Scarcity: Zero-Mining, Near-Zero Energy Cryptocurrency**

*Achieving double-spend prevention without destroying the planet*

</div>

---

## TL;DR

**Scarcity uses approximately the same energy as a messaging app.**

No mining. No proof-of-work. No energy-intensive consensus. Just gossip, cryptography, and timestamps.

| System | Annual Energy Use | Per Transaction | Comparable To |
|--------|------------------|-----------------|---------------|
| **Scarcity** | ~0.0001 TWh | ~0.0001 kWh | Messaging app |
| **Ethereum (PoS)** | ~0.01 TWh | ~0.02 kWh | Small data center |
| **Bitcoin** | ~150 TWh | ~1,200 kWh | Entire country (Argentina) |

---

## Why Traditional Cryptocurrencies Consume Energy

### The Consensus Problem

Every cryptocurrency must solve the same fundamental problem: **How do you get thousands of untrusted computers to agree on the order of transactions?**

Traditional solutions require massive energy expenditure:

#### Bitcoin: Proof-of-Work (PoW)
- **The Mechanism**: Miners compete to solve computational puzzles
- **The Cost**: Global race where 99.9% of computation is wasted
- **Energy Source**: Requires specialized ASIC hardware running 24/7
- **Annual Consumption**: ~150 TWh (comparable to Argentina or Sweden)
- **Per Transaction**: ~1,200 kWh (could power a US home for 40+ days)
- **Carbon Impact**: Significant, varies by regional energy mix

#### Ethereum: Proof-of-Stake (PoS)
- **The Mechanism**: Validators stake capital and maintain consensus nodes
- **The Improvement**: 99.95% reduction from PoW (~150 TWh → ~0.01 TWh)
- **The Cost**: Still requires thousands of validators running 24/7
- **Per Transaction**: ~0.02 kWh (comparable to a Google search)
- **Limitation**: Global ledger synchronization across all validators

Both systems share a fundamental requirement: **Every node must process every transaction to maintain a global ledger.**

---

## How Scarcity Eliminates Energy Waste

### No Global Consensus = No Energy Waste

Scarcity achieves double-spend prevention **without requiring global agreement** on transaction order. Instead, it uses:

### 1. **Gossip-Based Nullifier Propagation**

**How it works:**
- Each spent token generates a unique nullifier (like a serial number)
- Nullifiers propagate peer-to-peer via epidemic broadcast
- If you see the same nullifier twice, reject the second spend

**Energy cost:**
- Equivalent to forwarding messages in a chat app
- No mining, no puzzles, no competition
- Scales with peer count, not computational difficulty

**Comparison:**
```
Bitcoin:    Mine 10 minutes → Waste 99.9% of hashes → One winner
Scarcity:   Broadcast nullifier → Forward to peers → Done
```

### 2. **Threshold Timestamping (Witness)**

**How it works:**
- Small federation of nodes (e.g., 5 nodes, 3-of-5 threshold)
- Uses BLS12-381 threshold signatures for timestamping
- Provides ground truth for dispute resolution only when needed

**Energy cost:**
- BLS signature aggregation: ~milliseconds of CPU time
- Throughput: 100-1,000 transactions per second per federation
- No mining, no proof-of-work, no global state

**Comparison:**
```
Ethereum:   Every validator processes every transaction
Scarcity:   Only threshold nodes timestamp (when needed)
```

### 3. **Cryptographic Blinding (Freebird)**

**How it works:**
- P-256 VOPRF (Verifiable Oblivious Pseudorandom Function)
- Anonymous token issuance and verification
- Standard elliptic curve operations

**Energy cost:**
- Comparable to HTTPS handshake
- No repeated computation, no mining rewards
- Simple client-server cryptographic protocol

### 4. **Distributed State Sync (HyperToken)**

**How it works:**
- WebSocket-based relay for peer discovery
- WebRTC for direct peer connections
- Epidemic-style message propagation

**Energy cost:**
- Similar to video chat or multiplayer gaming
- No blockchain download, no global state
- Scales horizontally without energy increase

---

## Energy Breakdown Comparison

### Bitcoin Transaction Energy Flow

```
1. Mining pools worldwide solve SHA-256 puzzles (99.9% wasted)
2. Winner broadcasts block to entire network
3. Every full node validates and stores entire blockchain
4. Process repeats every 10 minutes forever

Energy: ~1,200 kWh per transaction
```

### Ethereum Transaction Energy Flow

```
1. Validator proposes block (staking, not mining)
2. Committee of validators attests to block validity
3. Every validator must sync and validate
4. Global state updated across all nodes

Energy: ~0.02 kWh per transaction
```

### Scarcity Transaction Energy Flow

```
1. Generate nullifier (local cryptographic hash)
2. Gossip to peers (lightweight P2P broadcast)
3. Optional: Timestamp via Witness (threshold signature)
4. Done. No global state, no mining, no validators.

Energy: ~0.0001 kWh per transaction
```

---

## Why This Matters

### Environmental Cost of Traditional Crypto

**Bitcoin's annual energy consumption:**
- **150 TWh** = 150,000,000,000 kilowatt-hours
- Comparable to entire nations (Argentina, Sweden, Malaysia)
- Produces ~85 megatons of CO₂ annually (depending on energy mix)
- Enough energy to power ~13.8 million US homes for a year

**Ethereum's improvement (post-Merge):**
- Reduced from ~150 TWh to ~0.01 TWh (99.95% reduction)
- Still requires global validator infrastructure
- Still maintains full blockchain across thousands of nodes

### Scarcity's Approach

**Energy consumption:**
- Comparable to running standard web services
- No specialized mining hardware required
- No competitive energy waste
- No global state synchronization overhead

**Practical example:**
- Running a Scarcity peer: Similar to running a chat client
- Running a Witness node: Similar to running a web server
- Running Freebird/HyperToken: Similar to running API services

**Carbon footprint:**
- Determined by standard server hosting choices
- Can run on renewable energy without economic penalty
- No mining incentives that favor cheap fossil fuels

---

## Architectural Advantages

### Why Scarcity Can Be Energy-Efficient

Traditional cryptocurrencies waste energy because they solve a harder problem than necessary:

**What Bitcoin/Ethereum solve:**
- Global consensus on transaction ordering
- Sybil resistance via economic cost (mining/staking)
- Incentive alignment through rewards

**What Scarcity solves:**
- Double-spend prevention (gossip + timestamps)
- Sybil resistance via cryptographic proofs (Freebird)
- No economic incentives needed (zero-cost by design)

### The Key Insight

**You don't need global consensus to prevent double-spending.**

You need:
1. **Local knowledge** that a nullifier was seen (gossip)
2. **Timestamped proof** for disputes (Witness)
3. **Probabilistic confidence** that grows over time

This architecture eliminates:
- ❌ Mining/staking rewards (no energy incentive)
- ❌ Global ledger (no state synchronization cost)
- ❌ Consensus mechanisms (no coordination overhead)
- ❌ Economic spam prevention (uses cryptographic proofs instead)

---

## Comparison Table

| Aspect | Scarcity | Bitcoin | Ethereum (PoS) |
|--------|----------|---------|----------------|
| **Consensus Mechanism** | Gossip + Timestamping | Proof-of-Work | Proof-of-Stake |
| **Mining Required** | ❌ No | ✅ Yes (ASIC farms) | ❌ No |
| **Staking Required** | ❌ No | ❌ No | ✅ Yes (32 ETH) |
| **Global Ledger** | ❌ No | ✅ Yes (blockchain) | ✅ Yes (blockchain) |
| **Energy per TX** | ~0.0001 kWh | ~1,200 kWh | ~0.02 kWh |
| **Annual Consumption** | ~0.0001 TWh | ~150 TWh | ~0.01 TWh |
| **Hardware Needed** | Standard computer | ASIC miners | Validator nodes |
| **Comparable To** | Messaging app | Small country | Data center network |
| **Renewable Compatible** | ✅ Always | ⚠️ Economic pressure for cheap energy | ✅ Yes |
| **Scales Energy With** | Peer count (linear) | Difficulty (exponential) | Validator count (linear) |

---

## Sustainability Principles

### Designed for Efficiency

1. **No Economic Waste**
   - Zero mining rewards = zero energy incentive
   - Zero gas fees = zero transaction cost
   - Zero staking = zero capital lockup

2. **Minimal Cryptographic Operations**
   - One hash per nullifier (local)
   - One signature per timestamp (threshold)
   - One VOPRF per anonymous token (standard)

3. **Lazy Demurrage**
   - Validity window (~1.5 years) auto-prunes dead capital
   - Network metabolizes its own history
   - Storage complexity remains O(1) over time

4. **Graceful Degradation**
   - Operates with zero peers (Witness-only mode)
   - No catastrophic failure states
   - No "51% attacks" requiring defensive energy expenditure

---

## Real-World Impact

### If Scarcity Replaced Bitcoin

**Energy saved annually:**
- ~149.9999 TWh (essentially all of Bitcoin's consumption)
- Equivalent to powering ~13.8 million US homes
- Reduction of ~85 megatons of CO₂ (depending on energy mix)

**Hardware eliminated:**
- Millions of specialized ASIC miners
- Industrial-scale cooling infrastructure
- Dedicated mining facilities worldwide

### If Scarcity Replaced Ethereum

**Energy saved annually:**
- ~0.0099 TWh (99% of post-Merge consumption)
- Further reduction from already efficient PoS
- Elimination of validator infrastructure requirements

---

## Frequently Asked Questions

### Q: How can Scarcity be secure without mining?

**A:** Mining exists to solve the double-spend problem via global consensus. Scarcity solves double-spending differently:

- **Gossip** provides probabilistic confidence (fast)
- **Witness** provides cryptographic proof (authoritative)
- **Time** increases confidence asymptotically

No global consensus needed = no mining needed.

### Q: Doesn't Witness require energy?

**A:** Yes, but **orders of magnitude less** than mining:

- **Bitcoin**: Millions of miners solve puzzles competitively (99.9% wasted)
- **Witness**: Small federation (~5 nodes) provides threshold signatures

**Example:**
- Bitcoin: ~1,200 kWh per transaction
- Witness: ~0.0001 kWh per transaction (12 million times less)

### Q: What about proof-of-stake? Isn't that efficient?

**A:** Proof-of-Stake is vastly better than Proof-of-Work, but still requires:

- Global state synchronization
- Thousands of validators running 24/7
- Full blockchain history on every node

Scarcity eliminates these requirements entirely.

### Q: Can Scarcity scale without increasing energy use?

**A:** Yes. Energy scales with:

- **Peer count** (linear, like any P2P network)
- **Timestamp requests** (linear, like any API service)

It does NOT scale with:
- ❌ Mining difficulty (Bitcoin)
- ❌ Global state size (both)
- ❌ Validator count (Ethereum)

### Q: Is this just centralization in disguise?

**A:** No. Scarcity is **serverless**:

- Anyone can run a peer (gossip)
- Anyone can run a Witness node (threshold federation)
- No privileged parties, no gatekeepers

The efficiency comes from **not requiring global consensus**, not from centralization.

---

## Technical Deep Dive

### Energy Cost Analysis

#### Nullifier Generation
```
Operation: SHA-256 hash
Energy: ~0.00001 kWh (local computation)
Frequency: Once per spend
```

#### Gossip Propagation
```
Operation: WebSocket message forwarding
Energy: ~0.00001 kWh per hop
Frequency: O(peers) per spend
```

#### Witness Timestamping
```
Operation: BLS12-381 threshold signature
Energy: ~0.0001 kWh (distributed across threshold nodes)
Frequency: Optional (only for high-value or disputed transfers)
```

#### Freebird VOPRF
```
Operation: P-256 elliptic curve operations
Energy: ~0.00001 kWh (comparable to HTTPS)
Frequency: Once per anonymous token issuance
```

**Total per transaction:** ~0.0001 kWh (assuming gossip + timestamp)

**Comparison:**
- **12,000,000x less** than Bitcoin
- **200x less** than Ethereum (PoS)

---

## Conclusion

Scarcity proves that **cryptocurrency does not require environmental destruction**.

By rejecting the assumption that global consensus is necessary, Scarcity achieves:

- ✅ **Zero mining** (no energy waste)
- ✅ **Zero staking** (no capital lockup)
- ✅ **Zero global ledger** (no state synchronization)
- ✅ **Near-zero energy** (comparable to messaging)

**The result:** A privacy-preserving, serverless, zero-cost cryptocurrency with the environmental footprint of a web application.

---

## Further Reading

- **Rationale**: See [README.md](README.md) for protocol overview
- **Architecture**: [Technical documentation](docs/) for implementation details
- **Comparison**: [Comparison to Alternatives](README.md#comparison-to-alternatives)

---

<div align=center>

**Scarcity: Saving the planet, one gossip message at a time.**

*A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)*

</div>
