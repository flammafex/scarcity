# Environmental Impact

## Summary

**Scarcity uses approximately 12 million times less energy per transaction than Bitcoin.**

| System | Energy per Transaction | Annual Energy |
|--------|----------------------|---------------|
| Bitcoin | ~1,200 kWh | ~150 TWh |
| Ethereum (PoS) | ~0.02 kWh | ~0.01 TWh |
| **Scarcity** | ~0.0001 kWh | Negligible |

## Why Traditional Crypto Uses So Much Energy

### Bitcoin: Proof-of-Work

- Millions of miners compete to solve SHA-256 puzzles
- 99.9% of computation is wasted (only one winner per block)
- Requires specialized ASIC hardware running 24/7
- Annual consumption: ~150 TWh (comparable to Argentina)

### Ethereum: Proof-of-Stake

- Validators stake capital and maintain consensus
- 99.95% reduction from PoW (~150 TWh → ~0.01 TWh)
- Still requires thousands of validators running 24/7
- Still maintains full blockchain across all nodes

**Both require global consensus** - every node processes every transaction.

## How Scarcity Avoids This

Scarcity doesn't need global consensus. It only needs:

1. **Gossip** - Nullifiers propagate peer-to-peer (like forwarding messages)
2. **Timestamps** - Small federation signs when needed (like an API call)
3. **Cryptographic proofs** - Standard elliptic curve operations (like HTTPS)

### Energy Breakdown

| Operation | Energy | Comparable To |
|-----------|--------|---------------|
| Nullifier hash | ~0.00001 kWh | Single computation |
| Gossip broadcast | ~0.00001 kWh/hop | Chat message |
| Witness timestamp | ~0.0001 kWh | API request |
| VOPRF token | ~0.00001 kWh | HTTPS handshake |

**Total per transaction: ~0.0001 kWh**

## Comparison

```
Bitcoin:    Mine block → Waste 99.9% of computation → One winner
Ethereum:   Every validator processes every transaction
Scarcity:   Broadcast nullifier → Forward to peers → Done
```

## The Key Insight

**You don't need global consensus to prevent double-spending.**

You need:
- Local knowledge that a nullifier was seen (gossip)
- Timestamped proof for disputes (Witness)
- Probabilistic confidence that grows over time

This eliminates:
- Mining/staking rewards (no energy incentive)
- Global ledger (no state synchronization)
- Consensus mechanisms (no coordination overhead)

## Infrastructure Requirements

Scarcity requires running services, but they're lightweight:

| Service | Resource Usage |
|---------|---------------|
| Freebird Issuer | Standard web server |
| Freebird Verifier | Standard web server |
| Witness Gateway | Standard web server |
| Witness Nodes | Standard web server |
| HyperToken Relay | WebSocket server |

All comparable to running typical web applications, not mining farms.

## Caveats

This analysis assumes:
- Freebird/Witness/HyperToken services are shared infrastructure
- Per-transaction energy is amortized across all users
- Network effects are similar to other P2P systems

Scarcity's efficiency comes from **not requiring global consensus**, not from magic.
