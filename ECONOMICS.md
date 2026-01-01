# Economic Model

Scarcity implements a **zero-cost, anti-accumulation** monetary system inspired by Silvio Gesell's Freigeld ("free money") and biological metabolism.

---

## Core Principles

### 1. Zero-Cost Transfers

**No fees. No gas. No mining rewards. No staking.**

Traditional cryptocurrencies impose costs on every transaction:
- Bitcoin: Mining fees (~$1-50 per transaction)
- Ethereum: Gas fees (variable, often $1-100+)
- Most L2s: Still have fees, just smaller

Scarcity eliminates all transaction costs:
- No miners to pay
- No validators to reward
- No gas market to navigate
- No MEV extraction

**Why this matters:**
- Micropayments become viable
- No rent extraction by infrastructure
- No economic barrier to participation

### 2. Lazy Demurrage

**Tokens expire if not transferred.**

Every Scarcity token has a validity window of approximately **576 days** (~1.5 years). After this period, the token can no longer be transferred.

```
Token Created: January 1, 2025
Expires: ~August 1, 2026
```

**How it works:**
- Validity is checked at transfer time (lazy evaluation)
- Transferring a token "refreshes" it with a new validity window
- Expired tokens cannot be spent - their value returns to the commons

**Why demurrage:**
- Discourages hoarding
- Encourages circulation
- Prevents wealth concentration over time
- Aligns with "use it or lose it" resource philosophy

### 3. Bearer Tokens

**Possession equals ownership. No accounts. No addresses.**

Scarcity tokens are bearer instruments, like physical cash:
- Whoever holds the secret key owns the token
- No on-chain identity or address
- No account balances to query
- No transaction history linked to identity

**Privacy implications:**
- Sender and receiver are unlinkable (via Freebird VOPRF)
- No address reuse problems
- No balance correlation attacks
- Transfers leave no identity trail

### 4. Anti-Accumulation Design

**The system structurally prevents wealth concentration.**

Traditional currencies reward accumulation:
- Interest on deposits
- Appreciation of scarce assets
- Compound growth over time

Scarcity inverts this:
- Demurrage penalizes holding
- No interest or yield
- Value must circulate to be preserved

---

## The ATP Metaphor

Scarcity tokens behave like **ATP (adenosine triphosphate)** in biological systems.

### Biological ATP
- Universal energy carrier in cells
- Cannot be stored long-term
- Must be continuously regenerated
- Enables work, then degrades

### Scarcity Tokens
- Universal value carrier in the network
- Cannot be hoarded indefinitely (demurrage)
- Must be transferred to stay valid
- Enables exchange, then expires

**The insight:** Money should behave like energy, not like property. It should flow, enable activity, and return to the commons - not accumulate in static pools.

---

## Gesellian Economics

Silvio Gesell (1862-1930) proposed **Freigeld** (free money) with built-in demurrage to prevent hoarding and stimulate circulation.

### Gesell's Critique
- Money has an unfair advantage over goods
- Goods decay; money doesn't
- This asymmetry enables money-holders to extract rent
- Result: chronic undercirculation and inequality

### Gesell's Solution
- Money should "rust" like goods
- Holding costs encourage spending
- Circulation velocity increases
- Economy runs at full capacity

### Scarcity's Implementation
- Validity windows instead of stamp taxes
- Cryptographic enforcement instead of physical stamps
- Lazy evaluation instead of periodic fees
- Digital bearer tokens instead of paper notes

---

## Comparison to Alternatives

| Property | Scarcity | Bitcoin | Fiat Currency |
|----------|----------|---------|---------------|
| **Transaction Cost** | Zero | High (mining fees) | Low-Medium (bank fees) |
| **Holding Cost** | Demurrage (~0.2%/month effective) | Zero | Inflation (~2-10%/year) |
| **Supply** | Federated issuance | Fixed (21M cap) | Central bank discretion |
| **Accumulation** | Discouraged | Encouraged | Depends on interest rates |
| **Privacy** | Unlinkable transfers | Pseudonymous (linkable) | Surveilled |
| **Finality** | Probabilistic (seconds) | Probabilistic (hours) | Varies |

---

## Economic Implications

### For Users

**Advantages:**
- No fees for any transaction
- True financial privacy
- No account freezes or seizures
- Micropayments are practical

**Considerations:**
- Must actively manage tokens (transfer before expiry)
- Cannot passively hold wealth long-term
- No interest or yield from holding

### For Society

**Potential Benefits:**
- Reduced wealth inequality (anti-accumulation)
- Increased economic velocity
- Elimination of rent-seeking by payment processors
- Financial inclusion (no minimum balances)

**Design Philosophy:**
- Money as public utility, not private property
- Circulation as the primary function
- Commons-based rather than extraction-based

---

## Validity Window Details

### Default Configuration

The token validity window is **configurable**. The default is ~576 days:

```
Validity: 24 * 24 * 24 * 3600 * 1000 ms
        = 49,766,400,000 ms
        ≈ 576 days
        ≈ 1.58 years
```

**Configuration options:**

```typescript
// NullifierGossip
const gossip = new NullifierGossip({
  witness,
  maxNullifierAge: 30 * 24 * 3600 * 1000  // 30 days
});

// TransferValidator (must match or be shorter)
const validator = new TransferValidator({
  gossip,
  witness,
  maxTokenAge: 30 * 24 * 3600 * 1000  // 30 days
});
```

The default is defined in `src/constants.ts` as `DEFAULT_TOKEN_VALIDITY_MS`.

### Rationale

The ~576 day default balances:
- **Long enough**: Users don't need to constantly manage tokens
- **Short enough**: Prevents indefinite accumulation
- **Practical**: Roughly 18 months gives ample time for normal use

### Edge Cases

**What happens to expired tokens?**
- They become untransferable
- The value effectively returns to the commons
- No action needed - they simply can't be spent

**Can tokens be "refreshed"?**
- Yes, by transferring to yourself (or anyone)
- Each transfer resets the validity window
- This is intentional - activity is rewarded

---

## Federation Economics

Scarcity operates within **federations** - groups of infrastructure operators running Freebird (issuance), Witness (timestamping), and HyperToken (networking).

### Issuance Control

- Federations control token issuance via Freebird
- MPC threshold prevents single-party inflation
- Different federations can have different policies

### Sybil Resistance

Uncontrolled token issuance would undermine the economic model. Freebird provides configurable Sybil resistance:

**Recommended configuration** (used in docker-compose.yaml):
```
SYBIL_RESISTANCE=combined
SYBIL_COMBINED_MODE=and
SYBIL_COMBINED_MECHANISMS=progressive_trust,proof_of_diversity
```

| Mechanism | Economic Function |
|-----------|-------------------|
| `progressive_trust` | New participants start with limited issuance; trust builds over time |
| `proof_of_diversity` | Prevents single actors from creating many identities |

**Why this matters:**
- Prevents inflation attacks (mass token creation)
- Prevents spam attacks (flooding network with transfers)
- Maintains scarcity without artificial caps
- Aligns with progressive trust philosophy

See [SECURITY.md](SECURITY.md) for technical details.

### No Central Bank

- No single entity controls supply
- No monetary policy decisions
- Issuance is algorithmic or policy-based per federation

### Cross-Federation

- Bridge protocol enables transfers between federations
- Atomic swaps via HTLCs
- Federations can have different trust models

---

## Philosophy

> "Money is not wealth. Money is a claim on wealth. Claims should expire."

Scarcity embodies several philosophical positions:

1. **Money as Commons**: Payment infrastructure should be public, not privately owned
2. **Anti-Rentierism**: No one should profit merely from holding money
3. **Circulation Primacy**: The purpose of money is to move, not to sit
4. **Privacy as Default**: Financial surveillance should require justification, not be automatic
5. **Sufficiency over Accumulation**: "Enough" is a valid economic goal

---

## Further Reading

- Silvio Gesell, *The Natural Economic Order* (1916)
- Bernard Lietaer, *The Future of Money* (2001)
- [Freicoin](http://freico.in/) - Earlier demurrage cryptocurrency
- [Circles UBI](https://joincircles.net/) - Demurrage with basic income

---

<div align="center">

*"The economy should work like an ecosystem: energy flows, nothing accumulates forever, and the commons regenerates."*

**A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org)**

</div>
