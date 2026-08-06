# 🩸 Scarcity

**Scarcity** is a Chaumian e-cash protocol: private, bearer-instrument digital tokens with double-spend prevention — no blockchains, no mining, no global ledgers.

Tokens are like digital banknotes. Whoever holds the secret owns the value. There are no accounts, no addresses, and no transaction history tied to identity. Scarcity handles the token arithmetic, ownership, and expiry; a small set of supporting services provide admission, ordering, and double-spend detection.

---

## Why it exists

Most digital money is built on a global ledger that every participant must agree on and store. That's expensive, slow, and energy-hungry.

Scarcity takes a different path. It's based on **Chaumian e-cash** — a design where a trusted mint issues blind-signed bearer tokens. The protocol guarantees privacy and double-spend detection without requiring everyone to agree on a shared ledger.

The result is a system that:
- **Has no fees** — no gas, no mining rewards, no staking
- **Has no addresses** — possession of the token is ownership
- **Is private** — issuance and spending can't be correlated
- **Is lightweight** — roughly the energy of a messaging app

---

## Core ideas

### Bearer tokens

A Scarcity token is a bearer instrument. Whoever holds its secret key owns it. There's no account to freeze, no balance to query, no identity attached.

### Lazy demurrage

Tokens expire if they aren't transferred. The default validity window is about **576 days** (~1.5 years). Transferring a token refreshes it; an expired token simply can't be spent. This discourages hoarding and keeps money circulating — an idea borrowed from Silvio Gesell's "Freigeld."

### Double-spend prevention

When a token is spent, it produces a unique **nullifier** — a deterministic "spend marker" derived from the token's secret. Nullifiers propagate through a peer-to-peer gossip network. If the same nullifier appears twice, the second spend is rejected. A federation of **Witness** nodes additionally timestamps transfers, providing deterministic ground truth for disputes.

### The supporting services

Scarcity composes three external services, each with a narrow role:

| Service | Role |
|---------|------|
| **Freebird** | Issues anonymous admission credentials and runs the bearer-token exchange/issuance used to create and move tokens |
| **Witness** | A federation that threshold-signs timestamps, providing ordering and auditability (optionally anchored to external systems) |
| **HyperToken** | P2P networking — broadcasts nullifiers across the gossip network for double-spend detection |

---

## How a transfer works

1. **Mint** — Scarcity creates a bearer token with a local token ID, amount, secret, and creation timestamp.
2. **Transfer** — The sender builds a recipient commitment, obtains an anonymous admission credential, timestamps the transfer via Witness, and broadcasts the nullifier to the gossip network.
3. **Validate** — The recipient verifies the admission credential, checks the token hasn't expired, checks the gossip network for a double-spend, verifies the Witness attestation, and computes a confidence score.
4. **Receive** — If validation passes, the recipient accepts the token with a fresh derived secret.

No global ledger is required. Nullifiers are single-use markers that prove a token was spent.

---

## Features

- **Private admission** — anonymous credentials authorize operations without revealing who you are
- **No blockchain** — nullifier gossip replaces global-ledger consensus
- **No fees** — no gas, mining rewards, or staking
- **No addresses** — bearer tokens with no on-chain identity
- **Token operations** — split, merge, multi-party transfers, hash/time-locked payments (HTLCs), cross-federation bridging
- **Auditability** — Witness attestations can be anchored to external systems for tamper-proof history
- **Lazy demurrage** — tokens expire after ~1.5 years if not transferred (configurable)

---

## Quick start (Docker)

```bash
git clone https://git.carpocratian.org/sibyl/scarcity.git
cd scarcity
docker compose up --build --abort-on-container-exit
```

This runs the full stack (Freebird, Witness, HyperToken) and the integration tests. You should see "All tests passed!" at the end.

## Local development

```bash
git clone https://git.carpocratian.org/sibyl/scarcity.git
cd scarcity
npm install
npm run build

# Start the supporting services
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay

# Run tests (fallback mode if services are down)
npm test

# Run tests against live services
npm run test:live
```

### Available scripts

```bash
npm run build          # Compile TypeScript
npm run clean          # Remove dist directory
npm run dev            # Watch mode compilation
npm test               # Integration tests (fallback mode)
npm run test:live      # Live-service tests (requires services running)
npm run web            # Start the web wallet (localhost:3000)
npm run explorer       # Start the Nullscape Explorer (localhost:3001)
```

---

## Web wallet

A browser-based wallet for managing tokens.

```bash
npm run web
# Open http://localhost:3000
```

Features:
- Create/import wallets with PIN-protected secret export
- Mint, send, receive, split, and merge tokens
- Token-expiration visibility with warning banners
- Step-by-step transaction progress feedback
- PWA support (installable, works offline)

## Nullscape Explorer

A real-time nullifier feed for network transparency.

```bash
npm run explorer
# Open http://localhost:3001
```

Features:
- Live WebSocket feed of nullifier propagation
- Historical search and activity charts
- Federation statistics
- SQLite persistence

---

## CLI

```bash
# Install globally
npm install -g .

# Or run directly
./dist/src/cli/index.js <command>
```

### Wallet commands

```bash
scar wallet create <name>     # Create a wallet
scar wallet list              # List wallets
scar wallet show <name>       # Show a wallet's public key
scar wallet export <name>     # Export a secret
```

### Token commands

```bash
scar token list <wallet>      # List tokens
scar token mint <wallet> <amount>
scar token show <token-id>
```

### Advanced operations

```bash
# Split a token into parts
scar split <token-id> --amounts 30,40,30 --recipients <key1>,<key2>,<key3>

# Merge tokens
scar merge <token-id-1>,<token-id-2> --recipient <key> --wallet <name>

# Multi-party transfer
scar multiparty <token-id> alice:30 bob:40 carol:30

# Hash-locked transfer (atomic swaps)
scar htlc create <token-id> <recipient> --hash-lock <hash>
scar htlc claim <package> --wallet <name> --preimage <preimage>

# Time-locked transfer
scar htlc create <token-id> <recipient> --time-lock <timestamp> --refund-key <key>
scar htlc refund <package> --wallet <name>  # After expiry

# Cross-federation bridge
scar bridge transfer <token-id> <recipient> --target-gateway <url> --target-network <id>
scar bridge claim <package> --wallet <name>
```

### Configuration

```bash
scar config list
scar config set witness.gatewayUrl http://localhost:8083
scar config set freebird.issuerEndpoints http://localhost:8081
scar config set freebird.verifierUrl http://localhost:8082
scar config set hypertoken.relayUrl ws://localhost:5001
```

---

## API usage

```typescript
import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter
} from 'scarcity';

// Initialize the supporting services
const auth = new FreebirdAdapter({
  issuerEndpoints: ['http://localhost:8081'],
  verifierUrl: 'http://localhost:8082'
});

const witness = new WitnessAdapter({
  gatewayUrl: 'http://localhost:8083'
});

const hypertoken = new HyperTokenAdapter({
  relayUrl: 'ws://localhost:5001'
});

await hypertoken.connect();

// Build the gossip network
const gossip = new NullifierGossip({ witness });
hypertoken.getPeers().forEach(peer => gossip.addPeer(peer));

// Create a validator (checks admission, double-spend, and Witness attestation)
const validator = new TransferValidator({
  auth,
  gossip,
  witness,
  waitTime: 5000,
  minConfidence: 0.7
});

// Mint and transfer
const token = ScarbuckToken.mint(100, auth, witness, gossip);
const pkg = await token.transfer(recipientPublicKey);

// Validate and receive
const result = await validator.validateTransfer(pkg);
if (result.valid) {
  const received = await ScarbuckToken.receive(pkg, recipientSecret, auth, witness, gossip);
}
```

---

## Security

### Protected against

- **Double-spending** — nullifier sets + Witness timestamps + gossip proof validation
- **Forgery** — Scarcity ownership proofs and Witness-covered transfer hashes
- **Replay attacks** — single-use nullifiers with timestamp binding
- **Token swapping** — admission credentials and source timestamps are bound into the Witness-covered package hash
- **Rogue key attacks** — BLS key aggregation checks Proof-of-Possession when available
- **Eclipse attacks** — outbound peers weighted higher in confidence scoring
- **Spam/flooding** — peer reputation scoring, rate limiting, optional proof-of-work
- **HTLC griefing** — two-phase nullifier publication (at claim/refund, not at lock)
- **Network partitions** — gossip heals on reconnect; Witness provides ordering

### Not protected against

- **Token theft** — secure your secrets; use TLS for transmission
- **Network correlation** — timing analysis by observers; use a VPN or other transport-level privacy layer
- **Quantum adversaries** — ECDLP-based cryptography (P-256)
- **Legal seizure** — bearer instruments have no account-freeze mechanism
- **Issuer misbehavior** — a Freebird issuer can set loose admission policy, but cannot mint Scarcity economic state by itself

### Trust assumptions

- Scarcity operators enforce honest monetary policy and persist economic state
- The gossip network has at least some honest peers
- The Witness federation threshold holds (fewer than the threshold collude)
- Freebird issuer and verifier run on separate infrastructure (prevents timing attacks)

See [SECURITY.md](SECURITY.md) for threat models and configuration examples.

---

## Limitations

- **Latency** — validation takes seconds (5s default wait), not milliseconds
- **Bandwidth** — gossip overhead scales with peer count
- **Not instant finality** — probabilistic confidence, not deterministic
- **Token expiry** — lazy demurrage means tokens must be refreshed periodically
- **No fixed denominations** — arbitrary amounts allow amount-based fingerprinting (a known trade-off vs. classic Chaumian fixed denominations)

---

## Economics

Scarcity implements zero-cost transfers with lazy demurrage (tokens expire after ~576 days if not transferred). This anti-accumulation design is inspired by Gesellian economics. See [ECONOMICS.md](ECONOMICS.md) for the full rationale.

## Environment

Scarcity uses significantly less energy than proof-of-work systems — no mining, no global state synchronization. See [ENVIRONMENT.md](ENVIRONMENT.md) for analysis.

---

## Project status

This is a research prototype. The core protocol, advanced features, and tooling are implemented and tested. Production deployment requires security audits and operational hardening.

| Phase | Status |
|-------|--------|
| Core protocol | Complete |
| Hardening (BLS, WebRTC, VOPRF) | Complete |
| Advanced features (split, merge, HTLC, bridge) | Complete |
| Tooling (web wallet, CLI, explorer) | Complete |
| Mobile SDK | Planned |

---

## License

Apache License 2.0

## Related projects

- [Freebird](https://git.carpocratian.org/sibyl/freebird) — anonymous admission and bearer-token issuance
- [Witness](https://git.carpocratian.org/sibyl/witness) — threshold timestamping with external anchoring
- [HyperToken](https://git.carpocratian.org/sibyl/hypertoken) — P2P networking
