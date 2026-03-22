# 🩸 Scarcity

**Scarcity** is a Chaumian e-cash protocol. It provides private, bearer-instrument digital tokens with double-spend prevention — without blockchains, mining, or global ledgers.

Freebird issuers act as mints (controlling who can issue tokens and under what policy), Witness federations provide ordering and auditability, and gossip networks propagate spent-token nullifiers for fast double-spend detection.

## Quick Start (Docker)

```bash
git clone https://git.carpocratian.org/sibyl/scarcity.git
cd scarcity
docker compose up --build --abort-on-container-exit
```

This runs the full stack (Freebird, Witness, HyperToken) and integration tests. You should see "All tests passed!" at the end.

## Features

- **Chaumian privacy** — Freebird VOPRF blind signatures make issuance and spending unlinkable
- **No blockchain** — Nullifier gossip replaces global ledger consensus
- **No fees** — No gas, mining rewards, or staking
- **No addresses** — Bearer tokens with no on-chain identity
- **Issuer-as-mint** — Freebird issuers control token policy; vendors choose which issuers to trust
- **Token operations** — Split, merge, multi-party transfers, HTLCs, cross-federation bridging
- **Auditability** — Witness attestations can be anchored to Ethereum for tamper-proof history
- **Lazy demurrage** — Tokens expire after ~1.5 years if not transferred (configurable)

## Design Philosophy

Scarcity separates three orthogonal concerns:

| Concern | Primitive | Role in e-cash |
|---------|-----------|----------------|
| **Identity** | Freebird (VOPRF) | Mint authority — issues blind-signed tokens, controls policy |
| **Time** | Witness (threshold sigs) | Ordering — timestamps transfers, anchors to external systems |
| **State** | HyperToken (gossip) | Propagation — broadcasts nullifiers for double-spend detection |

The software provides cryptographic guarantees (privacy, unlinkability, double-spend detection). The Freebird issuer operator establishes economic policy (who can mint, how much, backed by what). The Witness federation makes that policy auditable.

This follows the Chaumian model: the protocol doesn't enforce supply limits — the mint does. Vendors choose which mints they trust, just as merchants choose which banks' cards they accept.

## Architecture

| Component | Purpose | Link |
|-----------|---------|------|
| **Freebird** | Anonymous authorization via P-256 VOPRF blind signatures | [git.carpocratian.org/sibyl/freebird](https://git.carpocratian.org/sibyl/freebird) |
| **Witness** | Threshold timestamping (Ed25519/BLS12-381) with external anchoring | [git.carpocratian.org/sibyl/witness](https://git.carpocratian.org/sibyl/witness) |
| **HyperToken** | P2P networking with WebSocket/WebRTC | [git.carpocratian.org/sibyl/hypertoken](https://git.carpocratian.org/sibyl/hypertoken) |

```
┌─────────────────────────────────────────────────────┐
│  Token Layer                                        │
│  • Mint, transfer, split, merge, HTLC, bridge       │
│  • Freebird VOPRF authorization + ownership proofs  │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Gossip Layer                                       │
│  • Nullifier broadcast with Witness proof validation │
│  • Adaptive routing (Naive → Supernode → Kademlia)  │
│  • E2E encryption between peers                     │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Validation Layer                                   │
│  • Freebird auth token verification (single-use V3) │
│  • Gossip check: probabilistic (~10-50ms)           │
│  • Witness check: deterministic (threshold signed)  │
│  • Confidence scoring: peer count + witness + time  │
└─────────────────────────────────────────────────────┘
```

## How It Works

### Token Lifecycle

1. **Mint**: Issuer operator creates tokens (policy-dependent — could require deposit, proof of work, etc.)
2. **Transfer**: Sender blinds a commitment via Freebird, obtains a VOPRF auth token, timestamps via Witness, broadcasts nullifier to gossip
3. **Validate**: Recipient verifies the auth token (single-use V3), checks gossip for double-spend, verifies Witness attestation, computes confidence score
4. **Receive**: If validation passes, recipient accepts the bearer token with a unique derived secret

### Double-Spend Prevention

1. **Nullifier generation**: Sender computes `SHA-256(secret || tokenId)` — a unique, deterministic spend marker
2. **Witness timestamping**: Transfer package hash is threshold-signed by the Witness federation
3. **Gossip broadcast**: Nullifier + Witness proof propagate to all peers (proof is validated before storage)
4. **Validation**: Recipient checks gossip (fast, probabilistic) then Witness (slow, deterministic)

No global ledger required. Nullifiers are single-use markers that prove a token was spent.

### VOPRF Flow (Freebird)

```
Sender                    Freebird Issuer              Freebird Verifier
  │                            │                             │
  │── blind(publicKey) ───────→│                             │
  │                            │── evaluate(blinded) ──→     │
  │←── token + DLEQ proof ────│                             │
  │                            │                             │
  │── unblind (local) ────→    │                             │
  │── build V3 redemption ──→  │                             │
  │                            │                             │
  │                    (later, at recipient)                  │
  │                            │                             │
  │── verifyToken(V3) ────────────────────────────────────→ │
  │←── ok (token consumed) ──────────────────────────────── │
```

V3 tokens are self-contained and single-use — consumed on first verification. The token embeds the issuer ID, so vendors know which mint issued it.

## Privacy Model

| Property | Mechanism |
|----------|-----------|
| **Anonymous issuance** | VOPRF blinds the commitment — issuer can't link issuance to spending |
| **Unlinkable transfers** | Nullifiers derived from secret + tokenId, not sender identity |
| **Issuer-aware, not issuer-tracked** | V3 tokens identify the mint but not the user |
| **No addresses** | Tokens are bearer instruments (possession = ownership) |
| **Per-token secrets** | Each received token derives a unique secret from the wallet master key |
| **Network privacy** | Optional Tor integration for .onion services |
| **E2E encryption** | All peer communication encrypted (ECDH + AES-256-GCM) |

## Installation

### Requirements

- Node.js 20+
- Docker (for running infrastructure)

### Local Development

```bash
git clone https://git.carpocratian.org/sibyl/scarcity.git
cd scarcity
npm install
npm run build

# Start infrastructure
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay

# Run tests
npm test

# Run tests against live services (no fallback)
npm run test:live
```

### Available Scripts

```bash
npm run build          # Compile TypeScript
npm run clean          # Remove dist directory
npm run dev            # Watch mode compilation
npm test               # Integration tests (fallback mode for unavailable services)
npm run test:live      # Live service tests (requires all services running)
npm run web            # Start web wallet (localhost:3000)
npm run explorer       # Start Nullscape Explorer (localhost:3001)
```

## Web Wallet

A browser-based wallet for managing tokens.

```bash
npm run web
# Open http://localhost:3000
```

Features:
- Create/import wallets with PIN-protected secret export
- Mint, send, receive, split, merge tokens
- Token expiration visibility with warning banners
- Step-by-step transaction progress feedback
- Privacy explainer modal
- PWA support (installable, works offline)

## Nullscape Explorer

Real-time nullifier feed for network transparency.

```bash
npm run explorer
# Open http://localhost:3001
```

Features:
- Live WebSocket feed of nullifier propagation
- Historical search and activity charts
- Federation statistics
- SQLite persistence

## CLI

```bash
# Install globally
npm install -g .

# Or run directly
./dist/src/cli/index.js <command>
```

### Wallet Commands

```bash
scar wallet create <name>     # Create wallet
scar wallet list              # List wallets
scar wallet show <name>       # Show public key
scar wallet export <name>     # Export secret (requires PIN in web wallet)
```

### Token Commands

```bash
scar token list <wallet>      # List tokens
scar token mint <wallet> <amount>
scar token show <token-id>
```

### Advanced Operations

```bash
# Split token into parts
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

## API Usage

```typescript
import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter
} from 'scarcity';

// Initialize infrastructure
const freebird = new FreebirdAdapter({
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

// Create gossip network
const gossip = new NullifierGossip({ witness });
hypertoken.getPeers().forEach(peer => gossip.addPeer(peer));

// Create validator (requires freebird for V3 token verification)
const validator = new TransferValidator({
  freebird,
  gossip,
  witness,
  waitTime: 5000,
  minConfidence: 0.7
});

// Mint and transfer
const token = ScarbuckToken.mint(100, freebird, witness, gossip);
const pkg = await token.transfer(recipientPublicKey);

// Validate and receive
const result = await validator.validateTransfer(pkg);
if (result.valid) {
  const received = await ScarbuckToken.receive(pkg, recipientSecret, freebird, witness, gossip);
}
```

## HyperToken Integration

Scarcity uses HyperToken for P2P networking with:

- **Hybrid transport**: WebSocket for signaling, auto-upgrade to WebRTC for lower latency
- **Adaptive routing**: Automatically switches strategy based on network size
  - <50 peers: Naive broadcast
  - 50-99 peers: Supernode hierarchical routing
  - 100+ peers: Kademlia DHT
- **E2E encryption**: ECDH P-256 key exchange + AES-256-GCM (mandatory, not optional)
- **State sync**: Delta-based catch-up for reconnecting peers
- **Auto-reconnection**: Exponential backoff with message buffering
- **Binary encoding**: MessagePack with compression for efficiency

## Security

### Protected Against

- **Double-spending**: Nullifier sets + Witness timestamps + gossip proof validation
- **Forgery**: Freebird's unforgeable VOPRF tokens with DLEQ proof verification (scalar range validated)
- **Replay attacks**: Single-use nullifiers with timestamp binding; bridge replay protection via target-federation nullifier check
- **Token swapping**: Auth tokens are included in the package hash covered by Witness proof
- **Rogue key attacks**: BLS key aggregation checks Proof-of-Possession when available
- **Eclipse attacks**: Outbound peers weighted 3x higher in confidence scoring
- **Spam/flooding**: Peer reputation scoring, rate limiting, optional PoW
- **HTLC griefing**: Two-phase nullifier publication (at claim/refund, not at lock)
- **Network partitions**: Gossip heals on reconnect, Witness provides ordering

### Not Protected Against

- **Token theft**: Secure your secrets. Use TLS for transmission.
- **Network correlation**: Timing analysis by observers. Use Tor.
- **Quantum adversaries**: ECDLP-based cryptography (P-256)
- **Legal seizure**: Bearer instruments have no account freeze mechanism
- **Issuer misbehavior**: A trusted issuer can over-issue. Ethereum anchoring via Witness makes this auditable but not preventable at the protocol level.

### Trust Assumptions

- Freebird issuer enforces honest monetary policy
- Gossip network has at least some honest peers
- Witness federation threshold holds (< T collude)
- Freebird issuer/verifier deployed on separate infrastructure (prevents timing attacks)

See [SECURITY.md](SECURITY.md) for threat models and configuration examples.

## Limitations

- **Latency**: Validation takes seconds (5s default wait), not milliseconds
- **Bandwidth**: Gossip overhead scales with peer count (O(peers) per transfer)
- **Not instant finality**: Probabilistic confidence, not deterministic
- **Token expiry**: Lazy demurrage means tokens must be refreshed periodically
- **No fixed denominations**: Arbitrary amounts allow amount-based fingerprinting (a known trade-off vs. classic Chaumian fixed denominations)

## Economics

Scarcity implements zero-cost transfers with lazy demurrage (tokens expire after ~576 days if not transferred). This anti-accumulation design is inspired by Gesellian economics. See [ECONOMICS.md](ECONOMICS.md) for the full rationale.

## Environment

Scarcity uses significantly less energy than proof-of-work systems. No mining, no global state synchronization. See [ENVIRONMENT.md](ENVIRONMENT.md) for analysis.

## Development

```bash
npm run build          # Build
npm run clean          # Clean dist
npm run dev            # Watch mode
npm test               # Integration tests (with fallback)
npm run test:live      # Live service tests (no fallback)
npm run test:basic     # Single test suite
```

### Test Suites

```bash
npm run test:basic         # Basic transfers
npm run test:double-spend  # Double-spend detection
npm run test:degradation   # Graceful degradation
npm run test:phase3        # Advanced features
npm run test:live          # All services, no fallback
```

## Project Status

This is a research prototype. Core protocol, advanced features, and tooling are implemented and tested. Production deployment requires security audits and operational hardening.

| Phase | Status |
|-------|--------|
| Core Protocol | Complete |
| Hardening (BLS, WebRTC, VOPRF, Tor) | Complete |
| Advanced Features (split, merge, HTLC, bridge) | Complete |
| Tooling (web wallet, CLI, explorer) | Complete |
| Mobile SDK | Planned |

## License

Apache License 2.0

## Related Projects

- [Freebird](https://git.carpocratian.org/sibyl/freebird) - Anonymous authorization (VOPRF mint)
- [HyperToken](https://git.carpocratian.org/sibyl/hypertoken) - P2P networking
- [Witness](https://git.carpocratian.org/sibyl/witness) - Threshold timestamping with external anchoring
