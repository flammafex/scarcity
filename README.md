# 🩸 Scarcity

**Scarcity** is a Chaumian e-cash protocol. It provides private, bearer-instrument digital tokens with double-spend prevention — without blockchains, mining, or global ledgers.

Scarcity owns token IDs, amounts, secrets, ownership proofs, split/merge arithmetic, and lazy demurrage state directly. Freebird is used only as privacy-preserving admission/authorization infrastructure; Witness federations provide ordering and auditability, and gossip networks propagate spent-token nullifiers for fast double-spend detection.

## Quick Start (Docker)

```bash
git clone https://git.carpocratian.org/sibyl/scarcity.git
cd scarcity
docker compose up --build --abort-on-container-exit
```

This runs the full stack (Freebird, Witness, HyperToken) and integration tests. You should see "All tests passed!" at the end.

## Features

- **Privacy-preserving admission** — Freebird V4 private tokens authorize Scarcity operations without carrying economic state
- **No blockchain** — Nullifier gossip replaces global ledger consensus
- **No fees** — No gas, mining rewards, or staking
- **No addresses** — Bearer tokens with no on-chain identity
- **Scarcity-owned economics** — Token supply, amounts, ownership, and demurrage are Scarcity state
- **Token operations** — Split, merge, multi-party transfers, HTLCs, cross-federation bridging
- **Auditability** — Witness attestations can be anchored to Ethereum for tamper-proof history
- **Lazy demurrage** — Tokens expire after ~1.5 years if not transferred (configurable)

## Design Philosophy

Scarcity separates three orthogonal concerns:

| Concern | Primitive | Role in e-cash |
|---------|-----------|----------------|
| **Admission** | Freebird V4 private tokens | Anonymous authorization only; no Scarcity amount, owner, or demurrage state |
| **Time** | Witness (threshold sigs) | Ordering — timestamps transfers, anchors to external systems |
| **State** | HyperToken (gossip) | Propagation — broadcasts nullifiers for double-spend detection |

The software provides cryptographic guarantees (privacy, unlinkability, double-spend detection). Scarcity enforces token arithmetic and demurrage locally and in transfer envelopes; Freebird only gates access to Scarcity infrastructure.

## Architecture

| Component | Purpose | Link |
|-----------|---------|------|
| **Freebird** | Anonymous authorization via V4 private tokens | [git.carpocratian.org/sibyl/freebird](https://git.carpocratian.org/sibyl/freebird) |
| **Witness** | Threshold timestamping (Ed25519/BLS12-381) with external anchoring | [git.carpocratian.org/sibyl/witness](https://git.carpocratian.org/sibyl/witness) |
| **HyperToken** | P2P networking with WebSocket/WebRTC | [git.carpocratian.org/sibyl/hypertoken](https://git.carpocratian.org/sibyl/hypertoken) |

```
┌─────────────────────────────────────────────────────┐
│  Token Layer                                        │
│  • Mint, transfer, split, merge, HTLC, bridge       │
│  • Scarcity economic state + ownership proofs       │
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
│  • Freebird V4 admission token verification         │
│  • Gossip check: probabilistic (~10-50ms)           │
│  • Witness check: deterministic (threshold signed)  │
│  • Confidence scoring: peer count + witness + time  │
└─────────────────────────────────────────────────────┘
```

## How It Works

### Token Lifecycle

1. **Mint**: Scarcity creates a bearer token with local token ID, amount, secret, and creation timestamp
2. **Transfer**: Sender creates a Scarcity recipient commitment, obtains a Freebird V4 admission token, timestamps via Witness, broadcasts nullifier to gossip
3. **Validate**: Recipient verifies the admission token, checks Scarcity source age, checks gossip for double-spend, verifies Witness attestation, computes confidence score
4. **Receive**: If validation passes, recipient accepts the bearer token with a unique derived secret

### Double-Spend Prevention

1. **Nullifier generation**: Sender computes `SHA-256(secret || tokenId)` — a unique, deterministic spend marker
2. **Witness timestamping**: Transfer package hash is threshold-signed by the Witness federation
3. **Gossip broadcast**: Nullifier + Witness proof propagate to all peers (proof is validated before storage)
4. **Validation**: Recipient checks gossip (fast, probabilistic) then Witness (slow, deterministic)

No global ledger required. Nullifiers are single-use markers that prove a token was spent.

### Admission Flow (Freebird V4)

```
Sender                    Freebird Issuer              Freebird Verifier
  │                            │                             │
  │── blind(verifier scope) ──→│                             │
  │                            │── evaluate(blinded) ──→     │
  │←── token + DLEQ proof ────│                             │
  │                            │                             │
  │── unblind (local) ────→    │                             │
  │── build V4 admission ───→  │                             │
  │                            │                             │
  │                    (later, at recipient)                  │
  │                            │                             │
  │── verifyAdmissionToken(V4) ───────────────────────────→ │
  │←── ok (token consumed) ──────────────────────────────── │
```

V4 tokens are self-contained and single-use. They authorize the Scarcity operation but do not include token IDs, amounts, owners, nullifiers, or demurrage timestamps.

## Privacy Model

| Property | Mechanism |
|----------|-----------|
| **Anonymous admission** | Freebird V4 blinds the verifier-scoped admission request |
| **Unlinkable transfers** | Nullifiers derived from secret + tokenId, not sender identity |
| **Auth-aware, not economy-aware** | Freebird verifies authorization without learning Scarcity economic state |
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

// Create gossip network
const gossip = new NullifierGossip({ witness });
hypertoken.getPeers().forEach(peer => gossip.addPeer(peer));

// Create validator (uses Freebird for V4 admission verification)
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
- **Forgery**: Scarcity ownership proofs and Witness-covered transfer hashes; Freebird V4 admission tokens are verified separately
- **Replay attacks**: Single-use nullifiers with timestamp binding; bridge replay protection via target-federation nullifier check
- **Token swapping**: Auth tokens and Scarcity source timestamps are included in the package hash covered by Witness proof
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
- **Issuer misbehavior**: Freebird authorization policy can be too loose, but it cannot mint Scarcity economic state by itself.

### Trust Assumptions

- Scarcity operators enforce honest monetary policy and persistence of economic state
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

- [Freebird](https://git.carpocratian.org/sibyl/freebird) - Anonymous authorization/admission
- [HyperToken](https://git.carpocratian.org/sibyl/hypertoken) - P2P networking
- [Witness](https://git.carpocratian.org/sibyl/witness) - Threshold timestamping with external anchoring
