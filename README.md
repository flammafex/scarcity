# 🩸 Scarcity

**Scarcity** is a P2P value transfer protocol that achieves double-spend prevention without blockchains, mining, or global ledgers. It uses gossip-based nullifier propagation and threshold timestamping.

## Quick Start (Docker)

```bash
git clone https://github.com/flammafex/scarcity.git
cd scarcity
docker compose up --build --abort-on-container-exit
```

This runs the full stack (Freebird, Witness, HyperToken) and integration tests. You should see "All tests passed!" at the end.

## Features

- **No blockchain** - Nullifier gossip replaces global ledger consensus
- **No fees** - No gas, mining rewards, or staking
- **No addresses** - Bearer tokens with no on-chain identity
- **Sender/receiver unlinkable** - Freebird VOPRF provides cryptographic anonymity
- **Token operations** - Split, merge, multi-party transfers, HTLCs, cross-federation bridging
- **Lazy demurrage** - Tokens expire after ~1.5 years if not transferred (configurable)

## Architecture

Scarcity combines three infrastructure components:

| Component | Purpose | Link |
|-----------|---------|------|
| **Freebird** | Anonymous token issuance via P-256 VOPRF with Sybil resistance | [github.com/flammafex/freebird](https://github.com/flammafex/freebird) |
| **Witness** | Threshold timestamping (Ed25519/BLS12-381) | [github.com/flammafex/witness](https://github.com/flammafex/witness) |
| **HyperToken** | P2P networking with WebSocket/WebRTC | [github.com/flammafex/hypertoken](https://github.com/flammafex/hypertoken) |

```
┌─────────────────────────────────────────────────────┐
│  Token Layer                                        │
│  • Mint, transfer, split, merge, HTLC               │
│  • Freebird ownership proofs (Schnorr signatures)   │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Gossip Layer                                       │
│  • Nullifier broadcast to all peers                 │
│  • Adaptive routing (Naive → Supernode → Kademlia)  │
│  • E2E encryption between peers                     │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Validation Layer                                   │
│  • Fast path: gossip check (~10-50ms)               │
│  • Witness path: threshold timestamp verification   │
│  • Confidence scoring: peer count + witness + time  │
└─────────────────────────────────────────────────────┘
```

## How Double-Spend Prevention Works

1. **Transfer**: Sender generates nullifier `SHA-256(secret || tokenId || timestamp)` and broadcasts to gossip network
2. **Propagation**: Nullifier spreads epidemic-style to all peers
3. **Validation**: Recipient checks if nullifier was already seen (reject if duplicate)
4. **Timestamping**: Witness federation provides ordering for dispute resolution

No global ledger required. Nullifiers are single-use markers that prove a token was spent.

## Privacy Model

| Property | Mechanism |
|----------|-----------|
| **Anonymous issuance** | Freebird VOPRF blinds token requests from issuer |
| **Unlinkable transfers** | Nullifiers cannot be correlated to sender/receiver |
| **No addresses** | Tokens are bearer instruments (possession = ownership) |
| **Network privacy** | Optional Tor integration for .onion services |
| **E2E encryption** | All peer communication is encrypted (ECDH + AES-256-GCM) |

## Installation

### Requirements

- Node.js 20+
- Docker (for running infrastructure)

### Local Development

```bash
git clone https://github.com/flammafex/scarcity.git
cd scarcity
npm install
npm run build

# Start infrastructure
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay

# Run tests
npm test
```

### Available Scripts

```bash
npm run build      # Compile TypeScript
npm run clean      # Remove dist directory
npm run dev        # Watch mode compilation
npm run test       # Run integration tests
npm run web        # Start web wallet (localhost:3000)
npm run explorer   # Start Nullscape Explorer (localhost:3001)
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
scar config set witness.gatewayUrl http://localhost:5001
scar config set freebird.issuerEndpoints http://localhost:8081
scar config set freebird.verifierUrl http://localhost:8082
scar config set hypertoken.relayUrl ws://localhost:3000
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
  gatewayUrl: 'http://localhost:5001'
});

const hypertoken = new HyperTokenAdapter({
  relayUrl: 'ws://localhost:3000'
});

await hypertoken.connect();

// Create gossip network
const gossip = new NullifierGossip({ witness });
hypertoken.getPeers().forEach(peer => gossip.addPeer(peer));

// Create validator
const validator = new TransferValidator({
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

- **Double-spending**: Nullifier sets + Witness timestamps
- **Forgery**: Freebird's unforgeable VOPRF tokens with DLEQ proofs
- **Replay attacks**: Single-use nullifiers with timestamp binding
- **Spam/flooding**: Peer reputation scoring, rate limiting, optional PoW
- **Network partitions**: Gossip heals on reconnect, Witness provides ordering

### Not Protected Against

- **Token theft**: Secure your secrets. Use TLS for transmission.
- **Network correlation**: Timing analysis by observers. Use Tor.
- **Quantum adversaries**: ECDLP-based cryptography (P-256, secp256k1)
- **Legal seizure**: Bearer instruments have no account freeze mechanism

### Trust Assumptions

- Gossip network has at least some honest peers
- Witness federation threshold holds (< T collude)
- Freebird issuer/verifier separation maintained

See [SECURITY.md](SECURITY.md) for threat models and configuration examples.

## Limitations

- **Latency**: Validation takes seconds (5s default wait), not milliseconds
- **Bandwidth**: Gossip overhead scales with peer count (O(peers) per transfer)
- **Not instant finality**: Probabilistic confidence, not deterministic
- **Token expiry**: Lazy demurrage means tokens must be refreshed periodically

## Economics

Scarcity implements zero-cost transfers with lazy demurrage (tokens expire after ~576 days if not transferred). This anti-accumulation design is inspired by Gesellian economics. See [ECONOMICS.md](ECONOMICS.md) for the full rationale.

## Environment

Scarcity uses significantly less energy than proof-of-work systems. No mining, no global state synchronization. See [ENVIRONMENT.md](ENVIRONMENT.md) for analysis.

## Development

```bash
npm run build          # Build
npm run clean          # Clean dist
npm run dev            # Watch mode
npm test               # Integration tests
npm run test:basic     # Single test suite
```

### Test Suites

```bash
npm run test:basic         # Basic transfers
npm run test:double-spend  # Double-spend detection
npm run test:degradation   # Graceful degradation
npm run test:phase3        # Advanced features
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

- [Freebird](https://github.com/flammafex/freebird) - Anonymous authorization
- [HyperToken](https://github.com/flammafex/hypertoken) - P2P networking
- [Witness](https://github.com/flammafex/witness) - Threshold timestamping
