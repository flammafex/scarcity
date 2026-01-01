# Scarcity Mobile SDK Roadmap

**Status:** Phase 4 - Mobile SDK (0% → 100%)
**Platform:** React Native (iOS + Android)
**Architecture:** Native TypeScript SDK with platform adapters

---

## Executive Summary

The Scarcity Mobile SDK will bring privacy-preserving digital cash to iOS and Android devices. Based on codebase analysis, **~80% of the core protocol can be reused directly** from the existing implementation, with strategic adapters needed for:

- Storage (AsyncStorage/MMKV replacing filesystem)
- Networking (native WebSocket/WebRTC replacing Node.js modules)
- Cryptography (Web Crypto API replacing Node.js crypto)

The SDK will expose the same functionality as the CLI and Web Wallet:
- Wallet creation and management
- Token minting and transfers
- Balance queries and history
- P2P gossip network participation
- Integration with Witness and Freebird services

---

## Platform Selection: React Native

**Why React Native?**

✅ **Strong WebRTC Support:** `react-native-webrtc` is mature and production-ready
✅ **TypeScript First-Class:** Direct code reuse from existing TypeScript codebase
✅ **Cross-Platform:** Single codebase for iOS and Android
✅ **Crypto Libraries Work:** `@noble/curves` and `@noble/hashes` are pure JavaScript
✅ **Active Ecosystem:** Rich set of security and storage libraries
✅ **Web Compatibility:** Can potentially share code with web wallet

**Alternative Considered:**
- **Flutter:** Would require full Dart rewrite (~0% code reuse)
- **Native iOS/Swift + Android/Kotlin:** Double the development effort
- **Expo:** Too restrictive for WebRTC and crypto requirements

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Scarcity Mobile SDK (@scarcity/react-native)               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Core Protocol (Portable TypeScript)                │   │
│  │  • ScarbuckToken                                    │   │
│  │  • NullifierGossip                                  │   │
│  │  • TransferValidator                                │   │
│  │  • BridgeProtocol                                   │   │
│  │  • Crypto utilities                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Integration Adapters (HTTP/Fetch)                  │   │
│  │  • FreebirdAdapter (VOPRF privacy)                  │   │
│  │  • WitnessAdapter (BLS timestamping)                │   │
│  │  • HyperTokenAdapter (P2P networking)               │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Platform Adapters (React Native)                   │   │
│  │  • MobileStorageAdapter (MMKV/SQLite)               │   │
│  │  • MobileNetworkAdapter (native WebSocket)          │   │
│  │  • MobileCryptoAdapter (Web Crypto API)             │   │
│  │  • MobileWebRTCAdapter (react-native-webrtc)        │   │
│  │  • SecureKeystore (Keychain/Keystore)               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  React Native App                                           │
│  • Wallet UI                                                │
│  • Transfer screens                                         │
│  • Transaction history                                      │
│  • Settings & backup                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Development Phases

### **Phase 1: Foundation & Setup**

**Objective:** Establish project structure and validate core assumptions

**Tasks:**
1. Create React Native library package (`@scarcity/react-native`)
2. Set up monorepo structure (SDK + example app)
3. Configure TypeScript with React Native targets
4. Install and test cryptographic dependencies
5. Validate `@noble/curves` performance on iOS/Android devices
6. Set up Jest testing infrastructure

**Key Deliverables:**
- [ ] React Native library scaffold
- [ ] TypeScript compilation working
- [ ] Crypto benchmarks on real devices
- [ ] CI/CD pipeline for mobile builds

**Dependencies Installed:**
```json
{
  "@noble/curves": "^1.9.7",
  "@noble/hashes": "^1.4.0",
  "react-native-mmkv": "^3.0.0",
  "react-native-webrtc": "^124.0.0",
  "@react-native-async-storage/async-storage": "^2.0.0",
  "react-native-quick-crypto": "^0.7.0"
}
```

**Critical Decision Point:**
- Benchmark P-256 and BLS12-381 operations on low-end Android devices
- If performance is insufficient, evaluate native crypto bridges

---

### **Phase 2: Core Module Extraction**

**Objective:** Extract and adapt portable TypeScript modules for mobile

**Tasks:**
1. **Copy Core Modules** (100% portable):
   - `src/token.ts` → `sdk/core/token.ts`
   - `src/types.ts` → `sdk/core/types.ts`
   - `src/validator.ts` → `sdk/core/validator.ts`
   - `src/bridge.ts` → `sdk/core/bridge.ts`
   - `src/gossip.ts` → `sdk/core/gossip.ts`

2. **Adapt Crypto Module**:
   - Replace `crypto.randomBytes()` with `crypto.getRandomValues()`
   - Alternatively use `react-native-quick-crypto` for better performance
   ```typescript
   // Before (Node.js)
   import { randomBytes } from 'crypto';
   const nonce = randomBytes(32);

   // After (React Native)
   import { getRandomValues } from 'react-native-quick-crypto';
   const nonce = getRandomValues(new Uint8Array(32));
   ```

3. **Copy Vendor Code**:
   - `src/vendor/freebird/` → `sdk/vendor/freebird/`
   - `src/vendor/hypertoken/` → `sdk/vendor/hypertoken/` (requires adaptation)

4. **Create Type Definitions**:
   - Define platform-agnostic interfaces for storage, network, crypto
   ```typescript
   export interface StorageAdapter {
     getItem(key: string): Promise<string | null>;
     setItem(key: string, value: string): Promise<void>;
     removeItem(key: string): Promise<void>;
   }

   export interface NetworkAdapter {
     fetch(url: string, init?: RequestInit): Promise<Response>;
     createWebSocket(url: string): WebSocket;
   }

   export interface CryptoAdapter {
     randomBytes(length: number): Uint8Array;
     hash(data: Uint8Array): Promise<Uint8Array>;
   }
   ```

**Key Deliverables:**
- [ ] All core modules compiling in React Native environment
- [ ] Platform adapter interfaces defined
- [ ] Unit tests passing for core token logic
- [ ] Crypto operations working with Web Crypto API

**Testing Strategy:**
- Run existing unit tests from main codebase
- Validate cryptographic outputs match Node.js version
- Test on both iOS simulator and Android emulator

---

### **Phase 3: Storage Layer**

**Objective:** Implement secure, performant storage for wallets and tokens

**Architecture:**
```
┌──────────────────────────────────────────────────┐
│  MobileWallet                                    │
│  • createWallet(name, password?)                 │
│  • importWallet(name, secretKey, password?)      │
│  • exportWallet(name, password?)                 │
│  • listWallets()                                 │
│  • getDefaultWallet()                            │
└──────────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────────┐
│  SecureKeyStorage (iOS: Keychain, Android: Keystore) │
│  • Encrypt private keys with device hardware     │
│  • Optional biometric unlock                     │
│  • Secure enclave integration (iOS)              │
└──────────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────────┐
│  MobileTokenStore (MMKV or SQLite)               │
│  • Fast key-value storage for tokens            │
│  • Encrypted at rest                             │
│  • Transaction history                           │
└──────────────────────────────────────────────────┘
```

**Tasks:**
1. **Implement MobileWallet:**
   - Port `src/cli/wallet.ts` logic
   - Use `react-native-keychain` for secure key storage
   - Implement password-based encryption (optional layer)
   - Support biometric authentication (Face ID, Touch ID, fingerprint)

2. **Implement MobileTokenStore:**
   - Use MMKV for performance (or SQLite for complex queries)
   - Store token proofs, transaction history, metadata
   - Implement efficient queries for balance calculations

3. **Implement Backup/Restore:**
   - Export wallet as encrypted JSON
   - Support mnemonic seed phrases (BIP-39 compatible)
   - Cloud backup integration (iCloud, Google Drive)

**Key Deliverables:**
- [ ] Wallet creation and import working
- [ ] Private keys stored in device Keychain/Keystore
- [ ] Token storage with history
- [ ] Backup and restore functionality
- [ ] Biometric authentication support

**Security Considerations:**
- Never store private keys in plain text
- Use AES-256 encryption for local storage
- Implement auto-lock after inactivity
- Support app-level PIN protection

**Library Choices:**
```json
{
  "react-native-keychain": "^8.2.0",      // Secure key storage
  "react-native-mmkv": "^3.0.0",          // Fast KV storage
  "react-native-biometrics": "^3.0.0",    // Biometric auth
  "bip39": "^3.1.0"                       // Mnemonic generation
}
```

---

### **Phase 4: Network Adapters**

**Objective:** Implement HTTP and WebSocket adapters for Freebird/Witness

**Tasks:**
1. **Adapt FreebirdAdapter:**
   - Port `src/integrations/freebird.ts`
   - Use native `fetch()` API (available in React Native)
   - **Add Tor support** (optional, disabled by default)
   - Integrate with Orbot on Android or custom SOCKS proxy
   - Fallback to HTTPS when Tor unavailable
   ```typescript
   export class MobileFreebirdAdapter implements Freebird {
     private useTor: boolean = false;
     private torProxy?: string;

     async blind(message: Uint8Array): Promise<BlindedToken> {
       const fetchOptions = this.useTor
         ? { agent: await this.getTorAgent() }
         : {};

       const response = await fetch(`${this.issuerUrl}/blind`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ message: toHex(message) }),
         ...fetchOptions
       });
       // ... rest of VOPRF protocol
     }
   }
   ```

2. **Adapt WitnessAdapter:**
   - Port `src/integrations/witness.ts`
   - Use native `fetch()` for HTTP requests
   - Support quorum witness configurations
   - Handle network errors gracefully (mobile connections are flaky)
   - Optional Tor support for witness requests

3. **Implement Tor Integration:**
   - Detect Orbot installation on Android
   - Provide configuration for custom SOCKS proxy
   - Graceful fallback when Tor unavailable
   - Add user setting to enable/disable Tor
   ```typescript
   export class TorManager {
     async isOrbotInstalled(): Promise<boolean> {
       // Check for Orbot on Android
     }

     async connectToTor(proxy?: string): Promise<boolean> {
       // Connect to Orbot or custom SOCKS proxy
     }
   }
   ```

4. **Create Mobile Network Manager:**
   - Monitor network state (WiFi, cellular, offline)
   - Implement request retry logic with exponential backoff
   - Queue operations when offline, sync when back online
   - Handle Tor connection failures
   ```typescript
   export class NetworkManager {
     private isOnline: boolean = true;
     private useTor: boolean = false;
     private pendingRequests: Queue<Request> = new Queue();

     async fetch(url: string, init?: RequestInit): Promise<Response> {
       if (!this.isOnline) {
         await this.pendingRequests.enqueue({ url, init });
         throw new Error('Offline - request queued');
       }

       if (this.useTor && !await this.torManager.isConnected()) {
         console.warn('Tor unavailable, falling back to HTTPS');
         this.useTor = false;
       }

       return fetch(url, init);
     }
   }
   ```

**Key Deliverables:**
- [ ] Freebird blinding working on mobile
- [ ] Witness timestamping working on mobile
- [ ] Optional Tor support via Orbot/SOCKS proxy
- [ ] Network state monitoring
- [ ] Offline request queuing
- [ ] Adaptive retry logic for flaky connections
- [ ] Graceful Tor fallback to HTTPS

**Testing:**
- Test on WiFi, cellular (4G/5G), and airplane mode
- Validate VOPRF outputs match desktop implementation
- Test witness quorum with unreliable networks

---

### **Phase 5: P2P Networking (HyperToken)**

**Objective:** Port WebRTC/WebSocket P2P networking to React Native

**This is the most complex phase** - HyperToken uses WebRTC for P2P connections and WebSocket for signaling.

**Tasks:**
1. **Adapt WebSocket Layer:**
   - Replace Node.js `ws` package with React Native's native WebSocket
   - Port `src/vendor/hypertoken/PeerConnection.ts`
   ```typescript
   // Before (Node.js)
   import * as Ws from "ws";
   const ws = new Ws(url);

   // After (React Native)
   const ws = new WebSocket(url);
   ```

2. **Adapt WebRTC Layer:**
   - Use `react-native-webrtc` for peer connections
   - Port `src/vendor/hypertoken/WebRTCConnection.ts`
   ```typescript
   import {
     RTCPeerConnection,
     RTCSessionDescription,
     RTCIceCandidate,
     mediaDevices
   } from 'react-native-webrtc';

   export class MobileWebRTCConnection implements PeerTransport {
     private pc: RTCPeerConnection;

     async connect(offer: RTCSessionDescription) {
       this.pc = new RTCPeerConnection(this.config);
       await this.pc.setRemoteDescription(offer);
       const answer = await this.pc.createAnswer();
       await this.pc.setLocalDescription(answer);
       return answer;
     }
   }
   ```

3. **Adapt HybridPeerManager:**
   - Port `src/vendor/hypertoken/HybridPeerManager.ts`
   - Handle mobile network transitions (WiFi ↔ cellular)
   - Implement background connection management
   - Test NAT traversal on cellular networks (often more restrictive)

4. **Port HyperTokenAdapter:**
   - Port `src/integrations/hypertoken.ts`
   - Connect gossip network to mobile P2P layer

5. **Background Processing:**
   - Use React Native Background Tasks for gossip when app is backgrounded
   - Implement push notifications for incoming transfers (optional)
   - Balance battery life vs real-time gossip

**Key Deliverables:**
- [ ] WebSocket connections working on mobile
- [ ] WebRTC peer connections established on WiFi
- [ ] WebRTC working on cellular networks (with TURN servers)
- [ ] Gossip protocol propagating nullifiers
- [ ] Background task for passive gossip
- [ ] Network transition handling (WiFi ↔ cellular ↔ offline)

**Critical Challenges:**
- **NAT Traversal:** Cellular networks have strict NAT, may need TURN servers
- **Battery Life:** P2P connections drain battery, need adaptive gossip
- **iOS Background Limits:** iOS restricts background networking to ~30 seconds
- **Android Doze Mode:** Android may kill background connections to save battery

**Solutions:**
- Deploy TURN servers for relay when direct P2P fails
- Use adaptive gossip (active when app open, passive when backgrounded)
- Implement push notifications for critical events (incoming transfers)
- Allow users to choose between "real-time" and "battery saver" modes

**Library Dependencies:**
```json
{
  "react-native-webrtc": "^124.0.0",
  "@react-native-community/netinfo": "^11.0.0",  // Network state
  "react-native-background-fetch": "^4.2.0"      // Background tasks
}
```

---

### **Phase 6: Gossip Protocol Integration**

**Objective:** Enable mobile devices to participate in nullifier gossip network

**Tasks:**
1. **Port NullifierGossip:**
   - Use adapted HyperToken P2P layer
   - Implement mobile-optimized gossip strategy
   - Reduce gossip frequency when on cellular (to save data/battery)

2. **Implement Gossip Modes:**
   ```typescript
   export enum GossipMode {
     REALTIME = 'realtime',     // Full participation (WiFi, app active)
     BALANCED = 'balanced',     // Reduced frequency (cellular, app active)
     BATTERY_SAVER = 'battery', // Passive only (app backgrounded)
     OFFLINE = 'offline'        // No gossip, queue for later
   }
   ```

3. **Network Awareness:**
   - Automatically switch gossip mode based on:
     - Network type (WiFi vs cellular vs offline)
     - Battery level (< 20% → battery saver mode)
     - App state (foreground vs background)
   - Allow user manual override

4. **Data Usage Optimization:**
   - Compress gossip messages
   - Batch nullifier propagation
   - Implement bloom filters to avoid redundant transfers

**Key Deliverables:**
- [ ] Mobile devices can publish nullifiers to network
- [ ] Mobile devices receive nullifiers from peers
- [ ] Adaptive gossip based on network conditions
- [ ] Data usage tracking and limits
- [ ] Battery-optimized gossip modes

**Testing:**
- Measure battery drain with gossip enabled/disabled
- Test data usage over 24 hours of active gossip
- Validate nullifiers propagate between mobile and desktop peers

---

### **Phase 7: SDK API Design**

**Objective:** Create developer-friendly API for React Native apps

**High-Level API:**
```typescript
import { ScarcitySDK, WalletConfig } from '@scarcity/react-native';

// Initialize SDK
const sdk = await ScarcitySDK.initialize({
  federation: 'production',
  witness: {
    gateways: ['https://witness1.scarcity.network'],
    quorum: 1
  },
  freebird: {
    issuers: ['https://freebird1.scarcity.network']
  },
  gossip: {
    mode: 'balanced', // realtime | balanced | battery | offline
    peers: 3
  },
  network: {
    tor: {
      enabled: false,  // Optional Tor support (default: false)
      proxy: 'socks5://127.0.0.1:9050',  // Custom SOCKS proxy (Orbot default)
      fallbackToHttps: true  // Fallback to HTTPS if Tor unavailable
    },
    turn: {
      servers: [  // TURN relay servers for WebRTC
        {
          urls: 'stun:stun.l.google.com:19302'
        },
        {
          urls: 'turn:turn.scarcity.network:3478',
          username: 'scarcity',
          credential: 'relay-secret'
        }
      ]
    }
  },
  storage: {
    encryption: true,
    biometrics: true
  }
});

// Wallet Management
const wallet = await sdk.wallet.create('my-wallet', {
  password: 'optional-password',
  biometrics: true
});

await sdk.wallet.setDefault('my-wallet');
const wallets = await sdk.wallet.list();
const exported = await sdk.wallet.export('my-wallet', { password: 'pwd' });

// Token Operations
const mintResult = await sdk.token.mint({
  amount: 1000,
  metadata: { note: 'Coffee money' }
});

const transferResult = await sdk.token.transfer({
  to: 'recipient-public-key',
  amount: 500,
  memo: 'Here you go!'
});

const balance = await sdk.token.getBalance();
// { total: 500, tokens: [...] }

const history = await sdk.token.getHistory({ limit: 20 });
// [{ type: 'mint', amount: 1000, timestamp: ... }, ...]

// Gossip Network
await sdk.gossip.start();
await sdk.gossip.setMode('battery');
const stats = await sdk.gossip.getStats();
// { peers: 3, nullifiersReceived: 142, ... }

// Event Listeners
sdk.on('transfer:received', (transfer) => {
  console.log(`Received ${transfer.amount} from ${transfer.from}`);
});

sdk.on('gossip:nullifier', (nullifier) => {
  console.log('New nullifier detected:', nullifier.hex);
});

sdk.on('network:offline', () => {
  console.log('Network offline - operations queued');
});
```

**React Hooks API:**
```typescript
import { useWallet, useBalance, useGossip } from '@scarcity/react-native';

function WalletScreen() {
  const { wallet, createWallet, importWallet } = useWallet();
  const { balance, isLoading } = useBalance();
  const { peers, mode, setMode } = useGossip();

  return (
    <View>
      <Text>Balance: {balance.total}</Text>
      <Text>Peers: {peers}</Text>
      <Button
        title="Switch to Battery Saver"
        onPress={() => setMode('battery')}
      />
    </View>
  );
}
```

**Key Deliverables:**
- [ ] Complete TypeScript API surface
- [ ] React hooks for common operations
- [ ] Event emitter for real-time updates
- [ ] Comprehensive JSDoc documentation
- [ ] TypeScript declaration files

---

### **Phase 8: Example Application**

**Objective:** Build reference implementation demonstrating SDK usage

**Features:**
1. **Onboarding Flow:**
   - Create new wallet or import existing
   - Biometric setup
   - Backup seed phrase

2. **Main Wallet Screen:**
   - Display balance (total + by denomination)
   - Transaction history
   - Gossip network status (peers, mode)

3. **Transfer Flow:**
   - Scan QR code for recipient
   - Enter amount
   - Preview transfer (fees, privacy info)
   - Confirm with biometrics
   - Show real-time status (blinding, timestamping, gossip)

4. **Settings:**
   - Manage wallets
   - Configure gossip mode
   - View data usage / battery stats
   - Export/backup wallet
   - Federation settings (witness, freebird endpoints)

5. **Developer Tools:**
   - Mint test tokens (testnet only)
   - View raw token proofs
   - Debug gossip network
   - Network request logs

**Tech Stack:**
```json
{
  "react-native": "^0.74.0",
  "@react-navigation/native": "^6.1.0",
  "react-native-camera": "^4.2.0",       // QR code scanning
  "react-native-qrcode-svg": "^6.3.0",   // QR code generation
  "react-native-charts": "^7.5.0"        // Usage graphs
}
```

**Key Deliverables:**
- [ ] Fully functional wallet app
- [ ] QR code send/receive
- [ ] Biometric authentication
- [ ] Transaction history
- [ ] Settings and configuration
- [ ] TestFlight (iOS) and Google Play Beta (Android) builds

---

### **Phase 9: Testing & Optimization**

**Objective:** Ensure SDK is production-ready

**Testing Strategy:**

1. **Unit Tests:**
   - All core modules (token, crypto, gossip, validator)
   - Storage adapters
   - Network adapters
   - Mock integrations for offline testing

2. **Integration Tests:**
   - End-to-end token transfers
   - Gossip propagation between mobile and desktop
   - Network failure scenarios
   - Offline queue and sync

3. **Device Testing:**
   - iOS: iPhone 12+ (minimum iOS 14)
   - Android: Pixel 4+ and Samsung Galaxy (minimum Android 10)
   - Low-end devices (budget Android phones)
   - Tablets (iPad, Android tablets)

4. **Performance Benchmarks:**
   - Crypto operation speed (P-256, BLS12-381)
   - Transfer latency (mint, transfer, validation)
   - Memory usage (idle, active gossip)
   - Battery drain (1 hour, 24 hours)
   - Network data usage

5. **Security Audit:**
   - Key storage security review
   - Crypto implementation audit
   - Network security (TLS pinning, certificate validation)
   - Code obfuscation for production builds

**Optimization Tasks:**
- [ ] Lazy-load crypto libraries to reduce startup time
- [ ] Implement connection pooling for HTTP requests
- [ ] Optimize gossip message batching
- [ ] Add ProGuard/R8 (Android) and symbol stripping (iOS)
- [ ] Implement app-level caching for frequent queries

**Key Deliverables:**
- [ ] >90% code coverage for core modules
- [ ] Performance benchmarks documented
- [ ] Security audit report
- [ ] Battery/network usage analysis
- [ ] Device compatibility matrix

---

### **Phase 10: Documentation & Release**

**Objective:** Publish SDK and enable developer adoption

**Documentation:**

1. **Getting Started Guide:**
   ```bash
   # Install SDK
   npm install @scarcity/react-native

   # Link native dependencies
   cd ios && pod install

   # Start development
   npm run android  # or npm run ios
   ```

2. **API Reference:**
   - Complete API documentation generated from TypeScript
   - Code examples for every method
   - Common patterns and recipes

3. **Integration Guides:**
   - "Add Scarcity to existing React Native app"
   - "Configure production federation endpoints"
   - "Implement custom UI with SDK hooks"
   - "Handle deep links for payment requests"

4. **Architecture Deep Dive:**
   - How gossip works on mobile
   - Privacy guarantees and threat model
   - Battery optimization strategies
   - Network resilience and offline support

5. **Migration Guides:**
   - "Migrate from web wallet to mobile"
   - "Import CLI wallet to mobile app"

**Release Checklist:**
- [ ] Publish to npm: `@scarcity/react-native`
- [ ] Publish example app to App Store and Google Play (as demo)
- [ ] Create GitHub releases with changelog
- [ ] Publish documentation website
- [ ] Create video tutorials
- [ ] Write blog post announcing mobile SDK
- [ ] Submit to React Native directory

**Versioning:**
- Follow Semantic Versioning (semver)
- Start with `v0.1.0-beta` for initial release
- Stabilize to `v1.0.0` after community feedback

---

## Technical Decisions

### **Storage: MMKV vs SQLite**

| Feature | MMKV | SQLite |
|---------|------|--------|
| Performance | ⚡ Very fast (mmap-based) | 🐢 Slower for KV access |
| Queries | ❌ Key-value only | ✅ Complex queries, indexes |
| Encryption | ✅ Built-in AES | ⚠️ Requires SQLCipher |
| Size | 📦 Small footprint | 📦 Larger binary |
| Use Case | Wallet data, settings | Transaction history, search |

**Decision:** Use **MMKV for wallet/token storage** (fast, encrypted), **SQLite for transaction history** (queryable).

### **Crypto: Web Crypto API vs Native Modules**

| Approach | Pros | Cons |
|----------|------|------|
| `@noble/curves` (pure JS) | ✅ Works everywhere, no native deps | ⚠️ Slower on low-end devices |
| `react-native-quick-crypto` | ⚡ Faster (native), drop-in replacement | 📦 Larger app size |
| Custom native bridge | ⚡ Maximum performance | 🛠️ High maintenance, platform-specific |

**Decision:** Start with **`@noble/curves`**, benchmark, and switch to **`react-native-quick-crypto`** if performance is insufficient.

### **Networking: Background Gossip Strategy**

| Mode | When | Behavior |
|------|------|----------|
| Real-time | WiFi + foreground | Full gossip, all peers active |
| Balanced | Cellular + foreground | Reduced frequency, fewer peers |
| Battery Saver | Backgrounded | Passive only, no active broadcasts |
| Offline | Airplane mode | Queue operations, sync later |

**Decision:** Default to **Balanced mode**, auto-switch based on network/battery.

### **WebRTC: Direct P2P vs TURN Relay**

**Challenge:** Cellular networks have strict NAT, direct P2P often fails.

**Solution:**
1. Attempt direct P2P connection first
2. Fall back to TURN relay if direct fails
3. Deploy public TURN servers (co-located with Witness gateways)
4. Support custom TURN servers in SDK config

**TURN Server Setup:**
```json
{
  "iceServers": [
    { "urls": "stun:stun.l.google.com:19302" },
    {
      "urls": "turn:turn.scarcity.network:3478",
      "username": "scarcity",
      "credential": "relay-secret"
    }
  ]
}
```

---

## Dependencies Summary

### **Core Dependencies:**
```json
{
  "@noble/curves": "^1.9.7",
  "@noble/hashes": "^1.4.0",
  "react-native": "^0.74.0",
  "react-native-webrtc": "^124.0.0",
  "react-native-mmkv": "^3.0.0",
  "react-native-keychain": "^8.2.0",
  "react-native-quick-crypto": "^0.7.0",
  "react-native-biometrics": "^3.0.0",
  "@react-native-community/netinfo": "^11.0.0",
  "react-native-background-fetch": "^4.2.0",
  "bip39": "^3.1.0",
  "react-native-tcp-socket": "^6.0.0",  // For SOCKS proxy (Tor support)
  "socks": "^2.8.0"  // SOCKS5 client for Tor/Orbot integration
}
```

### **Development Dependencies:**
```json
{
  "@types/react": "^18.2.0",
  "@types/react-native": "^0.74.0",
  "jest": "^29.7.0",
  "@testing-library/react-native": "^12.4.0",
  "detox": "^20.0.0",
  "typescript": "^5.3.0"
}
```

---

## Success Metrics

### **Phase 1-3 (Foundation):**
- [ ] SDK compiles on React Native without errors
- [ ] All crypto unit tests passing
- [ ] Wallet creation working on iOS and Android
- [ ] Token storage and retrieval working

### **Phase 4-6 (Networking):**
- [ ] Freebird blinding completes in <2 seconds
- [ ] Witness timestamp completes in <3 seconds
- [ ] Gossip connects to at least 3 peers
- [ ] Nullifiers propagate to network within 10 seconds

### **Phase 7-8 (API & App):**
- [ ] End-to-end transfer completes in <10 seconds
- [ ] Example app passes App Store and Google Play review
- [ ] SDK documentation complete and published

### **Phase 9-10 (Production):**
- [ ] Battery drain <5% per hour with active gossip
- [ ] Network data usage <10 MB per day
- [ ] Zero critical security vulnerabilities
- [ ] Successful transfers on 100+ device/OS combinations

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| **WebRTC on cellular fails** | High | Deploy TURN relay servers |
| **Crypto too slow on old Android** | Medium | Use `react-native-quick-crypto` |
| **iOS background limits kill gossip** | Medium | Use push notifications for alerts |
| **App Store rejects crypto app** | High | Emphasize privacy, not anonymity; comply with export regulations |
| **Battery drain complaints** | Medium | Default to battery-optimized mode, educate users |
| **Large app size (>50 MB)** | Low | Strip debug symbols, use ProGuard/R8 |

---

## Confirmed Design Decisions

The following questions have been resolved:

1. **Tor Support on Mobile** ✅ **APPROVED**
   - Will support Tor via Orbot (Android) or custom SOCKS proxy
   - Optional feature, disabled by default to preserve battery
   - Users can enable in settings for maximum privacy

2. **SDK Strategy** ✅ **SDK-ONLY**
   - Provide core SDK without UI components
   - Developers build their own custom UI
   - Keeps SDK lightweight and flexible
   - _UI component library may be added in future versions_

3. **React Native Web Support** ✅ **APPROVED**
   - Target React Native Web for code sharing with web wallet
   - Single codebase for mobile (iOS/Android) and web
   - Requires WebRTC polyfills for web platform
   - Enables unified developer experience across platforms

4. **TURN Server Strategy** ✅ **PUBLIC + CUSTOMIZABLE**
   - Deploy public TURN relay servers (default endpoints)
   - Allow users to configure custom TURN servers
   - Provide fallback to public servers if custom servers fail
   - Document TURN server setup for self-hosting

5. **Distribution Strategy** ✅ **SDK-ONLY**
   - Publish SDK to npm: `@scarcity/react-native`
   - No reference app published to App Store/Google Play
   - Developers build and publish their own apps
   - Provide example app in repository for reference

## Open Questions

The following remain to be decided:

1. **How to handle app updates with active gossip connections?**
   - Need graceful shutdown and reconnect
   - **Recommendation:** Implement connection migration protocol

2. **Should we support hardware wallets (Ledger, etc.)?**
   - High security for large balances
   - Complex integration, small user base initially
   - **Recommendation:** Defer to v2.0

---

## Next Steps

To begin Mobile SDK development:

1. **Immediate (Weeks 1-2):**
   - Create React Native library scaffold
   - Set up monorepo with example app
   - Install and test `@noble/curves` on real devices
   - Benchmark crypto performance

2. **Short-term (Weeks 3-6):**
   - Extract core modules (token, crypto, gossip)
   - Implement mobile storage adapters
   - Port Freebird and Witness HTTP clients
   - Create wallet management API

3. **Medium-term (Weeks 7-12):**
   - Port HyperToken WebRTC/WebSocket layer
   - Implement gossip network integration
   - Build example wallet app
   - Comprehensive testing on real devices

4. **Long-term (Weeks 13+):**
   - Security audit
   - Performance optimization
   - Documentation and tutorials
   - Beta release and community feedback

---

## Stakeholder Decisions ✅

**Core decisions confirmed:**

1. ✅ **Target Platforms:** iOS + Android + React Native Web
2. ✅ **TURN Servers:** Deploy public TURN relays with user customization support
3. ✅ **Distribution:** SDK-only release (npm package, no app stores)
4. ✅ **Tor Support:** Include for v1.0 (optional, disabled by default)
5. ✅ **SDK Strategy:** SDK-only, no UI component library for v1.0

**Remaining questions:**

1. **Minimum OS Versions:** iOS 14+, Android 10+? (needs confirmation)
2. **Timeline:** Are there any hard deadlines or milestones?

---

**Status:** ✅ **APPROVED - Ready to begin Phase 1**
**Estimated Effort:** 10-14 weeks for v1.0-beta
**Next Milestone:** Phase 1 completion (foundation + crypto validation)
**Platforms:** iOS + Android + Web (React Native Web)
