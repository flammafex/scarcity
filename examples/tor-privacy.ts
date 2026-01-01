/**
 * Example: Tor Onion Service Support
 *
 * Demonstrates how to use Scarcity with Tor hidden services (.onion addresses)
 * for maximum privacy and censorship resistance.
 */

import {
  ScarceToken,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter,
  NullifierGossip,
  TorProxy,
  configureTor
} from '../dist/index.js';

async function main() {
  console.log('═══════════════════════════════════════════════');
  console.log('Tor Onion Service Integration Example');
  console.log('═══════════════════════════════════════════════\n');

  // Option 1: Global Tor configuration
  console.log('1. Configuring global Tor proxy...');
  configureTor({
    proxyHost: 'localhost',
    proxyPort: 9050,          // Default Tor SOCKS port
    forceProxy: false         // Only use Tor for .onion addresses
  });

  // Option 2: Per-adapter Tor configuration
  console.log('2. Creating adapters with .onion addresses...\n');

  // Freebird with .onion address
  const freebird = new FreebirdAdapter({
    issuerUrl: 'http://freebirdissuer123456.onion',      // Example .onion address
    verifierUrl: 'http://freebirdverifier789.onion',
    tor: {
      proxyHost: 'localhost',
      proxyPort: 9050
    }
  });

  // Witness with .onion address
  const witness = new WitnessAdapter({
    gatewayUrl: 'http://witnessgateway456.onion',        // Example .onion address
    networkId: 'scarcity-tor-network',
    tor: {
      proxyHost: 'localhost',
      proxyPort: 9050
    }
  });

  // HyperToken (Note: WebSocket over SOCKS5 requires additional setup)
  const hypertoken = new HyperTokenAdapter({
    relayUrl: 'ws://localhost:8080'  // Currently limited to clearnet
  });

  console.log('✅ Adapters configured for Tor\n');

  // Check Tor connection
  console.log('3. Checking Tor connectivity...');
  const torProxy = new TorProxy();
  const isTorConnected = await torProxy.checkConnection();

  if (isTorConnected) {
    console.log('✅ Tor is running and connected\n');
  } else {
    console.warn('⚠️  Tor not detected. Install and start Tor:');
    console.warn('   Ubuntu/Debian: sudo apt install tor && sudo service tor start');
    console.warn('   macOS: brew install tor && brew services start tor');
    console.warn('   Or download from: https://www.torproject.org/download/\n');
    console.warn('   Continuing with fallback mode...\n');
  }

  // Create gossip network
  const gossip = new NullifierGossip({ witness });

  // Mint a token (will use fallback if Tor services aren't available)
  console.log('4. Minting token with privacy-enhanced services...');
  const token = ScarceToken.mint(100, freebird, witness, gossip);
  console.log(`✅ Token minted: ${token.getMetadata().id}\n`);

  // Privacy benefits
  console.log('═══════════════════════════════════════════════');
  console.log('Privacy Benefits with Tor:');
  console.log('═══════════════════════════════════════════════');
  console.log('✓ Hidden IP address (Tor anonymity)');
  console.log('✓ Unlinkable sender/receiver (Freebird VOPRF)');
  console.log('✓ No transaction graph (no blockchain)');
  console.log('✓ Censorship-resistant (.onion services)');
  console.log('✓ End-to-end encryption (Tor + VOPRF)');
  console.log('');

  console.log('═══════════════════════════════════════════════');
  console.log('Deployment Considerations:');
  console.log('═══════════════════════════════════════════════');
  console.log('1. Run your own Freebird issuer as hidden service');
  console.log('2. Run your own Witness gateway as hidden service');
  console.log('3. Use multiple .onion mirrors for redundancy');
  console.log('4. Configure hidden service in /etc/tor/torrc:');
  console.log('   HiddenServiceDir /var/lib/tor/scarcity/');
  console.log('   HiddenServicePort 8080 127.0.0.1:8080');
  console.log('');

  // Graceful degradation
  console.log('═══════════════════════════════════════════════');
  console.log('Graceful Degradation:');
  console.log('═══════════════════════════════════════════════');
  console.log('If Tor or .onion services are unavailable:');
  console.log('✓ Automatically falls back to clearnet URLs');
  console.log('✓ Simulated crypto for testing');
  console.log('✓ No crashes or failures');
  console.log('✓ Warnings logged for visibility');
  console.log('');

  gossip.destroy();
  torProxy.destroy();
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
