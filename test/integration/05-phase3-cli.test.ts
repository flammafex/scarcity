/**
 * Integration Test: Phase 3 CLI Operations
 *
 * Tests the CLI commands for Phase 3 advanced features:
 * - HTLC commands (create, claim, refund)
 * - Bridge commands (transfer, claim)
 * - Token commands (split, merge, multiparty)
 */

import {
  ScarbuckToken,
  NullifierGossip,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter,
  Crypto,
  FederationBridge,
  type PublicKey,
  type HTLCCondition
} from '../../src/index.js';

import { TokenStorage } from '../../src/cli/token-store.js';
import { WalletManager } from '../../src/cli/wallet.js';
import { ConfigManager } from '../../src/cli/config.js';
import { TestRunner, createTestKeyPair, sleep, TestConfig } from '../helpers/test-utils.js';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';

export async function runPhase3CLITests(): Promise<any> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Phase 3 CLI Operations');
  console.log('='.repeat(60) + '\n');

  // Create temporary test directory
  const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scarcity-test-'));
  const configPath = path.join(testDir, 'config.json');
  const walletsPath = path.join(testDir, 'wallets.json');
  const tokensPath = path.join(testDir, 'tokens.json');

  // Setup test infrastructure
  const freebird = new FreebirdAdapter({
    issuerEndpoints: [TestConfig.freebird.issuer],
    verifierUrl: TestConfig.freebird.verifier
  });

  const witness = new WitnessAdapter({
    gatewayUrl: TestConfig.witness.gateway,
    networkId: 'gateway-1'
  });

  const hypertoken = new HyperTokenAdapter({
    relayUrl: TestConfig.hypertoken.relay
  });

  const gossip = new NullifierGossip({
    witness
  });

  // Setup CLI managers with custom paths
  const tokenStorage = new TokenStorage(tokensPath);
  const walletManager = new WalletManager(walletsPath);
  const configManager = new ConfigManager(configPath);

  // Create test wallets
  let alice: PublicKey;
  let bob: PublicKey;
  let charlie: PublicKey;
  let aliceSecret: Uint8Array;
  let bobSecret: Uint8Array;
  let charlieSecret: Uint8Array;

  await runner.run('Initialize test wallets', async () => {
    const aliceWallet = walletManager.createWallet('alice', true);
    const bobWallet = walletManager.createWallet('bob', false);
    const charlieWallet = walletManager.createWallet('charlie', false);

    alice = { bytes: Crypto.fromHex(aliceWallet.publicKey) };
    bob = { bytes: Crypto.fromHex(bobWallet.publicKey) };
    charlie = { bytes: Crypto.fromHex(charlieWallet.publicKey) };

    aliceSecret = Crypto.fromHex(aliceWallet.secretKey);
    bobSecret = Crypto.fromHex(bobWallet.secretKey);
    charlieSecret = Crypto.fromHex(charlieWallet.secretKey);

    const wallets = walletManager.listWallets();
    runner.assertEquals(wallets.length, 3, 'Should have 3 wallets');
  });

  // Create test tokens for Alice
  let aliceToken: ScarbuckToken;
  let aliceTokenId: string;

  await runner.run('Create test token for Alice', async () => {
    aliceToken = new ScarbuckToken({
      id: Crypto.toHex(Crypto.randomBytes(16)),
      amount: 100,
      secret: aliceSecret,
      freebird,
      witness,
      gossip
    });

    const metadata = aliceToken.getMetadata();
    aliceTokenId = metadata.id;

    // Store token
    tokenStorage.addToken({
      id: metadata.id,
      amount: metadata.amount,
      secretKey: Crypto.toHex(aliceSecret),
      wallet: 'alice',
      created: Date.now(),
      spent: false,
      metadata: { type: 'minted' }
    });

    const stored = tokenStorage.getToken(aliceTokenId);
    runner.assert(stored !== null, 'Token should be stored');
    runner.assertEquals(stored!.amount, 100, 'Token amount should be 100');
  });

  // Test 1: Token Split Operation
  await runner.run('CLI: Token split operation', async () => {
    const amounts = [30, 40, 30];
    const recipients = [alice, bob, charlie];

    // Perform split
    const splitPkg = await aliceToken.split(amounts, recipients);

    runner.assertEquals(splitPkg.splits.length, 3, 'Should have 3 splits');
    runner.assertEquals(splitPkg.sourceAmount, 100, 'Source amount should be 100');

    const totalAmount = splitPkg.splits.reduce((sum, s) => sum + s.amount, 0);
    runner.assertEquals(totalAmount, 100, 'Total split amounts should equal source');

    // Mark original as spent
    tokenStorage.markSpent(aliceTokenId);
    const spentToken = tokenStorage.getToken(aliceTokenId);
    runner.assert(spentToken!.spent, 'Original token should be marked spent');

    // Store split tokens
    splitPkg.splits.forEach((split, idx) => {
      const walletName = idx === 0 ? 'alice' : idx === 1 ? 'bob' : 'charlie';
      const secretKey = idx === 0 ? aliceSecret : idx === 1 ? bobSecret : charlieSecret;
      tokenStorage.addToken({
        id: split.tokenId,
        amount: split.amount,
        secretKey: Crypto.toHex(secretKey),
        wallet: walletName,
        created: Date.now(),
        spent: false,
        metadata: { type: 'received', source: 'split' }
      });
    });

    const bobTokens = tokenStorage.listTokens({ wallet: 'bob', spent: false });
    runner.assertEquals(bobTokens.length, 1, 'Bob should have 1 token');
    runner.assertEquals(bobTokens[0].amount, 40, 'Bob token should be 40');
  });

  // Test 2: Token Merge Operation
  await runner.run('CLI: Token merge operation', async () => {
    // Get Alice's split tokens (should have 30)
    const aliceTokens = tokenStorage.listTokens({ wallet: 'alice', spent: false });
    const bobTokens = tokenStorage.listTokens({ wallet: 'bob', spent: false });

    runner.assertGreaterThan(aliceTokens.length, 0, 'Alice should have tokens');
    runner.assertGreaterThan(bobTokens.length, 0, 'Bob should have tokens');

    // Recreate tokens from storage
    const tokensToMerge = [
      new ScarbuckToken({
        id: aliceTokens[0].id,
        amount: aliceTokens[0].amount,
        secret: Crypto.fromHex(aliceTokens[0].secretKey),
        freebird,
        witness,
        gossip
      }),
      new ScarbuckToken({
        id: bobTokens[0].id,
        amount: bobTokens[0].amount,
        secret: Crypto.fromHex(bobTokens[0].secretKey),
        freebird,
        witness,
        gossip
      })
    ];

    // Perform merge
    const mergePkg = await ScarbuckToken.merge(tokensToMerge, alice);

    runner.assertEquals(mergePkg.targetAmount, 70, 'Merged amount should be 70');
    runner.assertEquals(mergePkg.sources.length, 2, 'Should have 2 source tokens');

    // Mark sources as spent
    [aliceTokens[0], bobTokens[0]].forEach(t => tokenStorage.markSpent(t.id));

    // Store merged token
    tokenStorage.addToken({
      id: mergePkg.targetTokenId,
      amount: mergePkg.targetAmount,
      secretKey: Crypto.toHex(aliceSecret),
      wallet: 'alice',
      created: Date.now(),
      spent: false,
      metadata: { type: 'received', source: 'merge' }
    });

    const aliceBalance = tokenStorage.getBalance('alice');
    runner.assertGreaterThan(aliceBalance, 0, 'Alice should have positive balance');
  });

  // Test 3: Multi-party Transfer
  await runner.run('CLI: Multi-party transfer', async () => {
    // Get one of Alice's tokens (merged token with 70)
    const aliceTokens = tokenStorage.listTokens({ wallet: 'alice', spent: false });
    runner.assertGreaterThan(aliceTokens.length, 0, 'Alice should have tokens');

    const sourceToken = new ScarbuckToken({
      id: aliceTokens[0].id,
      amount: aliceTokens[0].amount,
      secret: Crypto.fromHex(aliceTokens[0].secretKey),
      freebird,
      witness,
      gossip
    });

    // Multi-party transfer: 20 to Bob, 30 to Charlie, 20 to Alice
    const recipients = [
      { publicKey: bob, amount: 20 },
      { publicKey: charlie, amount: 30 },
      { publicKey: alice, amount: 20 }
    ];

    const multiPartyPkg = await sourceToken.transferMultiParty(recipients);

    runner.assertEquals(multiPartyPkg.recipients.length, 3, 'Should have 3 recipients');
    runner.assertEquals(multiPartyPkg.sourceAmount, 70, 'Source amount should be 70');

    const totalTransferred = multiPartyPkg.recipients.reduce((sum, r) => sum + r.amount, 0);
    runner.assertEquals(totalTransferred, 70, 'Total transferred should equal source');

    // Mark source as spent
    tokenStorage.markSpent(aliceTokens[0].id);

    // Store received tokens
    multiPartyPkg.recipients.forEach((recipient, idx) => {
      const walletName = idx === 0 ? 'bob' : idx === 1 ? 'charlie' : 'alice';
      const secretKey = idx === 0 ? bobSecret : idx === 1 ? charlieSecret : aliceSecret;
      tokenStorage.addToken({
        id: recipient.tokenId,
        amount: recipient.amount,
        secretKey: Crypto.toHex(secretKey),
        wallet: walletName,
        created: Date.now(),
        spent: false,
        metadata: { type: 'received', source: 'multiparty' }
      });
    });

    const charlieBalance = tokenStorage.getBalance('charlie');
    runner.assertGreaterThan(charlieBalance, 0, 'Charlie should have positive balance');
  });

  // Test 4: HTLC Creation with Hash Lock
  let htlcPackage: any;
  let htlcPreimage: Uint8Array;

  await runner.run('CLI: Create hash-locked HTLC', async () => {
    const bobTokens = tokenStorage.listTokens({ wallet: 'bob', spent: false });
    runner.assertGreaterThan(bobTokens.length, 0, 'Bob should have tokens');

    const bobToken = new ScarbuckToken({
      id: bobTokens[0].id,
      amount: bobTokens[0].amount,
      secret: Crypto.fromHex(bobTokens[0].secretKey),
      freebird,
      witness,
      gossip
    });

    // Generate preimage and hash
    htlcPreimage = Crypto.randomBytes(32); // Use random bytes as preimage
    const hashLock = Crypto.hashString(Crypto.toHex(htlcPreimage));

    const condition: HTLCCondition = {
      type: 'hash',
      hashlock: hashLock
    };

    htlcPackage = await bobToken.transferHTLC(charlie, condition);

    runner.assertEquals(htlcPackage.condition.type, 'hash', 'Should be hash-locked');
    runner.assertEquals(htlcPackage.condition.hashlock, hashLock, 'Hash should match');
    runner.assertEquals(htlcPackage.amount, bobTokens[0].amount, 'Amount should match');

    // Mark as spent
    tokenStorage.markSpent(bobTokens[0].id);
  });

  // Test 5: HTLC Claim with Preimage
  await runner.run('CLI: Claim HTLC with preimage', async () => {
    // Verify preimage
    const computedHash = Crypto.hashString(Crypto.toHex(htlcPreimage));
    runner.assertEquals(computedHash, htlcPackage.condition.hashlock, 'Preimage should match hash');

    // Claim HTLC
    const claimedToken = await ScarbuckToken.receiveHTLC(
      htlcPackage,
      charlieSecret,
      htlcPreimage,
      freebird,
      witness,
      gossip
    );

    const metadata = claimedToken.getMetadata();
    runner.assertEquals(metadata.amount, htlcPackage.amount, 'Claimed amount should match');

    // Store claimed token
    tokenStorage.addToken({
      id: metadata.id,
      amount: metadata.amount,
      secretKey: Crypto.toHex(charlieSecret),
      wallet: 'charlie',
      created: Date.now(),
      spent: false,
      metadata: { type: 'received', source: 'htlc' }
    });

    const charlieBalance = tokenStorage.getBalance('charlie');
    runner.assertGreaterThan(charlieBalance, 30, 'Charlie should have increased balance');
  });

  // Test 6: HTLC Creation with Time Lock
  let timeLockedHTLC: any;

  await runner.run('CLI: Create time-locked HTLC', async () => {
    const charlieTokens = tokenStorage.listTokens({ wallet: 'charlie', spent: false });
    runner.assertGreaterThan(charlieTokens.length, 0, 'Charlie should have tokens');

    const charlieToken = new ScarbuckToken({
      id: charlieTokens[0].id,
      amount: charlieTokens[0].amount,
      secret: Crypto.fromHex(charlieTokens[0].secretKey),
      freebird,
      witness,
      gossip
    });

    // Create time lock that expires in 2 seconds (use milliseconds)
    const timeLock = Date.now() + 2000;

    const condition: HTLCCondition = {
      type: 'time',
      timelock: timeLock
    };

    timeLockedHTLC = await charlieToken.transferHTLC(alice, condition, charlie);

    runner.assertEquals(timeLockedHTLC.condition.type, 'time', 'Should be time-locked');
    runner.assertEquals(timeLockedHTLC.condition.timelock, timeLock, 'Time lock should match');

    // Mark as spent
    tokenStorage.markSpent(charlieTokens[0].id);
  });

  // Test 7: HTLC Refund after Timeout
  await runner.run('CLI: Refund expired time-locked HTLC', async () => {
    // Wait for time lock to expire
    console.log('   Waiting for time lock to expire...');
    await sleep(2500);

    const currentTime = Date.now();
    runner.assertGreaterThan(currentTime, timeLockedHTLC.condition.timelock, 'Time lock should be expired');

    // Refund HTLC
    const refundedToken = await ScarbuckToken.refundHTLC(
      timeLockedHTLC,
      charlieSecret,
      freebird,
      witness,
      gossip
    );

    const metadata = refundedToken.getMetadata();
    runner.assertEquals(metadata.amount, timeLockedHTLC.amount, 'Refunded amount should match');

    // Store refunded token
    tokenStorage.addToken({
      id: metadata.id,
      amount: metadata.amount,
      secretKey: Crypto.toHex(charlieSecret),
      wallet: 'charlie',
      created: Date.now(),
      spent: false,
      metadata: { type: 'received', source: 'htlc-refund' }
    });
  });

  // Test 8: Bridge Transfer (Cross-Federation)
  let bridgePackage: any;

  await runner.run('CLI: Bridge token to target federation', async () => {
    // Setup target federation (separate gateway for cross-federation testing)
    const targetWitness = new WitnessAdapter({
      gatewayUrl: TestConfig.witness.gateway2,
      networkId: 'gateway-2'
    });

    const targetGossip = new NullifierGossip({
      witness: targetWitness
    });

    const bridge = new FederationBridge({
      sourceFederation: 'gateway-1',
      targetFederation: 'gateway-2',
      sourceWitness: witness,
      targetWitness,
      sourceGossip: gossip,
      targetGossip,
      freebird
    });

    // Get Alice's token
    const aliceTokens = tokenStorage.listTokens({ wallet: 'alice', spent: false });
    runner.assertGreaterThan(aliceTokens.length, 0, 'Alice should have tokens');

    const aliceToken = new ScarbuckToken({
      id: aliceTokens[0].id,
      amount: aliceTokens[0].amount,
      secret: Crypto.fromHex(aliceTokens[0].secretKey),
      freebird,
      witness,
      gossip
    });

    // Bridge token
    bridgePackage = await bridge.bridgeToken(aliceToken, bob);

    runner.assertEquals(bridgePackage.sourceFederation, 'gateway-1', 'Source federation should match');
    runner.assertEquals(bridgePackage.targetFederation, 'gateway-2', 'Target federation should match');
    runner.assertEquals(bridgePackage.amount, aliceTokens[0].amount, 'Amount should match');

    // Mark as spent
    tokenStorage.markSpent(aliceTokens[0].id);
  });

  // Test 9: Package Serialization/Deserialization
  await runner.run('CLI: Package JSON serialization', async () => {
    // Test HTLC package serialization
    const htlcJson = JSON.stringify({
      type: 'htlc',
      tokenId: htlcPackage.tokenId,
      amount: htlcPackage.amount,
      commitment: Crypto.toHex(htlcPackage.commitment),
      condition: htlcPackage.condition,
      nullifier: Crypto.toHex(htlcPackage.nullifier),
      proof: htlcPackage.proof,
      ownershipProof: htlcPackage.ownershipProof ? Crypto.toHex(htlcPackage.ownershipProof) : undefined
    });

    const parsed = JSON.parse(htlcJson);
    runner.assertEquals(parsed.type, 'htlc', 'Type should be preserved');
    runner.assertEquals(parsed.amount, htlcPackage.amount, 'Amount should be preserved');

    // Test bridge package serialization
    const bridgeJson = JSON.stringify({
      type: 'bridge',
      sourceTokenId: bridgePackage.sourceTokenId,
      sourceFederation: bridgePackage.sourceFederation,
      targetFederation: bridgePackage.targetFederation,
      amount: bridgePackage.amount,
      commitment: Crypto.toHex(bridgePackage.commitment),
      nullifier: Crypto.toHex(bridgePackage.nullifier),
      sourceProof: bridgePackage.sourceProof,
      targetProof: bridgePackage.targetProof,
      ownershipProof: bridgePackage.ownershipProof ? Crypto.toHex(bridgePackage.ownershipProof) : undefined
    });

    const parsedBridge = JSON.parse(bridgeJson);
    runner.assertEquals(parsedBridge.type, 'bridge', 'Bridge type should be preserved');
    runner.assertEquals(parsedBridge.sourceFederation, 'gateway-1', 'Source federation should be preserved');
  });

  // Test 10: Token Storage Queries
  await runner.run('CLI: Token storage queries', async () => {
    // Test balance calculation
    const aliceBalance = tokenStorage.getBalance('alice');
    const bobBalance = tokenStorage.getBalance('bob');
    const charlieBalance = tokenStorage.getBalance('charlie');

    console.log(`   Alice balance: ${aliceBalance}`);
    console.log(`   Bob balance: ${bobBalance}`);
    console.log(`   Charlie balance: ${charlieBalance}`);

    runner.assert(aliceBalance >= 0, 'Alice balance should be non-negative');
    runner.assert(bobBalance >= 0, 'Bob balance should be non-negative');
    runner.assert(charlieBalance >= 0, 'Charlie balance should be non-negative');

    // Test filtering
    const allTokens = tokenStorage.listTokens();
    const spentTokens = tokenStorage.listTokens({ spent: true });
    const unspentTokens = tokenStorage.listTokens({ spent: false });

    runner.assertEquals(allTokens.length, spentTokens.length + unspentTokens.length, 'All tokens should equal spent + unspent');

    // Test wallet filtering
    const aliceTokens = tokenStorage.listTokens({ wallet: 'alice' });
    runner.assertGreaterThan(aliceTokens.length, 0, 'Alice should have tokens (spent or unspent)');
  });

  // Cleanup
  await runner.run('Cleanup test directory', async () => {
    await fs.rm(testDir, { recursive: true, force: true });
    runner.assert(true, 'Test directory cleaned up');
  });

  // Print summary
  runner.printSummary();

  return runner.getSummary();
}

// Run tests if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runPhase3CLITests()
    .then(summary => {
      process.exit(summary.failed > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('Test suite failed:', error);
      process.exit(1);
    });
}