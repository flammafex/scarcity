/**
 * Integration Test: Live Services (No Fallback)
 *
 * Verifies that all external services are running and that Scarcity
 * communicates with them for real. Fails immediately if any service
 * is unreachable — no silent fallbacks.
 *
 * Required services:
 *   - Freebird Issuer   (FREEBIRD_ISSUER_URL)
 *   - Freebird Verifier (FREEBIRD_VERIFIER_URL)
 *   - Witness Gateway   (WITNESS_GATEWAY_URL)
 *   - HyperToken Relay  (HYPERTOKEN_RELAY_URL)
 */

import {
  ScarbuckToken,
  NullifierGossip,
  TransferValidator,
  FreebirdAdapter,
  WitnessAdapter,
  HyperTokenAdapter
} from '../../src/index.js';

import { TestRunner, createTestKeyPair, sleep, TestConfig } from '../helpers/test-utils.js';

export async function runLiveServicesTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Live Services (No Fallback)');
  console.log('='.repeat(60) + '\n');

  // ── Pre-flight: verify every service is reachable ──────────────

  let issuerMeta: any;

  await runner.run('Freebird Issuer reachable', async () => {
    const res = await fetch(`${TestConfig.freebird.issuer}/.well-known/issuer`, {
      signal: AbortSignal.timeout(5000)
    });
    runner.assert(res.ok, `Issuer returned HTTP ${res.status}`);
    issuerMeta = await res.json();
    runner.assert(!!issuerMeta.voprf?.pubkey, 'Issuer must expose VOPRF public key');
    console.log(`  Issuer ID: ${issuerMeta.issuer_id ?? 'unknown'}`);
    console.log(`  VOPRF pubkey: ${issuerMeta.voprf.pubkey.slice(0, 16)}...`);
  });

  await runner.run('Freebird Verifier reachable', async () => {
    // Send an invalid verify request — any non-5xx response proves the service is alive.
    const res = await fetch(`${TestConfig.freebird.verifier}/v1/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token_b64: 'invalid' }),
      signal: AbortSignal.timeout(5000)
    });
    runner.assert(res.status < 500, `Verifier returned HTTP ${res.status} (expected < 500)`);
    console.log(`  Verifier responded with HTTP ${res.status} (alive)`);
  });

  await runner.run('Witness Gateway reachable', async () => {
    const res = await fetch(`${TestConfig.witness.gateway}/v1/config`, {
      signal: AbortSignal.timeout(5000)
    });
    runner.assert(res.ok, `Witness gateway returned HTTP ${res.status}`);
    const config = await res.json();
    console.log(`  Network: ${config.network_id ?? config.id ?? 'unknown'}`);
    console.log(`  Witnesses: ${config.witnesses?.length ?? '?'}`);
  });

  await runner.run('HyperToken Relay reachable', async () => {
    const probe = new HyperTokenAdapter({ relayUrl: TestConfig.hypertoken.relay });
    await probe.connect(); // throws on connection failure / timeout
    const peerId = probe.getMyPeerId();
    runner.assert(!!peerId, 'Should receive a peer ID from relay');
    console.log(`  Connected as: ${peerId}`);
    probe.disconnect();
  });

  // ── Freebird VOPRF: blind → issue → verify ────────────────────

  // Explicit allowInsecureFallback: false overrides the env var
  // that test-utils sets, so adapters will throw instead of silently
  // falling back when a service is unreachable.
  const freebird = new FreebirdAdapter({
    issuerEndpoints: [TestConfig.freebird.issuer],
    verifierUrl: TestConfig.freebird.verifier,
    allowInsecureFallback: false
  });

  let voprfToken: Uint8Array;

  await runner.run('VOPRF blind + issue (hits issuer)', async () => {
    const { publicKey } = createTestKeyPair();
    const blinded = await freebird.blind(publicKey);
    runner.assert(
      blinded.length === 33,
      `Expected 33-byte compressed P-256 point, got ${blinded.length} bytes`
    );

    voprfToken = await freebird.issueToken(blinded);
    runner.assert(voprfToken.length > 0, 'issueToken must return non-empty token');
    console.log(`  Blinded element: ${blinded.length} bytes`);
    console.log(`  VOPRF token: ${voprfToken.length} bytes`);
  });

  await runner.run('VOPRF verify (hits verifier)', async () => {
    const valid = await freebird.verifyToken(voprfToken!);
    runner.assert(valid, 'Verifier must accept a freshly-issued VOPRF token');
  });

  // ── Witness: timestamp → verify ───────────────────────────────

  const witness = new WitnessAdapter({
    gatewayUrl: TestConfig.witness.gateway,
    networkId: 'test-network',
    allowInsecureFallback: false
  });

  let attestation: any;

  await runner.run('Witness timestamp (hits gateway)', async () => {
    const testHash = 'deadbeef'.repeat(8); // 64-char hex
    attestation = await witness.timestamp(testHash);

    runner.assert(!!attestation.hash, 'Attestation must have hash');
    runner.assert(attestation.timestamp > 0, 'Attestation must have timestamp');
    runner.assert(
      attestation.signatures.length > 0,
      `Expected real signatures, got ${attestation.signatures.length}`
    );
    runner.assert(
      attestation.witnessIds.length > 0,
      `Expected witness IDs, got ${attestation.witnessIds.length}`
    );

    // Ensure these aren't fallback witness IDs
    const hasFallback = attestation.witnessIds.some(
      (id: string) => id.startsWith('fallback-')
    );
    runner.assert(!hasFallback, 'Witness IDs must not be fallback stubs');

    console.log(`  Witnesses: ${attestation.witnessIds.join(', ')}`);
    console.log(`  Signatures: ${attestation.signatures.length}`);
  });

  await runner.run('Witness verify (hits gateway)', async () => {
    const valid = await witness.verify(attestation);
    runner.assert(valid, 'Gateway must verify its own attestation');
  });

  // ── Full transfer: mint → transfer → validate → receive ───────

  const hypertoken = new HyperTokenAdapter({
    relayUrl: TestConfig.hypertoken.relay
  });

  try {
    await hypertoken.connect();
  } catch {
    console.log('  ⚠️  HyperToken relay connect failed — gossip will be limited');
  }

  const gossip = new NullifierGossip({ witness });
  for (let i = 0; i < 3; i++) {
    gossip.addPeer(hypertoken.createPeer(`live-peer-${i}`));
  }

  const validator = new TransferValidator({
    freebird,
    gossip,
    witness,
    waitTime: 2000,
    minConfidence: 0.5
  });

  const { publicKey: recipientPubKey, secret: recipientSecret } = createTestKeyPair();
  let transferPkg: any;

  await runner.run('Token transfer (full flow, no fallback)', async () => {
    const token = ScarbuckToken.mint(42, freebird, witness, gossip);
    transferPkg = await token.transfer(recipientPubKey);

    // Commitment must be 33 bytes (real VOPRF), not 32 (fallback hash)
    runner.assert(
      transferPkg.commitment.length === 33,
      `Commitment must be 33 bytes (VOPRF), got ${transferPkg.commitment.length}`
    );

    // Auth token must be present (issueToken was called)
    runner.assert(
      transferPkg.authToken && transferPkg.authToken.length > 0,
      'Transfer must include Freebird auth token'
    );
    console.log(`  Auth token: ${transferPkg.authToken.length} bytes`);

    // Proof must have real witness signatures
    runner.assert(
      transferPkg.proof.signatures.length > 0,
      'Transfer proof must have real witness signatures'
    );
    const hasFallback = transferPkg.proof.witnessIds.some(
      (id: string) => id.startsWith('fallback-')
    );
    runner.assert(!hasFallback, 'Transfer proof must not use fallback witnesses');

    console.log(`  Amount: ${transferPkg.amount}`);
    console.log(`  Commitment: ${transferPkg.commitment.length} bytes (VOPRF)`);
    console.log(`  Witness sigs: ${transferPkg.proof.signatures.length}`);
  });

  await runner.run('Transfer validation (gossip + witness)', async () => {
    await sleep(2500);
    const result = await validator.validateTransfer(transferPkg);

    runner.assert(result.valid, `Validation failed: ${result.reason}`);
    runner.assertBetween(result.confidence, 0.5, 1.0, 'Confidence in range');
    console.log(`  Valid: ${result.valid}, confidence: ${result.confidence.toFixed(2)}`);
  });

  await runner.run('Token reception (witness verify, no fallback)', async () => {
    const received = await ScarbuckToken.receive(
      transferPkg,
      recipientSecret,
      freebird,
      witness,
      gossip
    );

    const meta = received.getMetadata();
    runner.assertEquals(meta.amount, 42, 'Received amount should be 42');
    runner.assertEquals(meta.spent, false, 'Received token should not be spent');
  });

  // ── Cleanup ────────────────────────────────────────────────────

  gossip.destroy();
  hypertoken.disconnect();

  runner.printSummary();

  const summary = runner.getSummary();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} test(s) failed`);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runLiveServicesTest()
    .then(() => {
      console.log('\n✅ All live-service tests passed!\n');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Live-service test suite failed:', error.message);
      process.exit(1);
    });
}
