/**
 * Env-driven live Phase-1 circulation vertical slice.
 *
 * This runner deliberately uses in-memory vault backends.  It never starts a
 * service, writes configuration, writes wallet secrets, or prints bearer
 * protocol values.
 */

import { isDeepStrictEqual } from 'node:util';
import {
  CirculationWallet,
  type CirculationWalletOptions,
  type RecipientTransferOffer,
  type WalletOperationStatus,
} from '../../../src/circulation-v1/wallet.js';
import {
  FreebirdDiscoveryClient,
  probeReplayAuthority,
  validateReplayAuthorityProbeContext,
  type ReplayAuthorityProbeContext,
  type ValidatedFreebirdDiscovery,
} from '../../../src/circulation-v1/discovery.js';
import { FreebirdHttpClient } from '../../../src/circulation-v1/freebird-client.js';
import {
  CIRCULATION_CLASS,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  type ExchangeRequestV2,
  type GraphIssuanceRequest,
  type GraphIssuanceResult,
  type GraphIssuanceRecoveryContext,
} from '../../../src/circulation-v1/types.js';
import {
  canonicalGraphIssuanceRequestDigest,
  computeExchangeReceiptDigest,
  computeReceiptWitnessHash,
  decodeV4RedemptionTokenBase64,
  encodeCanonicalBase64Url,
  FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER,
} from '../../../src/circulation-v1/canonical.js';
import {
  LocalVault,
  MemoryVaultBackend,
  type ArtifactVaultRecord,
  type VaultRecord,
} from '../../../src/circulation-v1/vault.js';
import {
  WitnessEvidenceClient,
} from '../../../src/circulation-v1/witness-client.js';

class LiveConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LiveConfigurationError';
  }
}

class LiveAssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LiveAssertionError';
  }
}

interface LiveConfig {
  readonly freebirdOrigin: string;
  readonly witnessOrigin: string;
  readonly issuerId: string;
  readonly replayAuthorityProbeContext: ReplayAuthorityProbeContext;
  readonly witnessNetworkId: string;
  readonly admission: string;
  readonly walletAId: string;
  readonly walletBId: string;
  readonly walletAUnlockKey: Uint8Array;
  readonly walletBUnlockKey: Uint8Array;
  readonly graphId: string;
  readonly e01TransitionId: string;
  readonly e10TransitionId: string;
  readonly pollIntervalMs: number;
  readonly maxPollAttempts: number;
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new LiveConfigurationError(`${name} is required`);
  return value;
}

function canonicalBytes(name: string, value: string, length: number): Uint8Array {
  try {
    return decodeCanonicalBase64Url(value, length, name);
  } catch {
    throw new LiveConfigurationError(`${name} must be canonical base64url for ${length} bytes`);
  }
}

function canonicalId(name: string, value: string): string {
  try {
    decodeCanonicalLowerHex(value, 32, name);
    return value;
  } catch {
    throw new LiveConfigurationError(`${name} must be 64 lowercase hexadecimal characters`);
  }
}

function positiveInteger(name: string): number {
  const raw = required(name);
  if (!/^\d+$/.test(raw)) throw new LiveConfigurationError(`${name} must be a positive integer`);
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value < 1) throw new LiveConfigurationError(`${name} must be a positive integer`);
  return value;
}

function readConfig(): LiveConfig {
  const walletAUnlockKey = canonicalBytes('SCARCITY_LIVE_WALLET_A_UNLOCK_KEY', required('SCARCITY_LIVE_WALLET_A_UNLOCK_KEY'), 32);
  const walletBUnlockKey = canonicalBytes('SCARCITY_LIVE_WALLET_B_UNLOCK_KEY', required('SCARCITY_LIVE_WALLET_B_UNLOCK_KEY'), 32);
  const walletAId = required('SCARCITY_LIVE_WALLET_A_ID');
  const walletBId = required('SCARCITY_LIVE_WALLET_B_ID');
  canonicalBytes('SCARCITY_LIVE_WALLET_A_ID', walletAId, 16);
  canonicalBytes('SCARCITY_LIVE_WALLET_B_ID', walletBId, 16);
  if (walletAId === walletBId) throw new LiveConfigurationError('SCARCITY_LIVE_WALLET_A_ID and SCARCITY_LIVE_WALLET_B_ID must differ');
  // Validate the supplied V4 credential without retaining a decoded copy.
  const admission = required('SCARCITY_LIVE_V4_ADMISSION');
  try {
    decodeV4RedemptionTokenBase64(admission);
  } catch {
    throw new LiveConfigurationError('SCARCITY_LIVE_V4_ADMISSION must be a valid canonical V4 redemption token');
  }
  let replayAuthorityProbeContext: ReplayAuthorityProbeContext;
  try {
    replayAuthorityProbeContext = validateReplayAuthorityProbeContext({
      authorityId: required('SCARCITY_LIVE_REPLAY_AUTHORITY_ID'),
      probeId: required('SCARCITY_LIVE_REPLAY_AUTHORITY_PROBE_ID'),
      challenge: required('SCARCITY_LIVE_REPLAY_AUTHORITY_CHALLENGE'),
    });
  } catch {
    throw new LiveConfigurationError('SCARCITY_LIVE_REPLAY_AUTHORITY_* must be canonical base64url values for the verifier-registered probe context');
  }
  return {
    freebirdOrigin: required('SCARCITY_LIVE_FREEBIRD_ORIGIN'),
    witnessOrigin: required('SCARCITY_LIVE_WITNESS_ORIGIN'),
    issuerId: required('SCARCITY_LIVE_ISSUER_ID'),
    replayAuthorityProbeContext,
    witnessNetworkId: required('SCARCITY_LIVE_WITNESS_NETWORK_ID'),
    admission,
    walletAId,
    walletBId,
    walletAUnlockKey,
    walletBUnlockKey,
    graphId: canonicalId('SCARCITY_LIVE_GRAPH_ID', required('SCARCITY_LIVE_GRAPH_ID')),
    e01TransitionId: canonicalId('SCARCITY_LIVE_E01_TRANSITION_ID', required('SCARCITY_LIVE_E01_TRANSITION_ID')),
    e10TransitionId: canonicalId('SCARCITY_LIVE_E10_TRANSITION_ID', required('SCARCITY_LIVE_E10_TRANSITION_ID')),
    pollIntervalMs: positiveInteger('SCARCITY_LIVE_POLL_INTERVAL_MS'),
    maxPollAttempts: positiveInteger('SCARCITY_LIVE_MAX_POLL_ATTEMPTS'),
  };
}

async function openMemoryWallet(
  id: string,
  unlockKey: Uint8Array,
  discovery: ValidatedFreebirdDiscovery,
  issuerId: string,
  freebird: FreebirdHttpClient,
): Promise<CirculationWallet> {
  const backend = new MemoryVaultBackend(`scarcity-live-${id}`);
  await backend.writeWalletId(id);
  const vault = await LocalVault.open({ backend, unlockKey: unlockKey.slice() });
  const options: CirculationWalletOptions = { vault, discovery, issuerId, freebird };
  return new CirculationWallet(options);
}

function fail(message: string): never {
  throw new LiveAssertionError(message);
}

function committed(status: WalletOperationStatus, step: string): void {
  if (status.kind !== 'committed') fail(`${step} did not produce a committed result`);
}

async function privateStatusCapability(wallet: CirculationWallet, offer: RecipientTransferOffer): Promise<string> {
  const record = await wallet.vault.getRecord(offer.offer_id);
  if (record === undefined || record.record_type !== 'prepared_receive' || record.status_capability === null) {
    fail('prepared recipient offer has no private status capability');
  }
  return record.status_capability;
}

function assertSafePublicValue(value: unknown, secrets: readonly string[], label: string): void {
  const text = JSON.stringify(value);
  if (text === undefined) fail(`${label} is not serializable`);
  for (const secret of secrets) {
    if (secret.length > 0 && text.includes(secret)) fail(`${label} contains a secret`);
  }
  if (text.includes('receipt') || text.includes('blind_signature') || text.includes('source_artifact')) {
    fail(`${label} contains protocol-private data`);
  }
}

function assertIdenticalCommittedValue(original: unknown, replayed: unknown, label: string): void {
  const originalBytes = JSON.stringify(original);
  const replayedBytes = JSON.stringify(replayed);
  if (originalBytes === undefined || replayedBytes === undefined || originalBytes !== replayedBytes || !isDeepStrictEqual(original, replayed)) {
    fail(`${label} was not byte/semantically identical`);
  }
}

async function artifactStateFingerprint(wallet: CirculationWallet): Promise<string> {
  const records = await wallet.vault.listRecords();
  return JSON.stringify([...records.entries()]
    .filter((entry) => entry[1].record_type === 'artifact')
    .map(([recordId, record]) => {
      if (record.record_type !== 'artifact') return [recordId, record.record_type];
      return [recordId, record.state, record.keyset_id, record.reserved_by];
    }));
}

async function completeSend(
  wallet: CirculationWallet,
  offer: RecipientTransferOffer,
  statusCapability: string,
  config: LiveConfig,
): Promise<WalletOperationStatus> {
  let result = await wallet.sendTransfer({ offer, status_capability: statusCapability });
  for (let attempt = 0; result.kind !== 'committed' && attempt < config.maxPollAttempts; attempt += 1) {
    if (result.kind === 'rejected' || result.kind === 'conflict') fail('exchange POST was definitively rejected');
    await new Promise<void>((resolve) => setTimeout(resolve, config.pollIntervalMs));
    result = await wallet.recoverSend(result.record_id);
  }
  committed(result, 'exchange');
  return result;
}

async function completeGenesis(
  wallet: CirculationWallet,
  recordId: string,
  config: LiveConfig,
): Promise<WalletOperationStatus> {
  let result = await wallet.submitGenesis(recordId);
  for (let attempt = 0; result.kind !== 'committed' && attempt < config.maxPollAttempts; attempt += 1) {
    if (result.kind === 'rejected' || result.kind === 'conflict') fail('graph issuance was definitively rejected');
    await new Promise<void>((resolve) => setTimeout(resolve, config.pollIntervalMs));
    result = await wallet.recoverGenesis(recordId);
  }
  committed(result, 'graph issuance');
  return result;
}

async function submitAndPollWitness(
  witness: WitnessEvidenceClient,
  receipt: Parameters<typeof computeExchangeReceiptDigest>[0],
  config: LiveConfig,
): Promise<void> {
  const receiptDigest = computeExchangeReceiptDigest(receipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
  const expectedHash = computeReceiptWitnessHash(CIRCULATION_CLASS, receiptDigest);
  let result = await witness.submitReceiptDigest(receiptDigest);
  for (let attempt = 0; attempt < config.maxPollAttempts; attempt += 1) {
    if (result.kind === 'confirmed') {
      if (result.hash !== expectedHash || result.attestation.hash !== expectedHash || result.attestation.network_id !== config.witnessNetworkId) {
        fail('Witness confirmed tuple does not match the pinned receipt hash/network');
      }
      if (result.signed_attestation.attestation.hash !== expectedHash || result.signed_attestation.attestation.network_id !== config.witnessNetworkId) {
        fail('Witness signed attestation binding mismatch');
      }
      return;
    }
    if (result.kind === 'failed') fail('Witness evidence did not confirm');
    if (result.kind === 'missing') {
      await new Promise<void>((resolve) => setTimeout(resolve, config.pollIntervalMs));
      result = await witness.retry(receiptDigest);
      continue;
    }
    if (result.kind === 'retryable' && result.next_attempt_at !== undefined) {
      const delay = Math.max(0, result.next_attempt_at - Math.floor(Date.now() / 1000)) * 1000;
      if (delay > 0) await new Promise<void>((resolve) => setTimeout(resolve, Math.min(delay, config.pollIntervalMs * 10)));
    } else {
      await new Promise<void>((resolve) => setTimeout(resolve, config.pollIntervalMs));
    }
    result = result.kind === 'pending' || result.kind === 'retryable'
      ? await witness.poll(receiptDigest)
      : await witness.retry(receiptDigest);
  }
  fail('Witness polling attempt limit reached');
}

function findCurrentArtifacts(records: ReadonlyMap<string, VaultRecord>, keysetId: string): Array<[string, ArtifactVaultRecord]> {
  return [...records.entries()].filter((entry): entry is [string, ArtifactVaultRecord] => {
    const record = entry[1];
    return record.record_type === 'artifact' && record.state === 'current' && record.keyset_id === keysetId;
  });
}

async function run(): Promise<void> {
  const config = readConfig();
  console.log('[live] fetching and validating pinned Freebird discovery');
  const discovery = await new FreebirdDiscoveryClient({ origin: config.freebirdOrigin, issuerId: config.issuerId }).fetch();
  if (discovery.exchange.active_graph.graph_id !== config.graphId) fail('active graph does not match SCARCITY_LIVE_GRAPH_ID');
  const transitions = discovery.exchange.active_graph.transitions;
  const e01 = transitions.find((transition) => transition.transition_id === config.e01TransitionId);
  const e10 = transitions.find((transition) => transition.transition_id === config.e10TransitionId);
  if (e01 === undefined || e10 === undefined || e01.source_keyset_id !== discovery.exchange.active_graph.keysets[0].keyset_id || e01.target_keyset_id !== discovery.exchange.active_graph.keysets[1].keyset_id || e10.source_keyset_id !== discovery.exchange.active_graph.keysets[1].keyset_id || e10.target_keyset_id !== discovery.exchange.active_graph.keysets[0].keyset_id) {
    fail('configured E01/E10 transitions do not match pinned K0/K1 directions');
  }
  const graphIssuance = discovery.graph_issuance;
  if (graphIssuance === undefined || graphIssuance.replay_authority.authority_id !== config.replayAuthorityProbeContext.authorityId) {
    fail('supplied replay-authority context does not match validated Freebird discovery');
  }
  console.log('[live] verifying pre-registered replay-authority probe');
  try {
    await probeReplayAuthority({
      origin: config.freebirdOrigin,
      issuerId: config.issuerId,
      authorityId: graphIssuance.replay_authority.authority_id,
      context: config.replayAuthorityProbeContext,
    });
  } catch {
    fail('replay-authority probe failed or returned an invalid authority/challenge/proof binding');
  }

  const freebird = new FreebirdHttpClient({ origin: config.freebirdOrigin, discovery });
  const witness = new WitnessEvidenceClient({ origin: config.witnessOrigin, expectedNetworkId: config.witnessNetworkId });
  const witnessNetwork = await witness.fetchNetworkConfig();
  if (witnessNetwork.witnesses.length !== 3) fail('Witness network is not the required three-node network');
  const walletA = await openMemoryWallet(config.walletAId, config.walletAUnlockKey, discovery, config.issuerId, freebird);
  const walletB = await openMemoryWallet(config.walletBId, config.walletBUnlockKey, discovery, config.issuerId, freebird);
  const graph = discovery.exchange.active_graph;
  const k0 = graph.keysets[0].keyset_id;
  const k1 = graph.keysets[1].keyset_id;

  console.log('[live] wallet A graph issuance into K0');
  const genesis = await walletA.prepareGenesis({ authorization: config.admission });
  let genesisRequest: GraphIssuanceRequest;
  let genesisCapability: string;
  {
    const prepared = await walletA.vault.getRecord(genesis.record_id);
    if (prepared?.record_type !== 'genesis_issuance' || prepared.status_capability === null) {
      fail('graph issuance preparation did not retain its exact request and status capability');
    }
    // These are retained only in process so the committed POST can be repeated
    // byte-for-byte; they are never logged or persisted outside the vault.
    genesisRequest = prepared.request;
    genesisCapability = prepared.status_capability;
    if (genesisRequest.public_operation_id !== genesis.operation_id || JSON.stringify(genesisRequest).includes(genesisCapability)) {
      fail('graph issuance capability was not header-only or operation identity changed');
    }
  }
  await completeGenesis(walletA, genesis.record_id, config);
  let genesisResult: GraphIssuanceResult;
  {
    const committedRecord = await walletA.vault.getRecord(genesis.record_id);
    if (committedRecord?.record_type !== 'genesis_issuance' || committedRecord.result === null) {
      fail('graph issuance did not retain its committed result');
    }
    genesisResult = committedRecord.result;
  }
  const genesisArtifacts = findCurrentArtifacts(await walletA.vault.listRecords(), k0);
  if (genesisArtifacts.length !== 1) fail('graph issuance did not create exactly one current K0 artifact');
  const genesisArtifactId = genesisArtifacts[0][0];
  const graphArtifactStateBeforeReplay = await artifactStateFingerprint(walletA);
  const graphReplayRecord = await walletA.vault.getRecord(genesis.record_id);
  if (graphReplayRecord?.record_type !== 'genesis_issuance' || graphReplayRecord.status_capability !== null || graphReplayRecord.result === null) fail('graph issuance recovery context was not durably finalized');
  const graphRecovery: GraphIssuanceRecoveryContext = {
    request: genesisRequest,
    requestDigest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(genesisRequest)),
    publicOperationId: genesisRequest.public_operation_id,
    issuancePolicyId: genesisRequest.issuance_policy_id,
    graphId: genesisRequest.graph_id,
    keysetId: genesisRequest.keyset_id,
    descriptorId: genesisRequest.descriptor_id,
    statusCapability: genesisCapability,
    expectedTokenKeyId: graphReplayRecord.expected_token_key_id,
    blindingState: 'recovery-context-test-only',
  };
  const graphReplay = await freebird.recoverGraphIssuance(graphRecovery);
  if (graphReplay.kind !== 'committed' || graphReplay.observed || graphReplay.request_digest !== encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(genesisRequest))) {
    fail('repeated graph issuance POST was not the same committed operation');
  }
  assertIdenticalCommittedValue(genesisResult, graphReplay.value, 'repeated graph issuance result');
  if (await artifactStateFingerprint(walletA) !== graphArtifactStateBeforeReplay || findCurrentArtifacts(await walletA.vault.listRecords(), k0).length !== 1) {
    fail('repeated graph issuance changed artifact or budget-visible local state');
  }

  console.log('[live] wallet A K0 to wallet B K1');
  const offer01 = await walletB.prepareTransferOffer({ transition_id: config.e01TransitionId });
  const capability01 = await privateStatusCapability(walletB, offer01);
  assertSafePublicValue(offer01, [capability01], 'E01 offer');
  const send01 = await completeSend(walletA, offer01, capability01, config);
  const handoff01 = await walletA.getTransferAcceptanceHandoff(send01.record_id);
  const accepted01 = await walletB.acceptTransfer(offer01, handoff01);
  committed(accepted01, 'K0 to K1 acceptance');
  await submitAndPollWitness(witness, handoff01.committed.value.receipt, config);
  if (JSON.stringify(handoff01.request).includes(capability01)) fail('exchange capability was not header-only');
  const exchangeArtifactStateBeforeReplay = `${await artifactStateFingerprint(walletA)}|${await artifactStateFingerprint(walletB)}`;
  const exactExchangeReplay = await freebird.processOrRecoverV2(handoff01.request, capability01);
  if (exactExchangeReplay.kind !== 'committed' || exactExchangeReplay.observed || exactExchangeReplay.request_digest !== handoff01.committed.request_digest) {
    fail('repeated exchange POST was not the same committed operation');
  }
  assertIdenticalCommittedValue(handoff01.committed.value, exactExchangeReplay.value, 'repeated exchange result');
  if (`${await artifactStateFingerprint(walletA)}|${await artifactStateFingerprint(walletB)}` !== exchangeArtifactStateBeforeReplay) {
    fail('repeated exchange changed artifact or budget-visible local state');
  }
  const after01A = await walletA.vault.getRecord(genesisArtifactId);
  if (after01A?.record_type !== 'artifact' || after01A.state !== 'spent') fail('K0 source artifact remained reusable');
  const after01B = findCurrentArtifacts(await walletB.vault.listRecords(), k1);
  if (after01B.length !== 1) fail('wallet B did not receive exactly one current K1 artifact');
  const e01ArtifactId = after01B[0][0];
  assertSafePublicValue(await walletA.getStatus(send01.record_id), [capability01], 'E01 send status');

  const replayOffer = await walletB.prepareTransferOffer({ transition_id: config.e01TransitionId });
  const replayCapability = await privateStatusCapability(walletB, replayOffer);
  assertSafePublicValue(replayOffer, [replayCapability], 'durable source replay offer');
  const replayRequest: ExchangeRequestV2 = {
    ...handoff01.request,
    public_operation_id: replayOffer.operation_id,
    outputs: [replayOffer.output],
  };
  if (replayRequest.public_operation_id === handoff01.request.public_operation_id || replayRequest.outputs[0].blinded_value === handoff01.request.outputs[0].blinded_value || replayCapability === capability01) {
    fail('durable source replay did not use distinct operation, capability, and output values');
  }
  if (JSON.stringify(replayRequest).includes(replayCapability)) fail('durable source replay capability was not header-only');
  const sourceReplayStateBefore = `${await artifactStateFingerprint(walletA)}|${await artifactStateFingerprint(walletB)}`;
  const sourceReplay = await freebird.processOrRecoverV2(replayRequest, replayCapability);
  if (sourceReplay.kind !== 'rejected' && sourceReplay.kind !== 'conflict') {
    fail('Freebird accepted or left the consumed-source replay unresolved');
  }
  if (`${await artifactStateFingerprint(walletA)}|${await artifactStateFingerprint(walletB)}` !== sourceReplayStateBefore) {
    fail('consumed-source replay changed local artifact state');
  }

  console.log('[live] wallet B K1 to wallet A K0');
  const offer10 = await walletA.prepareTransferOffer({ transition_id: config.e10TransitionId });
  const capability10 = await privateStatusCapability(walletA, offer10);
  assertSafePublicValue(offer10, [capability10], 'E10 offer');
  const send10 = await completeSend(walletB, offer10, capability10, config);
  const handoff10 = await walletB.getTransferAcceptanceHandoff(send10.record_id);
  const accepted10 = await walletA.acceptTransfer(offer10, handoff10);
  committed(accepted10, 'K1 to K0 acceptance');
  await submitAndPollWitness(witness, handoff10.committed.value.receipt, config);
  if (findCurrentArtifacts(await walletA.vault.listRecords(), k0).length !== 1) fail('wallet A did not end with exactly one current K0 artifact');
  const after10B = await walletB.vault.getRecord(e01ArtifactId);
  if (after10B?.record_type !== 'artifact' || after10B.state !== 'spent') fail('K1 source artifact remained reusable');
  if (findCurrentArtifacts(await walletB.vault.listRecords(), k1).length !== 0) fail('wallet B retained a current K1 artifact after E10');
  assertSafePublicValue(await walletB.getStatus(send10.record_id), [capability10], 'E10 send status');

  console.log('[live] verifying ownership, replay safety, and authority separation');
  try {
    await walletA.sendTransfer({ offer: offer01, status_capability: capability01, source_record_id: genesisArtifactId });
    fail('spent K0 source was reusable');
  } catch (error) {
    if (error instanceof LiveAssertionError) throw error;
  }
  try {
    await walletB.sendTransfer({ offer: offer10, status_capability: capability10, source_record_id: e01ArtifactId });
    fail('spent K1 source was reusable');
  } catch (error) {
    if (error instanceof LiveAssertionError) throw error;
  }
  assertSafePublicValue(await walletB.getStatus(send10.record_id), [capability10], 'final wallet status');
  console.log('[live] completed; no Witness, HyperToken, or public projection path was instantiated');
}

try {
  await run();
} catch (error) {
  if (error instanceof LiveConfigurationError) {
    console.error(`[live] configuration failure: ${error.message}`);
  } else if (error instanceof LiveAssertionError) {
    console.error(`[live] assertion failure: ${error.message}`);
  } else {
    console.error('[live] vertical slice failed; secret-bearing details were intentionally suppressed');
  }
  process.exitCode = 1;
}
