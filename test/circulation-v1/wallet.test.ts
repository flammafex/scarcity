/** Deterministic dependency-injected Phase-1 wallet orchestration tests. */

import assert from 'node:assert/strict';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import {
  CIRCULATION_CLASS,
  parseGraphIssuanceDiscoveryV1,
  type ExchangeAcceptedResponseV2,
  type ExchangeRequestV2,
  type FreebirdV5DescriptorV2,
  type GraphIssuanceRequestV1,
  type GraphIssuanceResultV1,
} from '../../src/circulation-v1/types.js';
import {
  FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER,
  FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER,
  canonicalDescriptorIdV2,
  canonicalExchangeRequestDigestV2,
  canonicalExchangeResultDigestV2,
  canonicalGraphIdV2,
  canonicalGraphIssuanceRequestDigestV1,
  canonicalGraphIssuanceResultDigestV1,
  canonicalKeysetIdV2,
  canonicalTransitionIdV2,
  computeExchangeReceiptDigest,
  decodeCanonicalBase64Url,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  encodeV4RedemptionTokenBase64,
  verifyExchangeResultDigest,
} from '../../src/circulation-v1/canonical.js';
import { validateDiscoverySnapshot } from '../../src/circulation-v1/bootstrap.js';
import { type FreebirdObservationOutcome, type FreebirdPostOutcome } from '../../src/circulation-v1/freebird-client.js';
import {
  CirculationWalletV1,
  type WalletFreebirdClient,
  type RecipientTransferOffer,
  type TransferAcceptanceHandoff,
} from '../../src/circulation-v1/wallet.js';
import {
  LocalVault,
  MemoryVaultBackend,
  type VaultRecord,
} from '../../src/circulation-v1/vault.js';
import type { ValidatedFreebirdDiscovery } from '../../src/circulation-v1/discovery.js';

const ISSUER = 'wallet-test-issuer';
const NOW = 1_750_000_001;
const RECEIPT_SEED = new Uint8Array(32).fill(0x71);
const AUTHORIZATION = encodeV4RedemptionTokenBase64(
  new Uint8Array(32).fill(0x21),
  new Uint8Array(32).fill(0x22),
  'kid:test-only',
  ISSUER,
  new Uint8Array(32).fill(0x23),
);

function wrapRsaSpkiAsRfc4055Pss(standard: Uint8Array): Uint8Array {
  const params = Uint8Array.of(
    0x30, 0x30,
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0xa2, 0x03, 0x02, 0x01, 0x30,
  );
  const algorithm = Uint8Array.of(0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, ...params);
  const raw = standard.slice(23);
  const bitString = Uint8Array.of(0x03, 0x82, (raw.length >>> 8) & 0xff, raw.length & 0xff);
  const body = new Uint8Array(algorithm.length + bitString.length + raw.length);
  body.set(algorithm, 0);
  body.set(bitString, algorithm.length);
  body.set(raw, algorithm.length + bitString.length);
  const output = new Uint8Array(4 + body.length);
  output.set(Uint8Array.of(0x30, 0x82, (body.length >>> 8) & 0xff, body.length & 0xff));
  output.set(body, 4);
  return output;
}

async function descriptor(key: CryptoKey): Promise<FreebirdV5DescriptorV2> {
  const standard = new Uint8Array(await crypto.subtle.exportKey('spki', key));
  const spki = wrapRsaSpkiAsRfc4055Pss(standard);
  const value: FreebirdV5DescriptorV2 = {
    descriptor_id: '',
    profile_id: 'freebird/public-bearer-exchange/v2',
    issuer_id: ISSUER,
    token_key_id: encodeCanonicalLowerHex(sha256(spki)),
    pubkey_spki_b64: encodeCanonicalBase64Url(spki),
    suite: 'RSABSSA-SHA384-PSS-Deterministic',
    valid_from: 1_700_000_000,
    valid_until: 2_000_000_000,
    audience: 'wallet-test-only',
  };
  return { ...value, descriptor_id: canonicalDescriptorIdV2(value) };
}

function sequence(seed: number): (length: number) => Uint8Array {
  let next = seed;
  return (length) => Uint8Array.from({ length }, () => {
    const value = next & 0xff;
    next += 1;
    return value;
  });
}

interface Fixture {
  readonly discovery: ValidatedFreebirdDiscovery;
  readonly descriptors: readonly [FreebirdV5DescriptorV2, FreebirdV5DescriptorV2];
  readonly privateKeys: ReadonlyMap<string, CryptoKey>;
  readonly transitions: readonly [string, string];
}

async function fixture(): Promise<Fixture> {
  const firstPair = await RSABSSA.SHA384.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const secondPair = await RSABSSA.SHA384.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const first = await descriptor(firstPair.publicKey);
  const second = await descriptor(secondPair.publicKey);
  const firstKeyset = { keyset_id: canonicalKeysetIdV2([first.descriptor_id]), descriptor_ids: [first.descriptor_id] as [string] };
  const secondKeyset = { keyset_id: canonicalKeysetIdV2([second.descriptor_id]), descriptor_ids: [second.descriptor_id] as [string] };
  const e01 = {
    transition_id: '',
    source_keyset_id: firstKeyset.keyset_id,
    target_keyset_id: secondKeyset.keyset_id,
    source_slots: [{ descriptor_id: first.descriptor_id, slot_id: 'input', class: CIRCULATION_CLASS, quantity: 1 as const }],
    output_slots: [{ descriptor_id: second.descriptor_id, slot_id: 'output', class: CIRCULATION_CLASS, quantity: 1 as const }],
    budget_id: 'wallet-budget-e01',
    budget_limit: 100 as const,
    admission_state: 'accepting_new' as const,
  };
  e01.transition_id = canonicalTransitionIdV2(e01 as any);
  const e10 = {
    transition_id: '',
    source_keyset_id: secondKeyset.keyset_id,
    target_keyset_id: firstKeyset.keyset_id,
    source_slots: [{ descriptor_id: second.descriptor_id, slot_id: 'input', class: CIRCULATION_CLASS, quantity: 1 as const }],
    output_slots: [{ descriptor_id: first.descriptor_id, slot_id: 'output', class: CIRCULATION_CLASS, quantity: 1 as const }],
    budget_id: 'wallet-budget-e10',
    budget_limit: 100 as const,
    admission_state: 'accepting_new' as const,
  };
  e10.transition_id = canonicalTransitionIdV2(e10 as any);
  const graph = {
    profile_id: 'freebird/public-bearer-exchange/v2' as const,
    graph_id: '',
    descriptors: [first, second] as [FreebirdV5DescriptorV2, FreebirdV5DescriptorV2],
    keysets: [firstKeyset, secondKeyset] as [typeof firstKeyset, typeof secondKeyset],
    transitions: [e01, e10] as [typeof e01, typeof e10],
  };
  graph.graph_id = canonicalGraphIdV2(graph);
  const receiptPublicKey = ed25519.getPublicKey(RECEIPT_SEED);
  const raw = {
    exchange: {
      active_graph: graph,
      retained_graphs: [],
      active_receipt_key: {
        key_id: encodeCanonicalLowerHex(sha256(receiptPublicKey)),
        algorithm: 'Ed25519',
        purpose: 'exchange_receipt_active',
        public_key_b64: encodeCanonicalBase64Url(receiptPublicKey),
        valid_from: 1_700_000_000,
        valid_until: 2_000_000_000,
      },
      retained_receipt_keys: [],
    },
    graph_issuance: {
      version: 1,
      policies: [{
        issuance_policy_id: 'wallet-genesis-policy',
        graph_id: graph.graph_id,
        keyset_id: firstKeyset.keyset_id,
        descriptor_id: first.descriptor_id,
        budget_id: 'wallet-genesis-budget',
        budget_limit: 100,
        quantity: 1,
        admission_state: 'accepting_new',
        authorization_scheme: 'v4_local',
      }],
    },
  };
  const exchange = validateDiscoverySnapshot({ exchange: raw.exchange }, { issuerId: ISSUER, circulationState: 'accepting_new' });
  const graphIssuance = parseGraphIssuanceDiscoveryV1(raw.graph_issuance);
  const document = { exchange, graph_issuance: graphIssuance };
  return {
    discovery: { origin: 'http://localhost:43123', exchange, graph_issuance: graphIssuance, document },
    descriptors: [first, second],
    privateKeys: new Map([[first.descriptor_id, firstPair.privateKey], [second.descriptor_id, secondPair.privateKey]]),
    transitions: [e01.transition_id, e10.transition_id],
  };
}

type ExchangeBehavior = 'normal' | 'retryable-once' | 'ambiguous-once';

class FakeFreebird implements WalletFreebirdClient {
  readonly graphCalls: Array<{ readonly request: GraphIssuanceRequestV1; readonly capability: string }> = [];
  readonly exchangeCalls: Array<{ readonly request: ExchangeRequestV2; readonly capability: string }> = [];
  readonly witnessCalls = 0;
  readonly hyperTokenCalls = 0;
  private readonly behavior = new Map<string, ExchangeBehavior>();
  private readonly tamperedExchangeResults = new Set<string>();
  private readonly graph: Fixture;
  private graphResultTampered = false;

  constructor(fixtureValue: Fixture) {
    this.graph = fixtureValue;
  }

  setExchangeBehavior(operationId: string, behavior: ExchangeBehavior): void {
    this.behavior.set(operationId, behavior);
  }

  setGraphResultTampered(value: boolean): void {
    this.graphResultTampered = value;
  }

  setExchangeResultTampered(operationId: string): void {
    this.tamperedExchangeResults.add(operationId);
  }

  async processOrRecoverGraphIssuance(request: GraphIssuanceRequestV1, capability: string): Promise<FreebirdPostOutcome<GraphIssuanceResultV1>> {
    this.graphCalls.push({ request: structuredClone(request), capability });
    const privateKey = this.graph.privateKeys.get(this.graph.descriptors[0].descriptor_id)!;
    const blindSignature = await RSABSSA.SHA384.PSS.Deterministic().blindSign(privateKey, decodeCanonicalBase64Url(request.blinded_message));
    const resultBase = {
      version: 1 as const,
      public_operation_id: request.public_operation_id,
      issuance_policy_id: request.issuance_policy_id,
      graph_id: request.graph_id,
      keyset_id: request.keyset_id,
      descriptor_id: request.descriptor_id,
      token_key_id: this.graphResultTampered ? '00'.repeat(32) : this.graph.descriptors[0].token_key_id,
      quantity: 1,
      request_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigestV1(request)),
      blind_signature: encodeCanonicalBase64Url(blindSignature),
    };
    const result = { ...resultBase, result_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceResultDigestV1(resultBase as any)) };
    return { kind: 'committed', status: 200, value: result, request_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigestV1(request)), observed: false };
  }

  async observeGraphIssuanceStatus(request: GraphIssuanceRequestV1, _capability: string): Promise<FreebirdObservationOutcome<GraphIssuanceResultV1>> {
    return { kind: 'rejected', status: 404, error: { code: 'operation_unknown', status: 404 }, request_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigestV1(request)), observed: true };
  }

  async processOrRecoverV2(request: ExchangeRequestV2, capability: string): Promise<FreebirdPostOutcome<ExchangeAcceptedResponseV2>> {
    this.exchangeCalls.push({ request: structuredClone(request), capability });
    const behavior = this.behavior.get(request.public_operation_id) ?? 'normal';
    if (behavior === 'retryable-once') {
      this.behavior.set(request.public_operation_id, 'normal');
      return { kind: 'retryable', status: 202, retry_after_seconds: 1, request_digest: encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(request)), observed: false };
    }
    if (behavior === 'ambiguous-once') {
      this.behavior.set(request.public_operation_id, 'normal');
      return { kind: 'ambiguous', status: 503, error: { code: 'ambiguous_post', status: 503 }, request_digest: encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(request)), observed: false };
    }
    const targetDescriptor = this.graph.descriptors.find((candidate) => candidate.descriptor_id === request.outputs[0].slot.descriptor_id)!;
    const privateKey = this.graph.privateKeys.get(targetDescriptor.descriptor_id)!;
    const blindSignature = await RSABSSA.SHA384.PSS.Deterministic().blindSign(privateKey, decodeCanonicalBase64Url(request.outputs[0].blinded_value));
    const resultBase = {
      version: 2 as const,
      public_operation_id: request.public_operation_id,
      graph_id: this.tamperedExchangeResults.has(request.public_operation_id) ? '00'.repeat(32) : request.graph_id,
      transition_id: request.transition_id,
      source_keyset_id: request.source_keyset_id,
      target_keyset_id: request.target_keyset_id,
      outputs: [{ ...request.outputs[0], blind_signature: encodeCanonicalBase64Url(blindSignature) }] as [{ slot: typeof request.outputs[0]['slot']; blinded_value: string; blind_signature: string }],
    };
    const result = { ...resultBase, result_digest: encodeCanonicalBase64Url(canonicalExchangeResultDigestV2(resultBase as any)) };
    const receiptBase = {
      version: 2 as const,
      public_operation_id: request.public_operation_id,
      graph_id: request.graph_id,
      transition_id: request.transition_id,
      source_keyset_id: request.source_keyset_id,
      target_keyset_id: request.target_keyset_id,
      result_digest: result.result_digest,
      created_at: NOW,
      expires_at: NOW + 2_592_000,
      receipt_key_id: encodeCanonicalLowerHex(sha256(ed25519.getPublicKey(RECEIPT_SEED))),
      signature: encodeCanonicalBase64Url(new Uint8Array(64)),
    };
    const receiptDigest = computeExchangeReceiptDigest(receiptBase, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    const receipt = { ...receiptBase, signature: encodeCanonicalBase64Url(ed25519.sign(receiptDigest, RECEIPT_SEED)) };
    const value = { result, receipt };
    verifyExchangeResultDigest(result, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    return { kind: 'committed', status: 200, value, request_digest: encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(request)), observed: false };
  }

  async observeExchangeStatus(request: ExchangeRequestV2, _capability: string): Promise<FreebirdObservationOutcome<ExchangeAcceptedResponseV2>> {
    return { kind: 'rejected', status: 404, error: { code: 'operation_unknown', status: 404 }, request_digest: encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(request)), observed: true };
  }
}

class FailOnceBackend extends MemoryVaultBackend {
  failNextRecordWrite = false;

  override async writeRecordEnvelope(recordId: string, envelope: string): Promise<void> {
    if (this.failNextRecordWrite) {
      this.failNextRecordWrite = false;
      throw new Error('TEST-ONLY injected record write failure');
    }
    return super.writeRecordEnvelope(recordId, envelope);
  }
}

async function wallet(fixtureValue: Fixture, freebird: FakeFreebird, seed: number, backend = new MemoryVaultBackend()): Promise<CirculationWalletV1> {
  const vault = await LocalVault.create({ backend, unlockKey: new Uint8Array(32).fill(seed), randomBytes: sequence(seed + 100) });
  return new CirculationWalletV1({ vault, discovery: fixtureValue.discovery, issuerId: ISSUER, freebird, randomBytes: sequence(seed), nowUnixSeconds: () => NOW });
}

function currentArtifact(records: ReadonlyMap<string, VaultRecord>, keysetId: string): string {
  for (const record of records.values()) {
    if (record.record_type === 'artifact' && record.state === 'current' && record.keyset_id === keysetId) return record.artifact;
  }
  throw new Error('TEST-ONLY expected current artifact');
}

function requestForOffer(offer: RecipientTransferOffer, sourceArtifact: string): ExchangeRequestV2 {
  return {
    version: 2,
    public_operation_id: offer.operation_id,
    graph_id: offer.graph_id,
    transition_id: offer.transition_id,
    source_keyset_id: offer.source_keyset_id,
    target_keyset_id: offer.target_keyset_id,
    sources: [{ slot: offer.source, artifact: sourceArtifact }],
    outputs: [offer.output],
  };
}

async function testEndToEndAndRecovery(): Promise<void> {
  const fixtureValue = await fixture();
  const freebird = new FakeFreebird(fixtureValue);
  const alice = await wallet(fixtureValue, freebird, 1);
  const bob = await wallet(fixtureValue, freebird, 33);

  const genesis = await alice.prepareGenesis({ authorization: AUTHORIZATION });
  const genesisRecord = await alice.vault.getRecord(genesis.record_id);
  assert.equal(genesisRecord?.record_type, 'genesis_issuance');
  assert.equal(genesisRecord?.state, 'prepared');
  assert.equal(JSON.stringify(genesis).includes(AUTHORIZATION), false);
  const genesisStatus = await alice.submitGenesis(genesis.record_id);
  assert.equal(genesisStatus.kind, 'committed');
  const aliceRecords = await alice.vault.listRecords();
  const k0 = aliceRecords.values().next().value;
  assert.ok(k0);
  const k0Keyset = fixtureValue.discovery.exchange.active_graph.keysets[0].keyset_id;
  assert.equal(currentArtifact(aliceRecords, k0Keyset).length > 0, true);

  const e01Offer = await bob.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const bobOfferRecord = await bob.vault.getRecord(e01Offer.offer_id);
  assert.equal(bobOfferRecord?.record_type, 'prepared_receive');
  assert.equal(JSON.stringify(e01Offer).includes('status_capability'), false);
  assert.equal(JSON.stringify(e01Offer).includes('blinding_state'), false);
  const e01Capability = (bobOfferRecord as any).status_capability as string;
  freebird.setExchangeBehavior(e01Offer.operation_id, 'retryable-once');
  const firstSend = await alice.sendTransfer({ offer: e01Offer, status_capability: e01Capability });
  assert.equal(firstSend.kind, 'retryable');
  assert.equal((await alice.getStatus(firstSend.record_id)).state, 'reserved_pending');
  const persistedSend = await alice.vault.getRecord(firstSend.record_id) as any;
  const conflictingRecoveryRequest = structuredClone(persistedSend.request) as any;
  conflictingRecoveryRequest.outputs[0].blinded_value = 'Ag';
  await assert.rejects(alice.recoverSend(firstSend.record_id, { request: conflictingRecoveryRequest, status_capability: e01Capability }));
  await assert.rejects(alice.recoverSend(firstSend.record_id, { request: persistedSend.request, status_capability: 'wrong-capability' }));
  assert.equal(freebird.exchangeCalls.length, 1, 'conflicting sender recovery inputs must not submit');
  const secondSend = await alice.recoverSend(firstSend.record_id);
  assert.equal(secondSend.kind, 'committed');
  assert.equal(freebird.exchangeCalls.length, 2);
  assert.deepEqual(freebird.exchangeCalls[0].request, freebird.exchangeCalls[1].request);
  assert.equal(freebird.exchangeCalls[0].capability, freebird.exchangeCalls[1].capability);
  const handoff01 = await alice.getTransferAcceptanceHandoff(firstSend.record_id);
  const accepted01 = await bob.acceptTransfer(e01Offer, handoff01);
  assert.equal(accepted01.kind, 'committed');
  const k1Keyset = fixtureValue.discovery.exchange.active_graph.keysets[1].keyset_id;
  assert.equal(currentArtifact(await bob.vault.listRecords(), k1Keyset).length > 0, true);

  const e10Offer = await alice.prepareTransferOffer({ transition_id: fixtureValue.transitions[1] });
  const e10Record = await alice.vault.getRecord(e10Offer.offer_id);
  const e10Capability = (e10Record as any).status_capability as string;
  freebird.setExchangeBehavior(e10Offer.operation_id, 'ambiguous-once');
  const ambiguousSend = await bob.sendTransfer({ offer: e10Offer, status_capability: e10Capability });
  assert.equal(ambiguousSend.kind, 'ambiguous');
  assert.equal((await bob.getStatus(ambiguousSend.record_id)).state, 'spend_unknown');
  const recoveredSend = await bob.recoverSend(ambiguousSend.record_id);
  assert.equal(recoveredSend.kind, 'committed');
  const handoff10 = await bob.getTransferAcceptanceHandoff(ambiguousSend.record_id);
  const accepted10 = await alice.acceptTransfer(e10Offer, handoff10);
  assert.equal(accepted10.kind, 'committed');
  assert.equal(currentArtifact(await alice.vault.listRecords(), k0Keyset).length > 0, true);

  const safeStatus = await alice.getStatus(genesis.record_id);
  assert.equal(JSON.stringify(safeStatus).includes(AUTHORIZATION), false);
  assert.equal(JSON.stringify(safeStatus).includes(e01Capability), false);
  assert.equal(JSON.stringify(safeStatus).includes('receipt'), false);
}

async function testWrongHandoffsAndVaultCrashRecovery(): Promise<void> {
  const fixtureValue = await fixture();
  const freebird = new FakeFreebird(fixtureValue);
  const alice = await wallet(fixtureValue, freebird, 77);
  const bobBackend = new FailOnceBackend();
  const bob = await wallet(fixtureValue, freebird, 101, bobBackend);

  const issueGenesis = async (): Promise<void> => {
    const genesis = await alice.prepareGenesis({ authorization: AUTHORIZATION });
    const committedGenesis = await alice.submitGenesis(genesis.record_id);
    assert.equal(committedGenesis.kind, 'committed');
  };
  await issueGenesis();
  const offer = await bob.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const offerRecord = await bob.vault.getRecord(offer.offer_id) as any;
  const senderCapability = offerRecord.status_capability as string;
  const sent = await alice.sendTransfer({ offer, status_capability: senderCapability });
  assert.equal(sent.kind, 'committed');
  const handoff = await alice.getTransferAcceptanceHandoff(sent.record_id);

  const wrongOffer = { ...offer, output: { ...offer.output, blinded_value: 'Ag' } };
  const wrongOfferResult = await bob.acceptTransfer(wrongOffer, handoff);
  assert.equal(wrongOfferResult.kind, 'rejected');
  assert.equal((await bob.getStatus(offer.offer_id)).state, 'rejected');
  assert.equal((await bob.acceptTransfer(offer, handoff)).kind, 'rejected', 'terminal receive rejection must not retry');

  await issueGenesis();
  const resultOffer = await bob.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const resultOfferRecord = await bob.vault.getRecord(resultOffer.offer_id) as any;
  const resultSent = await alice.sendTransfer({ offer: resultOffer, status_capability: resultOfferRecord.status_capability });
  assert.equal(resultSent.kind, 'committed');
  const resultHandoff = await alice.getTransferAcceptanceHandoff(resultSent.record_id);
  const wrongResult = structuredClone(resultHandoff) as any as TransferAcceptanceHandoff;
  (wrongResult as any).committed.value.result.outputs[0].slot.slot_id = 'wrong';
  const wrongResultStatus = await bob.acceptTransfer(resultOffer, wrongResult);
  assert.equal(wrongResultStatus.kind, 'rejected');
  assert.equal((await bob.getStatus(resultOffer.offer_id)).state, 'rejected');

  await issueGenesis();
  const receiptOffer = await bob.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const receiptOfferRecord = await bob.vault.getRecord(receiptOffer.offer_id) as any;
  const receiptSent = await alice.sendTransfer({ offer: receiptOffer, status_capability: receiptOfferRecord.status_capability });
  assert.equal(receiptSent.kind, 'committed');
  const receiptHandoff = await alice.getTransferAcceptanceHandoff(receiptSent.record_id);
  const wrongReceipt = structuredClone(receiptHandoff) as any as TransferAcceptanceHandoff;
  (wrongReceipt as any).committed.value.receipt.signature = encodeCanonicalBase64Url(new Uint8Array(64).fill(0x44));
  const wrongReceiptStatus = await bob.acceptTransfer(receiptOffer, wrongReceipt);
  assert.equal(wrongReceiptStatus.kind, 'rejected');
  assert.equal((await bob.getStatus(receiptOffer.offer_id)).state, 'rejected');

  await issueGenesis();
  const crashOffer = await bob.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const crashOfferRecord = await bob.vault.getRecord(crashOffer.offer_id) as any;
  const crashSent = await alice.sendTransfer({ offer: crashOffer, status_capability: crashOfferRecord.status_capability });
  assert.equal(crashSent.kind, 'committed');
  const crashHandoff = await alice.getTransferAcceptanceHandoff(crashSent.record_id);
  bobBackend.failNextRecordWrite = true;
  await assert.rejects(bob.acceptTransfer(crashOffer, crashHandoff));
  const recoveredStatus = await bob.getStatus(crashOffer.offer_id);
  assert.equal(recoveredStatus.kind, 'committed');
  assert.equal(recoveredStatus.state, 'current');
  assert.equal(currentArtifact(await bob.vault.listRecords(), fixtureValue.discovery.exchange.active_graph.keysets[1].keyset_id).length > 0, true);

  const genesisBackend = new FailOnceBackend();
  const crashWallet = await wallet(fixtureValue, freebird, 133, genesisBackend);
  const crashGenesis = await crashWallet.prepareGenesis({ authorization: AUTHORIZATION });
  await crashWallet.vault.markGenesisSubmitted(crashGenesis.record_id);
  genesisBackend.failNextRecordWrite = true;
  await assert.rejects(crashWallet.recoverGenesis(crashGenesis.record_id));
  const recoveredGenesis = await crashWallet.getStatus(crashGenesis.record_id);
  assert.equal(recoveredGenesis.kind, 'committed');
  assert.equal(recoveredGenesis.state, 'current');
}

async function testAtomicReservationAndReceiveRecovery(): Promise<void> {
  const fixtureValue = await fixture();
  const freebird = new FakeFreebird(fixtureValue);
  const senderBackend = new FailOnceBackend();
  const sender = await wallet(fixtureValue, freebird, 177, senderBackend);
  const receiver = await wallet(fixtureValue, freebird, 199);
  const genesis = await sender.prepareGenesis({ authorization: AUTHORIZATION });
  assert.equal((await sender.submitGenesis(genesis.record_id)).kind, 'committed');
  const offer = await receiver.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const offerRecord = await receiver.vault.getRecord(offer.offer_id) as any;
  const sourceArtifact = currentArtifact(await sender.vault.listRecords(), fixtureValue.discovery.exchange.active_graph.keysets[0].keyset_id);

  senderBackend.failNextRecordWrite = true;
  await assert.rejects(sender.sendTransfer({ offer, status_capability: offerRecord.status_capability }));
  assert.equal(freebird.exchangeCalls.length, 0, 'a failed atomic reservation must not submit');
  const recoveredRecords = await sender.vault.listRecords();
  const sendRecord = [...recoveredRecords.values()].find((record) => record.record_type === 'prepared_send');
  assert.ok(sendRecord && sendRecord.record_type === 'prepared_send');
  const reservedSource = recoveredRecords.get(sendRecord.source_record_id);
  assert.equal(sendRecord.state, 'reserved_pending');
  assert.equal(reservedSource?.record_type, 'artifact');
  assert.equal(reservedSource?.state, 'reserved');
  assert.equal(reservedSource?.reserved_by, sendRecord.operation_id);
  const sendRecordId = [...recoveredRecords.entries()].find(([, record]) => record.record_type === 'prepared_send')![0];
  const mutatedSourceRequest = structuredClone(sendRecord.request) as any;
  mutatedSourceRequest.sources[0].artifact = 'Ag';
  await assert.rejects(sender.recoverSend(sendRecordId, { request: mutatedSourceRequest, status_capability: sendRecord.status_capability! }));
  const recoveredSend = await sender.recoverSend(sendRecordId);
  assert.equal(recoveredSend.kind, 'committed');

  const receiveOffer = await receiver.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const receiveRecord = await receiver.vault.getRecord(receiveOffer.offer_id) as any;
  const request = requestForOffer(receiveOffer, sourceArtifact);
  freebird.setExchangeBehavior(receiveOffer.operation_id, 'retryable-once');
  const first = await receiver.recoverReceive(receiveOffer, request, receiveRecord.status_capability);
  assert.equal(first.kind, 'retryable');
  const receiveCalls = freebird.exchangeCalls.length;
  const mutatedRequest = structuredClone(request) as any;
  mutatedRequest.outputs[0].blinded_value = 'Ag';
  await assert.rejects(receiver.recoverReceive(receiveOffer, mutatedRequest, receiveRecord.status_capability));
  await assert.rejects(receiver.recoverReceive(receiveOffer, request, 'malformed-status-capability'));
  assert.equal(freebird.exchangeCalls.length, receiveCalls, 'conflicting recovery inputs must not submit');
  const completed = await receiver.recoverReceive(receiveOffer, request, receiveRecord.status_capability);
  assert.equal(completed.kind, 'committed');
  assert.equal(freebird.exchangeCalls.length, receiveCalls + 1);
}

async function testTerminalGenesisRejectionAndPins(): Promise<void> {
  const fixtureValue = await fixture();
  const freebird = new FakeFreebird(fixtureValue);
  freebird.setGraphResultTampered(true);
  const genesisWallet = await wallet(fixtureValue, freebird, 211);
  const genesis = await genesisWallet.prepareGenesis({ authorization: AUTHORIZATION });
  const rejected = await genesisWallet.submitGenesis(genesis.record_id);
  assert.equal(rejected.kind, 'rejected');
  assert.equal((await genesisWallet.getStatus(genesis.record_id)).state, 'rejected');
  assert.equal((await genesisWallet.submitGenesis(genesis.record_id)).kind, 'rejected');
  assert.equal(freebird.graphCalls.length, 1, 'terminal genesis rejection must not retry');

  const backend = new MemoryVaultBackend();
  const vault = await LocalVault.create({ backend, unlockKey: new Uint8Array(32).fill(1), randomBytes: sequence(244) });
  assert.throws(() => new CirculationWalletV1({ vault, discovery: fixtureValue.discovery, issuerId: 'wrong-issuer', freebird, randomBytes: sequence(244) }));
  assert.throws(() => new CirculationWalletV1({ vault, discovery: { ...fixtureValue.discovery, origin: 'http://not-loopback.example' }, issuerId: ISSUER, freebird, randomBytes: sequence(244) }));
  const badGraph = structuredClone(fixtureValue.discovery) as any;
  badGraph.document.exchange.active_graph.profile_id = 'wrong/profile';
  assert.throws(() => new CirculationWalletV1({ vault, discovery: badGraph, issuerId: ISSUER, freebird, randomBytes: sequence(244) }));

  freebird.setGraphResultTampered(false);
  const sender = await wallet(fixtureValue, freebird, 255);
  const receiver = await wallet(fixtureValue, freebird, 277);
  const sendGenesis = await sender.prepareGenesis({ authorization: AUTHORIZATION });
  assert.equal((await sender.submitGenesis(sendGenesis.record_id)).kind, 'committed');
  const sendOffer = await receiver.prepareTransferOffer({ transition_id: fixtureValue.transitions[0] });
  const sendOfferRecord = await receiver.vault.getRecord(sendOffer.offer_id) as any;
  freebird.setExchangeResultTampered(sendOffer.operation_id);
  const invalidSend = await sender.sendTransfer({ offer: sendOffer, status_capability: sendOfferRecord.status_capability });
  assert.equal(invalidSend.kind, 'rejected');
  assert.equal((await sender.getStatus(invalidSend.record_id)).state, 'rejected');
  const exchangeCallCount = freebird.exchangeCalls.length;
  assert.equal((await sender.recoverSend(invalidSend.record_id)).kind, 'rejected');
  assert.equal(freebird.exchangeCalls.length, exchangeCallCount, 'terminal send rejection must not retry');
}

async function testNoExternalAuthorityComposition(): Promise<void> {
  const fixtureValue = await fixture();
  const freebird = new FakeFreebird(fixtureValue);
  const alice = await wallet(fixtureValue, freebird, 266);
  const genesis = await alice.prepareGenesis({ authorization: AUTHORIZATION });
  assert.equal((await alice.submitGenesis(genesis.record_id)).kind, 'committed');
  assert.equal(freebird.witnessCalls, 0);
  assert.equal(freebird.hyperTokenCalls, 0);
}

async function testDiscoverySourceIsLoadedBeforeUse(): Promise<void> {
  const fixtureValue = await fixture();
  const freebird = new FakeFreebird(fixtureValue);
  const alice = await wallet(fixtureValue, freebird, 155);
  let fetched = false;
  const loaded = await CirculationWalletV1.open({
    vault: alice.vault,
    freebird,
    issuerId: ISSUER,
    discovery: {
      fetch: async () => {
        fetched = true;
        return fixtureValue.discovery;
      },
    },
    randomBytes: sequence(155),
    nowUnixSeconds: () => NOW,
  });
  assert.equal(fetched, true);
  assert.equal(loaded.discovery.exchange.active_graph.graph_id, fixtureValue.discovery.exchange.active_graph.graph_id);
}

async function main(): Promise<void> {
  await testEndToEndAndRecovery();
  await testWrongHandoffsAndVaultCrashRecovery();
  await testAtomicReservationAndReceiveRecovery();
  await testTerminalGenesisRejectionAndPins();
  await testNoExternalAuthorityComposition();
  await testDiscoverySourceIsLoadedBeforeUse();
  console.log('circulation-v1 wallet: all deterministic tests passed');
}

await main();
