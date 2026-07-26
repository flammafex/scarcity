/** Deterministic, service-free Phase-1 circulation foundation gates. */

import assert from 'node:assert/strict';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import {
  BoundaryValidationError,
  CIRCULATION_CLASS,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  parseExchangeReceiptV2,
  parseExchangeRequestV2,
  parseExchangeResultV2,
  parseFreebirdV5Descriptor,
  parseGraphIssuanceRequestV1,
  parseGraphIssuanceResultV1,
  validateBootstrapManifest,
  validateDiscoverySnapshot,
  buildV5PublicBearerMessage,
  buildReceiptHashEnvelope,
  computeExchangeReceiptDigest,
  computeReceiptDigest,
  computeReceiptWitnessHash,
  decodeV5BearerArtifactBase64,
  decodeV4RedemptionTokenBase64,
  encodeV5BearerArtifact,
  encodeV4RedemptionTokenBase64,
  verifyExchangeResultDigest,
  verifyGraphIssuanceRequestDigest,
  verifyGraphIssuanceResultDigest,
  FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER,
  FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER,
  canonicalExchangeResultDigestV2,
  canonicalExchangeRequestDigestV2,
  canonicalGraphIssuanceRequestDigestV1,
  canonicalGraphIssuanceResultDigestV1,
  blindV5Message,
  finalizeV5Message,
  importRsaPssSpki,
  prepareV5Message,
  tokenKeyIdForSpki,
  verifyV5Signature,
  canonicalDescriptorIdV2,
  canonicalGraphIdV2,
  canonicalKeysetIdV2,
  canonicalTransitionIdV2,
  type ExchangeGraphV2,
  type FreebirdV5DescriptorV2,
} from '../../src/circulation-v1/index.js';

const zeros = (length: number): Uint8Array => new Uint8Array(length);
const hex = (byte: number): string => byte.toString(16).padStart(2, '0').repeat(32);
const id0 = hex(0x10);
const id1 = hex(0x11);
const id2 = hex(0x12);
const id3 = hex(0x13);
const id4 = hex(0x14);
const id5 = hex(0x15);
const id6 = hex(0x16);
const id7 = hex(0x17);
const id8 = hex(0x18);
const id9 = hex(0x19);
const operationId = encodeCanonicalBase64Url(zeros(16));
const digest = encodeCanonicalBase64Url(zeros(32));
const signature64 = encodeCanonicalBase64Url(zeros(64));

function expectReject(fn: () => unknown | Promise<unknown>, label: string): void | Promise<void> {
  const result = fn();
  if (!(result instanceof Promise)) {
    assert.throws(() => result, BoundaryValidationError, label);
    return;
  }
  return assert.rejects(result, BoundaryValidationError, label);
}

function descriptor(
  issuerId: string,
  tokenKeyId: string,
  spki: string,
): FreebirdV5DescriptorV2 {
  return {
    descriptor_id: '',
    profile_id: 'freebird/public-bearer-exchange/v2',
    issuer_id: issuerId,
    token_key_id: tokenKeyId,
    pubkey_spki_b64: spki,
    suite: 'RSABSSA-SHA384-PSS-Deterministic',
    audience: 'scarcity-phase-1',
    valid_from: 1_700_000_000,
    valid_until: 1_800_000_000,
  };
}

function wrapRsaSpkiAsRfc4055Pss(standard: Uint8Array): Uint8Array {
  // TEST-ONLY DER wrapper matching Freebird's RFC 4055 fixture shape.
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
  output.set(Uint8Array.of(0x30, 0x82, (body.length >>> 8) & 0xff, body.length & 0xff), 0);
  output.set(body, 4);
  return output;
}

function graphFixture(first: FreebirdV5DescriptorV2, second: FreebirdV5DescriptorV2): Record<string, unknown> {
  const firstKeyset = { keyset_id: '', descriptor_ids: [first.descriptor_id] };
  const secondKeyset = { keyset_id: '', descriptor_ids: [second.descriptor_id] };
  firstKeyset.keyset_id = canonicalKeysetIdV2(firstKeyset.descriptor_ids);
  secondKeyset.keyset_id = canonicalKeysetIdV2(secondKeyset.descriptor_ids);
  const sourceKeysetId = firstKeyset.keyset_id;
  const targetKeysetId = secondKeyset.keyset_id;
  const firstTransition = {
    transition_id: '',
    source_keyset_id: sourceKeysetId,
    target_keyset_id: targetKeysetId,
    source_slots: [{ descriptor_id: first.descriptor_id, slot_id: 'input', quantity: 1, class: CIRCULATION_CLASS }],
    output_slots: [{ descriptor_id: second.descriptor_id, slot_id: 'output', quantity: 1, class: CIRCULATION_CLASS }],
    budget_id: 'budget-e01',
    budget_limit: 100,
    admission_state: 'disabled',
  };
  firstTransition.transition_id = canonicalTransitionIdV2(firstTransition as any);
  const secondTransition = {
    transition_id: '',
    source_keyset_id: targetKeysetId,
    target_keyset_id: sourceKeysetId,
    source_slots: [{ descriptor_id: second.descriptor_id, slot_id: 'input', quantity: 1, class: CIRCULATION_CLASS }],
    output_slots: [{ descriptor_id: first.descriptor_id, slot_id: 'output', quantity: 1, class: CIRCULATION_CLASS }],
    budget_id: 'budget-e10',
    budget_limit: 100,
    admission_state: 'disabled',
  };
  secondTransition.transition_id = canonicalTransitionIdV2(secondTransition as any);
  const graph = {
    profile_id: 'freebird/public-bearer-exchange/v2',
    graph_id: '',
    descriptors: [first, second],
    keysets: [firstKeyset, secondKeyset],
    transitions: [firstTransition, secondTransition],
  };
  graph.graph_id = canonicalGraphIdV2(graph);
  return {
    profile_id: graph.profile_id,
    graph_id: graph.graph_id,
    descriptors: graph.descriptors,
    keysets: graph.keysets,
    transitions: graph.transitions,
  };
}

function discoveryFixture(first: FreebirdV5DescriptorV2, second: FreebirdV5DescriptorV2): Record<string, unknown> {
  const receiptPublicKey = ed25519.getPublicKey(zeros(32));
  return {
    exchange: {
      active_graph: graphFixture(first, second),
      retained_graphs: [],
      active_receipt_key: {
        key_id: encodeCanonicalLowerHex(sha256(receiptPublicKey)),
        algorithm: 'Ed25519',
        purpose: 'exchange_receipt_active',
        public_key_b64: encodeCanonicalBase64Url(receiptPublicKey),
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
      },
      retained_receipt_keys: [],
    },
  };
}

function bootstrapFixture(first: FreebirdV5DescriptorV2, second: FreebirdV5DescriptorV2): Record<string, unknown> {
  const graph = graphFixture(first, second);
  const transitionIds = (graph.transitions as Array<{ transition_id: string }>).map((transition) => transition.transition_id);
  return {
    version: 'scarcity/bootstrap-manifest/v1',
    issuer_id: 'issuer-phase-1',
    discovery: discoveryFixture(first, second),
    graph_issuance: {
      issuance_policy_id: 'bootstrap-v1',
      graph_id: graph.graph_id,
      keyset_id: (graph.keysets as Array<{ keyset_id: string }>)[0].keyset_id,
      descriptor_id: first.descriptor_id,
      budget_id: 'genesis-budget',
      budget_limit: 100,
      quantity: 1,
      admission_state: 'accepting_new',
      authorization_scheme: 'v4_local',
    },
    disabled_publication_ack: {
      version: 'freebird/exchange-disabled-publication-ack/v1',
      issuer_id: 'issuer-phase-1',
      graph_id: graph.graph_id,
      disabled_transition_ids: transitionIds,
      acknowledged_admission_state: 'disabled',
      operator: 'operator-test-only',
      acknowledged_at_unix: 1_700_000_001,
    },
  };
}

async function rsaFixture(): Promise<{ pair: CryptoKeyPair; first: FreebirdV5DescriptorV2; second: FreebirdV5DescriptorV2 }> {
  const pair = await RSABSSA.SHA384.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const secondPair = await RSABSSA.SHA384.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const secondSpki = new Uint8Array(await crypto.subtle.exportKey('spki', secondPair.publicKey));
  const spki = wrapRsaSpkiAsRfc4055Pss(standardSpki);
  const secondPssSpki = wrapRsaSpkiAsRfc4055Pss(secondSpki);
  const spkiB64 = encodeCanonicalBase64Url(spki);
  const secondSpkiB64 = encodeCanonicalBase64Url(secondPssSpki);
  const keyId = tokenKeyIdForSpki(spki);
  const secondKeyId = tokenKeyIdForSpki(secondPssSpki);
  return {
    pair,
    first: (() => { const value = descriptor('issuer-phase-1', keyId, spkiB64); return { ...value, descriptor_id: canonicalDescriptorIdV2(value) }; })(),
    second: (() => { const value = descriptor('issuer-phase-1', secondKeyId, secondSpkiB64); return { ...value, descriptor_id: canonicalDescriptorIdV2(value) }; })(),
  };
}

async function testRfc9474AndV5(): Promise<void> {
  const { pair, first } = await rsaFixture();
  const message = Uint8Array.from({ length: 48 }, (_, index) => index + 1);
  const suite = RSABSSA.SHA384.PSS.Deterministic();
  assert.deepEqual(suite.prepare(message), message, 'Deterministic suite must use PrepareIdentity');
  const blind = await suite.blind(pair.publicKey, message);
  const blindSignature = await suite.blindSign(pair.privateKey, blind.blindedMsg);
  const finalized = await suite.finalize(pair.publicKey, message, blindSignature, blind.inv);
  assert.equal(await suite.verify(pair.publicKey, finalized, message), true, 'RFC 9474 Appendix-A suite round trip');

  const publicKey = await importRsaPssSpki(first);
  const nonce = Uint8Array.from({ length: 32 }, (_, index) => index);
  const preparation = await blindV5Message(first, publicKey, nonce);
  const nativeBlindSignature = await suite.blindSign(pair.privateKey, decodeCanonicalBase64Url(preparation.blinded_value));
  const artifact = await finalizeV5Message(first, publicKey, preparation, nativeBlindSignature);
  assert.equal(artifact.version, 5);
  assert.equal(await verifyV5Signature(first, publicKey, preparation, artifact.signature), true);
  assert.deepEqual(prepareV5Message(first, nonce), preparation.message);
  assert.equal(artifact.token_key_id, first.token_key_id);
  assert.equal(artifact.issuer_id, first.issuer_id);
}

async function testFreebirdV5FixtureAndCanonicalVectors(): Promise<void> {
  // TEST-ONLY pinned Freebird fixture: freebird/crypto/src/lib.rs lines
  // 867-901, with provenance in crypto/tests/fixture-provenance.md.
  const spkiB64 = 'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAoxaXGOdxdxj6I3S_lbNJ4T1CQ76A3cVJJUJECn0SiyKwKAA_FFTZQdmKq8gz3JDhrxayLXrhaoFtgTsmeMMlhPsYfyIOOzfe4khh3W-1nKhBqO5Kdr6KbVxgHkgoDWvKLXPCgSOpCG_1BAG1hJveWjd0LUAubxz3e2v5t9J_Vxddhsb9iqKylY0ZWXIsgqyEwPesqShxEb8qoJrIZ_Yi6_27Y9GR3MS6IzK5Ot0rNlEn3PCFW8phxVwofcMlxPgq_ZbdCRH_WJClQl6lWXBmL3DuSN8sMVJH4-rk9psHwrjiDciOpMvIotAEmIg1ZaTO-2DaKGRvV8oPlvXwPBp_gwIDAQAB';
  const signatureB64 = 'lR5zKsB-yqyRurEsESMmslQih5gjqVIGhl55yFHpuP40_PX2hG1wCljQcSL8xSYE3k5HeXcvKQsLy4DVz7GiUCHzhEQQqDU1usXI1IPVjZIGwPbWq1R-GyMfUrw0t01IPoAzACChZ267KWuEZ-o7JI9Jk9dS8B67YAl8VZqw2Y0nZU-l0Zbt1DNpYIGX8e9Z-ASJ76WjR2AV7ANNqWIYklRrCJtqySOmDMf3SjkXL6AaYUmIYb98ENizrngKA2voJBSTsHF2FVaXKPNn9GYueYyCZNhfRWsyLQT6gjmvNHnMJWwNQc_ApNwRNKkbNZbkwQfXU-vurMEK-OkuI-C_8Q';
  const artifactB64 = 'BSAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_Qlf_qAoZ8HL_J7KNYHR-0DG0s2wD_ccSUrPfal_pgvkRaXNzdWVyOmZpeHR1cmU6djUBAJUecyrAfsqskbqxLBEjJrJUIoeYI6lSBoZeechR6bj-NPz19oRtcApY0HEi_MUmBN5OR3l3LykLC8uA1c-xolAh84REEKg1NbrFyNSD1Y2SBsD21qtUfhsjH1K8NLdNSD6AMwAgoWduuylrhGfqOySPSZPXUvAeu2AJfFWasNmNJ2VPpdGW7dQzaWCBl_HvWfgEie-lo0dgFewDTaliGJJUawibaskjpgzH90o5Fy-gGmFJiGG_fBDYs654CgNr6CQUk7BxdhVWlyjzZ_RmLnmMgmTYX0VrMi0E-oI5rzR5zCVsDUHPwKTcETSpGzWW5MEH11Pr7qzBCvjpLiPgv_E';
  const spki = decodeCanonicalBase64Url(spkiB64);
  const tokenKeyId = decodeCanonicalLowerHex('4257ffa80a19f072ff27b28d60747ed031b4b36c03fdc71252b3df6a5fe982f9', 32);
  const nonce = Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index);
  const message = buildV5PublicBearerMessage(nonce, tokenKeyId, 'issuer:fixture:v5');
  assert.equal(encodeCanonicalLowerHex(message), '2d1659912a7e91228969587ea710dc0655f4904eaef8c142e989021e15e88c93cf5b56eb0a250dca9134fc0d007c2db5');
  const artifactBytes = decodeCanonicalBase64Url(artifactB64);
  assert.deepEqual(encodeV5BearerArtifact(nonce, tokenKeyId, 'issuer:fixture:v5', decodeCanonicalBase64Url(signatureB64)), artifactBytes);
  const artifact = decodeV5BearerArtifactBase64(artifactB64);
  assert.equal(artifact.token_key_id, encodeCanonicalLowerHex(tokenKeyId));
  assert.equal(artifact.signature, signatureB64);
  const fixtureDescriptorBase = {
    descriptor_id: '',
    profile_id: 'freebird/public-bearer-exchange/v2' as const,
    issuer_id: 'issuer:fixture:v5',
    token_key_id: encodeCanonicalLowerHex(tokenKeyId),
    pubkey_spki_b64: spkiB64,
    suite: 'RSABSSA-SHA384-PSS-Deterministic' as const,
    valid_from: 1,
    valid_until: 2,
    audience: 'fixture',
  };
  const fixtureDescriptor = { ...fixtureDescriptorBase, descriptor_id: canonicalDescriptorIdV2(fixtureDescriptorBase) };
  const fixturePublicKey = await importRsaPssSpki(fixtureDescriptor);
  assert.equal(await verifyV5Signature(fixtureDescriptor, fixturePublicKey, {
    nonce,
    message,
    token_key_id: fixtureDescriptor.token_key_id,
    issuer_id: fixtureDescriptor.issuer_id,
  }, signatureB64), true, 'pinned Freebird V5 fixture interoperability');
  const v4 = encodeV4RedemptionTokenBase64(nonce, zeros(32), 'kid:test', 'issuer:fixture:v4', zeros(32));
  const parsedV4 = decodeV4RedemptionTokenBase64(v4);
  assert.equal(parsedV4.version, 4);
  assert.equal(parsedV4.kid, 'kid:test');

  const receiptDigest = computeReceiptDigest(Uint8Array.of(1, 2, 3, 4));
  assert.equal(encodeCanonicalLowerHex(receiptDigest), 'd95b96d884f137288a79832b0e3c587ba41b24f76970cda6c80c40686d32d143');
  assert.equal(
    encodeCanonicalLowerHex(buildReceiptHashEnvelope(CIRCULATION_CLASS, receiptDigest)),
    '0000001e73636172636974792f63697263756c6174696e672d6265617265722f7631d95b96d884f137288a79832b0e3c587ba41b24f76970cda6c80c40686d32d143',
  );
  assert.equal(computeReceiptWitnessHash(CIRCULATION_CLASS, receiptDigest), 'edf7cc1b0e92c76ffc7c2c4855363f7fff8ea94a8e13ccf0b5ddf3c128d48d66');

  const request = {
    version: 2,
    public_operation_id: operationId,
    graph_id: id0,
    transition_id: id1,
    source_keyset_id: id2,
    target_keyset_id: id3,
    sources: [{ slot: { descriptor_id: id4, keyset_id: id2, slot_id: id5, quantity: 1 }, artifact: 'AA' }],
    outputs: [{ slot: { descriptor_id: id6, keyset_id: id3, slot_id: id7, quantity: 1 }, blinded_value: 'AQ' }],
  };
  const resultBase = {
    version: 2,
    public_operation_id: operationId,
    graph_id: id0,
    transition_id: id1,
    source_keyset_id: id2,
    target_keyset_id: id3,
    outputs: [{ slot: { descriptor_id: id6, keyset_id: id3, slot_id: id7, quantity: 1 }, blinded_value: 'AQ', blind_signature: 'Ag' }],
  };
  const result = { ...resultBase, result_digest: encodeCanonicalBase64Url(canonicalExchangeResultDigestV2(resultBase as any)) };
  assert.equal(result.result_digest, 'FyHUSb6M1l6BR8iE5BSNPRJN3bYeswlwaQwF2IGZiDc');
  const receipt = {
    version: 2,
    public_operation_id: operationId,
    graph_id: id0,
    transition_id: id1,
    source_keyset_id: id2,
    target_keyset_id: id3,
    result_digest: result.result_digest,
    created_at: 1_700_000_000,
    expires_at: 1_700_000_000 + 2_592_000,
    receipt_key_id: id4,
    signature: signature64,
  };
  const parsedRequest = parseExchangeRequestV2(request);
  const parsedResult = parseExchangeResultV2(result);
  const parsedReceipt = parseExchangeReceiptV2(receipt);
  const requestDigest = encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(parsedRequest));
  assert.equal(requestDigest, 'BGxWe4g51k-IvU1q8nhYYpRLyoZOO3YkVfTlX2e0kCs');
  verifyExchangeResultDigest(parsedResult, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
  assert.equal(computeExchangeReceiptDigest(parsedReceipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER).length, 32);
  const issuanceRequest = parseGraphIssuanceRequestV1({
    version: 1,
    public_operation_id: operationId,
    issuance_policy_id: 'bootstrap-v1',
    graph_id: id0,
    keyset_id: id1,
    descriptor_id: id2,
    blinded_message: 'AQ',
    authorization: 'Ag',
  });
  const issuanceResultBase = {
    version: 1,
    public_operation_id: operationId,
    issuance_policy_id: 'bootstrap-v1',
    graph_id: id0,
    keyset_id: id1,
    descriptor_id: id2,
    token_key_id: id3,
    quantity: 1,
    request_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigestV1(issuanceRequest)),
    blind_signature: 'Ag',
  };
  assert.equal(issuanceResultBase.request_digest, 'SWv3xcIvIJnpqU9Ekbs7UOaGt4hKbqtxJi0AnGg4kj8');
  const issuanceResult = parseGraphIssuanceResultV1({ ...issuanceResultBase, result_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceResultDigestV1(issuanceResultBase as any)) });
  assert.equal(issuanceResult.result_digest, 'aOy32sb-rxw7AuQAvI9K5uCfHchfVmA1IhpNNPbg97I');
  verifyGraphIssuanceRequestDigest(issuanceRequest, issuanceResult, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
  verifyGraphIssuanceResultDigest(issuanceResult, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
}

async function testBoundaryRejections(): Promise<void> {
  assert.throws(() => decodeCanonicalBase64Url('A==='), BoundaryValidationError);
  assert.throws(() => decodeCanonicalBase64Url('ab+_'), BoundaryValidationError);
  assert.throws(() => decodeCanonicalLowerHex('AA'), BoundaryValidationError);
  assert.throws(() => decodeCanonicalLowerHex('0G'.repeat(32), 32), BoundaryValidationError);
  const fixture = await rsaFixture();
  assert.throws(() => parseFreebirdV5Descriptor({ ...fixture.first, unknown: true }), BoundaryValidationError);
  assert.throws(() => parseFreebirdV5Descriptor({ ...fixture.first, suite: 'RSABSSA-SHA384-PSS-Randomized' }), BoundaryValidationError);
  assert.throws(() => parseFreebirdV5Descriptor({ ...fixture.first, token_key_id: id0 }), BoundaryValidationError);
  await assert.rejects(importRsaPssSpki({ ...fixture.first, pubkey_spki_b64: 'AA' }), BoundaryValidationError);
  const incompatibleSpki = decodeCanonicalBase64Url(fixture.first.pubkey_spki_b64);
  incompatibleSpki[64] ^= 0x01;
  const incompatibleDescriptor = { ...fixture.first, pubkey_spki_b64: encodeCanonicalBase64Url(incompatibleSpki), token_key_id: tokenKeyIdForSpki(incompatibleSpki) };
  await assert.rejects(importRsaPssSpki({ ...incompatibleDescriptor, descriptor_id: canonicalDescriptorIdV2(incompatibleDescriptor) }), BoundaryValidationError);
  assert.throws(() => buildV5PublicBearerMessage(zeros(31), zeros(32), fixture.first.issuer_id), BoundaryValidationError);
  const key = await importRsaPssSpki(fixture.first);
  const preparation = await blindV5Message(fixture.first, key, zeros(32));
  await assert.rejects(finalizeV5Message(fixture.first, key, preparation, 'AA'), BoundaryValidationError);
  await assert.rejects(verifyV5Signature(fixture.first, key, preparation, 'AA'), BoundaryValidationError);
  assert.throws(() => parseExchangeRequestV2({ version: 2, public_operation_id: operationId, graph_id: id0, transition_id: id1, source_keyset_id: id2, target_keyset_id: id3, sources: [], outputs: [], extra: 1 }), BoundaryValidationError);
}

async function testBootstrapProfile(): Promise<void> {
  const fixture = await rsaFixture();
  const manifest = bootstrapFixture(fixture.first, fixture.second);
  assert.equal(validateBootstrapManifest(manifest).graph_issuance.keyset_id, (manifest.discovery as any).exchange.active_graph.keysets[0].keyset_id);
  const accepting = structuredClone(manifest) as Record<string, any>;
  for (const transition of accepting.discovery.exchange.active_graph.transitions) transition.admission_state = 'accepting_new';
  assert.equal(validateDiscoverySnapshot(accepting.discovery, { circulationState: 'accepting_new' }).active_graph.transitions[0].admission_state, 'accepting_new');

  const mutations: Array<[string, (value: Record<string, any>) => void]> = [
    ['wrong class', (value) => { value.discovery.exchange.active_graph.transitions[0].source_slots[0].class = 'other/v1'; }],
    ['wrong quantity', (value) => { value.discovery.exchange.active_graph.transitions[0].source_slots[0].quantity = 2; }],
    ['wrong budget', (value) => { value.discovery.exchange.active_graph.transitions[0].budget_limit = 99; }],
    ['extra edge', (value) => { value.discovery.exchange.active_graph.transitions.push(structuredClone(value.discovery.exchange.active_graph.transitions[0])); }],
    ['self edge', (value) => { value.discovery.exchange.active_graph.transitions[0].target_keyset_id = value.discovery.exchange.active_graph.transitions[0].source_keyset_id; }],
    ['genesis K1', (value) => { value.graph_issuance.keyset_id = value.discovery.exchange.active_graph.keysets[1].keyset_id; }],
    ['wrong authorizer', (value) => { value.graph_issuance.authorization_scheme = 'other'; }],
    ['wrong profile', (value) => { value.discovery.exchange.active_graph.profile_id = 'other/profile'; }],
    ['active without lifecycle option', (value) => { value.discovery.exchange.active_graph.transitions[0].admission_state = 'accepting_new'; value.discovery.exchange.active_graph.transitions[1].admission_state = 'accepting_new'; }],
    ['unknown manifest field', (value) => { value.unknown = true; }],
  ];
  for (const [name, mutate] of mutations) {
    const changed = structuredClone(manifest) as Record<string, any>;
    mutate(changed);
    assert.throws(() => validateBootstrapManifest(changed), BoundaryValidationError, name);
  }
}

async function main(): Promise<void> {
  await testRfc9474AndV5();
  testFreebirdV5FixtureAndCanonicalVectors();
  await testBoundaryRejections();
  await testBootstrapProfile();
  console.log('circulation-v1 foundation: all deterministic tests passed');
}

await main();
