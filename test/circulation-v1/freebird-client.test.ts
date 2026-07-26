/** Deterministic local-server gates for the pinned Freebird HTTP boundary. */

import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import {
  CIRCULATION_CLASS,
  BoundaryValidationError,
  type ExchangeRequestV2,
  type FreebirdV5DescriptorV2,
  type GraphIssuanceRequestV1,
} from '../../src/circulation-v1/types.js';
import {
  canonicalDescriptorIdV2,
  canonicalExchangeResultDigestV2,
  canonicalGraphIdV2,
  canonicalGraphIssuanceRequestDigestV1,
  canonicalGraphIssuanceResultDigestV1,
  canonicalKeysetIdV2,
  canonicalTransitionIdV2,
  computeExchangeReceiptDigest,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER,
} from '../../src/circulation-v1/canonical.js';
import {
  V1_GRAPH_ISSUANCE_PATH,
  V1_GRAPH_ISSUANCE_STATUS_PATH,
  V2_EXCHANGE_PATH,
  V2_EXCHANGE_STATUS_PATH,
  FreebirdHttpClient,
} from '../../src/circulation-v1/freebird-client.js';
import { fetchFreebirdDiscovery, type ValidatedFreebirdDiscovery } from '../../src/circulation-v1/discovery.js';

const issuerId = 'issuer-test-only';
const operationId = encodeCanonicalBase64Url(new Uint8Array(16).fill(7));
const statusCapability = encodeCanonicalBase64Url(new Uint8Array(32).fill(8));
const now = 1_750_000_001;
const receiptSeed = new Uint8Array(32).fill(9);

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
    issuer_id: issuerId,
    token_key_id: encodeCanonicalLowerHex(sha256(spki)),
    pubkey_spki_b64: encodeCanonicalBase64Url(spki),
    suite: 'RSABSSA-SHA384-PSS-Deterministic',
    valid_from: 1_700_000_000,
    valid_until: 2_000_000_000,
    audience: 'test-only',
  };
  return { ...value, descriptor_id: canonicalDescriptorIdV2(value) };
}

async function discoveryFixture(): Promise<{ discovery: ValidatedFreebirdDiscovery; raw: Record<string, unknown> }> {
  const firstPair = await RSABSSA.SHA384.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const secondPair = await RSABSSA.SHA384.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
  const first = await descriptor(firstPair.publicKey);
  const second = await descriptor(secondPair.publicKey);
  const firstKeyset = { keyset_id: canonicalKeysetIdV2([first.descriptor_id]), descriptor_ids: [first.descriptor_id] as [string] };
  const secondKeyset = { keyset_id: canonicalKeysetIdV2([second.descriptor_id]), descriptor_ids: [second.descriptor_id] as [string] };
  const firstTransition = {
    transition_id: '',
    source_keyset_id: firstKeyset.keyset_id,
    target_keyset_id: secondKeyset.keyset_id,
    source_slots: [{ descriptor_id: first.descriptor_id, slot_id: 'input', class: CIRCULATION_CLASS, quantity: 1 as const }],
    output_slots: [{ descriptor_id: second.descriptor_id, slot_id: 'output', class: CIRCULATION_CLASS, quantity: 1 as const }],
    budget_id: 'budget-e01-test-only',
    budget_limit: 100 as const,
    admission_state: 'accepting_new' as const,
  };
  firstTransition.transition_id = canonicalTransitionIdV2(firstTransition as any);
  const secondTransition = {
    transition_id: '',
    source_keyset_id: secondKeyset.keyset_id,
    target_keyset_id: firstKeyset.keyset_id,
    source_slots: [{ descriptor_id: second.descriptor_id, slot_id: 'input', class: CIRCULATION_CLASS, quantity: 1 as const }],
    output_slots: [{ descriptor_id: first.descriptor_id, slot_id: 'output', class: CIRCULATION_CLASS, quantity: 1 as const }],
    budget_id: 'budget-e10-test-only',
    budget_limit: 100 as const,
    admission_state: 'accepting_new' as const,
  };
  secondTransition.transition_id = canonicalTransitionIdV2(secondTransition as any);
  const graph = {
    profile_id: 'freebird/public-bearer-exchange/v2' as const,
    graph_id: '',
    descriptors: [first, second] as [FreebirdV5DescriptorV2, FreebirdV5DescriptorV2],
    keysets: [firstKeyset, secondKeyset] as [typeof firstKeyset, typeof secondKeyset],
    transitions: [firstTransition, secondTransition] as [typeof firstTransition, typeof secondTransition],
  };
  graph.graph_id = canonicalGraphIdV2(graph);
  const receiptPublicKey = ed25519.getPublicKey(receiptSeed);
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
        issuance_policy_id: 'bootstrap-test-only',
        graph_id: graph.graph_id,
        keyset_id: firstKeyset.keyset_id,
        descriptor_id: first.descriptor_id,
        budget_id: 'genesis-test-only',
        budget_limit: 100,
        quantity: 1,
        admission_state: 'accepting_new',
        authorization_scheme: 'v4_local',
      }],
    },
  };
  const server = await listen((request, response) => {
    if (request.url === '/.well-known/keys') json(response, 200, raw);
    else json(response, 404, { error: 'not found' });
  });
  try {
    const discovery = await fetchFreebirdDiscovery({ origin: server.origin, issuerId });
    return { discovery, raw };
  } finally {
    await close(server.server);
  }
}

function json(response: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const body = JSON.stringify(value);
  response.writeHead(status, { 'content-type': 'application/json', ...headers });
  response.end(body);
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => { body += chunk; });
    request.on('end', () => resolve(body));
    request.on('error', reject);
  });
}

interface LocalServer {
  readonly server: Server;
  readonly origin: string;
  readonly requests: Array<{ method: string; url: string; body: string; capability?: string }>;
}

async function listen(handler: (request: IncomingMessage, response: ServerResponse, state: LocalServer) => void): Promise<LocalServer> {
  const requests: LocalServer['requests'] = [];
  let state!: LocalServer;
  const server = createServer(async (request, response) => {
    const body = request.method === 'POST' ? await readBody(request) : '';
    requests.push({
      method: request.method ?? '',
      url: request.url ?? '',
      body,
      capability: request.headers['exchange-status-capability'] as string | undefined
        ?? request.headers['graph-issuance-status-capability'] as string | undefined,
    });
    handler(request, response, state);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  state = { server, origin: `http://127.0.0.1:${address.port}`, requests };
  return state;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function exchangeRequest(discovery: ValidatedFreebirdDiscovery): ExchangeRequestV2 {
  const graph = discovery.exchange.active_graph;
  const sourceKeyset = graph.keysets[0];
  const targetKeyset = graph.keysets[1];
  const transition = graph.transitions.find((candidate) => candidate.source_keyset_id === sourceKeyset.keyset_id)!;
  return {
    version: 2,
    public_operation_id: operationId,
    graph_id: graph.graph_id,
    transition_id: transition.transition_id,
    source_keyset_id: sourceKeyset.keyset_id,
    target_keyset_id: targetKeyset.keyset_id,
    sources: [{ slot: { descriptor_id: transition.source_slots[0].descriptor_id, keyset_id: sourceKeyset.keyset_id, slot_id: transition.source_slots[0].slot_id, quantity: 1 }, artifact: 'AA' }],
    outputs: [{ slot: { descriptor_id: transition.output_slots[0].descriptor_id, keyset_id: targetKeyset.keyset_id, slot_id: transition.output_slots[0].slot_id, quantity: 1 }, blinded_value: 'AQ' }],
  };
}

async function exchangeResponse(request: ExchangeRequestV2, tamper: 'none' | 'digest' | 'selector' = 'none', receiptLifetime = 2_592_000): Promise<unknown> {
  const output = { ...request.outputs[0], blind_signature: 'Ag' as const };
  const resultBase = {
    version: 2 as const,
    public_operation_id: request.public_operation_id,
    graph_id: request.graph_id,
    transition_id: request.transition_id,
    source_keyset_id: request.source_keyset_id,
    target_keyset_id: request.target_keyset_id,
    outputs: [output] as [typeof output],
  };
  const result = {
    ...resultBase,
    ...(tamper === 'selector' ? { graph_id: '00'.repeat(32) } : {}),
    result_digest: encodeCanonicalBase64Url(canonicalExchangeResultDigestV2(resultBase as any)),
  };
  if (tamper === 'digest') result.result_digest = encodeCanonicalBase64Url(new Uint8Array(32).fill(1));
  const receiptBase = {
    version: 2 as const,
    public_operation_id: request.public_operation_id,
    graph_id: request.graph_id,
    transition_id: request.transition_id,
    source_keyset_id: request.source_keyset_id,
    target_keyset_id: request.target_keyset_id,
    result_digest: result.result_digest,
    created_at: now,
    expires_at: now + receiptLifetime,
    receipt_key_id: '00'.repeat(32),
    signature: encodeCanonicalBase64Url(new Uint8Array(64)),
  };
  return { result, receipt: receiptBase };
}

function graphIssuanceRequest(discovery: ValidatedFreebirdDiscovery): GraphIssuanceRequestV1 {
  const policy = discovery.graph_issuance!.policies[0];
  return {
    version: 1 as const,
    public_operation_id: operationId,
    issuance_policy_id: policy.issuance_policy_id,
    graph_id: policy.graph_id,
    keyset_id: policy.keyset_id,
    descriptor_id: policy.descriptor_id,
    blinded_message: 'AQ',
    authorization: 'Ag',
  };
}

function graphIssuanceResponse(
  request: Record<string, unknown>,
  tokenKeyId: string,
  tamper: 'none' | 'selector' | 'request-digest' | 'result-digest' | 'quantity' = 'none',
): Record<string, unknown> {
  const resultBase: Record<string, unknown> = {
    version: 1,
    public_operation_id: request.public_operation_id,
    issuance_policy_id: request.issuance_policy_id,
    graph_id: request.graph_id,
    keyset_id: request.keyset_id,
    descriptor_id: request.descriptor_id,
    token_key_id: tokenKeyId,
    quantity: 1,
    request_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigestV1(request as any)),
    blind_signature: 'Ag',
  };
  if (tamper === 'selector') resultBase.graph_id = '00'.repeat(32);
  if (tamper === 'request-digest') resultBase.request_digest = encodeCanonicalBase64Url(new Uint8Array(32).fill(1));
  if (tamper === 'quantity') resultBase.quantity = 2;
  const resultDigest = encodeCanonicalBase64Url(canonicalGraphIssuanceResultDigestV1(resultBase as any));
  return {
    ...resultBase,
    result_digest: tamper === 'result-digest' ? encodeCanonicalBase64Url(new Uint8Array(32).fill(2)) : resultDigest,
  };
}

async function testDiscoveryAndClientBoundary(): Promise<void> {
  const fixture = await discoveryFixture();
  assert.equal(fixture.discovery.origin.startsWith('http://127.0.0.1:'), true);
  await assert.rejects(fetchFreebirdDiscovery({ origin: 'http://user:pass@127.0.0.1:1', issuerId }), BoundaryValidationError);
  await assert.rejects(fetchFreebirdDiscovery({ origin: 'https://example.test', issuerId }), BoundaryValidationError);

  const redirect = await listen((_request, response) => {
    response.writeHead(302, { location: 'http://example.test/.well-known/keys' });
    response.end();
  });
  await assert.rejects(fetchFreebirdDiscovery({ origin: redirect.origin, issuerId }), BoundaryValidationError);
  await close(redirect.server);

  const malformed = await listen((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{');
  });
  await assert.rejects(fetchFreebirdDiscovery({ origin: malformed.origin, issuerId }), BoundaryValidationError);
  await close(malformed.server);

  const mismatch = await listen((_request, response) => {
    const changed = structuredClone(fixture.raw) as Record<string, any>;
    changed.exchange.active_graph.descriptors[0].issuer_id = 'wrong-issuer';
    json(response, 200, changed);
  });
  await assert.rejects(fetchFreebirdDiscovery({ origin: mismatch.origin, issuerId }), BoundaryValidationError);
  await close(mismatch.server);

  const request = exchangeRequest(fixture.discovery);
  const responseBody = await exchangeResponse(request);
  const receipt = responseBody as any;
  receipt.receipt.receipt_key_id = fixture.discovery.exchange.active_receipt_key.key_id;
  const receiptDigest = computeExchangeReceiptDigest(receipt.receipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
  receipt.receipt.signature = encodeCanonicalBase64Url(ed25519.sign(receiptDigest, receiptSeed));
  const server = await listen(async (incoming, response, state) => {
    if (incoming.url === '/.well-known/keys') return json(response, 200, fixture.raw);
    if (incoming.method === 'POST' && incoming.url === V2_EXCHANGE_PATH) {
      const count = state.requests.filter((item) => item.method === 'POST' && item.url === V2_EXCHANGE_PATH).length;
      if (count === 1) return json(response, 202, { status: 'exchange_retryable' }, { 'cache-control': 'no-store', 'retry-after': '1' });
      return json(response, 200, responseBody, { 'cache-control': 'no-store' });
    }
    if (incoming.method === 'GET' && incoming.url?.startsWith(`${V2_EXCHANGE_STATUS_PATH}?`)) {
      return json(response, 200, responseBody, { 'cache-control': 'no-store' });
    }
    if (incoming.method === 'POST' && incoming.url === V1_GRAPH_ISSUANCE_PATH) {
      const parsed = JSON.parse(state.requests.at(-1)!.body) as Record<string, unknown>;
      const resultBase = {
        version: 1 as const,
        public_operation_id: parsed.public_operation_id,
        issuance_policy_id: parsed.issuance_policy_id,
        graph_id: parsed.graph_id,
        keyset_id: parsed.keyset_id,
        descriptor_id: parsed.descriptor_id,
        token_key_id: fixture.discovery.exchange.active_graph.descriptors[0].token_key_id,
        quantity: 1,
        request_digest: '',
        blind_signature: 'Ag',
      } as any;
      const issuanceRequest = parsed as any;
      resultBase.request_digest = encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigestV1(issuanceRequest));
      return json(response, 200, { ...resultBase, result_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceResultDigestV1(resultBase)) }, { 'cache-control': 'no-store' });
    }
    return json(response, 404, {});
  });
  // The fixture discovery was fetched from a setup server; pin the operation
  // client to this server and retain the validated snapshot for receipt checks.
  const client = new FreebirdHttpClient({ origin: server.origin, discovery: { ...fixture.discovery, origin: server.origin }, nowUnixSeconds: () => now });
  const retry = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(retry.kind, 'retryable');
  const observation = await client.observeExchangeStatus(request, statusCapability);
  assert.equal(observation.kind, 'committed');
  assert.equal(observation.observed, true);
  const postRecords = server.requests.filter((item) => item.method === 'POST' && item.url === V2_EXCHANGE_PATH);
  assert.equal(postRecords.length, 1, 'GET observation must not perform recovery');
  assert.equal(postRecords[0].url.includes(statusCapability), false);
  assert.equal(postRecords[0].body.includes(statusCapability), false);

  const committed = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(committed.kind, 'committed');
  assert.equal(server.requests.filter((item) => item.method === 'POST' && item.url === V2_EXCHANGE_PATH).length, 2);
  await close(server.server);
}

async function testStrictResponseAndEndpointSeparation(): Promise<void> {
  const fixture = await discoveryFixture();
  const request = exchangeRequest(fixture.discovery);
  const issuanceRequest = graphIssuanceRequest(fixture.discovery);
  const tokenKeyId = fixture.discovery.exchange.active_graph.descriptors[0].token_key_id;
  let mode: 'missing-no-store' | 'wrong-lifetime' | 'content-type' | 'digest' | 'selector' | 'v2-400' | 'v2-409' | 'v2-503' | 'redirect' | 'valid' | 'v1-missing-no-store' | 'v1-status-missing-no-store' | 'v1-202' | 'v1-200' | 'v1-selector' | 'v1-request-digest' | 'v1-result-digest' | 'v1-quantity' = 'missing-no-store';
  let exchangeStatusCalls = 0;
  let issuanceStatusCalls = 0;
  const server = await listen(async (incoming, response, state) => {
    if (incoming.method === 'POST' && incoming.url === V2_EXCHANGE_PATH) {
      if (mode === 'missing-no-store') return json(response, 200, {}, {});
      if (mode === 'content-type') {
        response.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
        return response.end('{}');
      }
      if (mode === 'v2-400') return json(response, 400, { error: 'invalid exchange' });
      if (mode === 'v2-409') return json(response, 409, { error: 'conflict' });
      if (mode === 'v2-503') return json(response, 503, { error: 'temporary failure' });
      if (mode === 'redirect') {
        response.writeHead(302, { location: 'http://example.test/v2/public/exchange' });
        return response.end();
      }
      const value = await exchangeResponse(
        request,
        mode === 'digest' ? 'digest' : mode === 'selector' ? 'selector' : 'none',
        mode === 'wrong-lifetime' ? 2_592_001 : 2_592_000,
      );
      const body = value as any;
      if (mode !== 'wrong-lifetime') {
        body.receipt.receipt_key_id = fixture.discovery.exchange.active_receipt_key.key_id;
        const digest = computeExchangeReceiptDigest(body.receipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
        body.receipt.signature = encodeCanonicalBase64Url(ed25519.sign(digest, receiptSeed));
      }
      return json(response, 200, body, { 'cache-control': 'no-store' });
    }
    if (incoming.method === 'GET' && incoming.url?.startsWith(`${V2_EXCHANGE_STATUS_PATH}?`)) {
      exchangeStatusCalls += 1;
      if (exchangeStatusCalls === 1) return json(response, 202, { status: 'pending' }, { 'cache-control': 'no-store' });
      if (exchangeStatusCalls === 2) return json(response, 404, {});
      if (exchangeStatusCalls === 3) return json(response, 403, {});
      return json(response, 200, {}, { 'cache-control': 'no-store' });
    }
    if (incoming.method === 'POST' && incoming.url === V1_GRAPH_ISSUANCE_PATH) {
      if (mode === 'v1-missing-no-store' || mode === 'v1-200' || mode === 'v1-selector' || mode === 'v1-request-digest' || mode === 'v1-result-digest' || mode === 'v1-quantity') {
        const parsed = JSON.parse(state.requests.at(-1)!.body) as Record<string, unknown>;
        const tamper = mode === 'v1-selector' ? 'selector' : mode === 'v1-request-digest' ? 'request-digest' : mode === 'v1-result-digest' ? 'result-digest' : mode === 'v1-quantity' ? 'quantity' : 'none';
        return json(response, 200, graphIssuanceResponse(parsed, tokenKeyId, tamper), mode === 'v1-missing-no-store' ? {} : { 'cache-control': 'no-store' });
      }
      return json(response, 202, { status: 'graph_issuance_retryable' }, { 'cache-control': 'no-store' });
    }
    if (incoming.method === 'GET' && incoming.url?.startsWith(V1_GRAPH_ISSUANCE_STATUS_PATH)) {
      issuanceStatusCalls += 1;
      if (mode === 'v1-status-missing-no-store') return json(response, 202, { status: 'pending' }, {});
      if (issuanceStatusCalls === 1) return json(response, 202, { status: 'pending' }, { 'cache-control': 'no-store' });
      if (issuanceStatusCalls === 2) return json(response, 404, {});
      return json(response, 403, {});
    }
    return json(response, 404, {});
  });
  const client = new FreebirdHttpClient({ origin: server.origin, discovery: { ...fixture.discovery, origin: server.origin }, nowUnixSeconds: () => now });

  const requestsBeforeCapabilityChecks = server.requests.length;
  await assert.rejects(client.processOrRecoverV2(request, 'malformed-capability'), BoundaryValidationError);
  await assert.rejects(client.observeExchangeStatus(request, undefined as unknown as string), BoundaryValidationError);
  assert.equal(server.requests.length, requestsBeforeCapabilityChecks, 'invalid capabilities must not reach the server');

  const missing = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(missing.kind, 'ambiguous', 'a POST 200 without no-store cannot be accepted');
  mode = 'content-type';
  const wrongContentType = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(wrongContentType.kind, 'ambiguous', 'operation responses require application/json');
  assert.equal(JSON.stringify(wrongContentType).includes(statusCapability), false);
  mode = 'wrong-lifetime';
  assert.equal((await client.processOrRecoverV2(request, statusCapability)).kind, 'rejected');
  mode = 'digest';
  assert.equal((await client.processOrRecoverV2(request, statusCapability)).kind, 'rejected');
  mode = 'selector';
  assert.equal((await client.processOrRecoverV2(request, statusCapability)).kind, 'rejected');
  mode = 'v2-400';
  assert.equal((await client.processOrRecoverV2(request, statusCapability)).kind, 'rejected');
  mode = 'v2-409';
  assert.equal((await client.processOrRecoverV2(request, statusCapability)).kind, 'conflict');
  mode = 'v2-503';
  const ambiguous = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(ambiguous.kind, 'ambiguous');
  assert.equal(JSON.stringify(ambiguous).includes(statusCapability), false);
  const ambiguousPost = server.requests.at(-1)!;
  mode = 'valid';
  const recovered = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(recovered.kind, 'committed');
  const recoveryPost = server.requests.at(-1)!;
  assert.equal(recoveryPost.body, ambiguousPost.body, 'recovery must repeat the exact request');
  assert.equal(recoveryPost.capability, ambiguousPost.capability, 'recovery must repeat the exact capability');

  mode = 'redirect';
  const redirectOutcome = await client.processOrRecoverV2(request, statusCapability);
  assert.equal(redirectOutcome.kind, 'ambiguous');
  assert.equal(JSON.stringify(redirectOutcome).includes('example.test'), false);

  const crossOriginFetch = async (): Promise<Response> => {
    const response = new Response('{}', { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
    Object.defineProperty(response, 'url', { value: 'https://foreign.test/v2/public/exchange' });
    return response;
  };
  const crossOriginOutcome = await new FreebirdHttpClient({
    origin: server.origin,
    discovery: { ...fixture.discovery, origin: server.origin },
    fetchImpl: crossOriginFetch,
  }).processOrRecoverV2(request, statusCapability);
  assert.equal(crossOriginOutcome.kind, 'ambiguous');
  assert.equal(JSON.stringify(crossOriginOutcome).includes('foreign.test'), false);

  exchangeStatusCalls = 0;
  assert.equal((await client.observeExchangeStatus(request, statusCapability)).kind, 'retryable');
  const unknown = await client.observeExchangeStatus(request, statusCapability);
  assert.equal(unknown.kind, 'rejected');
  assert.equal(unknown.error.code, 'operation_unknown');
  const unauthorized = await client.observeExchangeStatus(request, statusCapability);
  assert.equal(unauthorized.kind, 'rejected');
  assert.equal(unauthorized.error.code, 'unauthorized');

  mode = 'v1-missing-no-store';
  const graphMissingNoStore = await client.processOrRecoverGraphIssuance(issuanceRequest, statusCapability);
  assert.equal(graphMissingNoStore.kind, 'ambiguous');
  assert.equal(graphMissingNoStore.error.code, 'missing_no_store');
  mode = 'v1-status-missing-no-store';
  issuanceStatusCalls = 0;
  const graphStatusMissingNoStore = await client.observeGraphIssuanceStatus(issuanceRequest, statusCapability);
  assert.equal(graphStatusMissingNoStore.kind, 'rejected');
  assert.equal(graphStatusMissingNoStore.error.code, 'missing_no_store');
  mode = 'v1-202';
  const graphRetry = await client.processOrRecoverGraphIssuance(issuanceRequest, statusCapability);
  assert.equal(graphRetry.kind, 'retryable');
  mode = 'v1-200';
  const graphCommitted = await client.processOrRecoverGraphIssuance(issuanceRequest, statusCapability);
  assert.equal(graphCommitted.kind, 'committed');
  assert.equal(Object.hasOwn(graphCommitted.value, 'receipt'), false, 'graph issuance has no receipt semantics');
  for (const tamper of ['v1-selector', 'v1-request-digest', 'v1-result-digest', 'v1-quantity'] as const) {
    mode = tamper;
    assert.equal((await client.processOrRecoverGraphIssuance(issuanceRequest, statusCapability)).kind, 'rejected', tamper);
  }
  issuanceStatusCalls = 0;
  assert.equal((await client.observeGraphIssuanceStatus(issuanceRequest, statusCapability)).kind, 'retryable');
  const graphUnknown = await client.observeGraphIssuanceStatus(issuanceRequest, statusCapability);
  assert.equal(graphUnknown.kind, 'rejected');
  assert.equal(graphUnknown.error.code, 'operation_unknown');
  const graphUnauthorized = await client.observeGraphIssuanceStatus(issuanceRequest, statusCapability);
  assert.equal(graphUnauthorized.kind, 'rejected');
  assert.equal(graphUnauthorized.error.code, 'unauthorized');

  assert.equal(server.requests.some((entry) => entry.url.includes(statusCapability)), false, 'capability must never enter a URL');
  assert.equal(server.requests.some((entry) => entry.url === V2_EXCHANGE_PATH && entry.method === 'POST'), true);
  assert.equal(server.requests.some((entry) => entry.url === V1_GRAPH_ISSUANCE_PATH && entry.method === 'POST'), true);
  assert.equal(server.requests.some((entry) => entry.url.startsWith(V1_GRAPH_ISSUANCE_STATUS_PATH) && entry.method === 'GET'), true);
  assert.equal(server.requests.some((entry) => entry.url.startsWith(V2_EXCHANGE_STATUS_PATH) && entry.method === 'GET'), true);
  assert.equal(V1_GRAPH_ISSUANCE_PATH, '/v1/public/graph/issue');
  assert.equal(V1_GRAPH_ISSUANCE_STATUS_PATH, '/v1/public/graph/issue/status');
  assert.notEqual(V1_GRAPH_ISSUANCE_PATH, V2_EXCHANGE_PATH);
  assert.notEqual(V1_GRAPH_ISSUANCE_STATUS_PATH, V2_EXCHANGE_STATUS_PATH);
  assert.equal(server.requests.some((entry) => entry.url === '/v1/graph/issuance'), false, 'legacy graph issuance route must not be used');
  assert.equal(server.requests.some((entry) => entry.url.startsWith('/v1/graph/issuance/status')), false, 'legacy graph issuance status route must not be used');
  const issuancePost = server.requests.find((entry) => entry.method === 'POST' && entry.url === V1_GRAPH_ISSUANCE_PATH);
  assert.equal(issuancePost?.capability, statusCapability);
  assert.equal(issuancePost?.body.includes(statusCapability), false, 'graph issuance capability must remain header-only');
  const issuanceStatus = server.requests.find((entry) => entry.method === 'GET' && entry.url.startsWith(V1_GRAPH_ISSUANCE_STATUS_PATH));
  assert.equal(issuanceStatus?.capability, statusCapability);
  await close(server.server);
}

async function main(): Promise<void> {
  await testDiscoveryAndClientBoundary();
  await testStrictResponseAndEndpointSeparation();
  console.log('circulation-v1 Freebird client: all deterministic tests passed');
}

await main();
