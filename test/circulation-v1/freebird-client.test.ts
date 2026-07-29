/** Freebird v0.8.1 graph-issuance HTTP boundary gates. */

import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import {
  GRAPH_ISSUANCE_PATH,
  GRAPH_ISSUANCE_STATUS_PATH,
  FreebirdHttpClient,
} from '../../src/circulation-v1/freebird-client.js';
import {
  BoundaryValidationError,
  canonicalGraphIssuanceRequestDigest,
  canonicalGraphIssuanceResultDigest,
  encodeCanonicalBase64Url,
  type GraphIssuanceRecoveryContext,
  parseGraphIssuanceRequest,
  type GraphIssuanceRequest,
  type GraphIssuanceResult,
} from '../../src/circulation-v1/index.js';
import { probeReplayAuthority, validateReplayAuthorityProbeContext } from '../../src/circulation-v1/discovery.js';
import { replayAuthorityProofV1 } from '../../src/circulation-v1/canonical.js';

const id = (byte: number): string => byte.toString(16).padStart(2, '0').repeat(32);
const b64 = (length: number, byte: number): string => encodeCanonicalBase64Url(new Uint8Array(length).fill(byte));
const request: GraphIssuanceRequest = parseGraphIssuanceRequest({
  version: 2, public_operation_id: b64(16, 7), issuance_policy_id: 'bootstrap-v2', graph_id: id(1), keyset_id: id(2), descriptor_id: id(3), blinded_message: b64(256, 4), authorization: b64(64, 5),
});
const expectedTokenKeyId = id(0xaa);
const capability = b64(32, 8);
const descriptor = { descriptor_id: request.descriptor_id, token_key_id: expectedTokenKeyId } as any;

function resultFor(value: GraphIssuanceRequest = request, tamper: 'none' | 'quantity' | 'token' | 'request' | 'result' = 'none'): GraphIssuanceResult {
  const base = {
    version: 2 as const, public_operation_id: value.public_operation_id, issuance_policy_id: value.issuance_policy_id,
    graph_id: value.graph_id, keyset_id: value.keyset_id, descriptor_id: value.descriptor_id,
    token_key_id: tamper === 'token' ? id(0xbb) : expectedTokenKeyId,
    quantity: tamper === 'quantity' ? 2 : 1,
    request_digest: encodeCanonicalBase64Url(tamper === 'request' ? new Uint8Array(32).fill(1) : canonicalGraphIssuanceRequestDigest(value)),
    blind_signature: b64(256, 9),
  };
  return { ...base, result_digest: encodeCanonicalBase64Url(tamper === 'result' ? new Uint8Array(32).fill(2) : canonicalGraphIssuanceResultDigest(base as any)) } as GraphIssuanceResult;
}

function recovery(): GraphIssuanceRecoveryContext {
  return {
    request, requestDigest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(request)), publicOperationId: request.public_operation_id,
    issuancePolicyId: request.issuance_policy_id, graphId: request.graph_id, keysetId: request.keyset_id, descriptorId: request.descriptor_id,
    statusCapability: capability, expectedTokenKeyId, blindingState: b64(256, 6),
  };
}

async function listen(handler: (url: string, method: string, body: unknown, headers: Headers) => { status: number; body: unknown; headers?: Record<string, string> }): Promise<{ server: Server; origin: string; seen: Array<{ url: string; method: string; body: unknown; capability?: string }> }> {
  const seen: Array<{ url: string; method: string; body: unknown; capability?: string }> = [];
  const server = createServer((req, res) => {
    let text = '';
    req.on('data', (chunk) => { text += String(chunk); });
    req.on('end', () => {
      const body = text ? JSON.parse(text) : undefined;
      seen.push({ url: req.url ?? '', method: req.method ?? '', body, capability: req.headers['graph-issuance-status-capability'] as string | undefined });
      const answer = handler(req.url ?? '', req.method ?? '', body, new Headers(req.headers as Record<string, string>));
      res.writeHead(answer.status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...(answer.headers ?? {}) });
      res.end(JSON.stringify(answer.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return { server, origin: `http://127.0.0.1:${address.port}`, seen };
}

async function close(server: Server): Promise<void> { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }

async function testReplayAuthorityProbe(): Promise<void> {
  const authorityId = b64(32, 9);
  const probeId = b64(32, 10);
  const challenge = b64(32, 11);
  const context = { authorityId, probeId, challenge };
  assert.deepEqual(validateReplayAuthorityProbeContext(context), context);
  assert.throws(() => validateReplayAuthorityProbeContext({ authorityId, probeId }), BoundaryValidationError);
  let mode: 'valid' | 'authority' | 'probe' | 'proof' = 'valid';
  const fixture = await listen((url, method, body) => {
    if (method !== 'POST' || url !== '/v1/public/graph/replay-authority/probe') return { status: 404, body: { error: 'not_found' } };
    assert.deepEqual(body, { version: 1, authority_id: authorityId, probe_id: probeId });
    const responseAuthority = mode === 'authority' ? b64(32, 12) : authorityId;
    const responseProbe = mode === 'probe' ? b64(32, 13) : probeId;
    const responseProof = mode === 'proof'
      ? b64(32, 14)
      : encodeCanonicalBase64Url(replayAuthorityProofV1(new Uint8Array(32).fill(11), new Uint8Array(32).fill(9), new Uint8Array(32).fill(10), 'issuer:test'));
    return { status: 200, body: { version: 1, authority_id: responseAuthority, probe_id: responseProbe, proof: responseProof } };
  });
  try {
    const valid = await probeReplayAuthority({ origin: fixture.origin, issuerId: 'issuer:test', authorityId, context });
    assert.equal(valid.authority_id, authorityId);
    assert.equal(valid.probe_id, probeId);
    assert.equal(fixture.seen[0].body && JSON.stringify(fixture.seen[0].body).includes(challenge), false, 'challenge is never sent to the issuer');
    mode = 'authority';
    await assert.rejects(probeReplayAuthority({ origin: fixture.origin, issuerId: 'issuer:test', authorityId, context }), BoundaryValidationError);
    mode = 'probe';
    await assert.rejects(probeReplayAuthority({ origin: fixture.origin, issuerId: 'issuer:test', authorityId, context }), BoundaryValidationError);
    mode = 'proof';
    await assert.rejects(probeReplayAuthority({ origin: fixture.origin, issuerId: 'issuer:test', authorityId, context }), BoundaryValidationError);
    await assert.rejects(probeReplayAuthority({ origin: fixture.origin, issuerId: 'issuer:test', authorityId } as any), BoundaryValidationError);
  } finally {
    await close(fixture.server);
  }
}

async function main(): Promise<void> {
  await testReplayAuthorityProbe();
  let mode: 'valid' | 'no-store' | 'quantity' | 'token' | 'request' | 'result' | 'post-retryable' | 'post-retryable-bad-body' | 'post-retryable-bad-retry' | 'status-pending' | 'status-bad-body' | 'status-no-store' = 'valid';
  const fixture = await listen((url, method): { status: number; body: unknown; headers?: Record<string, string> } => {
    if (method === 'POST' && url === GRAPH_ISSUANCE_PATH) {
      if (mode === 'no-store') return { status: 200, body: resultFor() , headers: { 'cache-control': '' } };
      if (mode === 'post-retryable') return { status: 202, body: { status: 'graph_issuance_retryable' }, headers: { 'retry-after': '1' } };
      if (mode === 'post-retryable-bad-body') return { status: 202, body: { status: 'pending' }, headers: { 'retry-after': '1' } };
      if (mode === 'post-retryable-bad-retry') return { status: 202, body: { status: 'graph_issuance_retryable' }, headers: { 'retry-after': '2' } };
      const tamper = mode === 'quantity' || mode === 'token' || mode === 'request' || mode === 'result' ? mode : 'none';
      return { status: 200, body: resultFor(request, tamper) };
    }
    if (method === 'GET' && url.startsWith(`${GRAPH_ISSUANCE_STATUS_PATH}?`)) {
      if (mode === 'status-pending') return { status: 202, body: { status: 'pending' } };
      if (mode === 'status-bad-body') return { status: 202, body: { status: 'graph_issuance_retryable' } };
      if (mode === 'status-no-store') return { status: 202, body: { status: 'pending' }, headers: { 'cache-control': '' } };
      return { status: 200, body: resultFor() };
    }
    return { status: 404, body: { error: 'unknown_operation' } };
  });
  try {
    const client = new FreebirdHttpClient({ origin: fixture.origin, graphIssuanceDescriptor: descriptor, nowUnixSeconds: () => 1 });
    const committed = await client.issueGraphIssuance(request, capability);
    assert.equal(committed.kind, 'committed');
    assert.equal(fixture.seen[0].url, GRAPH_ISSUANCE_PATH);
    assert.equal(fixture.seen[0].capability, capability);
    assert.equal(JSON.stringify(fixture.seen[0].body).includes(capability), false);

    mode = 'no-store';
    assert.equal((await client.issueGraphIssuance(request, capability)).kind, 'ambiguous');
    for (const tamper of ['quantity', 'token', 'request', 'result'] as const) {
      mode = tamper;
      assert.equal((await client.issueGraphIssuance(request, capability)).kind, 'rejected', tamper);
    }

    mode = 'post-retryable';
    const retry = await client.issueGraphIssuance(request, capability);
    assert.equal(retry.kind, 'retryable');
    assert.equal(retry.status, 202);
    assert.equal(retry.retry_after_seconds, 1);
    assert.equal(retry.request_digest, encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(request)));
    assert.deepEqual(fixture.seen.at(-1)?.body, request, 'retryable POST preserves the exact request identity');
    assert.equal(fixture.seen.at(-1)?.capability, capability, 'retryable POST preserves the capability');
    mode = 'post-retryable-bad-body';
    assert.equal((await client.issueGraphIssuance(request, capability)).kind, 'ambiguous');
    mode = 'post-retryable-bad-retry';
    assert.equal((await client.issueGraphIssuance(request, capability)).kind, 'ambiguous');

    mode = 'valid';
    const recoveryContext = recovery();
    const recovered = await new FreebirdHttpClient({ origin: fixture.origin }).recoverGraphIssuance(recoveryContext);
    assert.equal(recovered.kind, 'committed');
    const observed = await new FreebirdHttpClient({ origin: fixture.origin }).getGraphIssuanceStatus(recoveryContext);
    assert.equal(observed.kind, 'committed');
    assert.equal(fixture.seen.at(-1)?.method, 'GET');
    assert.equal(fixture.seen.at(-1)?.capability, capability);
    assert.equal(fixture.seen.at(-1)?.url.includes(capability), false);
    mode = 'status-pending';
    const pending = await client.getGraphIssuanceStatus(recoveryContext);
    assert.equal(pending.kind, 'retryable');
    assert.equal(pending.status, 202);
    assert.equal(pending.observed, true);
    assert.equal(pending.request_digest, recoveryContext.requestDigest);
    mode = 'status-bad-body';
    assert.equal((await client.getGraphIssuanceStatus(recoveryContext)).kind, 'rejected');
    mode = 'status-no-store';
    const missingStatusNoStore = await client.getGraphIssuanceStatus(recoveryContext);
    assert.equal(missingStatusNoStore.kind, 'rejected');
    if (missingStatusNoStore.kind === 'rejected') assert.equal(missingStatusNoStore.error.code, 'missing_no_store');
    assert.throws(() => client.validateGraphIssuanceRecoveryContext({ ...recoveryContext, requestDigest: b64(32, 1) }));
    assert.equal((await client.recoverGraphIssuance({ ...recoveryContext, expectedTokenKeyId: id(0xbb) })).kind, 'rejected');
  } finally { await close(fixture.server); }
  console.log('circulation-v2 Freebird client: all deterministic tests passed');
}

await main();
