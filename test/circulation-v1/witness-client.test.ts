/** Deterministic fake-server gates for the Phase-1 asynchronous Witness client. */

import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { bls12_381 } from '@noble/curves/bls12-381';
import { ed25519 } from '@noble/curves/ed25519';
import {
  CIRCULATION_CLASS,
  BoundaryValidationError,
  WitnessEvidenceClient,
  WITNESS_ATTESTATIONS_PATH,
  WITNESS_NETWORK_PATH,
  canonicalWitnessAttestationBytes,
  computeReceiptWitnessHash,
  encodeCanonicalLowerHex,
  type WitnessAttestationTuple,
} from '../../src/circulation-v1/index.js';

const RECEIPT_DIGEST = new Uint8Array(32).fill(0x42);
const HASH = computeReceiptWitnessHash(CIRCULATION_CLASS, RECEIPT_DIGEST);
const NETWORK_ID = 'witness-test-network';
const SEEDS = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)];

type Mode = 'pending' | 'retryable' | 'confirmed' | 'failed' | 'bad-hash' | 'tuple-mismatch' | 'signed-network-mismatch' | 'insufficient' | 'duplicate' | 'bad-ed' | 'missing';
type NoStoreEndpoint = 'network' | 'post' | 'get';

interface RequestRecord {
  readonly method: string;
  readonly url: string;
  readonly body: string;
}

interface LocalServer {
  readonly server: Server;
  readonly origin: string;
  readonly requests: RequestRecord[];
  mode: Mode;
  network: Record<string, unknown>;
  omitNoStore?: NoStoreEndpoint;
  cacheControlOverride?: string | null;
}

function json(response: ServerResponse, status: number, value: unknown, contentType = 'application/json', cacheControl: string | null = 'no-store'): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    'content-type': contentType,
    ...(cacheControl === null ? {} : { 'cache-control': cacheControl }),
  });
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

async function listen(handler: (request: IncomingMessage, response: ServerResponse, state: LocalServer) => void): Promise<LocalServer> {
  const requests: RequestRecord[] = [];
  let state!: LocalServer;
  const server = createServer(async (request, response) => {
    const body = request.method === 'POST' ? await readBody(request) : '';
    requests.push({ method: request.method ?? '', url: request.url ?? '', body });
    handler(request, response, state);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  state = {
    server,
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    mode: 'confirmed',
    network: networkFixture(),
    omitNoStore: undefined,
    cacheControlOverride: undefined,
  };
  return state;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function networkFixture(): Record<string, unknown> {
  return {
    id: NETWORK_ID,
    threshold: 2,
    witnesses: SEEDS.map((seed, index) => ({
      id: `ed-${index + 1}`,
      algorithm: 'Ed25519',
      public_key: encodeCanonicalLowerHex(ed25519.getPublicKey(seed)),
    })),
  };
}

function tuple(overrides: Partial<WitnessAttestationTuple> = {}): WitnessAttestationTuple {
  return {
    hash: HASH,
    timestamp: 1_750_000_000,
    network_id: NETWORK_ID,
    sequence: 9,
    ...overrides,
  };
}

function signedEd(tupleValue: WitnessAttestationTuple, indexes: readonly number[] = [0, 1], bad = false): Record<string, unknown> {
  return {
    contract_version: 'sophia/v1',
    artifact_type: 'witness.signed_attestation',
    attestation: tupleValue,
    signatures: {
      kind: 'multisig',
      signatures: indexes.map((index) => ({
        witness_id: `ed-${index + 1}`,
        signature: encodeCanonicalLowerHex(ed25519.sign(canonicalWitnessAttestationBytes(tupleValue), SEEDS[index])),
      })).map((entry, index) => bad && index === 0 ? { ...entry, signature: '00'.repeat(64) } : entry),
    },
  };
}

function jobFor(state: LocalServer): Record<string, unknown> {
  const unsignedTuple = state.mode === 'bad-hash' ? tuple({ hash: '00'.repeat(32) }) : tuple();
  let signedAttestation: Record<string, unknown> | undefined;
  if (state.mode === 'confirmed' || state.mode === 'tuple-mismatch' || state.mode === 'signed-network-mismatch' || state.mode === 'insufficient' || state.mode === 'duplicate' || state.mode === 'bad-ed') {
    const signedTuple = state.mode === 'tuple-mismatch'
      ? tuple({ timestamp: unsignedTuple.timestamp + 1 })
      : state.mode === 'signed-network-mismatch'
        ? tuple({ network_id: 'wrong-network' })
        : unsignedTuple;
    const indexes = state.mode === 'insufficient' ? [0] : state.mode === 'duplicate' ? [0, 0] : [0, 1];
    signedAttestation = signedEd(signedTuple, indexes, state.mode === 'bad-ed');
  }
  return {
    attestation: unsignedTuple,
    status: state.mode === 'pending' || state.mode === 'retryable' || state.mode === 'bad-hash' ? state.mode === 'bad-hash' ? 'pending' : state.mode : state.mode === 'failed' || state.mode === 'missing' ? 'failed' : 'confirmed',
    attempts: 1,
    ...(state.mode === 'pending' || state.mode === 'retryable' ? { next_attempt_at: 1_750_000_010 } : {}),
    ...(signedAttestation === undefined ? {} : { signed_attestation: signedAttestation }),
  };
}

function standardServer(): Promise<LocalServer> {
  return listen((request, response, state) => {
    const cacheControl = (endpoint: NoStoreEndpoint): string | null => {
      if (state.cacheControlOverride !== undefined) return state.cacheControlOverride;
      return state.omitNoStore === endpoint ? null : 'no-store';
    };
    if (request.method === 'GET' && request.url === WITNESS_NETWORK_PATH) return json(response, 200, state.network, 'application/json', cacheControl('network'));
    if (request.method === 'POST' && request.url === WITNESS_ATTESTATIONS_PATH) return json(response, state.mode === 'pending' || state.mode === 'retryable' ? 202 : 200, jobFor(state), 'application/json', cacheControl('post'));
    if (request.method === 'GET' && request.url === `${WITNESS_ATTESTATIONS_PATH}/${HASH}`) {
      if (state.mode === 'missing') return json(response, 404, { error: 'missing' });
      return json(response, 200, jobFor(state), 'application/json', cacheControl('get'));
    }
    if (request.url?.startsWith('/v1/timestamp') || request.url?.startsWith('/v1/config') || request.url?.startsWith('/v1/verify')) {
      return json(response, 500, { error: 'removed endpoint called' });
    }
    return json(response, 404, { error: 'not found' });
  });
}

function client(server: LocalServer, now = 1_750_000_000): WitnessEvidenceClient {
  return new WitnessEvidenceClient({ origin: server.origin, expectedNetworkId: NETWORK_ID, nowUnixSeconds: () => now });
}

function testNativeAttestationFraming(): void {
  const value = tuple();
  const bytes = canonicalWitnessAttestationBytes(value);
  const network = new TextEncoder().encode(NETWORK_ID);
  assert.equal(bytes.length, 32 + 8 + 4 + network.length + 8);
  assert.deepEqual(bytes.slice(40, 44), Uint8Array.of(network.length, 0, 0, 0));
  assert.deepEqual(bytes.slice(44, 44 + network.length), network);
}

async function testLifecycleAndDisclosure(): Promise<void> {
  const server = await standardServer();
  try {
    let now = 1_750_000_000;
    const pendingClient = new WitnessEvidenceClient({ origin: server.origin, expectedNetworkId: NETWORK_ID, nowUnixSeconds: () => now });
    server.mode = 'pending';
    const pending = await pendingClient.submit({ hash: HASH, receipt_digest: RECEIPT_DIGEST });
    assert.equal(pending.kind, 'pending');
    const getBeforeRetry = server.requests.length;
    const tooEarly = await pendingClient.poll({ hash: HASH, receipt_digest: RECEIPT_DIGEST });
    assert.equal(tooEarly.kind, 'retryable');
    assert.equal(server.requests.length, getBeforeRetry, 'next_attempt_at prevents early polling');

    server.mode = 'confirmed';
    now = 1_750_000_011;
    const confirmed = await pendingClient.poll(HASH);
    assert.equal(confirmed.kind, 'confirmed');
    assert.equal(confirmed.status, 'confirmed');

    server.mode = 'retryable';
    const retryable = await client(server).submit(HASH);
    assert.equal(retryable.kind, 'retryable');
    server.mode = 'failed';
    const failed = await client(server).submit(HASH);
    assert.equal(failed.kind, 'failed');

    server.mode = 'missing';
    const missing = await client(server).poll(HASH);
    assert.equal(missing.kind, 'missing');

    const posts = server.requests.filter((record) => record.method === 'POST');
    assert.ok(posts.length > 0);
    for (const post of posts) {
      assert.deepEqual(JSON.parse(post.body), { hash: HASH }, 'Witness receives only the hash');
      assert.equal(post.url.includes('receipt'), false);
      assert.equal(post.url.includes('operation'), false);
    }
    assert.equal(server.requests.some((record) => record.url.startsWith('/v1/timestamp')), false);
    assert.equal(server.requests.some((record) => record.url.startsWith('/v1/config')), false);
    assert.equal(server.requests.some((record) => record.url.startsWith('/v1/verify')), false);
  } finally {
    await close(server.server);
  }
}

async function testEndpointDefenseAndHashBinding(): Promise<void> {
  const redirect = await listen((_request, response) => {
    response.writeHead(302, { location: 'https://foreign.example/v1/network' });
    response.end();
  });
  try {
    const outcome = await client(redirect).submit(HASH);
    assert.equal(outcome.kind, 'retryable');
    assert.equal(JSON.stringify(outcome).includes('foreign.example'), false);
  } finally {
    await close(redirect.server);
  }

  const wrongContentType = await listen((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end(JSON.stringify(networkFixture()));
  });
  try {
    const outcome = await client(wrongContentType).submit(HASH);
    assert.equal(outcome.kind, 'retryable');
    assert.equal(outcome.error?.code, 'invalid_response');
  } finally {
    await close(wrongContentType.server);
  }

  const crossOriginFetch: typeof fetch = async () => {
    const response = new Response(JSON.stringify(networkFixture()), { status: 200, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: 'https://foreign.example/v1/network' });
    return response;
  };
  const crossOrigin = new WitnessEvidenceClient({ origin: 'http://127.0.0.1:1', expectedNetworkId: NETWORK_ID, fetchImpl: crossOriginFetch });
  const crossOriginOutcome = await crossOrigin.submit(HASH);
  assert.equal(crossOriginOutcome.kind, 'retryable');
  assert.equal(JSON.stringify(crossOriginOutcome).includes('foreign.example'), false);

  const server = await standardServer();
  try {
    await assert.rejects(client(server).submit('AA'), BoundaryValidationError);
    assert.equal(server.requests.length, 0, 'bad hash must not reach Witness');
    await assert.rejects(client(server).submit({ hash: HASH, receipt_digest: new Uint8Array(32).fill(0x43) }), BoundaryValidationError);
    assert.equal(server.requests.length, 0, 'bad envelope binding must not reach Witness');
  } finally {
    await close(server.server);
  }
}

async function testNoStoreDefense(): Promise<void> {
  const missingNetwork = await standardServer();
  try {
    missingNetwork.omitNoStore = 'network';
    const outcome = await client(missingNetwork).submit(HASH);
    assert.equal(outcome.kind, 'retryable');
    assert.equal(outcome.error?.code, 'invalid_response');
    assert.equal(missingNetwork.requests.some((record) => record.method === 'POST'), false, 'network metadata must be rejected before POST');
  } finally {
    await close(missingNetwork.server);
  }

  const malformedNetwork = await standardServer();
  try {
    malformedNetwork.cacheControlOverride = 'no-store=1';
    const outcome = await client(malformedNetwork).submit(HASH);
    assert.equal(outcome.kind, 'retryable');
    assert.equal(outcome.error?.code, 'invalid_response');
    assert.equal(malformedNetwork.requests.some((record) => record.method === 'POST'), false, 'malformed caching directives must be rejected before POST');
  } finally {
    await close(malformedNetwork.server);
  }

  const missingPost = await standardServer();
  try {
    missingPost.omitNoStore = 'post';
    const outcome = await client(missingPost).submit(HASH);
    assert.equal(outcome.kind, 'failed');
    if (outcome.kind === 'failed') assert.equal(outcome.error.code, 'invalid_response');
  } finally {
    await close(missingPost.server);
  }

  const missingGet = await standardServer();
  try {
    let now = 1_750_000_000;
    const witness = new WitnessEvidenceClient({ origin: missingGet.origin, expectedNetworkId: NETWORK_ID, nowUnixSeconds: () => now });
    missingGet.mode = 'pending';
    const pending = await witness.submit(HASH);
    assert.equal(pending.kind, 'pending');
    missingGet.mode = 'confirmed';
    missingGet.omitNoStore = 'get';
    now = 1_750_000_011;
    const outcome = await witness.poll(HASH);
    assert.equal(outcome.kind, 'failed');
    if (outcome.kind === 'failed') assert.equal(outcome.error.code, 'invalid_response');
  } finally {
    await close(missingGet.server);
  }
}

async function testLocalRejectionVectors(): Promise<void> {
  const cases: Array<[Mode, string]> = [
    ['bad-hash', 'hash_mismatch'],
    ['tuple-mismatch', 'tuple_mismatch'],
    ['signed-network-mismatch', 'tuple_mismatch'],
    ['insufficient', 'threshold_failure'],
    ['duplicate', 'threshold_failure'],
    ['bad-ed', 'invalid_signature'],
  ];
  for (const [mode, expectedCode] of cases) {
    const server = await standardServer();
    try {
      server.mode = mode;
      const outcome = await client(server).submit(HASH);
      assert.equal(outcome.kind, 'failed', mode);
      if (outcome.kind === 'failed') assert.equal(outcome.error.code, expectedCode, mode);
    } finally {
      await close(server.server);
    }
  }

  const mismatch = await standardServer();
  try {
    mismatch.network = { ...networkFixture(), id: 'different-network' };
    const outcome = await client(mismatch).submit(HASH);
    assert.equal(outcome.kind, 'failed');
    if (outcome.kind === 'failed') assert.equal(outcome.error.code, 'network_mismatch');
    assert.equal(mismatch.requests.some((record) => record.method === 'POST'), false);
  } finally {
    await close(mismatch.server);
  }

  const malformed = await standardServer();
  try {
    malformed.network = { ...networkFixture(), unexpected: true };
    const outcome = await client(malformed).submit(HASH);
    assert.equal(outcome.kind, 'failed');
    if (outcome.kind === 'failed') assert.equal(outcome.error.code, 'invalid_config');
  } finally {
    await close(malformed.server);
  }
}

async function testBlsVerification(): Promise<void> {
  const secrets = [new Uint8Array(32).fill(11), new Uint8Array(32).fill(12)];
  const config = {
    id: NETWORK_ID,
    threshold: 2,
    witnesses: secrets.map((secret, index) => ({
      id: `bls-${index + 1}`,
      algorithm: 'BLS12-381',
      public_key: encodeCanonicalLowerHex(bls12_381.getPublicKey(secret)),
    })),
  };
  let corrupt = false;
  const server = await listen((request, response, state) => {
    if (request.method === 'GET' && request.url === WITNESS_NETWORK_PATH) return json(response, 200, config);
    if (request.method === 'POST' && request.url === WITNESS_ATTESTATIONS_PATH) {
      const attestation = tuple();
      const message = canonicalWitnessAttestationBytes(attestation);
      const first = bls12_381.G2.ProjectivePoint.fromHex(bls12_381.sign(message, secrets[0]));
      const second = bls12_381.G2.ProjectivePoint.fromHex(bls12_381.sign(message, secrets[1]));
      const signature = corrupt ? '00'.repeat(96) : encodeCanonicalLowerHex(first.add(second).toRawBytes());
      return json(response, 200, {
        attestation,
        status: 'confirmed',
        attempts: 1,
        signed_attestation: { attestation, signatures: { kind: 'aggregated', signature, signers: ['bls-1', 'bls-2'] } },
      });
    }
    return json(response, 404, { error: 'not found', mode: state.mode });
  });
  try {
    const witness = client(server);
    const outcome = await witness.submit(HASH);
    assert.equal(outcome.kind, 'confirmed');
    corrupt = true;
    const invalid = await witness.submit(HASH);
    assert.equal(invalid.kind, 'failed');
    if (invalid.kind === 'failed') assert.equal(invalid.error.code, 'invalid_signature');
  } finally {
    await close(server.server);
  }
}

async function testWitnessCannotChangeOwnershipOnFailure(): Promise<void> {
  let owner = 'bearer-owned-by-wallet';
  const outageFetch: typeof fetch = async () => { throw new Error('network outage'); };
  const clientWithOutage = new WitnessEvidenceClient({
    origin: 'http://127.0.0.1:1',
    expectedNetworkId: NETWORK_ID,
    fetchImpl: outageFetch,
  });
  const outcome = await clientWithOutage.submit(HASH);
  assert.equal(outcome.kind, 'retryable');
  assert.equal(owner, 'bearer-owned-by-wallet', 'Witness failure has no wallet ownership capability');
}

async function main(): Promise<void> {
  testNativeAttestationFraming();
  await testLifecycleAndDisclosure();
  await testEndpointDefenseAndHashBinding();
  await testNoStoreDefense();
  await testLocalRejectionVectors();
  await testBlsVerification();
  await testWitnessCannotChangeOwnershipOnFailure();
  console.log('circulation-v1 Witness client: all deterministic tests passed');
}

await main();
