/** Freebird v0.8.1 V2 graph-issuance vectors and boundary gates. */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  BoundaryValidationError,
  GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  parseGraphIssuanceDiscovery,
  parseGraphIssuanceRequest,
  parseGraphIssuanceResult,
  type ExchangeDiscoveryV2,
} from '../../src/circulation-v1/index.js';
import {
  buildGraphIssuanceHmacAuthorizationV2,
  buildV5PublicBearerMessage,
  canonicalGraphIssuanceAuthorizationBinding,
  canonicalGraphIssuanceRequestDigest,
  canonicalGraphIssuanceResultDigest,
  DOMAIN_GRAPH_ISSUANCE_HMAC_AUTHORIZATION_V2,
  encodeCanonicalLowerHex,
  encodeV4RedemptionToken,
  encodeV5BearerArtifact,
  graphIssuanceHmacAuthorizationTagV2,
  graphIssuanceHmacAuthorizationTranscriptV2,
  parseGraphIssuanceHmacAuthorizationV2,
  replayAuthorityProofV1,
  verifyGraphIssuanceHmacAuthorizationV2,
  verifyGraphIssuanceRequestDigest,
  verifyGraphIssuanceResultDigest,
  FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER,
} from '../../src/circulation-v1/canonical.js';
import { validateGraphIssuanceDiscoverySnapshot, validateGraphIssuanceDiscoveryUpdate } from '../../src/circulation-v1/bootstrap.js';
import { crypto as sdkCrypto, FreebirdClient as SdkFreebirdClient } from '../../src/vendor/freebird-sdk/index.js';

const b64 = (bytes: number[]): string => encodeCanonicalBase64Url(Uint8Array.from(bytes));
const op = b64(new Array(16).fill(7));
const request = parseGraphIssuanceRequest({
  version: 2,
  public_operation_id: op,
  issuance_policy_id: 'bootstrap-v2',
  graph_id: '1'.repeat(64),
  keyset_id: '2'.repeat(64),
  descriptor_id: '3'.repeat(64),
  blinded_message: b64(new Array(256).fill(4)),
  authorization: b64(new Array(64).fill(5)),
});

function exchange(): ExchangeDiscoveryV2 {
  return ({
    active_graph: {
      profile_id: 'freebird/public-bearer-exchange/v2',
      graph_id: '1'.repeat(64),
      descriptors: [],
      keysets: [{ keyset_id: '2'.repeat(64), descriptor_ids: ['3'.repeat(64)] }],
      transitions: [],
    },
    retained_graphs: [],
    active_receipt_key: {} as ExchangeDiscoveryV2['active_receipt_key'],
    retained_receipt_keys: [],
  } as unknown) as ExchangeDiscoveryV2;
}

function discovery(scope: string): Record<string, unknown> {
  return {
    version: 2,
    policies: [{
      issuance_policy_id: 'bootstrap-v2', graph_id: '1'.repeat(64), keyset_id: '2'.repeat(64), descriptor_id: '3'.repeat(64),
      budget_id: 'bootstrap-lifetime-v2', budget_limit: 100, quantity: 1, admission_state: 'recovery_only',
      authorization_scheme: GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
    }],
    replay_authority: { authority_id: b64(new Array(32).fill(9)), v4_scope_digest_tombstones: [scope] },
  };
}

function expectReject(action: () => unknown): void {
  assert.throws(action, BoundaryValidationError);
}

interface HmacVector {
  readonly version: number;
  readonly secret_ascii: string;
  readonly nonce_hex: string;
  readonly issuance_policy_id: string;
  readonly authorization_binding_digest_hex: string;
  readonly framing: string;
  readonly transcript_domain_hex: string;
  readonly authorization_base64url: string;
}

function hmacVector(): HmacVector {
  return JSON.parse(readFileSync(resolve(process.cwd(), 'test/fixtures/circulation-v2/public-bearer-graph-issuance-hmac-v2-vector.json'), 'utf8')) as HmacVector;
}

function main(): void {
  assert.equal(encodeCanonicalBase64Url(canonicalGraphIssuanceAuthorizationBinding(request)), 'XlKH0YegK8esWoKbeWQtIDCVzGwT1JLcrx0Uag_ykEw');
  assert.equal(encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(request)), 'GmoCf632DNZaUd1RcVagcvRaJiKMMhVJZq7MVgtZFxI');

  const resultBase = {
    version: 2 as const,
    public_operation_id: request.public_operation_id,
    issuance_policy_id: request.issuance_policy_id,
    graph_id: request.graph_id,
    keyset_id: request.keyset_id,
    descriptor_id: request.descriptor_id,
    token_key_id: 'a'.repeat(64),
    quantity: 1 as const,
    request_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(request)),
    blind_signature: b64(new Array(256).fill(9)),
  };
  const result = parseGraphIssuanceResult({ ...resultBase, result_digest: encodeCanonicalBase64Url(canonicalGraphIssuanceResultDigest(resultBase)) });
  assert.equal(result.result_digest, 'NBV2aptoc6c0G9bkKEeNZVF4YYMtjUziOkMfw2kP1N0');
  verifyGraphIssuanceRequestDigest(request, result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
  verifyGraphIssuanceResultDigest(result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);

  const vector = hmacVector();
  assert.equal(vector.version, 2);
  assert.equal(vector.framing, 'nonce_raw[32] || tag_raw[32]');
  const vectorSecret = new TextEncoder().encode(vector.secret_ascii);
  const vectorNonce = decodeCanonicalLowerHex(vector.nonce_hex, 32, 'vector.nonce_hex');
  const vectorBinding = decodeCanonicalLowerHex(vector.authorization_binding_digest_hex, 32, 'vector.authorization_binding_digest_hex');
  const vectorDomain = decodeCanonicalLowerHex(vector.transcript_domain_hex, undefined, 'vector.transcript_domain_hex');
  assert.deepEqual(vectorDomain, DOMAIN_GRAPH_ISSUANCE_HMAC_AUTHORIZATION_V2);
  const vectorTranscript = graphIssuanceHmacAuthorizationTranscriptV2(vectorNonce, vector.issuance_policy_id, vectorBinding);
  assert.deepEqual(vectorTranscript.slice(0, vectorDomain.length), vectorDomain);
  assert.deepEqual(vectorTranscript.slice(vectorDomain.length, vectorDomain.length + vectorNonce.length), vectorNonce);
  assert.deepEqual(vectorTranscript.slice(vectorDomain.length + vectorNonce.length, vectorDomain.length + vectorNonce.length + 4), Uint8Array.of(0, 0, 0, vector.issuance_policy_id.length));
  assert.deepEqual(vectorTranscript.slice(-vectorBinding.length), vectorBinding);
  const vectorAuthorization = buildGraphIssuanceHmacAuthorizationV2(vectorSecret, vectorNonce, vector.issuance_policy_id, vectorBinding);
  assert.equal(vectorAuthorization, vector.authorization_base64url);
  const parsedVectorAuthorization = parseGraphIssuanceHmacAuthorizationV2(vectorAuthorization);
  assert.deepEqual(parsedVectorAuthorization.nonce, vectorNonce);
  assert.deepEqual(parsedVectorAuthorization.tag, graphIssuanceHmacAuthorizationTagV2(vectorSecret, vectorNonce, vector.issuance_policy_id, vectorBinding));
  assert.deepEqual(verifyGraphIssuanceHmacAuthorizationV2(vectorSecret, vector.issuance_policy_id, vectorBinding, vectorAuthorization), vectorNonce);
  expectReject(() => verifyGraphIssuanceHmacAuthorizationV2(vectorSecret, vector.issuance_policy_id, vectorBinding, `${vectorAuthorization.slice(0, -1)}${vectorAuthorization.endsWith('A') ? 'B' : 'A'}`));
  assert.equal(encodeCanonicalBase64Url(replayAuthorityProofV1(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(32).fill(3), 'issuer:test')), 'THFSTMyc6htC_fEHvc1kgs5dgayJJuTJixk87B6yzgI');

  // ==========================================================================
  // Framing/HMAC parity gate: canonical.ts must stay byte-identical to the
  // vendored @freebird/sdk crypto namespace for the delegable bloc (V4/V5
  // framing + graph-issuance HMAC). This gate must pass BEFORE and AFTER the
  // delegation of these functions to the SDK (see AGENTS.md "Freebird
  // integration surfaces"). The V2 exchange/graph digests are intentionally
  // NOT covered here — the SDK's public crypto namespace does not export them.
  // ==========================================================================
  {
    const pNonce = new Uint8Array(32).fill(1);
    const pScope = new Uint8Array(32).fill(2);
    const pKid = 'kid-1';
    const pIssuer = 'issuer:test';
    const pAuth = new Uint8Array(32).fill(3);
    const pTokenKeyId = new Uint8Array(32).fill(4);
    const pSig = new Uint8Array(256).fill(5);
    const pSecret = new TextEncoder().encode('0123456789abcdef0123456789abcdef');
    const pPolicy = 'bootstrap-v2';
    const pBinding = new Uint8Array(32).fill(6);

    // V4 redemption-token framing
    assert.deepEqual(
      encodeV4RedemptionToken(pNonce, pScope, pKid, pIssuer, pAuth),
      sdkCrypto.buildRedemptionToken(pNonce, pScope, pKid, pIssuer, pAuth),
      'V4 encode parity'
    );

    // V5 public-bearer message + artifact framing
    assert.deepEqual(
      buildV5PublicBearerMessage(pNonce, pTokenKeyId, pIssuer),
      sdkCrypto.buildPublicBearerMessage(pNonce, pTokenKeyId, pIssuer),
      'V5 message parity'
    );
    assert.deepEqual(
      encodeV5BearerArtifact(pNonce, pTokenKeyId, pIssuer, pSig),
      sdkCrypto.buildPublicBearerPass(pNonce, pTokenKeyId, pIssuer, pSig),
      'V5 artifact parity'
    );

    // Graph-issuance HMAC authorization
    assert.deepEqual(
      graphIssuanceHmacAuthorizationTranscriptV2(pNonce, pPolicy, pBinding),
      sdkCrypto.graphIssuanceHmacAuthorizationTranscriptV2(pNonce, pPolicy, pBinding),
      'HMAC transcript parity'
    );
    assert.deepEqual(
      graphIssuanceHmacAuthorizationTagV2(pSecret, pNonce, pPolicy, pBinding),
      sdkCrypto.graphIssuanceHmacAuthorizationTagV2(pSecret, pNonce, pPolicy, pBinding),
      'HMAC tag parity'
    );
    assert.equal(
      buildGraphIssuanceHmacAuthorizationV2(pSecret, pNonce, pPolicy, pBinding),
      sdkCrypto.buildGraphIssuanceHmacAuthorizationV2(pSecret, pNonce, pPolicy, pBinding),
      'HMAC build parity'
    );
  }

  // ==========================================================================
  // Retained-digest parity tripwire: the V2 exchange/graph-issuance digests
  // stay hand-written in canonical.ts (the SDK's public crypto namespace does
  // not export them), but the SDK's FreebirdClient exposes three of them as
  // instance methods. This tripwire converts the latent duplication of the
  // retained digests into an active check on every vendor sync. The client
  // constructor is pure (no network), so this runs offline.
  // ==========================================================================
  {
    const client = new SdkFreebirdClient({ issuerUrl: 'https://issuer.invalid' });
    assert.equal(
      client.graphIssuanceRequestDigest(request),
      encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(request)),
      'graphIssuanceRequestDigest parity'
    );
    assert.equal(
      client.graphIssuanceAuthorizationBindingDigest(request),
      encodeCanonicalBase64Url(canonicalGraphIssuanceAuthorizationBinding(request)),
      'graphIssuanceAuthorizationBindingDigest parity'
    );
  }

  expectReject(() => parseGraphIssuanceRequest({ ...request, version: 3 }));
  assert.throws(() => parseGraphIssuanceRequest({ ...request, version: 1 }), /must be 2/);
  expectReject(() => parseGraphIssuanceRequest({ ...request, unknown: true }));
  expectReject(() => parseGraphIssuanceRequest({ ...request, blinded_message: `${request.blinded_message}=` }));
  expectReject(() => parseGraphIssuanceResult({ ...result, quantity: 2 }));
  expectReject(() => parseGraphIssuanceResult({ ...result, token_key_id: 'A'.repeat(64) }));

  const scope = b64(new Array(32).fill(8));
  const parsed = parseGraphIssuanceDiscovery(discovery(scope));
  assert.equal(validateGraphIssuanceDiscoverySnapshot(parsed, exchange()).version, 2);
  const added = { ...parsed, replay_authority: { ...parsed.replay_authority, v4_scope_digest_tombstones: [...parsed.replay_authority.v4_scope_digest_tombstones, b64(new Array(32).fill(7))] } };
  assert.equal(validateGraphIssuanceDiscoveryUpdate(exchange(), parsed, added)?.replay_authority.v4_scope_digest_tombstones.length, 2);
  expectReject(() => validateGraphIssuanceDiscoveryUpdate(exchange(), parsed, { ...parsed, replay_authority: { ...parsed.replay_authority, authority_id: b64(new Array(32).fill(6)) } }));
  expectReject(() => parseGraphIssuanceDiscovery({ ...discovery(scope), policies: [{ ...(discovery(scope).policies as any)[0], authorization_scope_digest_b64: scope }] }));
  assert.equal(encodeCanonicalLowerHex(decodeCanonicalBase64Url(scope)), '08'.repeat(32));
  console.log('circulation-v2 foundation: all deterministic tests passed');
}

main();
