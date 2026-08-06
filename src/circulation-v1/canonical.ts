/**
 * Byte-level helpers for the Phase-1 composition contract.
 *
 * The V2 graph and digest functions below are exact ports of the pinned
 * Freebird source: common/src/exchange_api.rs lines 214-269 and 326-504, and
 * common/src/graph_issuance_api.rs lines 56-199.  The V4/V5 framing and
 * graph-issuance HMAC are delegated to the vendored `@freebird/sdk` `crypto`
 * namespace (byte-identical; see the framing/HMAC parity gate in
 * test/circulation-v1/foundation.test.ts).  No RSA arithmetic is implemented.
 *
 * NOTE — this file is part of the `src/circulation-v1/` Freebird V2 subsystem,
 * a SEPARATE Freebird surface from `src/integrations/freebird.ts` (legacy V4/V5
 * admission) and `src/vendor/freebird/` (vendored SDK crypto). The V2
 * exchange/graph-issuance digests, replay-authority proof, and Witness envelope
 * stay hand-written here — the SDK's public `crypto` namespace does not export
 * them. See AGENTS.md "Freebird integration surfaces".
 */

import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes } from '@noble/hashes/utils';
import { crypto as sdkCrypto } from '../vendor/freebird-sdk/index.js';
import {
  BoundaryValidationError,
  CIRCULATION_CLASS,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  parseExchangeReceiptV2,
  type CanonicalBase64Url,
  type CanonicalSha256Hex,
  type ExchangeReceiptV2,
  type ExchangeRequestV2,
  type ExchangeResultV2,
  type FreebirdV5DescriptorV2,
  type GraphIssuanceRequest,
  type GraphIssuanceResult,
  type GraphTransitionV2,
  type V4RedemptionTokenEnvelope,
  type V5BearerArtifactEnvelope,
  parseV5BearerArtifactEnvelope,
} from './types.js';

export {
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
} from './types.js';

export const DOMAIN_RECEIPT_V2 = new TextEncoder().encode('freebird exchange receipt v2\0');

function invalid(message: string): never {
  throw new BoundaryValidationError(message);
}

function assertDigestBytes(value: Uint8Array, field: string): Uint8Array {
  if (value.length !== 32) invalid(`${field}: expected 32 bytes`);
  return value;
}

function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) invalid('length: outside u32 range');
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function u64be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) invalid('integer: outside u64 range');
  const output = new ArrayBuffer(8);
  const view = new DataView(output);
  const high = Math.floor(value / 0x1_0000_0000);
  const low = value - high * 0x1_0000_0000;
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);
  return new Uint8Array(output);
}

function i64be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) invalid('integer: outside supported positive i64 range');
  return u64be(value);
}

function put(output: Uint8Array[], value: Uint8Array): void {
  output.push(u32be(value.length), value);
}

function ascii(value: string, field: string): Uint8Array {
  if (value.length === 0 || value.length > 128 || !/^[\x00-\x7f]+$/.test(value)) invalid(`${field}: expected bounded ASCII`);
  return new TextEncoder().encode(value);
}

function domainDigest(domain: string, bytes: Uint8Array): Uint8Array {
  return sha256(concatBytes(new TextEncoder().encode(domain), bytes));
}

function domainHex(domain: string, bytes: Uint8Array): CanonicalSha256Hex {
  return encodeCanonicalLowerHex(domainDigest(domain, bytes));
}

function utf8(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length === 0 || bytes.length > 255) invalid('issuer_id: expected 1-255 UTF-8 bytes');
  return bytes;
}

function readUtf8(bytes: Uint8Array, field: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    invalid(`${field}: invalid UTF-8`);
  }
}

/**
 * Exact Freebird V4 redemption-token framing port.  Source reference:
 * src/vendor/freebird/voprf.ts lines 169-224.  This helper does not validate
 * V4 policy; generic v4_local remains the authority for that credential.
 *
 * Delegated to the vendored @freebird/sdk crypto namespace (byte-identical;
 * see the framing/HMAC parity gate in test/circulation-v1/foundation.test.ts).
 */
export function encodeV4RedemptionToken(
  nonce: Uint8Array,
  scopeDigest: Uint8Array,
  kid: string,
  issuerId: string,
  authenticator: Uint8Array,
): Uint8Array {
  return sdkCrypto.buildRedemptionToken(nonce, scopeDigest, kid, issuerId, authenticator);
}

/**
 * Parse the exact Freebird V4 redemption-token framing.
 *
 * Delegated to the vendored @freebird/sdk crypto namespace. The SDK's parser
 * is lossy on UTF-8 (invalid bytes decode to U+FFFD), so we re-impose the
 * strict fatal-UTF-8 boundary on the kid/issuer_id fields to preserve this
 * module's validation posture.
 */
export function decodeV4RedemptionToken(bytes: Uint8Array): V4RedemptionTokenEnvelope {
  const parsed = sdkCrypto.parseRedemptionToken(bytes);
  // Re-impose fatal UTF-8 (the SDK decodes lossily).
  readUtf8(new TextEncoder().encode(parsed.kid), 'V4 redemption token.kid');
  readUtf8(new TextEncoder().encode(parsed.issuerId), 'V4 redemption token.issuer_id');
  return {
    version: 4,
    nonce: parsed.nonce,
    scope_digest: parsed.scopeDigest,
    kid: parsed.kid,
    issuer_id: parsed.issuerId,
    authenticator: parsed.authenticator,
  };
}

export function encodeV4RedemptionTokenBase64(
  nonce: Uint8Array,
  scopeDigest: Uint8Array,
  kid: string,
  issuerId: string,
  authenticator: Uint8Array,
): CanonicalBase64Url {
  return encodeCanonicalBase64Url(encodeV4RedemptionToken(nonce, scopeDigest, kid, issuerId, authenticator));
}

export function decodeV4RedemptionTokenBase64(value: unknown): V4RedemptionTokenEnvelope {
  return decodeV4RedemptionToken(decodeCanonicalBase64Url(value, undefined, 'V4 redemption token'));
}

/** Exact Freebird V2 descriptor/keyset/transition/graph identity ports. */
export function canonicalDescriptorBytesV2(descriptor: FreebirdV5DescriptorV2): Uint8Array {
  const output: Uint8Array[] = [];
  for (const [value, field] of [
    [descriptor.profile_id, 'descriptor.profile_id'],
    [descriptor.issuer_id, 'descriptor.issuer_id'],
    [descriptor.token_key_id, 'descriptor.token_key_id'],
    [descriptor.suite, 'descriptor.suite'],
  ] as const) put(output, ascii(value, field));
  if (descriptor.audience === undefined) {
    output.push(Uint8Array.of(0));
    put(output, new Uint8Array());
  } else {
    output.push(Uint8Array.of(1));
    put(output, ascii(descriptor.audience, 'descriptor.audience'));
  }
  put(output, decodeCanonicalBase64Url(descriptor.pubkey_spki_b64, undefined, 'descriptor.pubkey_spki_b64'));
  output.push(i64be(descriptor.valid_from), i64be(descriptor.valid_until));
  return concatBytes(...output);
}

export function canonicalDescriptorIdV2(descriptor: FreebirdV5DescriptorV2): CanonicalSha256Hex {
  return domainHex('freebird exchange descriptor v2\0', canonicalDescriptorBytesV2(descriptor));
}

export function canonicalKeysetBytesV2(descriptorIds: readonly string[]): Uint8Array {
  const output: Uint8Array[] = [];
  for (const [index, descriptorId] of descriptorIds.entries()) put(output, ascii(descriptorId, `keyset.descriptor_ids[${index}]`));
  return concatBytes(...output);
}

export function canonicalKeysetIdV2(descriptorIds: readonly string[]): CanonicalSha256Hex {
  return domainHex('freebird exchange keyset v2\0', canonicalKeysetBytesV2(descriptorIds));
}

function canonicalTransitionSlotBytes(slot: GraphTransitionV2['source_slots'][number]): Uint8Array {
  const output: Uint8Array[] = [];
  put(output, ascii(slot.descriptor_id, 'transition.slot.descriptor_id'));
  put(output, ascii(slot.slot_id, 'transition.slot.slot_id'));
  put(output, ascii(slot.class, 'transition.slot.class'));
  output.push(u32be(slot.quantity));
  return concatBytes(...output);
}

export function canonicalTransitionBytesV2(transition: GraphTransitionV2): Uint8Array {
  const output: Uint8Array[] = [];
  put(output, ascii(transition.source_keyset_id, 'transition.source_keyset_id'));
  put(output, ascii(transition.target_keyset_id, 'transition.target_keyset_id'));
  for (const slots of [transition.source_slots, transition.output_slots]) {
    output.push(u32be(slots.length));
    for (const slot of slots) output.push(canonicalTransitionSlotBytes(slot));
  }
  put(output, ascii(transition.budget_id, 'transition.budget_id'));
  output.push(u64be(transition.budget_limit));
  return concatBytes(...output);
}

export function canonicalTransitionIdV2(transition: GraphTransitionV2): CanonicalSha256Hex {
  return domainHex('freebird exchange transition v2\0', canonicalTransitionBytesV2(transition));
}

export function canonicalGraphIdV2(graph: { profile_id: string; keysets: readonly { keyset_id: string }[]; transitions: readonly { transition_id: string }[] }): CanonicalSha256Hex {
  const output: Uint8Array[] = [];
  put(output, ascii(graph.profile_id, 'graph.profile_id'));
  for (const keyset of graph.keysets) put(output, ascii(keyset.keyset_id, 'graph.keyset_id'));
  for (const transition of graph.transitions) put(output, ascii(transition.transition_id, 'graph.transition_id'));
  return domainHex('freebird exchange graph v2\0', concatBytes(...output));
}

/**
 * Exact Freebird V5 public-bearer message framing before RSABSSA.
 *
 * Delegated to the vendored @freebird/sdk crypto namespace (byte-identical;
 * see the framing/HMAC parity gate in test/circulation-v1/foundation.test.ts).
 */
export function buildV5PublicBearerMessage(
  nonce: Uint8Array,
  tokenKeyId: Uint8Array,
  issuerId: string,
): Uint8Array {
  return sdkCrypto.buildPublicBearerMessage(nonce, tokenKeyId, issuerId);
}

/**
 * Exact Freebird V5 public-bearer framing.  The message digest is SHA-384;
 * this helper only frames the resulting RSA-PSS signature.
 *
 * Delegated to the vendored @freebird/sdk crypto namespace (byte-identical;
 * see the framing/HMAC parity gate in test/circulation-v1/foundation.test.ts).
 */
export function encodeV5BearerArtifact(
  nonce: Uint8Array,
  tokenKeyId: Uint8Array,
  issuerId: string,
  signature: Uint8Array,
): Uint8Array {
  return sdkCrypto.buildPublicBearerPass(nonce, tokenKeyId, issuerId, signature);
}

/**
 * Parse and strictly validate the exact Freebird V5 bearer framing.
 *
 * Delegated to the vendored @freebird/sdk crypto namespace. The SDK's parser
 * is lossy on UTF-8 (invalid bytes decode to U+FFFD), so we re-impose the
 * strict fatal-UTF-8 boundary on the issuer_id field to preserve this module's
 * validation posture.
 */
export function decodeV5BearerArtifact(bytes: Uint8Array): V5BearerArtifactEnvelope {
  const parsed = sdkCrypto.parsePublicBearerPass(bytes);
  // Re-impose fatal UTF-8 (the SDK decodes lossily).
  readUtf8(new TextEncoder().encode(parsed.issuerId), 'V5 bearer.issuer_id');
  return parseV5BearerArtifactEnvelope({
    version: 5,
    nonce: encodeCanonicalBase64Url(parsed.nonce),
    token_key_id: encodeCanonicalLowerHex(parsed.tokenKeyId),
    issuer_id: parsed.issuerId,
    signature: encodeCanonicalBase64Url(parsed.signature),
  });
}

export function encodeV5BearerArtifactBase64(
  nonce: Uint8Array,
  tokenKeyId: Uint8Array,
  issuerId: string,
  signature: Uint8Array,
): CanonicalBase64Url {
  return encodeCanonicalBase64Url(encodeV5BearerArtifact(nonce, tokenKeyId, issuerId, signature));
}

export function decodeV5BearerArtifactBase64(value: unknown): V5BearerArtifactEnvelope {
  return decodeV5BearerArtifact(decodeCanonicalBase64Url(value, undefined, 'V5 bearer artifact'));
}

function canonicalExchangeSelectorsV2(value: Pick<ExchangeRequestV2, 'version' | 'public_operation_id' | 'graph_id' | 'transition_id' | 'source_keyset_id' | 'target_keyset_id'>): Uint8Array[] {
  if (value.version !== 2) invalid('exchange.version: must be 2');
  const output: Uint8Array[] = [Uint8Array.of(2)];
  put(output, decodeCanonicalBase64Url(value.public_operation_id, 16, 'exchange.public_operation_id'));
  put(output, ascii(value.graph_id, 'exchange.graph_id'));
  put(output, ascii(value.transition_id, 'exchange.transition_id'));
  put(output, ascii(value.source_keyset_id, 'exchange.source_keyset_id'));
  put(output, ascii(value.target_keyset_id, 'exchange.target_keyset_id'));
  return output;
}

function canonicalExchangeSlotV2(slot: { descriptor_id: string; keyset_id: string; slot_id: string; quantity: number }): Uint8Array {
  const output: Uint8Array[] = [];
  put(output, ascii(slot.descriptor_id, 'exchange.slot.descriptor_id'));
  put(output, ascii(slot.keyset_id, 'exchange.slot.keyset_id'));
  put(output, ascii(slot.slot_id, 'exchange.slot.slot_id'));
  output.push(u32be(slot.quantity));
  return concatBytes(...output);
}

/** Exact V2 request canonical bytes from Freebird common/src/exchange_api.rs. */
export function canonicalExchangeRequestBytesV2(request: ExchangeRequestV2): Uint8Array {
  const output = canonicalExchangeSelectorsV2(request);
  if (request.sources.length > 64 || request.outputs.length > 64) {
    invalid('exchange request: bounds exceeded');
  }
  output.push(u32be(request.sources.length));
  for (const source of request.sources) {
    if (source.slot.keyset_id !== request.source_keyset_id) invalid('exchange request: source keyset mismatch');
    output.push(canonicalExchangeSlotV2(source.slot));
    put(output, decodeCanonicalBase64Url(source.artifact, undefined, 'exchange source artifact'));
  }
  output.push(u32be(request.outputs.length));
  for (const target of request.outputs) {
    if (target.slot.keyset_id !== request.target_keyset_id) invalid('exchange request: target keyset mismatch');
    output.push(canonicalExchangeSlotV2(target.slot));
    put(output, decodeCanonicalBase64Url(target.blinded_value, undefined, 'exchange blinded value'));
  }
  return concatBytes(...output);
}

export function canonicalExchangeRequestDigestV2(request: ExchangeRequestV2): Uint8Array {
  return domainDigest('freebird exchange request v2\0', canonicalExchangeRequestBytesV2(request));
}

function canonicalExchangeResultPartsV2(result: ExchangeResultV2): Uint8Array[] {
  const output = canonicalExchangeSelectorsV2(result);
  if (result.outputs.length > 64) invalid('exchange result: bounds exceeded');
  output.push(u32be(result.outputs.length));
  for (const target of result.outputs) {
    if (target.slot.keyset_id !== result.target_keyset_id) invalid('exchange result: target keyset mismatch');
    output.push(canonicalExchangeSlotV2(target.slot));
    put(output, decodeCanonicalBase64Url(target.blinded_value, undefined, 'exchange result blinded value'));
    put(output, decodeCanonicalBase64Url(target.blind_signature,  undefined, 'exchange result blind signature'));
  }
  return output;
}

export function canonicalExchangeResultDigestV2(result: ExchangeResultV2): Uint8Array {
  return domainDigest('freebird exchange result v2\0', concatBytes(...canonicalExchangeResultPartsV2(result)));
}

export function canonicalExchangeResultBytesV2(result: ExchangeResultV2): Uint8Array {
  const output = canonicalExchangeResultPartsV2(result);
  put(output, decodeCanonicalBase64Url(result.result_digest, 32, 'exchange result.result_digest'));
  return concatBytes(...output);
}

/** Exact Freebird V2 receipt payload bytes, excluding the receipt signature. */
export function canonicalExchangeReceiptPayloadV2(receipt: ExchangeReceiptV2): Uint8Array {
  const output = canonicalExchangeSelectorsV2(receipt);
  put(output, decodeCanonicalBase64Url(receipt.result_digest, 32, 'exchange receipt.result_digest'));
  if (receipt.expires_at <= receipt.created_at) invalid('exchange receipt: invalid validity');
  output.push(u64be(receipt.created_at), u64be(receipt.expires_at));
  put(output, ascii(receipt.receipt_key_id, 'exchange receipt.receipt_key_id'));
  return concatBytes(...output);
}

function canonicalGraphIssuanceSelectorParts(
  value: GraphIssuanceRequest | GraphIssuanceResult | Omit<GraphIssuanceResult, 'result_digest'>,
): Uint8Array[] {
  const output: Uint8Array[] = [Uint8Array.of(2)];
  put(output, decodeCanonicalBase64Url(value.public_operation_id, 16, 'graph issuance.public_operation_id'));
  put(output, ascii(value.issuance_policy_id, 'graph issuance.issuance_policy_id'));
  put(output, ascii(value.graph_id, 'graph issuance.graph_id'));
  put(output, ascii(value.keyset_id, 'graph issuance.keyset_id'));
  put(output, ascii(value.descriptor_id, 'graph issuance.descriptor_id'));
  return output;
}

/** Exact graph-issuance request selector bytes from Freebird common. */
export function canonicalGraphIssuanceRequestBytes(request: GraphIssuanceRequest): Uint8Array {
  const output = canonicalGraphIssuanceSelectorParts(request);
  put(output, decodeCanonicalBase64Url(request.blinded_message, undefined, 'graph issuance.blinded_message'));
  put(output, decodeCanonicalBase64Url(request.authorization, undefined, 'graph issuance.authorization'));
  return concatBytes(...output);
}

export function canonicalGraphIssuanceAuthorizationBinding(request: GraphIssuanceRequest): Uint8Array {
  const output = canonicalGraphIssuanceSelectorParts(request);
  put(output, decodeCanonicalBase64Url(request.blinded_message, undefined, 'graph issuance.blinded_message'));
  return domainDigest('freebird graph blind issuance authorization binding v2\0', concatBytes(...output));
}

export function canonicalGraphIssuanceRequestDigest(request: GraphIssuanceRequest): Uint8Array {
  return domainDigest('freebird graph blind issuance request v2\0', canonicalGraphIssuanceRequestBytes(request));
}

function canonicalGraphIssuanceResultParts(result: Omit<GraphIssuanceResult, 'result_digest'> | GraphIssuanceResult): Uint8Array[] {
  const output = canonicalGraphIssuanceSelectorParts(result);
  put(output, ascii(result.token_key_id, 'graph issuance.token_key_id'));
  output.push(u32be(result.quantity));
  put(output, decodeCanonicalBase64Url(result.request_digest, 32, 'graph issuance.request_digest'));
  put(output, decodeCanonicalBase64Url(result.blind_signature, undefined, 'graph issuance.blind_signature'));
  return output;
}

export function canonicalGraphIssuanceResultDigest(result: Omit<GraphIssuanceResult, 'result_digest'> | GraphIssuanceResult): Uint8Array {
  return domainDigest('freebird graph blind issuance result v2\0', concatBytes(...canonicalGraphIssuanceResultParts(result)));
}

export function canonicalGraphIssuanceResultBytes(result: GraphIssuanceResult): Uint8Array {
  const output = canonicalGraphIssuanceResultParts(result);
  put(output, decodeCanonicalBase64Url(result.result_digest, 32, 'graph issuance.result_digest'));
  return concatBytes(...output);
}

/**
 * The receipt digest algorithm specified by Scarcity Section 6/7.  The
 * `canonicalPayload` argument must come from the pinned Freebird receipt
 * canonicalizer; JSON.stringify is intentionally not used here.
 */
export function computeReceiptDigest(canonicalPayload: Uint8Array): Uint8Array {
  return sha256(concatBytes(DOMAIN_RECEIPT_V2, canonicalPayload));
}

/** Build the binary Witness envelope from the raw Freebird receipt digest. */
export function buildReceiptHashEnvelope(
  circulationClass: string,
  receiptDigest: Uint8Array,
): Uint8Array {
  if (circulationClass !== CIRCULATION_CLASS) invalid('class: unsupported circulation class');
  assertDigestBytes(receiptDigest, 'receipt_digest');
  const classBytes = new TextEncoder().encode(circulationClass);
  return concatBytes(u32be(classBytes.length), classBytes, receiptDigest);
}

/** Compute the exactly-64-lowercase-hex Witness submission hash. */
export function computeReceiptWitnessHash(
  circulationClass: string,
  receiptDigest: Uint8Array,
): CanonicalSha256Hex {
  return encodeCanonicalLowerHex(sha256(buildReceiptHashEnvelope(circulationClass, receiptDigest)));
}

export interface FreebirdV2CanonicalDigestVerifier {
  /** Exact pinned-Freebird canonical request digest. */
  readonly requestDigest: (request: ExchangeRequestV2) => Uint8Array;
  /** Exact pinned-Freebird canonical result digest. */
  readonly resultDigest: (result: ExchangeResultV2) => Uint8Array;
  /** Exact pinned-Freebird receipt payload encoding, excluding its signature. */
  readonly receiptPayload: (receipt: ExchangeReceiptV2) => Uint8Array;
}

export interface GraphIssuanceCanonicalDigestVerifier {
  /** Exact pinned-Freebird graph-issuance request digest. */
  readonly requestDigest: (request: GraphIssuanceRequest) => Uint8Array;
  /** Exact pinned-Freebird graph-issuance result digest. */
  readonly resultDigest: (result: GraphIssuanceResult) => Uint8Array;
}

/** Native TypeScript consumer for the canonical Freebird V2 contract. */
export const FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER: FreebirdV2CanonicalDigestVerifier = {
  requestDigest: canonicalExchangeRequestDigestV2,
  resultDigest: canonicalExchangeResultDigestV2,
  receiptPayload: canonicalExchangeReceiptPayloadV2,
};

/** Native TypeScript consumer for the canonical Freebird graph-issuance contract. */
export const FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER: GraphIssuanceCanonicalDigestVerifier = {
  requestDigest: canonicalGraphIssuanceRequestDigest,
  resultDigest: canonicalGraphIssuanceResultDigest,
};

function assertEncodedDigest(actual: unknown, expected: Uint8Array, field: string): void {
  const actualBytes = decodeCanonicalBase64Url(actual, 32, field);
  if (actualBytes.length !== expected.length || actualBytes.some((byte, index) => byte !== expected[index])) {
    invalid(`${field}: digest mismatch`);
  }
}

/** Verify a V2 result digest without implementing Freebird's canonicalizer. */
export function verifyExchangeResultDigest(
  result: ExchangeResultV2,
  verifier: FreebirdV2CanonicalDigestVerifier,
): void {
  assertEncodedDigest(result.result_digest, assertDigestBytes(verifier.resultDigest(result), 'result_digest'), 'exchange result.result_digest');
}

/** Verify a graph-issuance result digest using the pinned native codec. */
export function verifyGraphIssuanceResultDigest(
  result: GraphIssuanceResult,
  verifier: GraphIssuanceCanonicalDigestVerifier,
): void {
  assertEncodedDigest(result.result_digest, assertDigestBytes(verifier.resultDigest(result), 'result_digest'), 'graph issuance result.result_digest');
}

/** Verify the request digest carried by a native graph-issuance result. */
export function verifyGraphIssuanceRequestDigest(
  request: GraphIssuanceRequest,
  result: GraphIssuanceResult,
  verifier: GraphIssuanceCanonicalDigestVerifier,
): void {
  assertEncodedDigest(result.request_digest, assertDigestBytes(verifier.requestDigest(request), 'request_digest'), 'graph issuance result.request_digest');
}

export const DOMAIN_GRAPH_ISSUANCE_HMAC_AUTHORIZATION_V2 = new TextEncoder().encode('freebird graph issuance hmac authorization v2\0');
export const DOMAIN_REPLAY_AUTHORITY_PROBE_V1 = new TextEncoder().encode('freebird v4 replay authority probe v1\0');

/**
 * Build Freebird's exact V2 external HMAC authorization transcript.
 *
 * Delegated to the vendored @freebird/sdk crypto namespace (byte-identical;
 * see the framing/HMAC parity gate in test/circulation-v1/foundation.test.ts).
 */
export function graphIssuanceHmacAuthorizationTranscriptV2(
  nonce: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
): Uint8Array {
  return sdkCrypto.graphIssuanceHmacAuthorizationTranscriptV2(nonce, policyId, authorizationBindingDigest);
}

/** Return the raw Freebird V2 HMAC-SHA256 authorization tag. */
export function graphIssuanceHmacAuthorizationTagV2(
  secret: Uint8Array,
  nonce: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
): Uint8Array {
  return sdkCrypto.graphIssuanceHmacAuthorizationTagV2(secret, nonce, policyId, authorizationBindingDigest);
}

/** Construct canonical nonce_raw || tag_raw authorization bytes. */
export function buildGraphIssuanceHmacAuthorizationV2(
  secret: Uint8Array,
  nonce: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
): CanonicalBase64Url {
  return sdkCrypto.buildGraphIssuanceHmacAuthorizationV2(secret, nonce, policyId, authorizationBindingDigest);
}

export function parseGraphIssuanceHmacAuthorizationV2(value: unknown): { readonly nonce: Uint8Array; readonly tag: Uint8Array } {
  try {
    return sdkCrypto.parseGraphIssuanceHmacAuthorizationV2(value as string);
  } catch {
    invalid('graph issuance HMAC authorization: invalid');
  }
}

export function verifyGraphIssuanceHmacAuthorizationV2(
  secret: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
  authorization: unknown,
): Uint8Array {
  try {
    return sdkCrypto.verifyGraphIssuanceHmacAuthorizationV2(secret, policyId, authorizationBindingDigest, authorization as string);
  } catch {
    invalid('graph issuance authorization: invalid HMAC');
  }
}

export const hmacAuthorizationTranscriptV2 = graphIssuanceHmacAuthorizationTranscriptV2;
export const hmacAuthorizationTagV2 = graphIssuanceHmacAuthorizationTagV2;
export const buildHmacAuthorizationV2 = buildGraphIssuanceHmacAuthorizationV2;
export const parseHmacAuthorizationV2 = parseGraphIssuanceHmacAuthorizationV2;
export const verifyHmacAuthorizationV2 = verifyGraphIssuanceHmacAuthorizationV2;

/** Build the exact raw replay-authority HMAC transcript used by Freebird. */
export function replayAuthorityProofTranscriptV1(
  authorityId: Uint8Array,
  probeId: Uint8Array,
  issuerId: string,
): Uint8Array {
  if (authorityId.length !== 32 || probeId.length !== 32) invalid('replay authority IDs: expected 32 bytes');
  const issuer = utf8(issuerId);
  return concatBytes(DOMAIN_REPLAY_AUTHORITY_PROBE_V1, authorityId, probeId, u32be(issuer.length), issuer);
}

export function replayAuthorityProofV1(
  challenge: Uint8Array,
  authorityId: Uint8Array,
  probeId: Uint8Array,
  issuerId: string,
): Uint8Array {
  if (challenge.length !== 32) invalid('replay authority challenge: expected 32 bytes');
  return hmac(sha256, challenge, replayAuthorityProofTranscriptV1(authorityId, probeId, issuerId));
}

export function buildReplayAuthorityProofV1(
  challenge: Uint8Array,
  authorityId: CanonicalBase64Url,
  probeId: CanonicalBase64Url,
  issuerId: string,
): CanonicalBase64Url {
  return encodeCanonicalBase64Url(replayAuthorityProofV1(
    challenge,
    decodeCanonicalBase64Url(authorityId, 32, 'authority_id'),
    decodeCanonicalBase64Url(probeId, 32, 'probe_id'),
    issuerId,
  ));
}

/** Compute the raw receipt digest after native Freebird receipt validation. */
export function computeExchangeReceiptDigest(
  receipt: ExchangeReceiptV2,
  verifier: FreebirdV2CanonicalDigestVerifier,
): Uint8Array {
  parseExchangeReceiptV2(receipt);
  return computeReceiptDigest(verifier.receiptPayload(receipt));
}

/**
 * Verify that a canonical hex receipt hash has the expected value.  This is
 * useful at the Witness HTTP boundary, where only lowercase hex is allowed.
 */
export function assertReceiptWitnessHash(value: unknown, expected: Uint8Array, field = 'hash'): CanonicalSha256Hex {
  const actual = decodeCanonicalLowerHex(value, 32, field);
  const expectedDigest = sha256(expected);
  if (actual.some((byte, index) => byte !== expectedDigest[index])) invalid(`${field}: digest mismatch`);
  return value as CanonicalSha256Hex;
}
