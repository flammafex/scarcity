/**
 * Strict wire and boundary types for Scarcity's Phase-1 circulation
 * composition.  These types are deliberately independent of the original
 * Scarcity protocol types.
 */

import { sha256 } from '@noble/hashes/sha256';

export const CIRCULATION_CLASS = 'scarcity/circulating-bearer/v1' as const;
export const FREEBIRD_EXCHANGE_PROFILE = 'freebird/public-bearer-exchange/v2' as const;
export const FREEBIRD_V5_SUITE = 'RSABSSA-SHA384-PSS-Deterministic' as const;
export const FREEBIRD_GRAPH_DISCOVERY_VERSION = 2 as const;
export const GRAPH_ISSUANCE_VERSION = 1 as const;
export const V5_BEARER_VERSION = 5 as const;
export const RECEIPT_LIFETIME_SECONDS = 2_592_000 as const;
export const EDGE_BUDGET_LIMIT = 100 as const;

export type CanonicalBase64Url = string;
export type CanonicalLowerHex = string;
export type CanonicalSha256Hex = string;

export type AdmissionState = 'accepting_new' | 'recovery_only' | 'disabled';
export type GraphIssuanceState = 'accepting_new' | 'disabled';

export class BoundaryValidationError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'BoundaryValidationError';
  }
}

function fail(field: string, message: string): never {
  throw new BoundaryValidationError(`${field}: ${message}`);
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(field, 'expected an object');
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  field = 'object',
): void {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      fail(`${field}.${key}`, 'missing field');
    }
  }
  for (const key of keys) {
    if (!allowed.has(key)) {
      fail(`${field}.${key}`, 'unknown field');
    }
  }
}

function stringValue(value: unknown, field: string, min = 1, max = 4096): string {
  if (typeof value !== 'string' || value.length < min || value.length > max) {
    fail(field, `expected a string of ${min}-${max} characters`);
  }
  return value;
}

function integerValue(value: unknown, field: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    fail(field, `expected an integer in [${min}, ${max}]`);
  }
  return value;
}

function bytesFromBase64Url(value: string, field: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = globalThis.atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    fail(field, 'invalid base64url');
  }
}

/** Return bytes for a canonical, unpadded base64url string. */
export function decodeCanonicalBase64Url(
  value: unknown,
  expectedBytes?: number,
  field = 'value',
): Uint8Array {
  const text = stringValue(value, field, 1);
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) {
    fail(field, 'expected unpadded canonical base64url');
  }
  const bytes = bytesFromBase64Url(text, field);
  const canonical = encodeCanonicalBase64Url(bytes);
  if (canonical !== text) fail(field, 'non-canonical base64url encoding');
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    fail(field, `expected ${expectedBytes} decoded bytes`);
  }
  return bytes;
}

/** Encode bytes as unpadded canonical base64url. */
export function encodeCanonicalBase64Url(bytes: Uint8Array): CanonicalBase64Url {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Validate and decode exactly the requested number of lowercase hex bytes. */
export function decodeCanonicalLowerHex(
  value: unknown,
  expectedBytes?: number,
  field = 'value',
): Uint8Array {
  const text = stringValue(value, field, 1);
  if (!/^[0-9a-f]+$/.test(text) || text.length % 2 !== 0) {
    fail(field, 'expected lowercase hexadecimal');
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    fail(field, `expected ${expectedBytes} decoded bytes`);
  }
  return bytes;
}

/** Encode bytes as lowercase hexadecimal. */
export function encodeCanonicalLowerHex(bytes: Uint8Array): CanonicalLowerHex {
  let result = '';
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0');
  return result;
}

export function assertCanonicalSha256Hex(value: unknown, field = 'value'): CanonicalSha256Hex {
  decodeCanonicalLowerHex(value, 32, field);
  return value as CanonicalSha256Hex;
}

function utf8(value: unknown, field: string, max = 255): Uint8Array {
  const text = stringValue(value, field, 1, max);
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > max) fail(field, `UTF-8 encoding exceeds ${max} bytes`);
  return bytes;
}

function assertId(value: unknown, field: string): CanonicalSha256Hex {
  return assertCanonicalSha256Hex(value, field);
}

export interface FreebirdV5DescriptorV2 {
  readonly descriptor_id: CanonicalSha256Hex;
  readonly profile_id: typeof FREEBIRD_EXCHANGE_PROFILE;
  readonly issuer_id: string;
  readonly token_key_id: CanonicalSha256Hex;
  readonly pubkey_spki_b64: CanonicalBase64Url;
  readonly suite: typeof FREEBIRD_V5_SUITE;
  readonly valid_from: number;
  readonly valid_until: number;
  readonly audience?: string;
}

export function parseFreebirdV5Descriptor(value: unknown, field = 'descriptor'): FreebirdV5DescriptorV2 {
  const object = record(value, field);
  exactKeys(
    object,
    ['descriptor_id', 'profile_id', 'issuer_id', 'token_key_id', 'pubkey_spki_b64', 'suite', 'valid_from', 'valid_until'],
    ['audience'],
    field,
  );
  assertId(object.descriptor_id, `${field}.descriptor_id`);
  if (object.profile_id !== FREEBIRD_EXCHANGE_PROFILE) fail(`${field}.profile_id`, 'wrong exchange profile');
  utf8(object.issuer_id, `${field}.issuer_id`);
  assertId(object.token_key_id, `${field}.token_key_id`);
  decodeCanonicalBase64Url(object.pubkey_spki_b64, undefined, `${field}.pubkey_spki_b64`);
  if (object.suite !== FREEBIRD_V5_SUITE) fail(`${field}.suite`, 'incompatible RSA-BSSA suite');
  const validFrom = integerValue(object.valid_from, `${field}.valid_from`, 1);
  const validUntil = integerValue(object.valid_until, `${field}.valid_until`, 1);
  if (validUntil <= validFrom) fail(`${field}.valid_until`, 'must be after valid_from');
  if (object.audience !== undefined) {
    const audience = stringValue(object.audience, `${field}.audience`, 1, 128);
    if (!/^[\x00-\x7f]+$/.test(audience)) fail(`${field}.audience`, 'must be bounded ASCII');
  }
  const spki = decodeCanonicalBase64Url(object.pubkey_spki_b64, undefined, `${field}.pubkey_spki_b64`);
  const expectedKeyId = encodeCanonicalLowerHex(sha256(spki));
  if (expectedKeyId !== object.token_key_id) fail(`${field}.token_key_id`, 'does not identify pubkey_spki_b64');
  return {
    descriptor_id: object.descriptor_id as string,
    profile_id: FREEBIRD_EXCHANGE_PROFILE,
    issuer_id: object.issuer_id as string,
    token_key_id: object.token_key_id as string,
    pubkey_spki_b64: object.pubkey_spki_b64 as string,
    suite: FREEBIRD_V5_SUITE,
    valid_from: validFrom,
    valid_until: validUntil,
    ...(object.audience === undefined ? {} : { audience: object.audience as string }),
  };
}

export interface GraphSlotSelectorV2 {
  readonly descriptor_id: CanonicalSha256Hex;
  readonly keyset_id: CanonicalSha256Hex;
  readonly slot_id: string;
  readonly quantity: 1;
}

export function parseGraphSlotSelector(value: unknown, field = 'slot'): GraphSlotSelectorV2 {
  const object = record(value, field);
  exactKeys(object, ['descriptor_id', 'keyset_id', 'slot_id', 'quantity'], [], field);
  assertId(object.descriptor_id, `${field}.descriptor_id`);
  assertId(object.keyset_id, `${field}.keyset_id`);
  const slotId = stringValue(object.slot_id, `${field}.slot_id`, 1, 128);
  if (!/^[\x00-\x7f]+$/.test(slotId)) fail(`${field}.slot_id`, 'must be bounded ASCII');
  if (object.quantity !== 1) fail(`${field}.quantity`, 'Phase-1 quantity must be 1');
  return {
    descriptor_id: object.descriptor_id as string,
    keyset_id: object.keyset_id as string,
    slot_id: slotId,
    quantity: 1,
  };
}

export interface ExchangeSourceV2 {
  readonly slot: GraphSlotSelectorV2;
  readonly artifact: CanonicalBase64Url;
}

export interface ExchangeOutputV2 {
  readonly slot: GraphSlotSelectorV2;
  readonly blinded_value: CanonicalBase64Url;
}

export interface ExchangeRequestV2 {
  readonly version: 2;
  readonly public_operation_id: CanonicalBase64Url;
  readonly graph_id: CanonicalSha256Hex;
  readonly transition_id: CanonicalSha256Hex;
  readonly source_keyset_id: CanonicalSha256Hex;
  readonly target_keyset_id: CanonicalSha256Hex;
  readonly sources: readonly [ExchangeSourceV2];
  readonly outputs: readonly [ExchangeOutputV2];
}

export interface ExchangeResultV2 {
  readonly version: 2;
  readonly public_operation_id: CanonicalBase64Url;
  readonly graph_id: CanonicalSha256Hex;
  readonly transition_id: CanonicalSha256Hex;
  readonly source_keyset_id: CanonicalSha256Hex;
  readonly target_keyset_id: CanonicalSha256Hex;
  readonly outputs: readonly [ExchangeOutputV2 & { readonly blind_signature: CanonicalBase64Url }];
  readonly result_digest: CanonicalBase64Url;
}

export interface ExchangeReceiptV2 {
  readonly version: 2;
  readonly public_operation_id: CanonicalBase64Url;
  readonly graph_id: CanonicalSha256Hex;
  readonly transition_id: CanonicalSha256Hex;
  readonly source_keyset_id: CanonicalSha256Hex;
  readonly target_keyset_id: CanonicalSha256Hex;
  readonly result_digest: CanonicalBase64Url;
  readonly created_at: number;
  readonly expires_at: number;
  readonly receipt_key_id: CanonicalSha256Hex;
  readonly signature: CanonicalBase64Url;
}

export interface ExchangeAcceptedResponseV2 {
  readonly result: ExchangeResultV2;
  readonly receipt: ExchangeReceiptV2;
}

function parseOperationId(value: unknown, field: string): CanonicalBase64Url {
  return encodeCanonicalBase64Url(decodeCanonicalBase64Url(value, 16, field));
}

function parseDigest(value: unknown, field: string): CanonicalBase64Url {
  return encodeCanonicalBase64Url(decodeCanonicalBase64Url(value, 32, field));
}

function parseBoundedBase64(value: unknown, field: string, maxBytes: number): CanonicalBase64Url {
  const bytes = decodeCanonicalBase64Url(value, undefined, field);
  if (bytes.length === 0 || bytes.length > maxBytes) fail(field, `expected 1-${maxBytes} bytes`);
  return encodeCanonicalBase64Url(bytes);
}

export function parseExchangeRequestV2(value: unknown): ExchangeRequestV2 {
  const object = record(value, 'exchange request');
  exactKeys(object, ['version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id', 'target_keyset_id', 'sources', 'outputs'], [], 'exchange request');
  if (object.version !== 2) fail('exchange request.version', 'must be 2');
  parseOperationId(object.public_operation_id, 'exchange request.public_operation_id');
  assertId(object.graph_id, 'exchange request.graph_id');
  assertId(object.transition_id, 'exchange request.transition_id');
  assertId(object.source_keyset_id, 'exchange request.source_keyset_id');
  assertId(object.target_keyset_id, 'exchange request.target_keyset_id');
  if (!Array.isArray(object.sources) || object.sources.length !== 1) fail('exchange request.sources', 'must contain exactly one source');
  if (!Array.isArray(object.outputs) || object.outputs.length !== 1) fail('exchange request.outputs', 'must contain exactly one output');
  const source = record(object.sources[0], 'exchange request.sources[0]');
  exactKeys(source, ['slot', 'artifact'], [], 'exchange request.sources[0]');
  parseGraphSlotSelector(source.slot, 'exchange request.sources[0].slot');
  parseBoundedBase64(source.artifact, 'exchange request.sources[0].artifact', 16 * 1024);
  const output = record(object.outputs[0], 'exchange request.outputs[0]');
  exactKeys(output, ['slot', 'blinded_value'], [], 'exchange request.outputs[0]');
  parseGraphSlotSelector(output.slot, 'exchange request.outputs[0].slot');
  parseBoundedBase64(output.blinded_value, 'exchange request.outputs[0].blinded_value', 16 * 1024);
  return object as unknown as ExchangeRequestV2;
}

export function parseExchangeResultV2(value: unknown): ExchangeResultV2 {
  const object = record(value, 'exchange result');
  exactKeys(object, ['version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id', 'target_keyset_id', 'outputs', 'result_digest'], [], 'exchange result');
  if (object.version !== 2) fail('exchange result.version', 'must be 2');
  parseOperationId(object.public_operation_id, 'exchange result.public_operation_id');
  assertId(object.graph_id, 'exchange result.graph_id');
  assertId(object.transition_id, 'exchange result.transition_id');
  assertId(object.source_keyset_id, 'exchange result.source_keyset_id');
  assertId(object.target_keyset_id, 'exchange result.target_keyset_id');
  parseDigest(object.result_digest, 'exchange result.result_digest');
  if (!Array.isArray(object.outputs) || object.outputs.length !== 1) fail('exchange result.outputs', 'must contain exactly one output');
  const output = record(object.outputs[0], 'exchange result.outputs[0]');
  exactKeys(output, ['slot', 'blinded_value', 'blind_signature'], [], 'exchange result.outputs[0]');
  parseGraphSlotSelector(output.slot, 'exchange result.outputs[0].slot');
  parseBoundedBase64(output.blinded_value, 'exchange result.outputs[0].blinded_value', 16 * 1024);
  parseBoundedBase64(output.blind_signature, 'exchange result.outputs[0].blind_signature', 512);
  return object as unknown as ExchangeResultV2;
}

export function parseExchangeReceiptV2(value: unknown): ExchangeReceiptV2 {
  const object = record(value, 'exchange receipt');
  exactKeys(object, ['version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id', 'target_keyset_id', 'result_digest', 'created_at', 'expires_at', 'receipt_key_id', 'signature'], [], 'exchange receipt');
  if (object.version !== 2) fail('exchange receipt.version', 'must be 2');
  parseOperationId(object.public_operation_id, 'exchange receipt.public_operation_id');
  assertId(object.graph_id, 'exchange receipt.graph_id');
  assertId(object.transition_id, 'exchange receipt.transition_id');
  assertId(object.source_keyset_id, 'exchange receipt.source_keyset_id');
  assertId(object.target_keyset_id, 'exchange receipt.target_keyset_id');
  parseDigest(object.result_digest, 'exchange receipt.result_digest');
  integerValue(object.created_at, 'exchange receipt.created_at');
  integerValue(object.expires_at, 'exchange receipt.expires_at');
  if ((object.expires_at as number) - (object.created_at as number) !== RECEIPT_LIFETIME_SECONDS) {
    fail('exchange receipt.expires_at', 'receipt lifetime must be exactly 30 days');
  }
  assertId(object.receipt_key_id, 'exchange receipt.receipt_key_id');
  decodeCanonicalBase64Url(object.signature, 64, 'exchange receipt.signature');
  return object as unknown as ExchangeReceiptV2;
}

export function parseExchangeAcceptedResponseV2(value: unknown): ExchangeAcceptedResponseV2 {
  const object = record(value, 'exchange response');
  exactKeys(object, ['result', 'receipt'], [], 'exchange response');
  return {
    result: parseExchangeResultV2(object.result),
    receipt: parseExchangeReceiptV2(object.receipt),
  };
}

export interface GraphIssuanceSelectorV1 {
  readonly issuance_policy_id: string;
  readonly graph_id: CanonicalSha256Hex;
  readonly keyset_id: CanonicalSha256Hex;
  readonly descriptor_id: CanonicalSha256Hex;
}

export interface GraphIssuanceRequestV1 extends GraphIssuanceSelectorV1 {
  readonly version: 1;
  readonly public_operation_id: CanonicalBase64Url;
  readonly blinded_message: CanonicalBase64Url;
  readonly authorization: CanonicalBase64Url;
}

export interface GraphIssuanceResultV1 extends GraphIssuanceSelectorV1 {
  readonly version: 1;
  readonly public_operation_id: CanonicalBase64Url;
  readonly token_key_id: CanonicalSha256Hex;
  readonly quantity: number;
  readonly request_digest: CanonicalBase64Url;
  readonly blind_signature: CanonicalBase64Url;
  readonly result_digest: CanonicalBase64Url;
}

function issuancePolicyId(value: unknown, field: string): string {
  const text = stringValue(value, field, 1, 128);
  if (!/^[\x00-\x7f]+$/.test(text)) fail(field, 'must be bounded ASCII');
  return text;
}

function parseGraphIssuanceSelector(value: Record<string, unknown>, field: string): GraphIssuanceSelectorV1 {
  const issuancePolicyId = issuancePolicyIdValue(value.issuance_policy_id, `${field}.issuance_policy_id`);
  const graphId = assertId(value.graph_id, `${field}.graph_id`);
  const keysetId = assertId(value.keyset_id, `${field}.keyset_id`);
  const descriptorId = assertId(value.descriptor_id, `${field}.descriptor_id`);
  return { issuance_policy_id: issuancePolicyId, graph_id: graphId, keyset_id: keysetId, descriptor_id: descriptorId };
}

function issuancePolicyIdValue(value: unknown, field: string): string {
  return issuancePolicyId(value, field);
}

export function parseGraphIssuanceRequestV1(value: unknown): GraphIssuanceRequestV1 {
  const object = record(value, 'graph issuance request');
  exactKeys(object, ['version', 'public_operation_id', 'issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'blinded_message', 'authorization'], [], 'graph issuance request');
  if (object.version !== 1) fail('graph issuance request.version', 'must be 1');
  const selector = parseGraphIssuanceSelector(object, 'graph issuance request');
  const operation = parseOperationId(object.public_operation_id, 'graph issuance request.public_operation_id');
  const blindedMessage = parseBoundedBase64(object.blinded_message, 'graph issuance request.blinded_message', 512);
  const authorization = parseBoundedBase64(object.authorization, 'graph issuance request.authorization', 16 * 1024);
  return { version: 1, public_operation_id: operation, ...selector, blinded_message: blindedMessage, authorization };
}

export function parseGraphIssuanceResultV1(value: unknown): GraphIssuanceResultV1 {
  const object = record(value, 'graph issuance result');
  exactKeys(object, ['version', 'public_operation_id', 'issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'token_key_id', 'quantity', 'request_digest', 'blind_signature', 'result_digest'], [], 'graph issuance result');
  if (object.version !== 1) fail('graph issuance result.version', 'must be 1');
  const operation = parseOperationId(object.public_operation_id, 'graph issuance result.public_operation_id');
  const selector = parseGraphIssuanceSelector(object, 'graph issuance result');
  const tokenKeyId = assertId(object.token_key_id, 'graph issuance result.token_key_id');
  const quantity = integerValue(object.quantity, 'graph issuance result.quantity', 1, 0xffff_ffff);
  parseDigest(object.request_digest, 'graph issuance result.request_digest');
  const blindSignature = parseBoundedBase64(object.blind_signature, 'graph issuance result.blind_signature', 512);
  parseDigest(object.result_digest, 'graph issuance result.result_digest');
  return { version: 1, public_operation_id: operation, ...selector, token_key_id: tokenKeyId, quantity, request_digest: object.request_digest as string, blind_signature: blindSignature, result_digest: object.result_digest as string };
}

export interface V5BearerArtifactEnvelope {
  readonly version: 5;
  readonly nonce: CanonicalBase64Url;
  readonly token_key_id: CanonicalSha256Hex;
  readonly issuer_id: string;
  readonly signature: CanonicalBase64Url;
}

/** Opaque Freebird V4 admission-token framing, represented after parsing. */
export interface V4RedemptionTokenEnvelope {
  readonly version: 4;
  readonly nonce: Uint8Array;
  readonly scope_digest: Uint8Array;
  readonly kid: string;
  readonly issuer_id: string;
  readonly authenticator: Uint8Array;
}

export function parseV5BearerArtifactEnvelope(value: unknown): V5BearerArtifactEnvelope {
  const object = record(value, 'V5 bearer artifact');
  exactKeys(object, ['version', 'nonce', 'token_key_id', 'issuer_id', 'signature'], [], 'V5 bearer artifact');
  if (object.version !== 5) fail('V5 bearer artifact.version', 'must be 5');
  decodeCanonicalBase64Url(object.nonce, 32, 'V5 bearer artifact.nonce');
  assertId(object.token_key_id, 'V5 bearer artifact.token_key_id');
  utf8(object.issuer_id, 'V5 bearer artifact.issuer_id');
  const signatureBytes = decodeCanonicalBase64Url(object.signature, undefined, 'V5 bearer artifact.signature');
  if (signatureBytes.length === 0 || signatureBytes.length > 512) fail('V5 bearer artifact.signature', 'invalid signature length');
  return object as unknown as V5BearerArtifactEnvelope;
}

export interface GraphKeysetV2 {
  readonly keyset_id: CanonicalSha256Hex;
  readonly descriptor_ids: readonly [CanonicalSha256Hex];
}

export interface GraphTransitionV2 {
  readonly transition_id: CanonicalSha256Hex;
  readonly source_keyset_id: CanonicalSha256Hex;
  readonly target_keyset_id: CanonicalSha256Hex;
  readonly source_slots: readonly [GraphTransitionSlotV2];
  readonly output_slots: readonly [GraphTransitionSlotV2];
  readonly budget_id: string;
  readonly budget_limit: 100;
  readonly admission_state: AdmissionState;
}

export interface GraphTransitionSlotV2 {
  readonly descriptor_id: CanonicalSha256Hex;
  readonly slot_id: string;
  readonly class: typeof CIRCULATION_CLASS;
  readonly quantity: 1;
}

export interface ReceiptVerificationKeyV2 {
  readonly key_id: CanonicalSha256Hex;
  readonly algorithm: 'Ed25519';
  readonly purpose: 'exchange_receipt_active' | 'exchange_receipt_retained';
  readonly public_key_b64: CanonicalBase64Url;
  readonly valid_from: number;
  readonly valid_until: number;
}

export interface ExchangeGraphV2 {
  readonly profile_id: typeof FREEBIRD_EXCHANGE_PROFILE;
  readonly graph_id: CanonicalSha256Hex;
  readonly descriptors: readonly [FreebirdV5DescriptorV2, FreebirdV5DescriptorV2];
  readonly keysets: readonly [GraphKeysetV2, GraphKeysetV2];
  readonly transitions: readonly [GraphTransitionV2, GraphTransitionV2];
}

export interface GraphIssuancePolicyV1 {
  readonly issuance_policy_id: string;
  readonly graph_id: CanonicalSha256Hex;
  readonly keyset_id: CanonicalSha256Hex;
  readonly descriptor_id: CanonicalSha256Hex;
  readonly budget_id: string;
  readonly budget_limit: 100;
  readonly quantity: 1;
  readonly admission_state: AdmissionState;
  readonly authorization_scheme: 'v4_local';
}

export interface GraphIssuanceDiscoveryV1 {
  readonly version: 1;
  readonly policies: readonly [GraphIssuancePolicyDiscoveryV1, ...GraphIssuancePolicyDiscoveryV1[]];
}

export interface GraphIssuancePolicyDiscoveryV1 {
  readonly issuance_policy_id: string;
  readonly graph_id: CanonicalSha256Hex;
  readonly keyset_id: CanonicalSha256Hex;
  readonly descriptor_id: CanonicalSha256Hex;
  readonly budget_id: string;
  readonly budget_limit: number;
  readonly quantity: number;
  readonly admission_state: AdmissionState;
  readonly authorization_scheme: string;
}

export function parseGraphIssuanceDiscoveryV1(value: unknown): GraphIssuanceDiscoveryV1 {
  const root = record(value, 'graph issuance discovery');
  exactKeys(root, ['version', 'policies'], [], 'graph issuance discovery');
  if (root.version !== 1 || !Array.isArray(root.policies) || root.policies.length === 0 || root.policies.length > 64) {
    fail('graph issuance discovery', 'invalid version or policy bounds');
  }
  const policies = root.policies.map((entry, index) => {
    const policy = record(entry, `graph issuance discovery.policies[${index}]`);
    exactKeys(policy, ['issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'budget_id', 'budget_limit', 'quantity', 'admission_state', 'authorization_scheme'], [], `graph issuance discovery.policies[${index}]`);
    const policyId = stringValue(policy.issuance_policy_id, `graph issuance discovery.policies[${index}].issuance_policy_id`, 1, 128);
    const budgetId = stringValue(policy.budget_id, `graph issuance discovery.policies[${index}].budget_id`, 1, 128);
    if (!/^[\x00-\x7f]+$/.test(policyId) || !/^[\x00-\x7f]+$/.test(budgetId)) fail(`graph issuance discovery.policies[${index}]`, 'policy and budget IDs must be bounded ASCII');
    const budgetLimit = integerValue(policy.budget_limit, `graph issuance discovery.policies[${index}].budget_limit`, 1);
    const quantity = integerValue(policy.quantity, `graph issuance discovery.policies[${index}].quantity`, 1);
    if (quantity > budgetLimit) fail(`graph issuance discovery.policies[${index}].quantity`, 'exceeds policy budget');
    const admissionState = policy.admission_state;
    if (admissionState !== 'accepting_new' && admissionState !== 'recovery_only' && admissionState !== 'disabled') fail(`graph issuance discovery.policies[${index}].admission_state`, 'invalid admission state');
    const authorizationScheme = stringValue(policy.authorization_scheme, `graph issuance discovery.policies[${index}].authorization_scheme`, 1, 128);
    if (!/^[\x00-\x7f]+$/.test(authorizationScheme)) fail(`graph issuance discovery.policies[${index}].authorization_scheme`, 'must be bounded ASCII');
    return {
      issuance_policy_id: policyId,
      graph_id: assertId(policy.graph_id, `graph issuance discovery.policies[${index}].graph_id`),
      keyset_id: assertId(policy.keyset_id, `graph issuance discovery.policies[${index}].keyset_id`),
      descriptor_id: assertId(policy.descriptor_id, `graph issuance discovery.policies[${index}].descriptor_id`),
      budget_id: budgetId,
      budget_limit: budgetLimit,
      quantity,
      admission_state: admissionState as AdmissionState,
      authorization_scheme: authorizationScheme,
    };
  });
  if (new Set(policies.map((policy) => policy.issuance_policy_id)).size !== policies.length) fail('graph issuance discovery.policies', 'duplicate policy ID');
  if (new Set(policies.map((policy) => policy.budget_id)).size !== policies.length) fail('graph issuance discovery.policies', 'duplicate budget ID');
  return { version: 1, policies: policies as [GraphIssuancePolicyDiscoveryV1, ...GraphIssuancePolicyDiscoveryV1[]] };
}

export interface ExchangeDiscoveryV2 {
  readonly active_graph: ExchangeGraphV2;
  readonly retained_graphs: readonly ExchangeGraphV2[];
  readonly active_receipt_key: ReceiptVerificationKeyV2;
  readonly retained_receipt_keys: readonly ReceiptVerificationKeyV2[];
}

export interface FreebirdDiscoveryDocumentV2 {
  readonly exchange: ExchangeDiscoveryV2;
}

/** Relevant fields from Freebird's complete /.well-known/keys container. */
export interface FreebirdKeysDiscoverySnapshotV2 extends FreebirdDiscoveryDocumentV2 {
  readonly graph_issuance?: GraphIssuanceDiscoveryV1;
}

export interface DisabledPublicationAcknowledgementV1 {
  readonly version: 'freebird/exchange-disabled-publication-ack/v1';
  readonly issuer_id: string;
  readonly graph_id: CanonicalSha256Hex;
  readonly disabled_transition_ids: readonly [CanonicalSha256Hex, CanonicalSha256Hex];
  readonly acknowledged_admission_state: 'disabled';
  readonly operator: string;
  readonly acknowledged_at_unix: number;
}

export interface Phase1BootstrapManifestV1 {
  readonly version: 'scarcity/bootstrap-manifest/v1';
  readonly issuer_id: string;
  readonly discovery: FreebirdDiscoveryDocumentV2;
  readonly graph_issuance: GraphIssuancePolicyV1;
  readonly disabled_publication_ack: DisabledPublicationAcknowledgementV1;
}
