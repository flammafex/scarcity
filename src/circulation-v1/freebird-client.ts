/**
 * HTTP-only consumer for the pinned Freebird V2 exchange and V1 graph-
 * issuance operations.  It does not invent a recovery endpoint: an exact
 * POST is the only operation that can process or recover work.
 */

import { ed25519 } from '@noble/curves/ed25519';
import {
  BoundaryValidationError,
  decodeCanonicalBase64Url,
  encodeCanonicalBase64Url,
  parseExchangeAcceptedResponseV2,
  parseExchangeRequestV2,
  parseGraphIssuanceRequestV1,
  parseGraphIssuanceResultV1,
  type CanonicalBase64Url,
  type ExchangeAcceptedResponseV2,
  type ExchangeRequestV2,
  type ExchangeResultV2,
  type ExchangeReceiptV2,
  type FreebirdV5DescriptorV2,
  type GraphIssuanceRequestV1,
  type GraphIssuanceResultV1,
  type GraphIssuancePolicyV1,
  type ReceiptVerificationKeyV2,
  RECEIPT_LIFETIME_SECONDS,
} from './types.js';
import {
  FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER,
  FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER,
  computeExchangeReceiptDigest,
  verifyExchangeResultDigest,
  verifyGraphIssuanceRequestDigest,
  verifyGraphIssuanceResultDigest,
} from './canonical.js';
import { assertPinnedFreebirdOrigin, assertPinnedFreebirdUrl, type ValidatedFreebirdDiscovery } from './discovery.js';
import { EDGE_BUDGET_LIMIT } from './types.js';

export const EXCHANGE_STATUS_CAPABILITY_HEADER = 'exchange-status-capability' as const;
export const GRAPH_ISSUANCE_STATUS_CAPABILITY_HEADER = 'graph-issuance-status-capability' as const;

export const V2_EXCHANGE_PATH = '/v2/public/exchange' as const;
export const V2_EXCHANGE_STATUS_PATH = '/v2/public/exchange/status' as const;
export const V1_GRAPH_ISSUANCE_PATH = '/v1/public/graph/issue' as const;
export const V1_GRAPH_ISSUANCE_STATUS_PATH = '/v1/public/graph/issue/status' as const;

export type FreebirdErrorCode =
  | 'transport_failure'
  | 'invalid_request'
  | 'invalid_response'
  | 'missing_no_store'
  | 'operation_unknown'
  | 'unauthorized'
  | 'http_rejected'
  | 'operation_conflict'
  | 'ambiguous_post';

/** Error data contains no URL, request body, response body, or secret. */
export interface RedactedFreebirdError {
  readonly code: FreebirdErrorCode;
  readonly status?: number;
  readonly retry_after_seconds?: number;
}

/** An exception form for caller/configuration and discovery failures. */
export class FreebirdClientError extends Error {
  readonly error: RedactedFreebirdError;

  constructor(error: RedactedFreebirdError) {
    super(error.code);
    this.name = 'FreebirdClientError';
    this.error = { ...error };
  }

  toJSON(): RedactedFreebirdError {
    return { ...this.error };
  }
}

export interface FreebirdCommittedOutcome<T> {
  readonly kind: 'committed';
  readonly status: 200;
  readonly value: T;
  readonly request_digest: CanonicalBase64Url;
  readonly observed: boolean;
}

export interface FreebirdRetryableOutcome {
  readonly kind: 'retryable';
  readonly status: 202;
  readonly retry_after_seconds?: number;
  readonly request_digest: CanonicalBase64Url;
  readonly observed: boolean;
}

export interface FreebirdRejectedOutcome {
  readonly kind: 'rejected';
  readonly status: number;
  readonly error: RedactedFreebirdError;
  readonly request_digest: CanonicalBase64Url;
  readonly observed: boolean;
}

export interface FreebirdConflictOutcome {
  readonly kind: 'conflict';
  readonly status: 409;
  readonly error: RedactedFreebirdError;
  readonly request_digest: CanonicalBase64Url;
  readonly observed: false;
}

export interface FreebirdAmbiguousOutcome {
  readonly kind: 'ambiguous';
  readonly status?: number;
  readonly error: RedactedFreebirdError;
  readonly request_digest: CanonicalBase64Url;
  readonly observed: false;
}

export type FreebirdPostOutcome<T> =
  | FreebirdCommittedOutcome<T>
  | FreebirdRetryableOutcome
  | FreebirdRejectedOutcome
  | FreebirdConflictOutcome
  | FreebirdAmbiguousOutcome;

export type FreebirdObservationOutcome<T> =
  | FreebirdCommittedOutcome<T>
  | FreebirdRetryableOutcome
  | FreebirdRejectedOutcome;

export interface FreebirdHttpClientOptions {
  readonly origin: string;
  readonly fetchImpl?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly nowUnixSeconds?: () => number;
  readonly discovery?: ValidatedFreebirdDiscovery;
  readonly graphIssuancePolicy?: GraphIssuancePolicyV1;
  readonly graphIssuanceDescriptor?: FreebirdV5DescriptorV2;
}

interface ResponseEnvelope {
  readonly response: Response;
  readonly body: unknown;
  readonly hasBody: boolean;
}

function invalid(message: string): never {
  throw new BoundaryValidationError(message);
}

function safeError(code: FreebirdErrorCode, status?: number, retryAfter?: number): RedactedFreebirdError {
  return {
    code,
    ...(status === undefined ? {} : { status }),
    ...(retryAfter === undefined ? {} : { retry_after_seconds: retryAfter }),
  };
}

function digestText(bytes: Uint8Array): CanonicalBase64Url {
  return encodeCanonicalBase64Url(bytes);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

function sameBase64(left: string, right: string, field: string): void {
  let leftBytes: Uint8Array;
  let rightBytes: Uint8Array;
  try {
    leftBytes = decodeCanonicalBase64Url(left, undefined, field);
    rightBytes = decodeCanonicalBase64Url(right, undefined, field);
  } catch {
    invalid(`${field}: invalid binding`);
  }
  if (!bytesEqual(leftBytes, rightBytes)) invalid(`${field}: binding mismatch`);
}

function sameSelector(left: { descriptor_id: string; keyset_id: string; slot_id: string; quantity: number }, right: { descriptor_id: string; keyset_id: string; slot_id: string; quantity: number }, field: string): void {
  if (
    left.descriptor_id !== right.descriptor_id
    || left.keyset_id !== right.keyset_id
    || left.slot_id !== right.slot_id
    || left.quantity !== right.quantity
  ) invalid(`${field}: selector mismatch`);
}

function sameExchangeResultBindings(request: ExchangeRequestV2, result: ExchangeResultV2): void {
  if (
    result.version !== request.version
    || result.public_operation_id !== request.public_operation_id
    || result.graph_id !== request.graph_id
    || result.transition_id !== request.transition_id
    || result.source_keyset_id !== request.source_keyset_id
    || result.target_keyset_id !== request.target_keyset_id
  ) invalid('exchange result: selector mismatch');
  sameSelector(result.outputs[0].slot, request.outputs[0].slot, 'exchange result.outputs[0].slot');
  sameBase64(result.outputs[0].blinded_value, request.outputs[0].blinded_value, 'exchange result.outputs[0].blinded_value');
}

function sameReceiptBindings(request: ExchangeRequestV2, result: ExchangeResultV2, receipt: ExchangeReceiptV2): void {
  if (
    receipt.version !== result.version
    || receipt.public_operation_id !== request.public_operation_id
    || receipt.graph_id !== request.graph_id
    || receipt.transition_id !== request.transition_id
    || receipt.source_keyset_id !== request.source_keyset_id
    || receipt.target_keyset_id !== request.target_keyset_id
  ) invalid('exchange receipt: selector mismatch');
  sameBase64(receipt.result_digest, result.result_digest, 'exchange receipt.result_digest');
}

function assertReceiptLifetime(receipt: ExchangeReceiptV2, field = 'exchange receipt'): void {
  if (receipt.expires_at - receipt.created_at !== RECEIPT_LIFETIME_SECONDS) {
    invalid(`${field}: receipt lifetime must be exactly 30 days`);
  }
}

function graphSelectorMatches(request: GraphIssuanceRequestV1, result: GraphIssuanceResultV1): void {
  if (
    result.version !== request.version
    || result.public_operation_id !== request.public_operation_id
    || result.issuance_policy_id !== request.issuance_policy_id
    || result.graph_id !== request.graph_id
    || result.keyset_id !== request.keyset_id
    || result.descriptor_id !== request.descriptor_id
  ) invalid('graph issuance result: selector mismatch');
}

function assertJsonContentType(response: Response): void {
  const contentType = response.headers.get('content-type');
  if (contentType === null || contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    invalid('response: unexpected content type');
  }
}

function hasNoStore(response: Response): boolean {
  const cacheControl = response.headers.get('cache-control');
  if (cacheControl === null) return false;
  return cacheControl.split(',').some((directive) => directive.trim().toLowerCase() === 'no-store');
}

function parseRetryAfter(response: Response, required: boolean): number | undefined {
  const value = response.headers.get('retry-after');
  if (value === null) {
    if (required) invalid('response: missing Retry-After');
    return undefined;
  }
  if (!/^\d+$/.test(value.trim())) invalid('response: invalid Retry-After');
  const seconds = Number(value.trim());
  if (!Number.isSafeInteger(seconds)) invalid('response: invalid Retry-After');
  return seconds;
}

function exactStatusBody(value: unknown, statuses: readonly string[], field: string): string {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field}: invalid status body`);
  const object = value as Record<string, unknown>;
  if (Object.keys(object).length !== 1 || typeof object.status !== 'string' || !statuses.includes(object.status)) {
    invalid(`${field}: invalid status body`);
  }
  return object.status;
}

function operationId(value: string): string {
  decodeCanonicalBase64Url(value, 16, 'public_operation_id');
  return value;
}

function capability(value: string, field: string): string {
  decodeCanonicalBase64Url(value, 32, field);
  return value;
}

function graphPolicyFromDiscovery(discovery: ValidatedFreebirdDiscovery, request: GraphIssuanceRequestV1): GraphIssuancePolicyV1 | undefined {
  const policies = discovery.graph_issuance?.policies;
  const policy = policies?.find((candidate) => candidate.issuance_policy_id === request.issuance_policy_id);
  if (policy === undefined) return undefined;
  const graph = discovery.exchange.active_graph;
  const k0 = graph.keysets[0];
  if (
    policy.graph_id !== graph.graph_id
    || policy.keyset_id !== k0.keyset_id
    || policy.descriptor_id !== k0.descriptor_ids[0]
    || policy.budget_limit !== EDGE_BUDGET_LIMIT
    || policy.quantity !== 1
    || policy.admission_state !== 'accepting_new'
    || policy.authorization_scheme !== 'v4_local'
  ) invalid('graph issuance discovery: policy is not the fixed K0 profile');
  return {
    issuance_policy_id: policy.issuance_policy_id,
    graph_id: policy.graph_id,
    keyset_id: policy.keyset_id,
    descriptor_id: policy.descriptor_id,
    budget_id: policy.budget_id,
    budget_limit: EDGE_BUDGET_LIMIT,
    quantity: 1,
    admission_state: policy.admission_state,
    authorization_scheme: 'v4_local',
  };
}

function assertGraphPolicy(policy: GraphIssuancePolicyV1, request: GraphIssuanceRequestV1): void {
  if (
    policy.issuance_policy_id !== request.issuance_policy_id
    || policy.graph_id !== request.graph_id
    || policy.keyset_id !== request.keyset_id
    || policy.descriptor_id !== request.descriptor_id
    || policy.budget_limit !== EDGE_BUDGET_LIMIT
    || policy.quantity !== 1
    || policy.authorization_scheme !== 'v4_local'
    || policy.admission_state !== 'accepting_new'
  ) invalid('graph issuance request: policy mismatch');
}

function findDescriptor(discovery: ValidatedFreebirdDiscovery, descriptorId: string): FreebirdV5DescriptorV2 | undefined {
  return discovery.exchange.active_graph.descriptors.find((descriptor) => descriptor.descriptor_id === descriptorId);
}

export class FreebirdHttpClient {
  readonly origin: string;
  private readonly fetchImpl: typeof fetch;
  private readonly signal?: AbortSignal;
  private readonly nowUnixSeconds: () => number;
  private readonly discovery?: ValidatedFreebirdDiscovery;
  private readonly configuredGraphPolicy?: GraphIssuancePolicyV1;
  private readonly configuredGraphDescriptor?: FreebirdV5DescriptorV2;

  constructor(options: FreebirdHttpClientOptions) {
    this.origin = assertPinnedFreebirdOrigin(options.origin);
    if (options.discovery !== undefined && options.discovery.origin !== this.origin) {
      invalid('client.discovery: origin does not match pinned origin');
    }
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') invalid('client: fetch is unavailable');
    this.signal = options.signal;
    this.nowUnixSeconds = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));
    this.discovery = options.discovery;
    this.configuredGraphPolicy = options.graphIssuancePolicy;
    this.configuredGraphDescriptor = options.graphIssuanceDescriptor;
  }

  private endpoint(path: string): URL {
    return assertPinnedFreebirdUrl(new URL(path, `${this.origin}/`), this.origin, 'endpoint');
  }

  private async request(path: string, method: 'GET' | 'POST', body: unknown, capabilityHeader: string, capabilityValue: string): Promise<ResponseEnvelope> {
    const url = this.endpoint(path);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers: {
          accept: 'application/json',
          ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
          [capabilityHeader]: capabilityValue,
        },
        ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
        redirect: 'manual',
        signal: this.signal,
      });
    } catch {
      throw new FreebirdClientError(safeError('transport_failure'));
    }
    if (response.url !== '') assertPinnedFreebirdUrl(response.url, this.origin, 'response URL');
    if (response.redirected || (response.status >= 300 && response.status < 400)) {
      const location = response.headers.get('location');
      if (location !== null) assertPinnedFreebirdUrl(location, this.origin, 'redirect');
      throw new FreebirdClientError(safeError('http_rejected', response.status));
    }

    const expectedBody = response.status >= 200 && response.status < 300;
    let text = '';
    try {
      text = await response.text();
    } catch {
      throw new FreebirdClientError(safeError('invalid_response', response.status));
    }
    const hasBody = text.length !== 0;
    if (expectedBody || hasBody) assertJsonContentType(response);
    if (!hasBody) return { response, body: undefined, hasBody: false };
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new FreebirdClientError(safeError('invalid_response', response.status));
    }
    return { response, body: parsed, hasBody: true };
  }

  private requestDigest(request: ExchangeRequestV2): CanonicalBase64Url {
    return digestText(FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER.requestDigest(request));
  }

  private assertExchangeRequestProfile(request: ExchangeRequestV2): void {
    const graph = this.discovery?.exchange.active_graph;
    if (graph === undefined) return;
    if (request.graph_id !== graph.graph_id) invalid('exchange request: graph is not pinned');
    const transition = graph.transitions.find((candidate) => candidate.transition_id === request.transition_id);
    if (transition === undefined) invalid('exchange request: transition is not pinned');
    if (
      transition.admission_state !== 'accepting_new'
      || request.source_keyset_id !== transition.source_keyset_id
      || request.target_keyset_id !== transition.target_keyset_id
    ) invalid('exchange request: transition is not accepting the pinned direction');
    const source = transition.source_slots[0];
    const output = transition.output_slots[0];
    sameSelector(
      request.sources[0].slot,
      { descriptor_id: source.descriptor_id, keyset_id: transition.source_keyset_id, slot_id: source.slot_id, quantity: source.quantity },
      'exchange request.sources[0].slot',
    );
    sameSelector(
      request.outputs[0].slot,
      { descriptor_id: output.descriptor_id, keyset_id: transition.target_keyset_id, slot_id: output.slot_id, quantity: output.quantity },
      'exchange request.outputs[0].slot',
    );
  }

  private issuanceRequestDigest(request: GraphIssuanceRequestV1): CanonicalBase64Url {
    return digestText(FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER.requestDigest(request));
  }

  private verifyExchangeResponse(request: ExchangeRequestV2, value: unknown): ExchangeAcceptedResponseV2 {
    const accepted = parseExchangeAcceptedResponseV2(value);
    sameExchangeResultBindings(request, accepted.result);
    verifyExchangeResultDigest(accepted.result, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    sameReceiptBindings(request, accepted.result, accepted.receipt);
    assertReceiptLifetime(accepted.receipt);
    const now = this.nowUnixSeconds();
    if (!Number.isSafeInteger(now)) invalid('exchange receipt: invalid local clock');
    if (accepted.receipt.created_at > now || accepted.receipt.expires_at < now) {
      invalid('exchange receipt: outside validity interval');
    }
    const receiptKey = this.receiptKey(accepted.receipt.receipt_key_id);
    if (receiptKey === undefined) invalid('exchange receipt: unknown receipt key');
    if (receiptKey.valid_from > accepted.receipt.created_at || receiptKey.valid_until < accepted.receipt.expires_at) {
      invalid('exchange receipt: receipt key does not cover interval');
    }
    const receiptDigest = computeExchangeReceiptDigest(accepted.receipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    const signature = decodeCanonicalBase64Url(accepted.receipt.signature, 64, 'exchange receipt.signature');
    const publicKey = decodeCanonicalBase64Url(receiptKey.public_key_b64, 32, 'receipt key.public_key_b64');
    if (!ed25519.verify(signature, receiptDigest, publicKey)) invalid('exchange receipt: invalid signature');
    return accepted;
  }

  private receiptKey(keyId: string): ReceiptVerificationKeyV2 | undefined {
    const exchange = this.discovery?.exchange;
    if (exchange === undefined) return undefined;
    if (exchange.active_receipt_key.key_id === keyId) return exchange.active_receipt_key;
    return exchange.retained_receipt_keys.find((key) => key.key_id === keyId);
  }

  /** Execute the exact V2 POST; this method is also the recovery operation. */
  async processOrRecoverV2(value: unknown, statusCapability: string): Promise<FreebirdPostOutcome<ExchangeAcceptedResponseV2>> {
    const request = parseExchangeRequestV2(value);
    this.assertExchangeRequestProfile(request);
    const digest = this.requestDigest(request);
    capability(statusCapability, EXCHANGE_STATUS_CAPABILITY_HEADER);
    let envelope: ResponseEnvelope;
    try {
      envelope = await this.request(V2_EXCHANGE_PATH, 'POST', request, EXCHANGE_STATUS_CAPABILITY_HEADER, statusCapability);
    } catch (error) {
      if (error instanceof FreebirdClientError) {
        return this.ambiguous(error.error, digest);
      }
      return this.ambiguous(safeError('ambiguous_post'), digest);
    }
    const { response, body } = envelope;
    if (response.status === 200) {
      if (!hasNoStore(response)) return this.ambiguous(safeError('missing_no_store', 200), digest);
      try {
        const accepted = this.verifyExchangeResponse(request, body);
        return { kind: 'committed', status: 200, value: accepted, request_digest: digest, observed: false };
      } catch {
        return this.rejected(safeError('invalid_response', 200), digest, false);
      }
    }
    if (response.status === 202) {
      if (!hasNoStore(response)) return this.ambiguous(safeError('missing_no_store', 202), digest);
      try {
        exactStatusBody(body, ['exchange_retryable'], 'exchange POST');
        const retryAfter = parseRetryAfter(response, true);
        if (retryAfter !== 1) return this.ambiguous(safeError('invalid_response', 202, retryAfter), digest);
        return { kind: 'retryable', status: 202, retry_after_seconds: retryAfter, request_digest: digest, observed: false };
      } catch {
        return this.ambiguous(safeError('invalid_response', 202), digest);
      }
    }
    if (response.status === 409) return { kind: 'conflict', status: 409, error: safeError('operation_conflict', 409), request_digest: digest, observed: false };
    if (response.status >= 500) return this.ambiguous(safeError('ambiguous_post', response.status), digest);
    if (response.status === 400 || response.status === 403 || response.status === 404 || response.status === 401) {
      return this.rejected(safeError('http_rejected', response.status), digest, false);
    }
    return this.rejected(safeError('http_rejected', response.status), digest, false);
  }

  /** Alias emphasizing that recovery never changes the operation identity. */
  processExchangeV2(value: unknown, statusCapability: string): Promise<FreebirdPostOutcome<ExchangeAcceptedResponseV2>> {
    return this.processOrRecoverV2(value, statusCapability);
  }

  postExchangeV2(value: unknown, statusCapability: string): Promise<FreebirdPostOutcome<ExchangeAcceptedResponseV2>> {
    return this.processOrRecoverV2(value, statusCapability);
  }

  /** Observe V2 state only.  This method never performs a POST or accepts a transfer. */
  async observeExchangeStatus(value: ExchangeRequestV2 | string, statusCapability: string): Promise<FreebirdObservationOutcome<ExchangeAcceptedResponseV2>> {
    const request = typeof value === 'string' ? undefined : parseExchangeRequestV2(value);
    if (request !== undefined) this.assertExchangeRequestProfile(request);
    const id = operationId(typeof value === 'string' ? value : value.public_operation_id);
    const digest = request === undefined ? encodeCanonicalBase64Url(new Uint8Array(32)) : this.requestDigest(request);
    capability(statusCapability, EXCHANGE_STATUS_CAPABILITY_HEADER);
    const path = `${V2_EXCHANGE_STATUS_PATH}?public_operation_id=${encodeURIComponent(id)}`;
    let envelope: ResponseEnvelope;
    try {
      envelope = await this.request(path, 'GET', undefined, EXCHANGE_STATUS_CAPABILITY_HEADER, statusCapability);
    } catch (error) {
      if (error instanceof FreebirdClientError) return this.rejected(error.error, digest, true);
      return this.rejected(safeError('invalid_response'), digest, true);
    }
    const { response, body } = envelope;
    if (response.status === 200) {
      if (!hasNoStore(response)) return this.rejected(safeError('missing_no_store', 200), digest, true);
      try {
        const accepted = request === undefined
          ? this.verifyExchangeObservation(id, body)
          : this.verifyExchangeResponse(request, body);
        return { kind: 'committed', status: 200, value: accepted, request_digest: digest, observed: true };
      } catch {
        return this.rejected(safeError('invalid_response', 200), digest, true);
      }
    }
    if (response.status === 202) {
      if (!hasNoStore(response)) return this.rejected(safeError('missing_no_store', 202), digest, true);
      try {
        exactStatusBody(body, ['pending'], 'exchange status');
        return { kind: 'retryable', status: 202, request_digest: digest, observed: true };
      } catch {
        return this.rejected(safeError('invalid_response', 202), digest, true);
      }
    }
    if (response.status === 404) return this.rejected(safeError('operation_unknown', 404), digest, true);
    if (response.status === 403) return this.rejected(safeError('unauthorized', 403), digest, true);
    return this.rejected(safeError('http_rejected', response.status), digest, true);
  }

  private verifyExchangeObservation(id: string, value: unknown): ExchangeAcceptedResponseV2 {
    const accepted = parseExchangeAcceptedResponseV2(value);
    if (accepted.result.public_operation_id !== id || accepted.receipt.public_operation_id !== id) invalid('exchange status: operation mismatch');
    verifyExchangeResultDigest(accepted.result, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    if (accepted.receipt.result_digest !== accepted.result.result_digest) invalid('exchange status: receipt mismatch');
    assertReceiptLifetime(accepted.receipt, 'exchange status receipt');
    const now = this.nowUnixSeconds();
    if (accepted.receipt.created_at > now || accepted.receipt.expires_at < now) invalid('exchange status: receipt expired');
    const receiptKey = this.receiptKey(accepted.receipt.receipt_key_id);
    if (receiptKey === undefined) invalid('exchange status: unknown receipt key');
    if (receiptKey.valid_from > accepted.receipt.created_at || receiptKey.valid_until < accepted.receipt.expires_at) {
      invalid('exchange status: receipt key does not cover interval');
    }
    const digest = computeExchangeReceiptDigest(accepted.receipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    const signature = decodeCanonicalBase64Url(accepted.receipt.signature, 64, 'exchange receipt.signature');
    const publicKey = decodeCanonicalBase64Url(receiptKey.public_key_b64, 32, 'receipt key.public_key_b64');
    if (!ed25519.verify(signature, digest, publicKey)) invalid('exchange status: invalid receipt signature');
    return accepted;
  }

  getExchangeStatusV2(value: ExchangeRequestV2 | string, statusCapability: string): Promise<FreebirdObservationOutcome<ExchangeAcceptedResponseV2>> {
    return this.observeExchangeStatus(value, statusCapability);
  }

  private graphProfile(request: GraphIssuanceRequestV1): { policy?: GraphIssuancePolicyV1; descriptor?: FreebirdV5DescriptorV2 } {
    const policy = this.configuredGraphPolicy ?? (this.discovery === undefined ? undefined : graphPolicyFromDiscovery(this.discovery, request));
    const descriptor = this.configuredGraphDescriptor ?? (this.discovery === undefined ? undefined : findDescriptor(this.discovery, request.descriptor_id));
    if (this.discovery !== undefined && policy === undefined) invalid('graph issuance request: no pinned issuance policy');
    if (policy !== undefined) assertGraphPolicy(policy, request);
    if (descriptor !== undefined && descriptor.descriptor_id !== request.descriptor_id) {
      invalid('graph issuance request: descriptor mismatch');
    }
    if (this.discovery !== undefined) {
      const graph = this.discovery.exchange.active_graph;
      if (policy === undefined || policy.graph_id !== graph.graph_id || policy.keyset_id !== graph.keysets[0].keyset_id || policy.descriptor_id !== graph.keysets[0].descriptor_ids[0]) {
        invalid('graph issuance request: policy is not pinned to K0');
      }
    }
    return { policy, descriptor };
  }

  private verifyGraphResult(request: GraphIssuanceRequestV1, value: unknown): GraphIssuanceResultV1 {
    const result = parseGraphIssuanceResultV1(value);
    graphSelectorMatches(request, result);
    const profile = this.graphProfile(request);
    if (profile.policy !== undefined) {
      if (profile.policy.keyset_id !== request.keyset_id || profile.policy.descriptor_id !== request.descriptor_id) invalid('graph issuance result: policy binding mismatch');
    }
    if (profile.descriptor !== undefined && result.token_key_id !== profile.descriptor.token_key_id) invalid('graph issuance result: token key mismatch');
    if (result.quantity !== 1) invalid('graph issuance result: quantity mismatch');
    verifyGraphIssuanceRequestDigest(request, result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
    verifyGraphIssuanceResultDigest(result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
    return result;
  }

  /** Execute the exact V1 graph-issuance POST; this method is also recovery. */
  async processOrRecoverGraphIssuance(value: unknown, statusCapability: string): Promise<FreebirdPostOutcome<GraphIssuanceResultV1>> {
    const request = parseGraphIssuanceRequestV1(value);
    this.graphProfile(request);
    const digest = this.issuanceRequestDigest(request);
    capability(statusCapability, GRAPH_ISSUANCE_STATUS_CAPABILITY_HEADER);
    let envelope: ResponseEnvelope;
    try {
      envelope = await this.request(V1_GRAPH_ISSUANCE_PATH, 'POST', request, GRAPH_ISSUANCE_STATUS_CAPABILITY_HEADER, statusCapability);
    } catch (error) {
      if (error instanceof FreebirdClientError) return this.ambiguous(error.error, digest);
      return this.ambiguous(safeError('ambiguous_post'), digest);
    }
    const { response, body } = envelope;
    if (response.status === 200) {
      if (!hasNoStore(response)) return this.ambiguous(safeError('missing_no_store', 200), digest);
      try {
        const result = this.verifyGraphResult(request, body);
        return { kind: 'committed', status: 200, value: result, request_digest: digest, observed: false };
      } catch {
        return this.rejected(safeError('invalid_response', 200), digest, false);
      }
    }
    if (response.status === 202) {
      if (!hasNoStore(response)) return this.ambiguous(safeError('missing_no_store', 202), digest);
      try {
        exactStatusBody(body, ['graph_issuance_retryable'], 'graph issuance POST');
        const retryAfter = parseRetryAfter(response, false);
        return { kind: 'retryable', status: 202, ...(retryAfter === undefined ? {} : { retry_after_seconds: retryAfter }), request_digest: digest, observed: false };
      } catch {
        return this.ambiguous(safeError('invalid_response', 202), digest);
      }
    }
    if (response.status === 409) return { kind: 'conflict', status: 409, error: safeError('operation_conflict', 409), request_digest: digest, observed: false };
    if (response.status >= 500) return this.ambiguous(safeError('ambiguous_post', response.status), digest);
    return this.rejected(safeError('http_rejected', response.status), digest, false);
  }

  processGraphIssuanceV1(value: unknown, statusCapability: string): Promise<FreebirdPostOutcome<GraphIssuanceResultV1>> {
    return this.processOrRecoverGraphIssuance(value, statusCapability);
  }

  postGraphIssuanceV1(value: unknown, statusCapability: string): Promise<FreebirdPostOutcome<GraphIssuanceResultV1>> {
    return this.processOrRecoverGraphIssuance(value, statusCapability);
  }

  /** Observe V1 issuance state only; it never completes or recovers an issuance. */
  async observeGraphIssuanceStatus(value: GraphIssuanceRequestV1 | string, statusCapability: string): Promise<FreebirdObservationOutcome<GraphIssuanceResultV1>> {
    const request = typeof value === 'string' ? undefined : parseGraphIssuanceRequestV1(value);
    if (request !== undefined) this.graphProfile(request);
    const id = operationId(typeof value === 'string' ? value : value.public_operation_id);
    const digest = request === undefined ? encodeCanonicalBase64Url(new Uint8Array(32)) : this.issuanceRequestDigest(request);
    capability(statusCapability, GRAPH_ISSUANCE_STATUS_CAPABILITY_HEADER);
    const path = `${V1_GRAPH_ISSUANCE_STATUS_PATH}?public_operation_id=${encodeURIComponent(id)}`;
    let envelope: ResponseEnvelope;
    try {
      envelope = await this.request(path, 'GET', undefined, GRAPH_ISSUANCE_STATUS_CAPABILITY_HEADER, statusCapability);
    } catch (error) {
      if (error instanceof FreebirdClientError) return this.rejected(error.error, digest, true);
      return this.rejected(safeError('invalid_response'), digest, true);
    }
    const { response, body } = envelope;
    if (response.status === 200) {
      if (!hasNoStore(response)) return this.rejected(safeError('missing_no_store', 200), digest, true);
      try {
        const result = request === undefined ? this.verifyGraphObservation(id, body) : this.verifyGraphResult(request, body);
        return { kind: 'committed', status: 200, value: result, request_digest: digest, observed: true };
      } catch {
        return this.rejected(safeError('invalid_response', 200), digest, true);
      }
    }
    if (response.status === 202) {
      if (!hasNoStore(response)) return this.rejected(safeError('missing_no_store', 202), digest, true);
      try {
        exactStatusBody(body, ['pending'], 'graph issuance status');
        return { kind: 'retryable', status: 202, request_digest: digest, observed: true };
      } catch {
        return this.rejected(safeError('invalid_response', 202), digest, true);
      }
    }
    if (response.status === 404) return this.rejected(safeError('operation_unknown', 404), digest, true);
    if (response.status === 403) return this.rejected(safeError('unauthorized', 403), digest, true);
    return this.rejected(safeError('http_rejected', response.status), digest, true);
  }

  private verifyGraphObservation(id: string, value: unknown): GraphIssuanceResultV1 {
    const result = parseGraphIssuanceResultV1(value);
    if (result.public_operation_id !== id) invalid('graph issuance status: operation mismatch');
    if (result.quantity !== 1) invalid('graph issuance status: quantity mismatch');
    const descriptor = this.discovery === undefined ? undefined : findDescriptor(this.discovery, result.descriptor_id);
    if (descriptor === undefined && this.discovery !== undefined) invalid('graph issuance status: unknown descriptor');
    if (descriptor !== undefined && descriptor.token_key_id !== result.token_key_id) invalid('graph issuance status: token key mismatch');
    verifyGraphIssuanceResultDigest(result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
    return result;
  }

  getGraphIssuanceStatusV1(value: GraphIssuanceRequestV1 | string, statusCapability: string): Promise<FreebirdObservationOutcome<GraphIssuanceResultV1>> {
    return this.observeGraphIssuanceStatus(value, statusCapability);
  }

  private rejected(error: RedactedFreebirdError, digest: CanonicalBase64Url, observed: boolean): FreebirdRejectedOutcome {
    return { kind: 'rejected', status: error.status ?? 0, error, request_digest: digest, observed };
  }

  private ambiguous(error: RedactedFreebirdError, digest: CanonicalBase64Url): FreebirdAmbiguousOutcome {
    return { kind: 'ambiguous', ...(error.status === undefined ? {} : { status: error.status }), error, request_digest: digest, observed: false };
  }
}

/** Concise constructor alias for callers that do not need subclassing. */
export function createFreebirdHttpClient(options: FreebirdHttpClientOptions): FreebirdHttpClient {
  return new FreebirdHttpClient(options);
}

/** Compatibility names remain local to this isolated client module. */
export { FreebirdHttpClient as PinnedFreebirdClient, FreebirdHttpClient as FreebirdClient };
