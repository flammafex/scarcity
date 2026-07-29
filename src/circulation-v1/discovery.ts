/**
 * Pinned, fail-closed Freebird discovery transport.
 *
 * Discovery is deliberately kept separate from the HTTP operation client.  A
 * caller gets a snapshot only after the complete public container has been
 * parsed and the Scarcity-local bootstrap validator has accepted it.
 */

import {
  BoundaryValidationError,
  decodeCanonicalBase64Url,
  encodeCanonicalBase64Url,
  parseGraphIssuanceDiscovery,
  type ExchangeDiscoveryV2,
  type FreebirdKeysDiscoverySnapshotV2,
  type GraphIssuanceDiscovery,
} from './types.js';
import { validateDiscoverySnapshot, validateGraphIssuanceDiscoverySnapshot, validateGraphIssuanceDiscoveryUpdate } from './bootstrap.js';
import { replayAuthorityProofV1 } from './canonical.js';

export const FREEBIRD_KEYS_PATH = '/.well-known/keys' as const;
export const FREEBIRD_JSON_MEDIA_TYPE = 'application/json' as const;

export interface DiscoveryFetchOptions {
  /** Operator-pinned origin.  It may be HTTPS, or HTTP on a loopback host. */
  readonly origin: string;
  /** Operator-pinned issuer identity. */
  readonly issuerId: string;
  /** Genesis can validate the pre-switch disabled graph explicitly. */
  readonly circulationState?: 'accepting_new' | 'disabled';
  readonly fetchImpl?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly maxResponseBytes?: number;
  readonly previous?: ValidatedFreebirdDiscovery;
}

export interface ValidatedFreebirdDiscovery {
  readonly origin: string;
  readonly exchange: ExchangeDiscoveryV2;
  readonly graph_issuance?: GraphIssuanceDiscovery;
  /** The normalized, validated public container; no transport metadata is retained. */
  readonly document: FreebirdKeysDiscoverySnapshotV2;
}

function invalid(message: string): never {
  throw new BoundaryValidationError(message);
}

function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

function parseUrl(value: string, field: string): URL {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    invalid(`${field}: invalid URL`);
  }
  try {
    return new URL(value);
  } catch {
    invalid(`${field}: invalid URL`);
  }
}

/** Normalize and validate the only origins accepted by the Phase-1 client. */
export function assertPinnedFreebirdOrigin(value: string): string {
  const url = parseUrl(value, 'origin');
  if (url.username !== '' || url.password !== '') invalid('origin: credentials are forbidden');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    invalid('origin: HTTPS is required except for loopback HTTP');
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    invalid('origin: path, query, and fragment are forbidden');
  }
  return url.origin;
}

/**
 * Validate a URL used by a discovery transport against the pinned origin.
 * Relative URLs are resolved against the pin; credentials and cross-origin
 * URLs are never accepted.
 */
export function assertPinnedFreebirdUrl(value: string | URL, origin: string, field = 'url'): URL {
  const pinnedOrigin = assertPinnedFreebirdOrigin(origin);
  let url: URL;
  try {
    url = value instanceof URL ? new URL(value.href) : new URL(value, `${pinnedOrigin}/`);
  } catch {
    invalid(`${field}: invalid URL`);
  }
  if (url.username !== '' || url.password !== '') invalid(`${field}: credentials are forbidden`);
  if (url.origin !== pinnedOrigin) invalid(`${field}: cross-origin URL`);
  return url;
}

function assertObject(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field}: expected an object`);
  return value as Record<string, unknown>;
}

function assertKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], field: string): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) invalid(`${field}.${key}: missing field`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) invalid(`${field}.${key}: unknown field`);
  }
}

function assertJsonContentType(response: Response): void {
  const contentType = response.headers.get('content-type');
  if (contentType === null || contentType.split(';', 1)[0].trim().toLowerCase() !== FREEBIRD_JSON_MEDIA_TYPE) {
    invalid('discovery response: unexpected content type');
  }
}

function responseOrigin(response: Response, pinnedOrigin: string): void {
  if (response.url === '') return;
  assertPinnedFreebirdUrl(response.url, pinnedOrigin, 'discovery response URL');
}

function assertNoRedirect(response: Response, requestedUrl: URL, pinnedOrigin: string): void {
  if (response.redirected || (response.status >= 300 && response.status < 400)) {
    const location = response.headers.get('location');
    if (location !== null) assertPinnedFreebirdUrl(location, pinnedOrigin, 'discovery redirect');
    invalid('discovery response: redirects are forbidden');
  }
  const location = response.headers.get('location');
  if (location !== null) {
    const link = assertPinnedFreebirdUrl(location, pinnedOrigin, 'discovery link');
    if (link.href !== requestedUrl.href) invalid('discovery response: discovery links are forbidden');
  }
}

function parseDiscoveryDocument(value: unknown, options: DiscoveryFetchOptions, origin: string): ValidatedFreebirdDiscovery {
  const root = assertObject(value, 'discovery');
  // Freebird's public container includes legacy V4/V5 key metadata alongside
  // the V2 exchange documents.  Scarcity deliberately normalizes only the
  // V2 fields, but the envelope is still allowlisted so unrelated fields do
  // not pass the boundary silently.
  assertKeys(root, ['exchange'], ['issuer_id', 'current_epoch', 'valid_epochs', 'epoch_duration_sec', 'voprf', 'public', 'graph_issuance'], 'discovery');
  if (root.issuer_id !== undefined) {
    if (typeof root.issuer_id !== 'string' || root.issuer_id !== options.issuerId) invalid('discovery.issuer_id: issuer mismatch');
  }

  // validateDiscoverySnapshot is intentionally the authority for the complete
  // exchange graph.  Its input is the exact exchange discovery object; the
  // optional graph-issuance container is validated independently below.
  const exchange = validateDiscoverySnapshot(
    { exchange: root.exchange },
    {
      issuerId: options.issuerId,
      circulationState: options.circulationState ?? 'accepting_new',
    },
  );

  let graphIssuance: GraphIssuanceDiscovery | undefined;
  if (root.graph_issuance !== undefined) graphIssuance = validateGraphIssuanceDiscoverySnapshot(root.graph_issuance, exchange);
  if (options.previous !== undefined) validateGraphIssuanceDiscoveryUpdate(exchange, options.previous.graph_issuance, root.graph_issuance);

  const document: FreebirdKeysDiscoverySnapshotV2 = {
    exchange: {
      active_graph: exchange.active_graph,
      retained_graphs: exchange.retained_graphs,
      active_receipt_key: exchange.active_receipt_key,
      retained_receipt_keys: exchange.retained_receipt_keys,
    },
    ...(graphIssuance === undefined ? {} : { graph_issuance: graphIssuance }),
  };
  return {
    origin,
    exchange,
    ...(graphIssuance === undefined ? {} : { graph_issuance: graphIssuance }),
    document,
  };
}

/** Fetch and atomically validate a complete Freebird /.well-known/keys document. */
export async function fetchFreebirdDiscovery(options: DiscoveryFetchOptions): Promise<ValidatedFreebirdDiscovery> {
  const origin = assertPinnedFreebirdOrigin(options.origin);
  if (typeof options.issuerId !== 'string' || options.issuerId.length === 0) invalid('issuerId: required');
  const requestedUrl = new URL(FREEBIRD_KEYS_PATH, `${origin}/`);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') invalid('discovery: fetch is unavailable');
  const maxResponseBytes = options.maxResponseBytes ?? 4 * 1024 * 1024;
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) invalid('discovery: invalid response limit');

  let response: Response;
  try {
    response = await fetchImpl(requestedUrl, {
      method: 'GET',
      headers: { accept: FREEBIRD_JSON_MEDIA_TYPE },
      redirect: 'manual',
      signal: options.signal,
    });
  } catch {
    throw new BoundaryValidationError('discovery: transport failure');
  }
  responseOrigin(response, origin);
  assertNoRedirect(response, requestedUrl, origin);
  if (response.status !== 200) invalid('discovery response: unexpected HTTP status');
  assertJsonContentType(response);

  let body: string;
  try {
    body = await response.text();
  } catch {
    invalid('discovery response: unreadable body');
  }
  if (new TextEncoder().encode(body).length > maxResponseBytes) invalid('discovery response: body too large');
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    invalid('discovery response: malformed JSON');
  }
  return parseDiscoveryDocument(parsed, options, origin);
}

/** Small state-free wrapper useful to keep discovery refreshes explicit. */
export class FreebirdDiscoveryClient {
  readonly options: DiscoveryFetchOptions;

  constructor(options: DiscoveryFetchOptions) {
    this.options = { ...options, origin: assertPinnedFreebirdOrigin(options.origin) };
  }

  fetch(): Promise<ValidatedFreebirdDiscovery> {
    return fetchFreebirdDiscovery(this.options);
  }
}

/** Explicit alias for callers that want the pinning guarantee in the name. */
export const fetchPinnedFreebirdDiscovery = fetchFreebirdDiscovery;

interface ReplayAuthorityProbeOptionsBase {
  readonly origin: string;
  readonly issuerId: string;
  /**
   * Verifier-owned probe material.  The challenge must already be registered
   * in the verifier's spend-store under the probe ID before this request is
   * sent.  The issuer has no public challenge-registration endpoint.
   */
  readonly fetchImpl?: typeof fetch;
  readonly signal?: AbortSignal;
}

export type ReplayAuthorityProbeOptions = ReplayAuthorityProbeOptionsBase & (
  | { readonly context: ReplayAuthorityProbeContext; readonly authorityId?: string; readonly challenge?: never; readonly probeId?: never }
  | { readonly authorityId: string; readonly challenge: string | Uint8Array; readonly probeId: string | Uint8Array; readonly context?: never }
);

/** A verifier-registered, single-use replay-authority probe context. */
export interface ReplayAuthorityProbeContext {
  readonly authorityId: string;
  readonly probeId: string;
  readonly challenge: string;
}

function canonicalProbeMaterial(value: unknown, field: string): string {
  if (value instanceof Uint8Array) {
    if (value.length !== 32) invalid(`${field}: expected 32 bytes`);
    return encodeCanonicalBase64Url(value);
  }
  return encodeCanonicalBase64Url(decodeCanonicalBase64Url(value, 32, field));
}

/** Validate and canonicalize verifier-supplied replay probe material. */
export function validateReplayAuthorityProbeContext(value: unknown): ReplayAuthorityProbeContext {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid('replay authority probe context: expected an object');
  const context = value as Record<string, unknown>;
  const keys = ['authorityId', 'probeId', 'challenge'];
  if (Object.keys(context).length !== keys.length || keys.some((key) => !Object.prototype.hasOwnProperty.call(context, key))) {
    invalid('replay authority probe context: unknown or missing field');
  }
  return {
    authorityId: canonicalProbeMaterial(context.authorityId, 'replay authority context.authorityId'),
    probeId: canonicalProbeMaterial(context.probeId, 'replay authority context.probeId'),
    challenge: canonicalProbeMaterial(context.challenge, 'replay authority context.challenge'),
  };
}

function hasNoStore(response: Response): boolean {
  const cacheControl = response.headers.get('cache-control');
  return cacheControl !== null && cacheControl.split(',').some((entry) => entry.trim().toLowerCase() === 'no-store');
}

/** Probe the pinned Freebird replay authority and verify strict bindings. */
export async function probeReplayAuthority(options: ReplayAuthorityProbeOptions): Promise<{
  readonly version: 1;
  readonly authority_id: string;
  readonly probe_id: string;
  readonly proof: string;
}> {
  const origin = assertPinnedFreebirdOrigin(options.origin);
  const context = 'context' in options && options.context !== undefined
    ? validateReplayAuthorityProbeContext(options.context)
    : validateReplayAuthorityProbeContext({
      authorityId: options.authorityId,
      probeId: canonicalProbeMaterial(options.probeId, 'replay authority probe.probeId'),
      challenge: canonicalProbeMaterial(options.challenge, 'replay authority probe.challenge'),
    });
  const authority = decodeCanonicalBase64Url(context.authorityId, 32, 'authority_id');
  const challenge = decodeCanonicalBase64Url(context.challenge, 32, 'replay authority challenge');
  const probe = decodeCanonicalBase64Url(context.probeId, 32, 'probe_id');
  if (options.authorityId !== undefined && options.authorityId !== context.authorityId) invalid('replay authority probe: authority does not match supplied context');
  const request = { version: 1 as const, authority_id: context.authorityId, probe_id: context.probeId };
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const requestedUrl = assertPinnedFreebirdUrl('/v1/public/graph/replay-authority/probe', origin);
  let response: Response;
  try {
    response = await fetchImpl(requestedUrl, {
      method: 'POST', headers: { accept: FREEBIRD_JSON_MEDIA_TYPE, 'content-type': FREEBIRD_JSON_MEDIA_TYPE },
      body: JSON.stringify(request), redirect: 'manual', signal: options.signal,
    });
  } catch {
    invalid('replay authority probe: transport failure');
  }
  responseOrigin(response, origin);
  assertNoRedirect(response, requestedUrl, origin);
  if (response.status !== 200 || !hasNoStore(response)) invalid('replay authority probe: rejected response');
  assertJsonContentType(response);
  let body: unknown;
  try { body = JSON.parse(await response.text()) as unknown; } catch { invalid('replay authority probe: malformed JSON'); }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) invalid('replay authority proof: expected object');
  const item = body as Record<string, unknown>;
  if (Object.keys(item).length !== 4 || item.version !== 1 || item.authority_id !== request.authority_id || item.probe_id !== request.probe_id) invalid('replay authority proof: binding mismatch');
  const proof = encodeCanonicalBase64Url(decodeCanonicalBase64Url(item.proof, 32, 'replay authority proof.proof'));
  const expected = encodeCanonicalBase64Url(replayAuthorityProofV1(challenge, authority, probe, options.issuerId));
  if (proof !== expected) invalid('replay authority proof: proof mismatch');
  return { version: 1, authority_id: request.authority_id, probe_id: request.probe_id, proof };
}
