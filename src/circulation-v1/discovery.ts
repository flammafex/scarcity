/**
 * Pinned, fail-closed Freebird discovery transport.
 *
 * Discovery is deliberately kept separate from the HTTP operation client.  A
 * caller gets a snapshot only after the complete public container has been
 * parsed and the Scarcity-local bootstrap validator has accepted it.
 */

import {
  BoundaryValidationError,
  parseGraphIssuanceDiscoveryV1,
  type ExchangeDiscoveryV2,
  type FreebirdKeysDiscoverySnapshotV2,
  type GraphIssuanceDiscoveryV1,
} from './types.js';
import { validateDiscoverySnapshot } from './bootstrap.js';

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
}

export interface ValidatedFreebirdDiscovery {
  readonly origin: string;
  readonly exchange: ExchangeDiscoveryV2;
  readonly graph_issuance?: GraphIssuanceDiscoveryV1;
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
  assertKeys(root, ['exchange'], ['graph_issuance'], 'discovery');

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

  let graphIssuance: GraphIssuanceDiscoveryV1 | undefined;
  if (root.graph_issuance !== undefined) {
    graphIssuance = parseGraphIssuanceDiscoveryV1(root.graph_issuance);
  }

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
