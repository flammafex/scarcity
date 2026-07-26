/**
 * Phase-1 Witness evidence transport.
 *
 * Witness is deliberately a post-acceptance evidence service in this module.
 * This client has no wallet or bearer references and therefore cannot change a
 * wallet's ownership decision.  The only value sent to Witness is the
 * already-computed receipt-envelope hash.
 */

import { bls12_381 } from '@noble/curves/bls12-381';
import { ed25519 } from '@noble/curves/ed25519';
import {
  BoundaryValidationError,
  CIRCULATION_CLASS,
  assertCanonicalSha256Hex,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  type CanonicalSha256Hex,
} from './types.js';
import {
  assertReceiptWitnessHash,
  buildReceiptHashEnvelope,
  computeReceiptWitnessHash,
} from './canonical.js';

export const WITNESS_NETWORK_PATH = '/v1/network' as const;
export const WITNESS_ATTESTATIONS_PATH = '/v1/attestations' as const;

export type WitnessSignatureAlgorithm = 'Ed25519' | 'BLS12-381';

export interface WitnessNetworkMember {
  readonly id: string;
  readonly algorithm: WitnessSignatureAlgorithm;
  readonly public_key: string;
}

export interface WitnessNetworkConfig {
  readonly id: string;
  readonly threshold: number;
  readonly witnesses: readonly WitnessNetworkMember[];
}

/** Wire-compatible aliases used by callers that name the service types. */
export type NetworkConfig = WitnessNetworkConfig;

export interface WitnessAttestationTuple {
  readonly hash: CanonicalSha256Hex;
  readonly timestamp: number;
  readonly network_id: string;
  readonly sequence: number;
}

export type WitnessMultisignatures = {
  readonly kind: 'multisig';
  readonly signatures: readonly {
    readonly witness_id: string;
    readonly signature: string;
  }[];
};

export type WitnessAggregatedSignature = {
  readonly kind: 'aggregated';
  readonly signature: string;
  readonly signers: readonly string[];
};

export type WitnessSignatureSet = WitnessMultisignatures | WitnessAggregatedSignature;

export interface WitnessSignedAttestation {
  readonly attestation: WitnessAttestationTuple;
  readonly signatures: WitnessSignatureSet;
  readonly contract_version?: 'sophia/v1';
  readonly artifact_type?: 'witness.signed_attestation';
}

export interface WitnessAttestationJobResponse {
  readonly attestation: WitnessAttestationTuple;
  readonly status: 'pending' | 'retryable' | 'confirmed' | 'failed';
  readonly attempts: number;
  readonly signed_attestation?: WitnessSignedAttestation;
  readonly next_attempt_at?: number;
}

/** Alias matching the durable Witness API name. */
export type AttestationJobResponse = WitnessAttestationJobResponse;

export type WitnessErrorCode =
  | 'transport_failure'
  | 'endpoint_rejected'
  | 'invalid_response'
  | 'invalid_config'
  | 'network_mismatch'
  | 'invalid_hash'
  | 'hash_mismatch'
  | 'tuple_mismatch'
  | 'threshold_failure'
  | 'invalid_signature'
  | 'job_failed';

/** Error data intentionally contains no URL, body, hash, or service message. */
export interface RedactedWitnessError {
  readonly code: WitnessErrorCode;
  readonly status?: number;
}

export class WitnessClientError extends Error {
  readonly error: RedactedWitnessError;

  constructor(error: RedactedWitnessError) {
    super(error.code);
    this.name = 'WitnessClientError';
    this.error = { ...error };
  }

  toJSON(): RedactedWitnessError {
    return { ...this.error };
  }
}

export interface WitnessEvidenceClientOptions {
  /** Operator-pinned Witness origin. */
  readonly origin: string;
  /** Operator-pinned expected NetworkConfig.id. */
  readonly expectedNetworkId?: string;
  /** Explicit alias for integrations using the wire/profile spelling. */
  readonly witnessNetworkId?: string;
  readonly fetchImpl?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly maxResponseBytes?: number;
  readonly nowUnixSeconds?: () => number;
}

export type WitnessHashInput =
  | string
  | Uint8Array
  | {
      readonly hash: unknown;
      /** Raw 32-byte receipt digest, used to recompute the envelope hash. */
      readonly receipt_digest?: Uint8Array;
      /** Complete binary receipt envelope, used to recompute the envelope hash. */
      readonly envelope?: Uint8Array;
    };

export interface WitnessSubmissionInput {
  readonly hash: unknown;
  readonly receipt_digest?: Uint8Array;
  readonly envelope?: Uint8Array;
}

interface ParsedWitnessMember extends WitnessNetworkMember {
  readonly keyBytes: Uint8Array;
}

interface ValidatedNetworkConfig extends WitnessNetworkConfig {
  readonly members: readonly ParsedWitnessMember[];
}

interface HttpEnvelope {
  readonly response: Response;
  readonly body: unknown;
}

interface InternalRequestFailure {
  readonly error: RedactedWitnessError;
}

export interface WitnessPendingJob {
  readonly kind: 'pending';
  readonly status: 'pending';
  readonly hash: CanonicalSha256Hex;
  readonly attestation?: WitnessAttestationTuple;
  readonly attempts?: number;
  readonly next_attempt_at?: number;
}

export interface WitnessRetryableJob {
  readonly kind: 'retryable';
  readonly status: 'retryable';
  readonly hash: CanonicalSha256Hex;
  readonly attestation?: WitnessAttestationTuple;
  readonly attempts?: number;
  readonly next_attempt_at?: number;
  readonly error?: RedactedWitnessError;
}

export interface WitnessConfirmedJob {
  readonly kind: 'confirmed';
  readonly status: 'confirmed';
  readonly hash: CanonicalSha256Hex;
  readonly attestation: WitnessAttestationTuple;
  readonly attempts: number;
  readonly signed_attestation: WitnessSignedAttestation;
}

export interface WitnessFailedJob {
  readonly kind: 'failed';
  readonly status: 'failed';
  readonly hash: CanonicalSha256Hex;
  readonly attestation?: WitnessAttestationTuple;
  readonly attempts?: number;
  readonly error: RedactedWitnessError;
}

export interface WitnessMissingJob {
  readonly kind: 'missing';
  readonly status: 'missing';
  readonly hash: CanonicalSha256Hex;
}

export type WitnessJobOutcome =
  | WitnessPendingJob
  | WitnessRetryableJob
  | WitnessConfirmedJob
  | WitnessFailedJob
  | WitnessMissingJob;

function invalid(message: string): never {
  throw new BoundaryValidationError(message);
}

function objectValue(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${field}: expected an object`);
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  field: string,
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) invalid(`${field}.${key}: missing field`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) invalid(`${field}.${key}: unknown field`);
  }
}

function boundedAscii(value: unknown, field: string, max = 128): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || !/^[\x00-\x7f]+$/.test(value)) {
    invalid(`${field}: expected bounded ASCII`);
  }
  return value;
}

function safeInteger(value: unknown, field: string, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) {
    invalid(`${field}: expected a safe integer`);
  }
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

function bytesForKey(value: unknown, expectedBytes: number, field: string): Uint8Array {
  if (typeof value !== 'string') invalid(`${field}: expected an encoded public key`);
  if (/^[0-9a-f]+$/.test(value) && value.length === expectedBytes * 2) {
    return decodeCanonicalLowerHex(value, expectedBytes, field);
  }
  return decodeCanonicalBase64Url(value, expectedBytes, field);
}

function bytesForSignature(value: unknown, expectedBytes: number, field: string): Uint8Array {
  return bytesForKey(value, expectedBytes, field);
}

function normalizeAlgorithm(value: unknown, field: string): WitnessSignatureAlgorithm {
  if (typeof value !== 'string') invalid(`${field}: missing signature algorithm`);
  const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (normalized === 'ed25519') return 'Ed25519';
  if (normalized === 'bls12381' || normalized === 'bls') return 'BLS12-381';
  invalid(`${field}: unsupported signature algorithm`);
}

function parseNetworkConfig(value: unknown): ValidatedNetworkConfig {
  const root = objectValue(value, 'network config');
  exactKeys(root, ['id', 'threshold', 'witnesses'], ['version', 'network_id', 'algorithm', 'signature_scheme'], 'network config');
  const id = boundedAscii(root.id, 'network config.id');
  if (root.network_id !== undefined && root.network_id !== id) invalid('network config.network_id: does not match id');
  const threshold = safeInteger(root.threshold, 'network config.threshold', 1);
  if (!Array.isArray(root.witnesses) || root.witnesses.length === 0 || root.witnesses.length > 256) {
    invalid('network config.witnesses: invalid witness list');
  }
  if (threshold > root.witnesses.length) invalid('network config.threshold: exceeds witness count');

  const defaultAlgorithm = root.algorithm ?? root.signature_scheme;
  const members: ParsedWitnessMember[] = root.witnesses.map((entry, index) => {
    const witness = objectValue(entry, `network config.witnesses[${index}]`);
    exactKeys(
      witness,
      ['id'],
      ['algorithm', 'public_key', 'public_key_b64', 'pubkey', 'pop', 'proof_of_possession'],
      `network config.witnesses[${index}]`,
    );
    const witnessId = boundedAscii(witness.id, `network config.witnesses[${index}].id`);
    const algorithm = normalizeAlgorithm(witness.algorithm ?? defaultAlgorithm, `network config.witnesses[${index}].algorithm`);
    const keyFields = ['public_key', 'public_key_b64', 'pubkey'].filter((field) => witness[field] !== undefined);
    if (keyFields.length !== 1) invalid(`network config.witnesses[${index}]: expected one public key`);
    const keyValue = witness[keyFields[0]];
    const expectedBytes = algorithm === 'Ed25519' ? 32 : 48;
    const keyBytes = bytesForKey(keyValue, expectedBytes, `network config.witnesses[${index}].${keyFields[0]}`);
    try {
      if (algorithm === 'Ed25519') {
        const point = ed25519.Point.fromHex(keyBytes);
        if (point.equals(ed25519.Point.ZERO)) invalid(`network config.witnesses[${index}]: identity public key`);
      } else {
        const point = bls12_381.G1.ProjectivePoint.fromHex(keyBytes);
        if (point.equals(bls12_381.G1.ProjectivePoint.ZERO)) invalid(`network config.witnesses[${index}]: identity public key`);
      }
    } catch {
      invalid(`network config.witnesses[${index}]: invalid public key`);
    }
    if (witness.pop !== undefined || witness.proof_of_possession !== undefined) {
      const pop = witness.pop ?? witness.proof_of_possession;
      bytesForSignature(pop, 96, `network config.witnesses[${index}].proof_of_possession`);
    }
    return { id: witnessId, algorithm, public_key: keyValue as string, keyBytes };
  });
  if (new Set(members.map((member) => member.id)).size !== members.length) invalid('network config.witnesses: duplicate witness ID');
  return { id, threshold, witnesses: members.map(({ id: witnessId, algorithm, public_key }) => ({ id: witnessId, algorithm, public_key })), members };
}

/** Parse and validate the current pinned Witness network metadata. */
export function parseWitnessNetworkConfig(value: unknown): WitnessNetworkConfig {
  const parsed = parseNetworkConfig(value);
  return { id: parsed.id, threshold: parsed.threshold, witnesses: parsed.witnesses };
}

function parseAttestationTuple(value: unknown, field: string): WitnessAttestationTuple {
  const object = objectValue(value, field);
  exactKeys(object, ['hash', 'timestamp', 'network_id', 'sequence'], [], field);
  const hash = assertCanonicalSha256Hex(object.hash, `${field}.hash`);
  const timestamp = safeInteger(object.timestamp, `${field}.timestamp`);
  const networkId = boundedAscii(object.network_id, `${field}.network_id`);
  const sequence = safeInteger(object.sequence, `${field}.sequence`);
  return { hash, timestamp, network_id: networkId, sequence };
}

function parseSignatureSet(value: unknown, field: string): WitnessSignatureSet {
  if (Array.isArray(value)) {
    const signatures = value.map((entry, index) => {
      const signature = objectValue(entry, `${field}.signatures[${index}]`);
      exactKeys(signature, ['witness_id', 'signature'], [], `${field}.signatures[${index}]`);
      return {
        witness_id: boundedAscii(signature.witness_id, `${field}.signatures[${index}].witness_id`),
        signature: signature.signature as string,
      };
    });
    if (signatures.length === 0) invalid(`${field}: empty signature set`);
    return { kind: 'multisig', signatures };
  }

  const object = objectValue(value, field);
  if (object.kind === 'multisig') {
    exactKeys(object, ['kind', 'signatures'], [], field);
    if (!Array.isArray(object.signatures) || object.signatures.length === 0) invalid(`${field}.signatures: empty signature set`);
    const signatures = object.signatures.map((entry, index) => {
      const signature = objectValue(entry, `${field}.signatures[${index}]`);
      exactKeys(signature, ['witness_id', 'signature'], [], `${field}.signatures[${index}]`);
      return {
        witness_id: boundedAscii(signature.witness_id, `${field}.signatures[${index}].witness_id`),
        signature: signature.signature as string,
      };
    });
    return { kind: 'multisig', signatures };
  }
  if (object.kind === 'aggregated') {
    exactKeys(object, ['kind', 'signature', 'signers'], [], field);
    if (!Array.isArray(object.signers) || object.signers.length === 0) invalid(`${field}.signers: empty signer set`);
    return {
      kind: 'aggregated',
      signature: object.signature as string,
      signers: object.signers.map((signer, index) => boundedAscii(signer, `${field}.signers[${index}]`)),
    };
  }
  invalid(`${field}: unsupported signature set`);
}

function parseSignedAttestation(value: unknown): WitnessSignedAttestation {
  const object = objectValue(value, 'signed_attestation');
  exactKeys(object, ['attestation', 'signatures'], ['contract_version', 'artifact_type'], 'signed_attestation');
  if (object.contract_version !== undefined && object.contract_version !== 'sophia/v1') invalid('signed_attestation.contract_version: unsupported value');
  if (object.artifact_type !== undefined && object.artifact_type !== 'witness.signed_attestation') invalid('signed_attestation.artifact_type: unsupported value');
  const attestation = parseAttestationTuple(object.attestation, 'signed_attestation.attestation');
  const signatures = parseSignatureSet(object.signatures, 'signed_attestation.signatures');
  return {
    attestation,
    signatures,
    ...(object.contract_version === undefined ? {} : { contract_version: 'sophia/v1' as const }),
    ...(object.artifact_type === undefined ? {} : { artifact_type: 'witness.signed_attestation' as const }),
  };
}

/** Parse the strict durable AttestationJobResponse envelope. */
export function parseWitnessAttestationJobResponse(value: unknown): WitnessAttestationJobResponse {
  const object = objectValue(value, 'attestation job');
  exactKeys(object, ['attestation', 'status', 'attempts'], ['signed_attestation', 'next_attempt_at', 'last_error'], 'attestation job');
  const attestation = parseAttestationTuple(object.attestation, 'attestation job.attestation');
  if (object.status !== 'pending' && object.status !== 'retryable' && object.status !== 'confirmed' && object.status !== 'failed') {
    invalid('attestation job.status: unsupported status');
  }
  const attempts = safeInteger(object.attempts, 'attestation job.attempts');
  const nextAttemptAt = object.next_attempt_at === undefined ? undefined : safeInteger(object.next_attempt_at, 'attestation job.next_attempt_at');
  if (object.last_error !== undefined && (typeof object.last_error !== 'string' || object.last_error.length > 1024)) {
    invalid('attestation job.last_error: invalid error');
  }
  let signedAttestation: WitnessSignedAttestation | undefined;
  if (object.signed_attestation !== undefined) signedAttestation = parseSignedAttestation(object.signed_attestation);
  if (object.status === 'confirmed' && signedAttestation === undefined) invalid('attestation job: confirmed job has no signed attestation');
  if (object.status === 'failed' && signedAttestation !== undefined) invalid('attestation job: failed job has signed attestation');
  return {
    attestation,
    status: object.status,
    attempts,
    ...(signedAttestation === undefined ? {} : { signed_attestation: signedAttestation }),
    ...(nextAttemptAt === undefined ? {} : { next_attempt_at: nextAttemptAt }),
  } as WitnessAttestationJobResponse;
}

function sameTuple(left: WitnessAttestationTuple, right: WitnessAttestationTuple): boolean {
  return left.hash === right.hash
    && left.timestamp === right.timestamp
    && left.network_id === right.network_id
    && left.sequence === right.sequence;
}

function u64le(value: number, field: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) invalid(`${field}: unsupported integer`);
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
}

/**
 * Canonical Witness signing bytes.  This is the pinned Witness tuple framing:
 * hash bytes || timestamp LE u64 || network ID UTF-8 bytes || sequence LE u64.
 */
export function canonicalWitnessAttestationBytes(tuple: WitnessAttestationTuple): Uint8Array {
  const hash = decodeCanonicalLowerHex(tuple.hash, 32, 'attestation.hash');
  const network = new TextEncoder().encode(boundedAscii(tuple.network_id, 'attestation.network_id'));
  return Uint8Array.from([
    ...hash,
    ...u64le(tuple.timestamp, 'attestation.timestamp'),
    ...network,
    ...u64le(tuple.sequence, 'attestation.sequence'),
  ]);
}

function sameOrigin(value: string, field: string): URL {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) invalid(`${field}: invalid URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    invalid(`${field}: invalid URL`);
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname.toLowerCase());
  if (url.username !== '' || url.password !== '') invalid(`${field}: credentials are forbidden`);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) invalid(`${field}: HTTPS is required except for loopback HTTP`);
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') invalid(`${field}: path, query, and fragment are forbidden`);
  return url;
}

/** Normalize and validate an operator-pinned Witness origin. */
export function assertPinnedWitnessOrigin(value: string): string {
  return sameOrigin(value, 'origin').origin;
}

/** Resolve a Witness URL while retaining the operator origin pin. */
export function assertPinnedWitnessUrl(value: string | URL, origin: string, field = 'url'): URL {
  const pinned = assertPinnedWitnessOrigin(origin);
  let url: URL;
  try {
    url = value instanceof URL ? new URL(value.href) : new URL(value, `${pinned}/`);
  } catch {
    invalid(`${field}: invalid URL`);
  }
  if (url.username !== '' || url.password !== '') invalid(`${field}: credentials are forbidden`);
  if (url.origin !== pinned) invalid(`${field}: cross-origin URL`);
  return url;
}

function responseContentType(response: Response): boolean {
  const contentType = response.headers.get('content-type');
  return contentType !== null && contentType.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

function hasNoStore(response: Response): boolean {
  const header = response.headers.get('cache-control');
  if (header === null || header.trim() === '') return false;
  const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
  let found = false;
  for (const rawDirective of header.split(',')) {
    const directive = rawDirective.trim();
    if (directive === '') return false;
    const equals = directive.indexOf('=');
    const name = (equals < 0 ? directive : directive.slice(0, equals)).trim();
    if (!token.test(name)) return false;
    if (equals >= 0) {
      const value = directive.slice(equals + 1).trim();
      if (value === '' || (!token.test(value) && !/^"(?:[^"\\]|\\.)*"$/.test(value))) return false;
    }
    if (equals < 0 && name.toLowerCase() === 'no-store') found = true;
  }
  return found;
}

function safeError(code: WitnessErrorCode, status?: number): RedactedWitnessError {
  return { code, ...(status === undefined ? {} : { status }) };
}

function isRetriableTransport(error: RedactedWitnessError): boolean {
  return error.code === 'transport_failure' || error.code === 'endpoint_rejected' || (error.status !== undefined && error.status >= 500);
}

function signatureBytes(value: string, expectedBytes: number, field: string): Uint8Array {
  try {
    return bytesForSignature(value, expectedBytes, field);
  } catch {
    return new Uint8Array();
  }
}

function verifyThresholdSignature(
  tuple: WitnessAttestationTuple,
  signed: WitnessSignedAttestation,
  config: ValidatedNetworkConfig,
): WitnessErrorCode | undefined {
  if (!sameTuple(tuple, signed.attestation)) return 'tuple_mismatch';
  const memberById = new Map(config.members.map((member) => [member.id, member]));
  const message = canonicalWitnessAttestationBytes(tuple);

  if (signed.signatures.kind === 'multisig') {
    if (signed.signatures.signatures.length < config.threshold) return 'threshold_failure';
    const seen = new Set<string>();
    for (const entry of signed.signatures.signatures) {
      if (seen.has(entry.witness_id)) return 'threshold_failure';
      seen.add(entry.witness_id);
      const member = memberById.get(entry.witness_id);
      if (member === undefined || member.algorithm !== 'Ed25519') return 'invalid_signature';
      const signature = signatureBytes(entry.signature, 64, 'ed25519.signature');
      if (signature.length !== 64) return 'invalid_signature';
      try {
        if (!ed25519.verify(signature, message, member.keyBytes)) return 'invalid_signature';
      } catch {
        return 'invalid_signature';
      }
    }
    return undefined;
  }

  if (signed.signatures.signers.length < config.threshold) return 'threshold_failure';
  const seen = new Set<string>();
  let aggregate = bls12_381.G1.ProjectivePoint.ZERO;
  for (const signerId of signed.signatures.signers) {
    if (seen.has(signerId)) return 'threshold_failure';
    seen.add(signerId);
    const member = memberById.get(signerId);
    if (member === undefined || member.algorithm !== 'BLS12-381') return 'invalid_signature';
    try {
      const point = bls12_381.G1.ProjectivePoint.fromHex(member.keyBytes);
      if (point.equals(bls12_381.G1.ProjectivePoint.ZERO)) return 'invalid_signature';
      aggregate = aggregate.add(point);
    } catch {
      return 'invalid_signature';
    }
  }
  const signature = signatureBytes(signed.signatures.signature, 96, 'bls.signature');
  if (signature.length !== 96) return 'invalid_signature';
  try {
    if (aggregate.equals(bls12_381.G1.ProjectivePoint.ZERO)) return 'invalid_signature';
    return bls12_381.verify(signature, message, aggregate.toRawBytes()) ? undefined : 'invalid_signature';
  } catch {
    return 'invalid_signature';
  }
}

function normalizeHashInput(input: WitnessHashInput, second?: Uint8Array): CanonicalSha256Hex {
  if (input instanceof Uint8Array) {
    if (input.length !== 32) invalid('receipt_digest: expected 32 bytes');
    buildReceiptHashEnvelope(CIRCULATION_CLASS, input);
    return computeReceiptWitnessHash(CIRCULATION_CLASS, input);
  }
  let value: unknown = input;
  let envelope: Uint8Array | undefined = second;
  if (typeof input === 'object' && input !== null) {
    const object = input as Record<string, unknown>;
    const keys = Object.keys(object);
    if (keys.some((key) => key !== 'hash' && key !== 'receipt_digest' && key !== 'envelope')) invalid('witness submission: unknown field');
    if (!Object.prototype.hasOwnProperty.call(object, 'hash')) invalid('witness submission.hash: missing field');
    value = object.hash;
    const receiptDigest = object.receipt_digest;
    const suppliedEnvelope = object.envelope;
    if (receiptDigest !== undefined && suppliedEnvelope !== undefined) invalid('witness submission: provide one receipt binding');
    if (receiptDigest !== undefined) {
      if (!(receiptDigest instanceof Uint8Array) || receiptDigest.length !== 32) invalid('witness submission.receipt_digest: expected 32 bytes');
      envelope = buildReceiptHashEnvelope(CIRCULATION_CLASS, receiptDigest);
    }
    if (suppliedEnvelope !== undefined) {
      if (!(suppliedEnvelope instanceof Uint8Array)) invalid('witness submission.envelope: expected bytes');
      envelope = suppliedEnvelope;
    }
  }
  const hash = assertCanonicalSha256Hex(value, 'witness submission.hash');
  if (envelope !== undefined) {
    const classBytes = new TextEncoder().encode(CIRCULATION_CLASS);
    if (envelope.length !== 4 + classBytes.length + 32) invalid('witness submission.envelope: invalid length');
    const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
    if (view.getUint32(0, false) !== classBytes.length || !bytesEqual(envelope.slice(4, 4 + classBytes.length), classBytes)) {
      invalid('witness submission.envelope: invalid class framing');
    }
    return assertReceiptWitnessHash(hash, envelope, 'witness submission.hash');
  }
  return hash;
}

function noAttestation(hash: CanonicalSha256Hex, error: RedactedWitnessError): WitnessFailedJob {
  return { kind: 'failed', status: 'failed', hash, error };
}

/**
 * Asynchronous Phase-1 Witness client.  It exposes only POST/GET durable job
 * operations and local signature verification; it has no acceptance callback.
 */
export class WitnessEvidenceClient {
  readonly origin: string;
  readonly expectedNetworkId: string;
  private readonly fetchImpl: typeof fetch;
  private readonly signal?: AbortSignal;
  private readonly maxResponseBytes: number;
  private readonly nowUnixSeconds: () => number;
  private network?: ValidatedNetworkConfig;
  private readonly tuples = new Map<string, WitnessAttestationTuple>();
  private readonly nextAttemptAt = new Map<string, number>();

  constructor(options: WitnessEvidenceClientOptions) {
    this.origin = assertPinnedWitnessOrigin(options.origin);
    const expectedNetworkId = options.expectedNetworkId ?? options.witnessNetworkId;
    this.expectedNetworkId = boundedAscii(expectedNetworkId, 'expectedNetworkId');
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') invalid('witness client: fetch is unavailable');
    this.signal = options.signal;
    this.maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes < 1) invalid('witness client: invalid response limit');
    this.nowUnixSeconds = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));
  }

  private endpoint(path: string): URL {
    return assertPinnedWitnessUrl(new URL(path, `${this.origin}/`), this.origin, 'witness endpoint');
  }

  private async request(path: string, method: 'GET' | 'POST', body?: unknown): Promise<HttpEnvelope | InternalRequestFailure> {
    const url = this.endpoint(path);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers: {
          accept: 'application/json',
          ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
        },
        ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
        redirect: 'manual',
        signal: this.signal,
      });
    } catch {
      return { error: safeError('transport_failure') };
    }
    try {
      if (response.url !== '') assertPinnedWitnessUrl(response.url, this.origin, 'witness response URL');
      if (response.redirected || (response.status >= 300 && response.status < 400) || response.headers.get('location') !== null) {
        return { error: safeError('endpoint_rejected', response.status) };
      }
    } catch {
      return { error: safeError('endpoint_rejected', response.status) };
    }
    if (response.status >= 200 && response.status < 300 && !hasNoStore(response)) {
      return { error: safeError('invalid_response', response.status) };
    }

    let text: string;
    try {
      text = await response.text();
    } catch {
      return { error: safeError('invalid_response', response.status) };
    }
    if (new TextEncoder().encode(text).length > this.maxResponseBytes) return { error: safeError('invalid_response', response.status) };
    if (text.length === 0) return { response, body: undefined };
    if (!responseContentType(response)) return { error: safeError('invalid_response', response.status) };
    try {
      return { response, body: JSON.parse(text) as unknown };
    } catch {
      return { error: safeError('invalid_response', response.status) };
    }
  }

  /** Fetch and validate the complete current network configuration. */
  async fetchNetworkConfig(forceRefresh = false): Promise<WitnessNetworkConfig> {
    if (!forceRefresh && this.network !== undefined) {
      return { id: this.network.id, threshold: this.network.threshold, witnesses: this.network.witnesses };
    }
    const result = await this.request(WITNESS_NETWORK_PATH, 'GET');
    if ('error' in result) throw new WitnessClientError(result.error);
    if (result.response.status !== 200) throw new WitnessClientError(safeError('endpoint_rejected', result.response.status));
    let config: ValidatedNetworkConfig;
    try {
      config = parseNetworkConfig(result.body);
    } catch {
      throw new WitnessClientError(safeError('invalid_config', result.response.status));
    }
    if (config.id !== this.expectedNetworkId) throw new WitnessClientError(safeError('network_mismatch'));
    this.network = config;
    return { id: config.id, threshold: config.threshold, witnesses: config.witnesses };
  }

  private async pinnedConfig(): Promise<ValidatedNetworkConfig> {
    if (this.network !== undefined) return this.network;
    await this.fetchNetworkConfig();
    return this.network!;
  }

  private rememberTuple(hash: CanonicalSha256Hex, tuple: WitnessAttestationTuple): RedactedWitnessError | undefined {
    const prior = this.tuples.get(hash);
    if (prior !== undefined && !sameTuple(prior, tuple)) return safeError('tuple_mismatch');
    this.tuples.set(hash, tuple);
    return undefined;
  }

  private outcomeForJob(hash: CanonicalSha256Hex, job: WitnessAttestationJobResponse, config: ValidatedNetworkConfig): WitnessJobOutcome {
    if (job.attestation.hash !== hash) return noAttestation(hash, safeError('hash_mismatch'));
    if (job.attestation.network_id !== config.id || job.attestation.network_id !== this.expectedNetworkId) {
      return { kind: 'failed', status: 'failed', hash, attestation: job.attestation, attempts: job.attempts, error: safeError('network_mismatch') };
    }
    const tupleError = this.rememberTuple(hash, job.attestation);
    if (tupleError !== undefined) return { kind: 'failed', status: 'failed', hash, attestation: job.attestation, attempts: job.attempts, error: tupleError };
    if (job.next_attempt_at !== undefined) this.nextAttemptAt.set(hash, job.next_attempt_at);
    if (job.status === 'pending') return { kind: 'pending', status: 'pending', hash, attestation: job.attestation, attempts: job.attempts, ...(job.next_attempt_at === undefined ? {} : { next_attempt_at: job.next_attempt_at }) };
    if (job.status === 'retryable') return { kind: 'retryable', status: 'retryable', hash, attestation: job.attestation, attempts: job.attempts, ...(job.next_attempt_at === undefined ? {} : { next_attempt_at: job.next_attempt_at }) };
    if (job.status === 'failed') return { kind: 'failed', status: 'failed', hash, attestation: job.attestation, attempts: job.attempts, error: safeError('job_failed') };
    const signed = job.signed_attestation;
    if (signed === undefined) return { kind: 'failed', status: 'failed', hash, attestation: job.attestation, attempts: job.attempts, error: safeError('invalid_response') };
    if (signed.attestation.hash !== hash) return { kind: 'failed', status: 'failed', hash, attestation: job.attestation, attempts: job.attempts, error: safeError('hash_mismatch') };
    const signatureError = verifyThresholdSignature(job.attestation, signed, config);
    if (signatureError !== undefined) return { kind: 'failed', status: 'failed', hash, attestation: job.attestation, attempts: job.attempts, error: safeError(signatureError) };
    return { kind: 'confirmed', status: 'confirmed', hash, attestation: job.attestation, attempts: job.attempts, signed_attestation: signed };
  }

  private async postHash(hash: CanonicalSha256Hex, config: ValidatedNetworkConfig): Promise<WitnessJobOutcome> {
    const result = await this.request(WITNESS_ATTESTATIONS_PATH, 'POST', { hash });
    if ('error' in result) {
      return isRetriableTransport(result.error)
        ? { kind: 'retryable', status: 'retryable', hash, error: result.error }
        : noAttestation(hash, result.error);
    }
    if (result.response.status >= 500) return { kind: 'retryable', status: 'retryable', hash, error: safeError('endpoint_rejected', result.response.status) };
    if (result.response.status !== 200 && result.response.status !== 202) return noAttestation(hash, safeError('endpoint_rejected', result.response.status));
    if (result.body === undefined) return noAttestation(hash, safeError('invalid_response', result.response.status));
    let job: WitnessAttestationJobResponse;
    try {
      job = parseWitnessAttestationJobResponse(result.body);
    } catch {
      return noAttestation(hash, safeError('invalid_response', result.response.status));
    }
    if (result.response.status === 202 && job.status !== 'pending' && job.status !== 'retryable') return noAttestation(hash, safeError('invalid_response', result.response.status));
    return this.outcomeForJob(hash, job, config);
  }

  /** Submit only a canonical receipt-envelope hash to Witness. */
  async submit(input: WitnessHashInput, expectedEnvelope?: Uint8Array): Promise<WitnessJobOutcome> {
    const hash = normalizeHashInput(input, expectedEnvelope);
    let config: ValidatedNetworkConfig;
    try {
      config = await this.pinnedConfig();
    } catch (error) {
      if (error instanceof WitnessClientError && (error.error.code === 'invalid_config' || error.error.code === 'network_mismatch')) {
        return noAttestation(hash, error.error);
      }
      const redacted = error instanceof WitnessClientError ? error.error : safeError('transport_failure');
      return { kind: 'retryable', status: 'retryable', hash, error: redacted };
    }
    return this.postHash(hash, config);
  }

  /** Submit a raw 32-byte receipt digest after constructing the frozen envelope hash. */
  submitReceiptDigest(receiptDigest: Uint8Array): Promise<WitnessJobOutcome> {
    return this.submit(receiptDigest);
  }

  /** Submit a hash while proving it is the hash of the supplied envelope. */
  submitReceiptEnvelope(hash: unknown, envelope: Uint8Array): Promise<WitnessJobOutcome> {
    return this.submit({ hash, envelope });
  }

  /** Explicit POST alias; it never posts to any legacy timestamp endpoint. */
  postAttestation(input: WitnessHashInput, expectedEnvelope?: Uint8Array): Promise<WitnessJobOutcome> {
    return this.submit(input, expectedEnvelope);
  }

  /** Poll a durable job, respecting a server-provided next_attempt_at. */
  async poll(input: WitnessHashInput): Promise<WitnessJobOutcome> {
    const hash = normalizeHashInput(input);
    const next = this.nextAttemptAt.get(hash);
    const now = this.nowUnixSeconds();
    if (next !== undefined && Number.isSafeInteger(now) && now < next) {
      return { kind: 'retryable', status: 'retryable', hash, next_attempt_at: next };
    }
    let config: ValidatedNetworkConfig;
    try {
      config = await this.pinnedConfig();
    } catch (error) {
      if (error instanceof WitnessClientError && (error.error.code === 'invalid_config' || error.error.code === 'network_mismatch')) return noAttestation(hash, error.error);
      const redacted = error instanceof WitnessClientError ? error.error : safeError('transport_failure');
      return { kind: 'retryable', status: 'retryable', hash, error: redacted };
    }
    const result = await this.request(`${WITNESS_ATTESTATIONS_PATH}/${hash}`, 'GET');
    if ('error' in result) {
      return isRetriableTransport(result.error)
        ? { kind: 'retryable', status: 'retryable', hash, error: result.error }
        : noAttestation(hash, result.error);
    }
    if (result.response.status === 404) return { kind: 'missing', status: 'missing', hash };
    if (result.response.status >= 500) return { kind: 'retryable', status: 'retryable', hash, error: safeError('endpoint_rejected', result.response.status) };
    if (result.response.status !== 200 || result.body === undefined) return noAttestation(hash, safeError('invalid_response', result.response.status));
    let job: WitnessAttestationJobResponse;
    try {
      job = parseWitnessAttestationJobResponse(result.body);
    } catch {
      return noAttestation(hash, safeError('invalid_response', result.response.status));
    }
    return this.outcomeForJob(hash, job, config);
  }

  /** GET alias for durable attestation jobs. */
  getAttestation(input: WitnessHashInput): Promise<WitnessJobOutcome> {
    return this.poll(input);
  }

  /** Re-submit the identical hash after a GET 404 or retryable result. */
  retry(input: WitnessHashInput, expectedEnvelope?: Uint8Array): Promise<WitnessJobOutcome> {
    return this.submit(input, expectedEnvelope);
  }
}

export const AsyncWitnessEvidenceClient = WitnessEvidenceClient;
export const createWitnessEvidenceClient = (options: WitnessEvidenceClientOptions): WitnessEvidenceClient => new WitnessEvidenceClient(options);
