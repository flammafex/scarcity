/**
 * Narrow Freebird V5 blind-RSA adapter.
 *
 * All RSA operations are delegated to the pinned Cloudflare implementation.
 * This module never performs RSA arithmetic and never keeps a blinding value
 * beyond the record returned to its caller.
 */

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { sha256 } from '@noble/hashes/sha256';
import {
  buildV5PublicBearerMessage,
  canonicalDescriptorIdV2,
  decodeV5BearerArtifact,
  encodeV5BearerArtifact,
  encodeV5BearerArtifactBase64,
} from './canonical.js';
import {
  BoundaryValidationError,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  parseFreebirdV5Descriptor,
  type CanonicalBase64Url,
  type FreebirdV5DescriptorV2,
  type V5BearerArtifactEnvelope,
} from './types.js';
import { concatBytes } from '@noble/hashes/utils';

export const V5_MESSAGE_BYTES = 48 as const;
export const V5_PSS_SALT_LENGTH = 48 as const;
export const V5_HASH = 'SHA-384' as const;
export const V5_MGF1_HASH = 'SHA-384' as const;

export interface V5BlindPreparationRecord {
  /** TEST-ONLY values may be deterministic in fixtures; production callers must use CSPRNG bytes. */
  readonly nonce: Uint8Array;
  readonly token_key_id: string;
  readonly issuer_id: string;
  readonly message: Uint8Array;
  readonly blinded_value: CanonicalBase64Url;
  /** Opaque RFC 9474 inverse; callers must keep it in their vault record. */
  readonly blinding_state: Uint8Array;
}

function invalid(message: string): never {
  throw new BoundaryValidationError(message);
}

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) invalid('WebCrypto is unavailable');
  return globalThis.crypto;
}

function copy(bytes: Uint8Array): Uint8Array {
  return bytes.slice();
}

function assertBytesEqual(left: Uint8Array, right: Uint8Array, field: string): void {
  if (left.length !== right.length) invalid(`${field}: does not match the prepared value`);
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  if (difference !== 0) invalid(`${field}: does not match the prepared value`);
}

function assertRsaPssKey(key: CryptoKey, descriptor: FreebirdV5DescriptorV2): number {
  if (key.type !== 'public' || key.algorithm.name !== 'RSA-PSS') invalid('key: expected an RSA-PSS public key');
  const algorithm = key.algorithm as RsaPssParams & { modulusLength?: number; hash?: { name: string } };
  if (algorithm.hash?.name !== V5_HASH) invalid('key: hash must be SHA-384');
  if (algorithm.modulusLength === undefined || algorithm.modulusLength < 2048 || algorithm.modulusLength % 8 !== 0) {
    invalid('key: modulus length must be a multiple of 8 and at least 2048 bits');
  }
  return algorithm.modulusLength / 8;
}

function assertDescriptor(descriptor: FreebirdV5DescriptorV2): FreebirdV5DescriptorV2 {
  const parsed = parseFreebirdV5Descriptor(descriptor);
  // The suite name is the Freebird PrepareIdentity variant.  These explicit
  // checks make a future descriptor extension fail closed rather than silently
  // selecting another Cloudflare suite.
  if (parsed.suite !== 'RSABSSA-SHA384-PSS-Deterministic') invalid('descriptor.suite: incompatible suite');
  if (canonicalDescriptorIdV2(parsed) !== parsed.descriptor_id) invalid('descriptor.descriptor_id: non-canonical identity');
  return parsed;
}

/** Import the descriptor's RFC 4055 RSA-PSS SPKI public key. */
export async function importRsaPssSpki(
  descriptor: FreebirdV5DescriptorV2,
): Promise<CryptoKey> {
  const checked = assertDescriptor(descriptor);
  const spki = decodeCanonicalBase64Url(checked.pubkey_spki_b64, undefined, 'descriptor.pubkey_spki_b64');
  try {
    // Chromium and current Node releases reject the RFC 4055
    // id-RSASSA-PSS AlgorithmIdentifier even though the contained RSA public
    // key is valid.  This is the same standards-preserving normalization used
    // by the pinned Freebird JS SDK (sdk/js/src/client.ts:1004-1025): replace
    // only the AlgorithmIdentifier with the rsaEncryption identifier and keep
    // the BIT STRING key bytes unchanged.  No RSA operation is performed here.
    const normalized = normalizeRfc4055PssSpki(spki);
    const key = await importSpki(normalized);
    assertRsaPssKey(key, checked);
    return key;
  } catch (error) {
    if (error instanceof BoundaryValidationError) throw error;
    invalid(`descriptor.pubkey_spki_b64: invalid RFC 4055 RSA-PSS SPKI (${error instanceof Error ? error.message : 'import failed'})`);
  }
}

async function importSpki(spki: Uint8Array): Promise<CryptoKey> {
  return webCrypto().subtle.importKey(
    'spki',
    spki.slice().buffer,
    { name: 'RSA-PSS', hash: V5_HASH },
    true,
    ['verify'],
  );
}

function normalizeRfc4055PssSpki(spki: Uint8Array): Uint8Array {
  // Pinned Freebird's JS consumer uses this fixed DER shape for the PSS
  // AlgorithmIdentifier.  Validate its exact SHA-384/MGF1-SHA384/salt-48
  // parameters before changing only the algorithm wrapper.
  const pssParameters = Uint8Array.of(
    0x30, 0x30,
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0xa2, 0x03, 0x02, 0x01, 0x30,
  );
  const pssOid = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a);
  if (spki.length < 72 || spki.length > 4096 || spki[0] !== 0x30 || spki[4] !== 0x30 || spki[17] !== 0x30) {
    invalid('descriptor.pubkey_spki_b64: malformed RFC 4055 wrapper');
  }
  for (let index = 0; index < pssOid.length; index++) {
    if (spki[index + 6] !== pssOid[index]) invalid('descriptor.pubkey_spki_b64: unsupported SPKI algorithm');
  }
  for (let index = 0; index < pssParameters.length; index++) {
    if (spki[index + 17] !== pssParameters[index]) invalid('descriptor.pubkey_spki_b64: PSS parameters must be SHA-384/MGF1-SHA384/salt-48');
  }
  const rawOffset = spki[5] + 10;
  if (rawOffset >= spki.length) invalid('descriptor.pubkey_spki_b64: malformed RSA bit string');
  const raw = spki.slice(rawOffset);
  const header = Uint8Array.of(
    0x30, 0x82, 0, 0,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    0x03, 0x82, 0, 0,
  );
  const outerLength = raw.length + 19;
  if (outerLength > 0xffff || raw.length > 0xffff) invalid('descriptor.pubkey_spki_b64: RSA SPKI is too large');
  header[2] = (outerLength >>> 8) & 0xff;
  header[3] = outerLength & 0xff;
  header[21] = (raw.length >>> 8) & 0xff;
  header[22] = raw.length & 0xff;
  return concatBytes(header, raw);
}

/** Synchronous descriptor-boundary validation of RFC 4055 suite parameters. */
export function validateRfc4055PssSpki(spki: Uint8Array): void {
  normalizeRfc4055PssSpki(spki);
}

/** Prepare the exact 48-byte Freebird V5 message digest. */
export function prepareV5Message(
  descriptor: FreebirdV5DescriptorV2,
  nonce: Uint8Array,
): Uint8Array {
  const checked = assertDescriptor(descriptor);
  if (nonce.length !== 32) invalid('nonce: expected 32 bytes');
  const keyId = decodeCanonicalLowerHex(checked.token_key_id, 32, 'descriptor.token_key_id');
  const message = buildV5PublicBearerMessage(nonce, keyId, checked.issuer_id);
  if (message.length !== V5_MESSAGE_BYTES) invalid('V5 message: expected SHA-384 output');
  return message;
}

/**
 * Blind a prepared V5 message.  The returned inverse is opaque state and is
 * intentionally owned by the caller-provided preparation record.
 */
export async function blindV5Message(
  descriptor: FreebirdV5DescriptorV2,
  publicKey: CryptoKey,
  nonce: Uint8Array,
): Promise<V5BlindPreparationRecord> {
  const checked = assertDescriptor(descriptor);
  const modulusBytes = assertRsaPssKey(publicKey, checked);
  const message = prepareV5Message(checked, nonce);
  const suite = RSABSSA.SHA384.PSS.Deterministic();
  const prepared = suite.prepare(message);
  assertBytesEqual(prepared, message, 'PrepareIdentity');
  const output = await suite.blind(publicKey, prepared);
  if (output.blindedMsg.length !== modulusBytes || output.inv.length !== modulusBytes) {
    invalid('blind output: unexpected RSA modulus length');
  }
  return {
    nonce: copy(nonce),
    token_key_id: checked.token_key_id,
    issuer_id: checked.issuer_id,
    message: copy(message),
    blinded_value: encodeCanonicalBase64Url(output.blindedMsg),
    blinding_state: copy(output.inv),
  };
}

/** Finalize a Freebird V5 blind signature into a bearer artifact. */
export async function finalizeV5Message(
  descriptor: FreebirdV5DescriptorV2,
  publicKey: CryptoKey,
  preparation: V5BlindPreparationRecord,
  blindSignature: Uint8Array | CanonicalBase64Url,
): Promise<V5BearerArtifactEnvelope> {
  const checked = assertDescriptor(descriptor);
  const modulusBytes = assertRsaPssKey(publicKey, checked);
  const nonce = decodeNonce(preparation.nonce);
  const expectedMessage = prepareV5Message(checked, nonce);
  assertBytesEqual(preparation.message, expectedMessage, 'preparation.message');
  if (preparation.token_key_id !== checked.token_key_id) invalid('preparation.token_key_id: mismatch');
  if (preparation.issuer_id !== checked.issuer_id) invalid('preparation.issuer_id: mismatch');
  const inverse = validateOpaqueState(preparation.blinding_state, modulusBytes, 'preparation.blinding_state');
  const blindSig = typeof blindSignature === 'string'
    ? decodeCanonicalBase64Url(blindSignature, modulusBytes, 'blind_signature')
    : validateOpaqueState(blindSignature, modulusBytes, 'blind_signature');
  const suite = RSABSSA.SHA384.PSS.Deterministic();
  const signature = await suite.finalize(publicKey, expectedMessage, blindSig, inverse);
  if (signature.length !== modulusBytes) invalid('signature: unexpected RSA modulus length');
  return parseArtifact(encodeV5BearerArtifact(nonce, decodeCanonicalLowerHex(checked.token_key_id, 32), checked.issuer_id, signature));
}

/** Verify an already finalized V5 RSA-PSS signature against a preparation. */
export async function verifyV5Signature(
  descriptor: FreebirdV5DescriptorV2,
  publicKey: CryptoKey,
  preparation: Pick<V5BlindPreparationRecord, 'nonce' | 'message' | 'token_key_id' | 'issuer_id'>,
  signature: Uint8Array | CanonicalBase64Url,
): Promise<boolean> {
  const checked = assertDescriptor(descriptor);
  const modulusBytes = assertRsaPssKey(publicKey, checked);
  const nonce = decodeNonce(preparation.nonce);
  const expectedMessage = prepareV5Message(checked, nonce);
  assertBytesEqual(preparation.message, expectedMessage, 'preparation.message');
  if (preparation.token_key_id !== checked.token_key_id || preparation.issuer_id !== checked.issuer_id) return false;
  const signatureBytes = typeof signature === 'string'
    ? decodeCanonicalBase64Url(signature, modulusBytes, 'signature')
    : validateOpaqueState(signature, modulusBytes, 'signature');
  return RSABSSA.SHA384.PSS.Deterministic().verify(publicKey, signatureBytes, expectedMessage);
}

/** Encode a finalized bearer using the canonical Freebird V5 envelope. */
export function encodeFinalizedV5Artifact(
  descriptor: FreebirdV5DescriptorV2,
  preparation: Pick<V5BlindPreparationRecord, 'nonce'>,
  signature: Uint8Array,
): CanonicalBase64Url {
  const checked = assertDescriptor(descriptor);
  const nonce = decodeNonce(preparation.nonce);
  const keyId = decodeCanonicalLowerHex(checked.token_key_id, 32, 'descriptor.token_key_id');
  return encodeV5BearerArtifactBase64(nonce, keyId, checked.issuer_id, signature);
}

function decodeNonce(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) invalid('preparation.nonce: expected 32 bytes');
  return copy(value);
}

function validateOpaqueState(value: Uint8Array, expectedLength: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== expectedLength) invalid(`${field}: unexpected length`);
  return copy(value);
}

function parseArtifact(bytes: Uint8Array): V5BearerArtifactEnvelope {
  // The framing parser is the only parser for the opaque bearer.  Keeping the
  // artifact as bytes/base64 in caller state avoids exposing RSA internals.
  return decodeV5BearerArtifact(bytes);
}

/** Expose the Freebird key-id formula for descriptor/test vector checking. */
export function tokenKeyIdForSpki(spki: Uint8Array): string {
  if (spki.length === 0) invalid('spki: empty');
  return encodeCanonicalLowerHex(sha256(spki));
}
