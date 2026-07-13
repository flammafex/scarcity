import { decode, encode, rfc8949EncodeOptions } from 'cborg';

export type V2ErrorCategory = 'decode-limit' | 'schema';
export class V2CborError extends Error {
  readonly category: V2ErrorCategory;
  constructor(category: V2ErrorCategory) { super(category); this.category = category; }
}

const MAX_UINT64 = (1n << 64n) - 1n;
const asBytes = (value: Uint8Array) => new Uint8Array(value);
const compareKeys = (a: string, b: string) => Buffer.compare(Buffer.from(encode(a, rfc8949EncodeOptions)), Buffer.from(encode(b, rfc8949EncodeOptions)));

/** Encode a V2 value using RFC 8949 deterministic CBOR. */
function validateForEncoding(value: unknown, depth: number, seen: WeakSet<object>): void {
  if (depth > 32) throw new V2CborError('decode-limit');
  if (value === undefined) throw new V2CborError('decode-limit');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') { if (Buffer.byteLength(value) > 4096) throw new V2CborError('decode-limit'); return; }
  if (typeof value === 'number') { if (!Number.isSafeInteger(value)) throw new V2CborError('decode-limit'); return; }
  if (typeof value === 'bigint') { if (value < -MAX_UINT64 || value > MAX_UINT64) throw new V2CborError('decode-limit'); return; }
  if (value instanceof Uint8Array) { if (value.byteLength > 65536) throw new V2CborError('decode-limit'); return; }
  if (typeof value !== 'object') throw new V2CborError('decode-limit');
  if (seen.has(value)) throw new V2CborError('decode-limit');
  seen.add(value);
  if (Array.isArray(value)) { if (value.length > 256) throw new V2CborError('decode-limit'); for (let index = 0; index < value.length; index++) { if (!(index in value)) throw new V2CborError('decode-limit'); validateForEncoding(value[index], depth + 1, seen); } seen.delete(value); return; }
  if (value instanceof Map) {
    if (value.size > 256) throw new V2CborError('decode-limit');
    for (const [key, child] of value) { if (typeof key !== 'string') throw new V2CborError('schema'); validateForEncoding(key, depth + 1, seen); validateForEncoding(child, depth + 1, seen); }
    seen.delete(value); return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new V2CborError('decode-limit');
  const entries = Object.entries(value);
  if (entries.length > 256) throw new V2CborError('decode-limit');
  for (const [key, child] of entries) { validateForEncoding(key, depth + 1, seen); validateForEncoding(child, depth + 1, seen); }
  seen.delete(value);
}

export function encodeCanonical(value: unknown): Uint8Array {
  validateForEncoding(value, 0, new WeakSet<object>());
  const encoded = encode(value, rfc8949EncodeOptions);
  if (encoded.byteLength > 1024 * 1024) throw new V2CborError('decode-limit');
  return encoded;
}

/** Decode a tagless V2 value and require exact deterministic re-encoding. */
export function decodeRestricted(input: Uint8Array): unknown {
  if (input.byteLength > 1024 * 1024) throw new V2CborError('decode-limit');
  let value: unknown;
  try { value = decode(asBytes(input), { strict: true, allowIndefinite: false, allowUndefined: false, allowInfinity: false, allowNaN: false, allowBigInt: true, useMaps: true, rejectDuplicateMapKeys: true }); }
  catch { throw new V2CborError('decode-limit'); }
  const walk = (item: unknown, depth: number): void => {
    if (depth > 32) throw new V2CborError('decode-limit');
    if (item === null || typeof item === 'boolean') return;
    if (typeof item === 'string') { if (Buffer.byteLength(item) > 4096) throw new V2CborError('decode-limit'); return; }
    if (typeof item === 'number') { if (!Number.isSafeInteger(item)) throw new V2CborError('decode-limit'); return; }
    if (typeof item === 'bigint') { if (item < -MAX_UINT64 || item > MAX_UINT64) throw new V2CborError('decode-limit'); return; }
    if (item instanceof Uint8Array) { if (item.byteLength > 65536) throw new V2CborError('decode-limit'); return; }
    if (item instanceof Map) {
      if (item.size > 256) throw new V2CborError('decode-limit');
      let previous: string | undefined;
      for (const [key, child] of item) {
        if (typeof key !== 'string' || (previous !== undefined && compareKeys(previous, key) >= 0)) throw new V2CborError('schema');
        previous = key; walk(child, depth + 1);
      }
      return;
    }
    if (Array.isArray(item)) { if (item.length > 256) throw new V2CborError('decode-limit'); item.forEach((child) => walk(child, depth + 1)); return; }
    throw new V2CborError('decode-limit');
  };
  walk(value, 0);
  if (!Buffer.from(encodeCanonical(value)).equals(Buffer.from(input))) throw new V2CborError('decode-limit');
  return value;
}
