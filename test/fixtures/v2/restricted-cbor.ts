import { decode, encode, rfc8949EncodeOptions } from 'cborg';

/** The tagless fixture boundary exercises protocol uint64 integers only. */
export const MAX_AMOUNT_UINT64 = (1n << 64n) - 1n;
const asBytes = (input: string) => Uint8Array.from(Buffer.from(input, 'hex'));
const keyOrder = (a: string, b: string) => Buffer.compare(Buffer.from(encode(a, rfc8949EncodeOptions)), Buffer.from(encode(b, rfc8949EncodeOptions)));

/** Decode, enforce V2's restricted profile and require byte-identical re-encoding. */
export function decodeRestricted(hex: string): unknown {
  const input = asBytes(hex);
  if (input.byteLength > 1024 * 1024) throw new Error('decode-limit');
  let value: unknown;
  try { value = decode(input, { strict: true, allowIndefinite: false, allowUndefined: false, allowInfinity: false, allowNaN: false, allowBigInt: true, useMaps: true, rejectDuplicateMapKeys: true }); }
  catch { throw new Error('decode-limit'); }
  const walk = (v: unknown, depth: number): void => {
    if (depth > 32) throw new Error('decode-limit');
    if (v === null || typeof v === 'boolean' || typeof v === 'string') {
      if (typeof v === 'string' && Buffer.byteLength(v) > 4096) throw new Error('decode-limit');
      return;
    }
    if (typeof v === 'bigint') { if (v < 0n || v > MAX_AMOUNT_UINT64) throw new Error('decode-limit'); return; }
    if (typeof v === 'number') { if (!Number.isSafeInteger(v)) throw new Error('decode-limit'); return; }
    if (v instanceof Uint8Array) { if (v.byteLength > 65536) throw new Error('decode-limit'); return; }
    if (v instanceof Map) {
      if (v.size > 256) throw new Error('decode-limit');
      let previous: string | undefined;
      for (const [key, child] of v) {
        if (typeof key !== 'string' || (previous !== undefined && keyOrder(previous, key) >= 0)) throw new Error('schema');
        previous = key; walk(child, depth + 1);
      }
      return;
    }
    if (Array.isArray(v)) { if (v.length > 256) throw new Error('decode-limit'); v.forEach((child) => walk(child, depth + 1)); return; }
    throw new Error('decode-limit');
  };
  walk(value, 0);
  if (!Buffer.from(encode(value, rfc8949EncodeOptions)).equals(Buffer.from(input))) throw new Error('decode-limit');
  return value;
}
