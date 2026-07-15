import { CborError, decodeRestricted, encodeCanonical } from '../../src/codec/canonical-cbor.js';

const expectRejected = (value: unknown, category: CborError['category']) => {
  try {
    encodeCanonical(value);
    throw new Error('value was accepted');
  } catch (error) {
    if (!(error instanceof CborError) || error.category !== category) throw error;
  }
};

const encoded = encodeCanonical({ z: 1, a: ['stable', new Uint8Array([1, 2, 3])] });
if (!(decodeRestricted(encoded) instanceof Map)) throw new Error('decoded maps must be preserved');
if (!Buffer.from(encodeCanonical(decodeRestricted(encoded))).equals(Buffer.from(encoded))) throw new Error('round trip changed bytes');
expectRejected(1.5, 'decode-limit');
expectRejected(undefined, 'decode-limit');
expectRejected(new Map([[1, 0]]), 'schema');
expectRejected('x'.repeat(4097), 'decode-limit');

console.log('Canonical CBOR primitive tests: passed');
