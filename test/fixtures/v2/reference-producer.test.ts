import { EXPECTED as expected } from './vectors.js';
import { produceVectors } from './reference-producer.js';
import { decodeRestricted } from './restricted-cbor.js';

const actual = produceVectors();
if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('V2 fixture output drifted from frozen vectors');
decodeRestricted(actual.canonical.policy); decodeRestricted(actual.canonical.asset); decodeRestricted(actual.canonical.transaction);
for (const [name, value] of Object.entries(actual.negative_canonicality)) {
  let rejected = false;
  try { decodeRestricted(value); } catch (error) {
    rejected = true;
    if ((error as Error).message !== actual.negative_categories[name as keyof typeof actual.negative_categories]) throw new Error(`wrong category for ${name}`);
  }
  if (!rejected) throw new Error(`negative canonicality case accepted: ${name}`);
}
console.log('V2 public fixture vectors: deterministic and canonical');
