import { EXPECTED } from './vectors.js';
import { decodeRestricted } from './restricted-cbor.js';
import { produceVectors } from './reference-producer.js';

const fields = [...Object.entries(EXPECTED.canonical), ...Object.entries(EXPECTED.negative_canonicality)];
const actual = produceVectors();

for (const [name, value] of fields) {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) throw new Error(`invalid public hex field: ${name}`);
}
for (const [name, value] of Object.entries(EXPECTED.canonical)) {
  decodeRestricted(value);
  if (actual.canonical[name as keyof typeof actual.canonical] !== value) throw new Error(`canonical public value drift: ${name}`);
}
for (const [name, value] of Object.entries(EXPECTED.negative_canonicality)) {
  try { decodeRestricted(value); throw new Error(`negative accepted: ${name}`); }
  catch (error) {
    if ((error as Error).message === `negative accepted: ${name}`) throw error;
    if ((error as Error).message !== EXPECTED.negative_categories[name as keyof typeof EXPECTED.negative_categories]) throw new Error(`negative category drift: ${name}`);
  }
}
console.log(`V2 encoded public-value gate: ${fields.length} fields verified`);
