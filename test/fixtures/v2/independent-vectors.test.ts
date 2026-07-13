import { createHash } from 'node:crypto';
import { encode, rfc8949EncodeOptions } from 'cborg';
import { EXPECTED } from './vectors.js';
import { decodeRestricted, MAX_AMOUNT_UINT64 } from './restricted-cbor.js';

const b = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));
const h = (label: string, payload: Uint8Array) => new Uint8Array(createHash('sha256').update(Buffer.concat([Buffer.from(`scarcity/v2/${label}\0`), Buffer.from(payload)])).digest());
const c = (value: unknown) => encode(value, rfc8949EncodeOptions);
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');
const repeated = (byte: number) => new Uint8Array(32).fill(byte);
const policy = { epoch_seconds: 3600, max_lifetime_epochs: 24, boundary: 'exclusive' };
const policyDigest = h('asset-policy', c(policy));
const asset = { issuer: repeated(0x11), asset_code: 'FIX', unit: 'unit', decimals: 2, policy_digest: policyDigest, expiry_policy: policy };
const assetId = h('asset', c(asset));
const domain = b(EXPECTED.proofs.input.spend_domain);
const inputSource = { transaction_id: b(EXPECTED.proofs.input.source_transaction_id), output_index: EXPECTED.proofs.input.source_output_index, output_commitment: b(EXPECTED.proofs.input.source_output_commitment) };
const inputOutputId = h('output', c(inputSource));
const inputNullifier = h('nullifier', c({ spend_domain: domain, output_id: inputOutputId }));
const inputs = [{ output_id: inputOutputId, nullifier: inputNullifier, owner_key_id: repeated(0x66) }];
const outputs = EXPECTED.proofs.outputs.map((proof) => {
  const output = { asset_id: b(proof.asset_id), amount: proof.amount, recipient_key: b(proof.recipient_key), spend_domain: b(proof.spend_domain), provenance: proof.provenance };
  const output_commitment = h('output-commitment', c(output));
  if (hex(output.asset_id) !== EXPECTED.digests.asset_id || output.amount <= 0 || hex(output.spend_domain) !== hex(domain)) throw new Error('frozen output proof semantics failed');
  if (output.provenance.kind !== 'transition' || output.recipient_key.byteLength !== 32) throw new Error('transition provenance or recipient shape failed');
  if (hex(output_commitment) !== proof.output_commitment) throw new Error('frozen output commitment failed');
  return { ...output, output_commitment };
});
const transaction = { spend_domain: domain, inputs, outputs };
const transactionId = h('transaction', c(transaction));

if (MAX_AMOUNT_UINT64 !== 18446744073709551615n) throw new Error('uint64 amount limit is incorrect');
if (outputs.some((output) => BigInt(output.amount) <= 0n || BigInt(output.amount) > MAX_AMOUNT_UINT64)) throw new Error('amount limit equation failed');

if (hex(policyDigest) !== EXPECTED.digests.policy) throw new Error('policy digest equation failed');
if (hex(assetId) !== EXPECTED.digests.asset_id) throw new Error('asset identity equation failed');
if (hex(transactionId) !== EXPECTED.digests.transaction_id) throw new Error('transaction projection failed');
if (hex(c(transaction)) !== EXPECTED.canonical.transaction) throw new Error('transaction bytes are not independently reproducible');
if (hex(inputNullifier) !== EXPECTED.proofs.input.nullifier) throw new Error('input nullifier equation failed');
if (EXPECTED.proofs.input.output_id !== hex(inputOutputId) || EXPECTED.proofs.input.asset_id !== EXPECTED.digests.asset_id) throw new Error('input proof identity failed');
if (outputs.reduce((sum, output) => sum + output.amount, 0) !== EXPECTED.proofs.input.amount) throw new Error('conservation equation failed');
outputs.forEach((output, i) => {
  if (EXPECTED.proofs.outputs[i].output_index !== i || EXPECTED.outputs[i].output_index !== i) throw new Error('output index equation failed');
  if (EXPECTED.outputs[i].output_commitment !== EXPECTED.proofs.outputs[i].output_commitment || EXPECTED.outputs[i].output_id !== EXPECTED.proofs.outputs[i].output_id) throw new Error('expected/proof output cross-check failed');
  if (hex(output.output_commitment) !== EXPECTED.proofs.outputs[i].output_commitment) throw new Error('output commitment equation failed');
  const outputId = h('output', c({ transaction_id: transactionId, output_index: i, output_commitment: output.output_commitment }));
  if (hex(outputId) !== EXPECTED.proofs.outputs[i].output_id) throw new Error('output id equation failed');
  if (hex(h('nullifier', c({ spend_domain: domain, output_id: outputId }))) !== EXPECTED.outputs[i].nullifier) throw new Error('nullifier equation failed');
});

const ids = EXPECTED.outputs.map((output) => b(output.output_id));
const leaf = (id: Uint8Array, index: number) => h('output-leaf', c({ output_index: index, output_id: id }));
const node = (left: Uint8Array, right: Uint8Array) => h('output-node', Buffer.concat([Buffer.from(left), Buffer.from(right)]));
const leaves = ids.map(leaf);
if (hex(h('output-empty', new Uint8Array())) !== EXPECTED.merkle['0'].root) throw new Error('empty Merkle root failed');
if (hex(leaves[0]) !== EXPECTED.merkle['1'].root) throw new Error('single Merkle root failed');
const oddRoot = node(node(leaves[0], leaves[1]), node(leaves[2], leaves[2]));
if (hex(oddRoot) !== EXPECTED.merkle['3'].root) throw new Error('odd Merkle root failed');
EXPECTED.outputs.forEach((output, i) => {
  if (EXPECTED.merkle['3'].proofs[i].leaf_index !== output.output_index) throw new Error('proof leaf index equation failed');
  if (EXPECTED.merkle['3'].proofs[i].siblings.length !== 2) throw new Error('proof height equation failed');
  let current = leaves[i]; let index = i;
  for (const siblingHex of EXPECTED.merkle['3'].proofs[i].siblings) { const sibling = b(siblingHex); current = index % 2 === 0 ? node(current, sibling) : node(sibling, current); index = Math.floor(index / 2); }
  if (hex(current) !== EXPECTED.merkle['3'].root) throw new Error('Merkle proof failed');
});
decodeRestricted(EXPECTED.canonical.policy); decodeRestricted(EXPECTED.canonical.asset); decodeRestricted(EXPECTED.canonical.transaction);
if (decodeRestricted(EXPECTED.limits.max_uint64) !== MAX_AMOUNT_UINT64) throw new Error('canonical max uint64 vector failed');
console.log('V2 independent frozen-vector equations: passed');
