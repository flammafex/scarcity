/** Public-only V2 reference producer. It is not a runtime protocol module. */
import { createHash } from 'node:crypto';
import { encode, rfc8949EncodeOptions } from 'cborg';

export const PUBLIC_INPUTS = {
  policy: { epoch_seconds: 3600, max_lifetime_epochs: 24, boundary: 'exclusive' },
  asset: { issuer: new Uint8Array(32).fill(0x11), asset_code: 'FIX', unit: 'unit', decimals: 2,
    expiry_policy: { epoch_seconds: 3600, max_lifetime_epochs: 24, boundary: 'exclusive' } },
  transaction: { spend_domain: new Uint8Array(32).fill(0x33),
    inputs: [{ owner_key_id: new Uint8Array(32).fill(0x66) }] },
} as const;

const hex = (v: Uint8Array) => Buffer.from(v).toString('hex');
const sha256 = (v: Uint8Array) => new Uint8Array(createHash('sha256').update(v).digest());
const join = (...vs: Uint8Array[]) => Uint8Array.from(vs.flatMap((v) => [...v]));
const cbor = (v: unknown) => encode(v, rfc8949EncodeOptions);
export const digest = (label: string, bytes: Uint8Array) => sha256(join(new TextEncoder().encode(`scarcity/v2/${label}\0`), bytes));

function tree(ids: Uint8Array[]) {
  const leaves = ids.map((output_id, output_index) => digest('output-leaf', cbor({ output_index, output_id })));
  const proofs = leaves.map((_, leaf_index) => ({ leaf_index, siblings: [] as Uint8Array[] }));
  let level: Uint8Array[] = leaves as Uint8Array[]; let positions = leaves.map((_, i) => i);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(digest('output-node', join(level[i], level[i + 1] ?? level[i])));
    positions.forEach((position, i) => { proofs[i].siblings.push(level[position % 2 ? position - 1 : position + 1] ?? level[position]); positions[i] = Math.floor(position / 2); });
    level = next;
  }
  return { root: level[0] ?? digest('output-empty', new Uint8Array()), proofs };
}

export function produceVectors() {
  const policy = { ...PUBLIC_INPUTS.policy };
  const policyBytes = cbor(policy);
  const policyDigest = digest('asset-policy', policyBytes);
  const asset = { ...PUBLIC_INPUTS.asset, policy_digest: policyDigest, expiry_policy: policy };
  const assetBytes = cbor(asset);
  const assetId = digest('asset', cbor({ ...asset }));
  const provisional = [
    { asset_id: assetId, amount: 7, recipient_key: new Uint8Array(32).fill(0x88), spend_domain: PUBLIC_INPUTS.transaction.spend_domain, output_commitment: new Uint8Array(32), provenance: { kind: 'transition' } },
    { asset_id: assetId, amount: 3, recipient_key: new Uint8Array(32).fill(0xaa), spend_domain: PUBLIC_INPUTS.transaction.spend_domain, output_commitment: new Uint8Array(32), provenance: { kind: 'transition' } },
    { asset_id: assetId, amount: 1, recipient_key: new Uint8Array(32).fill(0xcc), spend_domain: PUBLIC_INPUTS.transaction.spend_domain, output_commitment: new Uint8Array(32), provenance: { kind: 'transition' } },
  ];
  const outputs = provisional.map((output) => ({ ...output, output_commitment: digest('output-commitment', cbor({ asset_id: output.asset_id, amount: output.amount, recipient_key: output.recipient_key, spend_domain: output.spend_domain, provenance: output.provenance })) }));
  const inputSource = { transaction_id: new Uint8Array(32).fill(0x12), output_index: 0, output_commitment: new Uint8Array(32).fill(0x13) };
  const inputOutputId = digest('output', cbor(inputSource));
  const inputNullifier = digest('nullifier', cbor({ spend_domain: PUBLIC_INPUTS.transaction.spend_domain, output_id: inputOutputId }));
  const inputs = [{ ...PUBLIC_INPUTS.transaction.inputs[0], output_id: inputOutputId, nullifier: inputNullifier }];
  const transactionCore = { spend_domain: PUBLIC_INPUTS.transaction.spend_domain, inputs, outputs };
  const transactionBytes = cbor(transactionCore); const transactionId = digest('transaction', transactionBytes);
  const outputIds = outputs.map((output_commitment, output_index) => digest('output', cbor({ transaction_id: transactionId, output_index, output_commitment: output_commitment.output_commitment })));
  const nullifiers = outputIds.map((output_id) => digest('nullifier', cbor({ spend_domain: PUBLIC_INPUTS.transaction.spend_domain, output_id })));
  const merkle = Object.fromEntries([[], outputIds.slice(0, 1), outputIds].map((ids) => [ids.length, (() => { const t = tree(ids); return { root: hex(t.root), proofs: t.proofs.map((p) => ({ leaf_index: p.leaf_index, siblings: p.siblings.map(hex) })) }; })()]));
  const overLimitMap = hex(cbor(new Map(Array.from({ length: 257 }, (_, i) => [`k${i}`, 0]))));
  const negative = { non_shortest_integer: '1801', indefinite_array: '9f01ff', duplicate_map_key: 'a2616101616102', tag: 'c101', float: 'fb3ff0000000000000', non_text_map_key: 'a10100', unordered_map: 'a2616201616102', trailing_bytes: `${hex(policyBytes)}00`, depth_limit: `${'81'.repeat(33)}01`, array_limit: `990101${'80'.repeat(257)}`, map_limit: overLimitMap, text_limit: `791001${'61'.repeat(4097)}`, byte_limit: `5a00010001${'00'.repeat(65537)}`, message_limit: `5a00100001${'00'.repeat(1048577)}` };
  return { canonical: { policy: hex(policyBytes), asset: hex(assetBytes), transaction: hex(transactionBytes) }, limits: { max_uint64: '1bffffffffffffffff' }, digests: { policy: hex(policyDigest), asset_id: hex(assetId), transaction_id: hex(transactionId) }, proofs: { input: { source_transaction_id: hex(inputSource.transaction_id), source_output_index: inputSource.output_index, source_output_commitment: hex(inputSource.output_commitment), output_id: hex(inputs[0].output_id), nullifier: hex(inputNullifier), asset_id: hex(assetId), amount: 11, spend_domain: hex(PUBLIC_INPUTS.transaction.spend_domain) }, outputs: outputs.map((output, output_index) => ({ output_index, asset_id: hex(output.asset_id), amount: output.amount, recipient_key: hex(output.recipient_key), spend_domain: hex(output.spend_domain), provenance: output.provenance, output_commitment: hex(output.output_commitment), output_id: hex(outputIds[output_index]) })) }, outputs: outputs.map((output, output_index) => ({ output_index, output_commitment: hex(output.output_commitment), output_id: hex(outputIds[output_index]), nullifier: hex(nullifiers[output_index]) })), merkle, negative_canonicality: negative, negative_categories: { non_shortest_integer: 'decode-limit', indefinite_array: 'decode-limit', duplicate_map_key: 'decode-limit', tag: 'decode-limit', float: 'decode-limit', non_text_map_key: 'schema', unordered_map: 'schema', trailing_bytes: 'decode-limit', depth_limit: 'decode-limit', array_limit: 'decode-limit', map_limit: 'decode-limit', text_limit: 'decode-limit', byte_limit: 'decode-limit', message_limit: 'decode-limit' } };
}
