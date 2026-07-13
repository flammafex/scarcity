import { createHash } from 'node:crypto';
import { encodeCanonical } from './cbor.js';

const join = (...values: Uint8Array[]) => Uint8Array.from(values.flatMap((value) => [...value]));

/** Scarcity V2 domain-separated SHA-256 over canonical CBOR bytes. */
export function v2Hash(label: string, canonicalPayload: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(join(new TextEncoder().encode(`scarcity/v2/${label}\0`), canonicalPayload)).digest());
}
export const policyDigest = (policy: unknown) => v2Hash('asset-policy', encodeCanonical(policy));
export const assetId = (assetIdentity: unknown) => v2Hash('asset', encodeCanonical(assetIdentity));
export const outputId = (transactionId: Uint8Array, outputIndex: number, outputCommitment: Uint8Array) => v2Hash('output', encodeCanonical({ transaction_id: transactionId, output_index: outputIndex, output_commitment: outputCommitment }));
export const nullifier = (spendDomain: Uint8Array, outputIdBytes: Uint8Array) => v2Hash('nullifier', encodeCanonical({ spend_domain: spendDomain, output_id: outputIdBytes }));
export const outputLeaf = (outputIndex: number, outputIdBytes: Uint8Array) => v2Hash('output-leaf', encodeCanonical({ output_index: outputIndex, output_id: outputIdBytes }));
export const outputNode = (left: Uint8Array, right: Uint8Array) => v2Hash('output-node', join(left, right));
export const emptyOutputRoot = () => v2Hash('output-empty', new Uint8Array());

/** Build the V2 output tree, duplicating an odd final child. */
export function merkleRoot(outputIds: Uint8Array[]): Uint8Array {
  let level = outputIds.map((id, index) => outputLeaf(index, id));
  while (level.length > 1) { const next: Uint8Array[] = []; for (let i = 0; i < level.length; i += 2) next.push(outputNode(level[i], level[i + 1] ?? level[i])); level = next; }
  return level[0] ?? emptyOutputRoot();
}
