import { createHash } from 'node:crypto';
import { encodeCanonical } from './cbor.js';

const join = (...values: Uint8Array[]) => Uint8Array.from(values.flatMap((value) => [...value]));

/** Scarcity V2 domain-separated SHA-256 over canonical CBOR bytes. */
export function v2Hash(label: string, canonicalPayload: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(join(new TextEncoder().encode(`scarcity/v2/${label}\0`), canonicalPayload)).digest());
}
export const policyDigest = (policy: unknown) => v2Hash('asset-policy', encodeCanonical(policy));
export const assetId = (assetIdentity: unknown) => v2Hash('asset', encodeCanonical(assetIdentity));
export const keysetId = (keysetIdentity: unknown) => v2Hash('rsa-keyset', encodeCanonical(keysetIdentity));
export const authorityKeyId = (identity: unknown) => v2Hash('authority-key', encodeCanonical(identity));
export const mintOutputCommitment = (keyset_id: Uint8Array, owner_material: Uint8Array, replay_nonce: Uint8Array) => v2Hash('output-commitment', encodeCanonical({ keyset_id, owner_material, replay_nonce }));
export const mintTransactionId = (keyset_id: Uint8Array, output_commitment: Uint8Array) => v2Hash('mint-transaction', encodeCanonical({ keyset_id, output_commitment }));
export const outputId = (transactionId: Uint8Array, outputIndex: number, outputCommitment: Uint8Array) => v2Hash('output', encodeCanonical({ transaction_id: transactionId, output_index: outputIndex, output_commitment: outputCommitment }));
export const nullifier = (spendDomain: Uint8Array, outputIdBytes: Uint8Array) => v2Hash('nullifier', encodeCanonical({ spend_domain: spendDomain, output_id: outputIdBytes }));
export const authorizationChallenge = (transactionDigest: Uint8Array, inputIndex: number, spendDomain: Uint8Array, ownerKeyId: Uint8Array) => v2Hash('authorization', encodeCanonical({ transaction_digest: transactionDigest, input_index: inputIndex, spend_domain: spendDomain, owner_key_id: ownerKeyId }));
export const outputLeaf = (outputIndex: number, outputIdBytes: Uint8Array) => v2Hash('output-leaf', encodeCanonical({ output_index: outputIndex, output_id: outputIdBytes }));
export const outputNode = (left: Uint8Array, right: Uint8Array) => v2Hash('output-node', join(left, right));
export const emptyOutputRoot = () => v2Hash('output-empty', new Uint8Array());

/** Build the V2 output tree, duplicating an odd final child. */
export function merkleRoot(outputIds: Uint8Array[]): Uint8Array {
  let level = outputIds.map((id, index) => outputLeaf(index, id));
  while (level.length > 1) { const next: Uint8Array[] = []; for (let i = 0; i < level.length; i += 2) next.push(outputNode(level[i], level[i + 1] ?? level[i])); level = next; }
  return level[0] ?? emptyOutputRoot();
}
