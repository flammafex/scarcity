import { encodeCanonical } from './cbor.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { assetId, authorityKeyId, authorizationChallenge, keysetId, mintOutputCommitment, mintTransactionId, nullifier as deriveNullifier, outputId, policyDigest, v2Hash } from './identifiers.js';
import type { AssetDescriptor, AuthorityKeyRecord, Authorization, Bytes, ExpiryPolicy, Input, MintNote, NoteFields, RSAKeyset, SpendableNote, Transaction, TxOutput } from './models.js';

const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT128 = (1n << 128n) - 1n;
export class V2ValidationError extends Error { constructor(readonly category: string) { super(category); } }
const fail = (category: string): never => { throw new V2ValidationError(category); };
const length = (value: Bytes, size: number) => { if (!(value instanceof Uint8Array) || value.byteLength !== size) fail('schema'); };
const amount = (value: number | bigint): bigint => { const n = typeof value === 'bigint' ? value : Number.isSafeInteger(value) ? BigInt(value) : fail('arithmetic'); if (n <= 0n || n > MAX_UINT64) fail('arithmetic'); return n; };
const uint64 = (value: number | bigint): bigint => { const n = typeof value === 'bigint' ? value : Number.isSafeInteger(value) ? BigInt(value) : fail('arithmetic'); if (n < 0n || n > MAX_UINT64) fail('arithmetic'); return n; };
const hex = (value: Bytes) => Buffer.from(value).toString('hex');
export const checkedUint128Add = (left: bigint, right: bigint) => { if (left < 0n || right < 0n) fail('arithmetic'); const result = left + right; if (result > MAX_UINT128) fail('arithmetic'); return result; };
const add = checkedUint128Add;
const opaque = (value: unknown) => { if (!(value instanceof Uint8Array) || value.byteLength === 0) fail('schema'); };
const ascii = (value: string, max: number) => { if (typeof value !== 'string' || value.length < 1 || value.length > max || !/^[\x00-\x7f]+$/.test(value)) fail('schema'); };
const epochTime = (epoch: number | bigint, seconds: number | bigint): bigint => { const result = uint64(epoch) * uint64(seconds); if (result > MAX_UINT64) fail('arithmetic'); return result; };
export function validateUniqueOutputIds(outputIds: Bytes[]): void { const seen = new Set<string>(); for (const id of outputIds) { length(id, 32); const key = hex(id); if (seen.has(key)) fail('schema'); seen.add(key); } }

function note(note: SpendableNote): void {
  const isMint = 'mint_transaction_id' in note;
  const base = noteFields(note);
  length(base.asset_id, 32); amount(base.amount); length(base.recipient_key, 32); length(base.spend_domain, 32); length(base.output_commitment, 32); length(base.output_id, 32); amount(base.expires_at);
  if (isMint) { amount(note.issued_at); length(note.mint_transaction_id, 32); length(note.keyset_id, 32); if (note.output_index !== 0) fail('schema'); provenance(note.mint_credential); }
  else { amount(note.committed_at); opaque(note.receipt); opaque(note.inclusion_proof); output(note.output, note.output.spend_domain); }
}
function noteFields(note: SpendableNote): NoteFields { return 'mint_transaction_id' in note ? note : { ...note.output, output_id: note.output_id, expires_at: note.expires_at }; }
function provenance(value: TxOutput['provenance']): void { if (value.kind === 'transition') return; if (value.kind !== 'mint') fail('schema'); length(value.keyset_id, 32); mintSignatureInput(value.credential_payload); opaque(value.signature_envelope); }
function mintSignatureInput(value: any): void { if (!value || typeof value !== 'object') fail('schema'); length(value.keyset_id, 32); length(value.asset_id, 32); length(value.spend_domain, 32); amount(value.denomination); uint64(value.issuance_epoch); uint64(value.expiry_epoch); if (!value.blinded_payload) fail('schema'); length(value.blinded_payload.owner_material, 32); length(value.blinded_payload.replay_nonce, 32); }
function output(value: TxOutput, domain: Bytes): void { length(value.asset_id, 32); amount(value.amount); length(value.recipient_key, 32); length(value.spend_domain, 32); if (hex(value.spend_domain) !== hex(domain)) fail('schema'); length(value.output_commitment, 32); provenance(value.provenance); }
function inputProjection(input: Input) { const fields = noteFields(input.note); return { output_id: fields.output_id, nullifier: input.nullifier, owner_key_id: v2Hash('owner-key', fields.recipient_key) }; }

export function validateExpiryPolicy(policy: ExpiryPolicy): void {
  if (uint64(policy.epoch_seconds) === 0n || uint64(policy.max_lifetime_epochs) === 0n || policy.boundary !== 'exclusive') fail('schema');
}
export function validateAuthorityKeyRecord(record: AuthorityKeyRecord): void {
  length(record.namespace_id, 32); length(record.public_key, 32); length(record.key_id, 32); opaque(record.root_signature); uint64(record.not_before_epoch); uint64(record.not_after_epoch); if (record.not_before_epoch >= record.not_after_epoch) fail('time');
  if (!['issuer-authority', 'issuer-revoke', 'federation-authority', 'witness-authority'].includes(record.role)) fail('schema'); if (record.predecessor_id !== null) length(record.predecessor_id, 32);
  const identity = { namespace_id: record.namespace_id, role: record.role, public_key: record.public_key, not_before_epoch: record.not_before_epoch, not_after_epoch: record.not_after_epoch, predecessor_id: record.predecessor_id };
  if (!Buffer.from(authorityKeyId(identity)).equals(Buffer.from(record.key_id))) fail('hash-binding');
}
export function validateAssetAuthorityBinding(descriptor: AssetDescriptor, record: AuthorityKeyRecord): void { validateAuthorityKeyRecord(record); validateAssetDescriptor(descriptor); if (record.role !== 'issuer-authority' || !Buffer.from(record.namespace_id).equals(Buffer.from(descriptor.issuer))) fail('provenance'); }
export function validateKeysetAuthorityBinding(keyset: RSAKeyset, descriptor: AssetDescriptor, record: AuthorityKeyRecord): void { validateAuthorityKeyRecord(record); validateRSAKeyset(keyset, descriptor); if (record.role !== 'issuer-authority' || !Buffer.from(record.namespace_id).equals(Buffer.from(keyset.issuer_id)) || !Buffer.from(record.key_id).equals(Buffer.from(keyset.authority_key_id))) fail('provenance'); }
export function validateAssetDescriptor(descriptor: AssetDescriptor): void {
  length(descriptor.issuer, 32); ascii(descriptor.asset_code, 64); ascii(descriptor.unit, 32); if (!Number.isInteger(descriptor.decimals) || descriptor.decimals < 0 || descriptor.decimals > 38) fail('schema');
  validateExpiryPolicy(descriptor.expiry_policy); length(descriptor.policy_digest, 32); length(descriptor.asset_id, 32); opaque(descriptor.issuer_signature);
  if (!Buffer.from(policyDigest(descriptor.expiry_policy)).equals(Buffer.from(descriptor.policy_digest))) fail('hash-binding');
  const identity = { issuer: descriptor.issuer, asset_code: descriptor.asset_code, unit: descriptor.unit, decimals: descriptor.decimals, policy_digest: descriptor.policy_digest, expiry_policy: descriptor.expiry_policy };
  if (!Buffer.from(assetId(identity)).equals(Buffer.from(descriptor.asset_id))) fail('hash-binding');
}
export function validateRSAKeyset(keyset: RSAKeyset, descriptor: AssetDescriptor): void {
  validateAssetDescriptor(descriptor); length(keyset.issuer_id, 32); length(keyset.keyset_id, 32); length(keyset.asset_id, 32); length(keyset.spend_domain, 32); amount(keyset.denomination); uint64(keyset.issuance_epoch); uint64(keyset.expiry_epoch); if (keyset.issuance_epoch >= keyset.expiry_epoch) fail('time');
  length(keyset.modulus, 384); if (keyset.public_exponent !== 65537 || keyset.suite !== 'RSABSSA-SHA384-PSS-Randomized') fail('schema'); length(keyset.authority_key_id, 32); opaque(keyset.authority_signature);
  if (!Buffer.from(keyset.issuer_id).equals(Buffer.from(descriptor.issuer)) || !Buffer.from(keyset.asset_id).equals(Buffer.from(descriptor.asset_id))) fail('provenance'); if (BigInt(keyset.expiry_epoch) - BigInt(keyset.issuance_epoch) > uint64(descriptor.expiry_policy.max_lifetime_epochs)) fail('time');
  const identity = { issuer_id: keyset.issuer_id, asset_id: keyset.asset_id, spend_domain: keyset.spend_domain, denomination: keyset.denomination, issuance_epoch: keyset.issuance_epoch, expiry_epoch: keyset.expiry_epoch, modulus: keyset.modulus, public_exponent: keyset.public_exponent, suite: keyset.suite, authority_key_id: keyset.authority_key_id };
  if (!Buffer.from(keysetId(identity)).equals(Buffer.from(keyset.keyset_id))) fail('hash-binding');
}
export function validateMintNote(noteValue: MintNote, descriptor: AssetDescriptor, keyset: RSAKeyset, headerTime?: number | bigint): void {
  validateAssetDescriptor(descriptor); validateRSAKeyset(keyset, descriptor); note(noteValue);
  if (!Buffer.from(noteValue.asset_id).equals(Buffer.from(descriptor.asset_id)) || !Buffer.from(noteValue.spend_domain).equals(Buffer.from(keyset.spend_domain)) || !Buffer.from(noteValue.keyset_id).equals(Buffer.from(keyset.keyset_id)) || BigInt(noteValue.amount) !== BigInt(keyset.denomination)) fail('provenance');
  if (noteValue.mint_credential.kind !== 'mint' || !Buffer.from(noteValue.mint_credential.keyset_id).equals(Buffer.from(keyset.keyset_id))) fail('provenance'); const payload = noteValue.mint_credential.credential_payload;
  if (!Buffer.from(payload.keyset_id).equals(Buffer.from(keyset.keyset_id)) || !Buffer.from(payload.asset_id).equals(Buffer.from(keyset.asset_id)) || !Buffer.from(payload.spend_domain).equals(Buffer.from(keyset.spend_domain)) || BigInt(payload.denomination) !== BigInt(keyset.denomination) || BigInt(payload.issuance_epoch) !== BigInt(keyset.issuance_epoch) || BigInt(payload.expiry_epoch) !== BigInt(keyset.expiry_epoch) || !Buffer.from(payload.blinded_payload.owner_material).equals(Buffer.from(noteValue.recipient_key))) fail('provenance');
  const commitment = mintOutputCommitment(keyset.keyset_id, payload.blinded_payload.owner_material, payload.blinded_payload.replay_nonce); if (!Buffer.from(commitment).equals(Buffer.from(noteValue.output_commitment))) fail('hash-binding');
  const mintId = mintTransactionId(keyset.keyset_id, commitment); if (!Buffer.from(mintId).equals(Buffer.from(noteValue.mint_transaction_id))) fail('hash-binding'); if (!Buffer.from(outputId(mintId, 0, commitment)).equals(Buffer.from(noteValue.output_id))) fail('hash-binding');
  const issued = epochTime(keyset.issuance_epoch, descriptor.expiry_policy.epoch_seconds); const expires = epochTime(keyset.expiry_epoch, descriptor.expiry_policy.epoch_seconds); if (BigInt(noteValue.issued_at) !== issued || BigInt(noteValue.expires_at) !== expires) fail('time'); if (headerTime !== undefined && (uint64(headerTime) < issued || uint64(headerTime) >= expires)) fail('time');
}

/** Validate structure and per-asset conservation without verifying opaque envelopes. */
export function validateTransaction(transaction: Transaction): { transaction_id: Bytes; output_ids: Bytes[] } {
  length(transaction.spend_domain, 32); if (transaction.outputs.length === 0) fail('schema');
  const inputs = transaction.inputs; const seenInputs = new Set<string>(); const seenNullifiers = new Set<string>();
  let previous: string | undefined; const inputTotals = new Map<string, bigint>();
  for (const input of inputs) {
    note(input.note); const noteDomain = 'mint_transaction_id' in input.note ? input.note.spend_domain : input.note.output.spend_domain; if (!Buffer.from(noteDomain).equals(Buffer.from(transaction.spend_domain))) fail('schema'); length(input.nullifier, 32); if (!Number.isInteger(input.authorization_ref) || input.authorization_ref < 0 || input.authorization_ref >= transaction.authorizations.length) fail('authorization');
    const id = hex(input.note.output_id); if (seenInputs.has(id) || (previous !== undefined && id <= previous)) fail('schema'); previous = id; seenInputs.add(id);
    const nf = hex(input.nullifier); if (seenNullifiers.has(nf) || !Buffer.from(deriveNullifier(transaction.spend_domain, input.note.output_id)).equals(Buffer.from(input.nullifier))) fail('nullifier'); seenNullifiers.add(nf);
    const fields = noteFields(input.note); const asset = hex(fields.asset_id); inputTotals.set(asset, add(inputTotals.get(asset) ?? 0n, amount(fields.amount)));
  }
  const core = { spend_domain: transaction.spend_domain, inputs: inputs.map(inputProjection), outputs: transaction.outputs };
  const transactionId = v2Hash('transaction', encodeCanonical(core));
  const outputIds: Bytes[] = []; const outputTotals = new Map<string, bigint>(); const seenOutputs = new Set<string>();
  transaction.outputs.forEach((value, index) => { output(value, transaction.spend_domain); const id = outputId(transactionId, index, value.output_commitment); const key = hex(id); if (seenOutputs.has(key)) fail('schema'); seenOutputs.add(key); outputIds.push(id); const asset = hex(value.asset_id); outputTotals.set(asset, add(outputTotals.get(asset) ?? 0n, amount(value.amount))); });
  validateUniqueOutputIds(outputIds);
  if (inputTotals.size !== outputTotals.size || [...inputTotals].some(([asset, total]) => outputTotals.get(asset) !== total)) fail('arithmetic');
  if (transaction.authorizations.length !== inputs.length) fail('authorization'); const refs = new Set<number>();
  transaction.authorizations.forEach((auth: Authorization, authorizationIndex) => { if (!Number.isInteger(auth.input_index) || auth.input_index < 0 || auth.input_index >= inputs.length || refs.has(auth.input_index) || inputs[auth.input_index].authorization_ref !== authorizationIndex) fail('authorization'); refs.add(auth.input_index); length(auth.owner_key_id, 32); length(auth.challenge, 32); length(auth.signature, 64); const input = inputs[auth.input_index]; const fields = noteFields(input.note); const ownerKeyId = inputProjection(input).owner_key_id; if (!Buffer.from(auth.owner_key_id).equals(Buffer.from(ownerKeyId))) fail('authorization'); const challenge = authorizationChallenge(transactionId, auth.input_index, transaction.spend_domain, auth.owner_key_id); if (!Buffer.from(auth.challenge).equals(Buffer.from(challenge)) || !ed25519.verify(auth.signature, auth.challenge, fields.recipient_key)) fail('authorization'); });
  if (refs.size !== inputs.length) fail('authorization');
  return { transaction_id: transactionId, output_ids: outputIds };
}
