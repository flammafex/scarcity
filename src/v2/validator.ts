import { encodeCanonical } from './cbor.js';
import { nullifier as deriveNullifier, outputId, v2Hash } from './identifiers.js';
import type { Authorization, Bytes, Input, NoteFields, SpendableNote, Transaction, TxOutput } from './models.js';

const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT128 = (1n << 128n) - 1n;
export class V2ValidationError extends Error { constructor(readonly category: string) { super(category); } }
const fail = (category: string): never => { throw new V2ValidationError(category); };
const length = (value: Bytes, size: number) => { if (!(value instanceof Uint8Array) || value.byteLength !== size) fail('schema'); };
const amount = (value: number | bigint): bigint => { const n = typeof value === 'bigint' ? value : Number.isSafeInteger(value) ? BigInt(value) : fail('arithmetic'); if (n <= 0n || n > MAX_UINT64) fail('arithmetic'); return n; };
const hex = (value: Bytes) => Buffer.from(value).toString('hex');
export const checkedUint128Add = (left: bigint, right: bigint) => { if (left < 0n || right < 0n) fail('arithmetic'); const result = left + right; if (result > MAX_UINT128) fail('arithmetic'); return result; };
const add = checkedUint128Add;
const opaque = (value: unknown) => { if (!(value instanceof Uint8Array) || value.byteLength === 0) fail('schema'); };
export function validateUniqueOutputIds(outputIds: Bytes[]): void { const seen = new Set<string>(); for (const id of outputIds) { length(id, 32); const key = hex(id); if (seen.has(key)) fail('schema'); seen.add(key); } }

function note(note: SpendableNote): void {
  const isMint = 'mint_transaction_id' in note;
  const base = noteFields(note);
  length(base.asset_id, 32); amount(base.amount); length(base.recipient_key, 32); length(base.spend_domain, 32); length(base.output_commitment, 32); length(base.output_id, 32); amount(base.expires_at);
  if (isMint) { amount(note.issued_at); length(note.mint_transaction_id, 32); length(note.keyset_id, 32); if (note.output_index !== 0) fail('schema'); provenance(note.mint_credential); }
  else { amount(note.committed_at); opaque(note.receipt); opaque(note.inclusion_proof); output(note.output, note.output.spend_domain); }
}
function noteFields(note: SpendableNote): NoteFields { return 'mint_transaction_id' in note ? note : { ...note.output, output_id: note.output_id, expires_at: note.expires_at }; }
function provenance(value: TxOutput['provenance']): void { if (value.kind === 'transition') return; if (value.kind !== 'mint') fail('schema'); length(value.keyset_id, 32); opaque(value.credential_payload); opaque(value.signature_envelope); }
function output(value: TxOutput, domain: Bytes): void { length(value.asset_id, 32); amount(value.amount); length(value.recipient_key, 32); length(value.spend_domain, 32); if (hex(value.spend_domain) !== hex(domain)) fail('schema'); length(value.output_commitment, 32); provenance(value.provenance); }
function inputProjection(input: Input) { const fields = noteFields(input.note); return { output_id: fields.output_id, nullifier: input.nullifier, owner_key_id: v2Hash('owner-key', fields.recipient_key) }; }

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
  transaction.authorizations.forEach((auth: Authorization, authorizationIndex) => { if (!Number.isInteger(auth.input_index) || auth.input_index < 0 || auth.input_index >= inputs.length || refs.has(auth.input_index) || inputs[auth.input_index].authorization_ref !== authorizationIndex) fail('authorization'); refs.add(auth.input_index); length(auth.owner_key_id, 32); length(auth.challenge, 32); length(auth.signature, 64); if (!Buffer.from(auth.owner_key_id).equals(Buffer.from(inputProjection(inputs[auth.input_index]).owner_key_id))) fail('authorization'); });
  if (refs.size !== inputs.length) fail('authorization');
  return { transaction_id: transactionId, output_ids: outputIds };
}
