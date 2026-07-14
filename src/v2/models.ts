/** In-memory Phase 1B shapes. Native envelopes are intentionally opaque bytes. */
export type Bytes = Uint8Array;
export type UInt64 = number | bigint;
export type OpaqueEnvelope = Bytes;

export interface TxOutput {
  asset_id: Bytes;
  amount: UInt64;
  recipient_key: Bytes;
  spend_domain: Bytes;
  output_commitment: Bytes;
  provenance: MintProvenance | TransitionProvenance;
}
export interface MintProvenance { kind: 'mint'; keyset_id: Bytes; credential_payload: OpaqueEnvelope; signature_envelope: OpaqueEnvelope; }
export interface TransitionProvenance { kind: 'transition'; }
export interface NoteFields { asset_id: Bytes; amount: UInt64; recipient_key: Bytes; spend_domain: Bytes; output_commitment: Bytes; output_id: Bytes; expires_at: UInt64; }
export interface MintNote extends NoteFields { kind: 'mint'; mint_transaction_id: Bytes; output_index: 0; issued_at: UInt64; keyset_id: Bytes; mint_credential: MintProvenance; }
export interface FinalNote { output: TxOutput; output_id: Bytes; committed_at: UInt64; expires_at: UInt64; receipt: OpaqueEnvelope; inclusion_proof: OpaqueEnvelope; }
export type SpendableNote = MintNote | FinalNote;
export interface Input { note: SpendableNote; nullifier: Bytes; authorization_ref: number; }
export interface Authorization { input_index: number; owner_key_id: Bytes; challenge: Bytes; signature: Bytes; }
export interface Transaction { spend_domain: Bytes; inputs: Input[]; outputs: TxOutput[]; authorizations: Authorization[]; }
