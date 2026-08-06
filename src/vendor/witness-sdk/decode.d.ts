/** A single decoded multi-sig entry (signature as raw bytes). */
export interface DecodedWitnessSignature {
    witness_id: string;
    signature: Uint8Array;
}
/** The discriminated result of decoding an `AttestationSignatures` payload. */
export type DecodedAttestationSignatures = {
    kind: 'multisig';
    signatures: DecodedWitnessSignature[];
} | {
    kind: 'aggregated';
    signature: Uint8Array;
    signers: string[];
};
/** Decode mixed-case hex; rejects odd-length and non-hex characters. */
export declare function decodeHex(s: string): Uint8Array;
/**
 * Decode an `AttestationSignatures` JSON payload per spec §3.5.
 *
 * Throws `DecodeError` for ambiguous, partial, or malformed payloads.
 */
export declare function decodeAttestationSignatures(json: string): DecodedAttestationSignatures;
