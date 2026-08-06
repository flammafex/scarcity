import type { LogConsistencyProof, LogInclusionProofResponse, NetworkConfig, ProofBundle, ProofBundleVerification, SignedAttestation, SignedTreeHead } from '../types.generated.js';
import type { WitnessClient } from '../client.js';
export { decodeAttestationSignatures, decodeHex } from '../decode.js';
export type { DecodedAttestationSignatures } from '../decode.js';
/**
 * Local verifier pinned to a caller-supplied trust anchor.
 *
 * The gateway's answer is never trusted for the verdict: every `verify*`
 * method runs client-side against `witness-core` semantics via WASM.
 */
export declare class WitnessVerifier {
    private readonly network;
    private readonly peers;
    /** Pinned trust anchor. Peers required for cross-anchor (Federated) verification. */
    constructor(network: NetworkConfig, peers?: NetworkConfig[]);
    /**
     * Async constructor: loads the WASM module and returns a ready verifier.
     */
    static create(network: NetworkConfig, peers?: NetworkConfig[]): Promise<WitnessVerifier>;
    /**
     * Explicit TOFU convenience: fetches the home network config (and each
     * cross-anchor peer's config) from the gateway, then loads the WASM module.
     */
    static fetch(client: WitnessClient): Promise<WitnessVerifier>;
    /** The pinned home-network config. */
    networkConfig(): NetworkConfig;
    /** The pinned peer configs (for cross-anchor verification). */
    peerConfigs(): NetworkConfig[];
    /**
     * Verify a threshold-signed attestation against the pinned network.
     *
     * Returns the number of valid signatures. Throws `VerificationError` with a
     * machine-readable `reason` (sub-threshold, duplicate-signer, unknown-witness,
     * bad-signature, ambiguous-signature-encoding).
     */
    verifyAttestation(signed: SignedAttestation): number;
    /**
     * Verify a self-contained `ProofBundle`.
     *
     * Returns a `ProofBundleVerification` describing the highest level achieved
     * (none/basic/batched/federated). Throws only if the home network's threshold
     * signature is invalid; other layers are reported per-layer.
     */
    verifyBundle(bundle: ProofBundle): ProofBundleVerification;
    /**
     * Verify a signed tree head against the pinned network.
     *
     * Returns the number of valid signatures. Throws `VerificationError` on
     * failure.
     */
    verifySth(sth: SignedTreeHead): number;
    /**
     * Verify a log consistency proof between two signed tree heads.
     *
     * Both STHs are verified individually, then RFC 9162 consistency is applied.
     * Throws `VerificationError` on failure.
     */
    verifyConsistency(proof: LogConsistencyProof): void;
    /**
     * Verify an RFC 9162 inclusion proof against the STH carried in the response.
     *
     * The STH is verified first, then the audit path is checked against the STH's
     * root. `leafHex` is the 32-byte attestation hash (mixed-case hex accepted via
     * the WASM verifier) being proven — required, since
     * `LogInclusionProofResponse` does not carry the leaf. The proof's
     * `tree_size` must match the STH's `tree_size` (position-awareness, §3.6).
     * Throws `VerificationError` on failure.
     */
    verifyLogInclusion(proof: LogInclusionProofResponse, leafHex: string): void;
}
