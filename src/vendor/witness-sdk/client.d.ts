import type { AttestationJobResponse, ExternalAnchorProof, LogConsistencyProof, LogInclusionProofResponse, MerkleProofResponse, NetworkConfig, NetworkConfigPublic, ProofBundle, SignedAttestation, SignedTreeHead, VerifyResponse } from './types.generated.js';
import { type EventsSubscription, type SubscribeOptions } from './ws.js';
/** Freebird token input: a bare string is sugar for `{ tokenB64 }`. */
export type FreebirdTokenInput = string | {
    tokenB64: string;
};
/** Configuration for [`WitnessClient::waitForConfirmation`]. */
export type PollConfig = {
    /** Base polling interval (ms). Default 2000. */
    intervalMs?: number;
    /** Overall deadline for confirmation (ms). Default 180_000. */
    timeoutMs?: number;
    /** Abort signal; aborting stops polling. */
    signal?: AbortSignal;
};
/**
 * A typed, keyless client for the Witness gateway.
 *
 * Covers the full attestation lifecycle, the transparency-log read surface,
 * optional WebSocket push events, and remote (non-authoritative) verification.
 */
export declare class WitnessClient {
    private readonly gatewayUrl;
    private readonly fetchImpl;
    private readonly timeoutMs;
    constructor(config: {
        gatewayUrl: string;
        fetch?: typeof fetch;
        timeoutMs?: number;
    });
    private url;
    private static assertHash;
    /**
     * Perform an HTTP request and decode the JSON response.
     *
     * HTTP classification: 404 on a read endpoint → `NotFoundError`; any other
     * non-2xx → `HttpStatusError`. Transport failures → `TransportError`.
     * Undecodable bodies → `DecodeError`.
     */
    private request;
    private sleep;
    /**
     * Submit a hash for attestation. Idempotent: duplicate hashes return the
     * canonical existing job.
     */
    createAttestation(hash: Uint8Array, opts?: {
        freebirdToken?: FreebirdTokenInput;
    }): Promise<AttestationJobResponse>;
    /** Fetch the canonical attestation job for a hash. */
    getAttestation(hash: Uint8Array): Promise<AttestationJobResponse>;
    /**
     * Poll `getAttestation` until the job reaches a terminal state.
     *
     * - `confirmed` with a `signed_attestation` → resolves with it.
     * - `confirmed` **without** a signed attestation is a protocol violation and
     *   throws `DecodeError` (never a silent success).
     * - `failed` → `JobFailedError`.
     * - Timeout → `ConfirmationTimeoutError` carrying the last status.
     * - `signal` abort stops polling.
     *
     * The effective sleep per iteration is `max(intervalMs, next_attempt_at -
     * now)` (honoring the server hint), clamped to the remaining timeout.
     */
    waitForConfirmation(hash: Uint8Array, poll?: PollConfig): Promise<SignedAttestation>;
    /** Fetch a self-contained `ProofBundle` for a hash. */
    getBundle(hash: Uint8Array): Promise<ProofBundle>;
    /** Fetch a Merkle inclusion proof for a hash. */
    getProof(hash: Uint8Array): Promise<MerkleProofResponse>;
    /**
     * Fetch external anchor proofs for a hash.
     *
     * An unknown attestation throws `NotFoundError` (404); a known but unbatched
     * attestation returns an empty list (200 with `[]`). The SDK does **not**
     * normalize 404 to empty.
     */
    getAnchors(hash: Uint8Array): Promise<ExternalAnchorProof[]>;
    /** Check gateway health (`{"status":"ok"}`). */
    health(): Promise<void>;
    /**
     * Fetch the public config (`GET /v1/config`).
     *
     * This is **informational only** (witness count, scheme, threshold). It is
     * **not** a trust anchor and is insufficient for verification — use
     * [`WitnessClient#network`] for a full witness pubkey set.
     */
    publicConfig(): Promise<NetworkConfigPublic>;
    /** Fetch the full `NetworkConfig` (`GET /v1/network`): the trust-anchor fetch. */
    network(): Promise<NetworkConfig>;
    /**
     * Fetch a `NetworkConfig` from an arbitrary gateway URL — used to fetch peer
     * network configs for cross-anchor (Federated) verification.
     */
    networkFrom(gatewayUrl: string): Promise<NetworkConfig>;
    /** Latest signed tree head for the gateway's home network. */
    sth(): Promise<SignedTreeHead>;
    /** Look up a historical STH at a specific tree size. */
    sthAtSize(treeSize: number): Promise<SignedTreeHead>;
    /** Consistency proof linking two prior STHs (`first ≥ 1`, `first ≤ second`). */
    consistency(first: number, second: number): Promise<LogConsistencyProof>;
    /** RFC 9162 inclusion proof for `hash` against the STH at `treeSize`. */
    logProof(hash: Uint8Array, treeSize: number): Promise<LogInclusionProofResponse>;
    /** Subscribe to attestation events over WebSocket (§6.4). */
    subscribeEvents(opts?: SubscribeOptions): EventsSubscription;
    /**
     * Ask the gateway to verify an attestation (`POST /v1/verify`).
     *
     * **Non-authoritative**: this is the gateway's opinion. Prefer local
     * verification for a trust-minimizing verdict.
     */
    verifyRemote(signed: SignedAttestation): Promise<VerifyResponse>;
}
