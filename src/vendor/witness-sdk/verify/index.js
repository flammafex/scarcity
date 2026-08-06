// Local verification — the default, trust-minimizing path (§6.3).
//
// `WitnessVerifier` pins a caller-supplied `NetworkConfig` (and optional peer
// configs for cross-anchor / Federated verification) and delegates every
// cryptographic check to the WASM-compiled `witness-core` module — the single
// trust root (spec §4.3, Path A). No crypto is hand-ported to JS.
//
// The WASM module is loaded lazily and cached. Use `WitnessVerifier.create`
// or `WitnessVerifier.fetch` (both async) to guarantee it is ready before
// calling the synchronous `verify*` methods.
import { VerificationError } from '../errors.js';
import { getLoadedModule, loadWitnessCore } from '../wasm/loader.js';
export { decodeAttestationSignatures, decodeHex } from '../decode.js';
function getCore() {
    const core = getLoadedModule();
    if (!core) {
        throw new VerificationError('bad-signature', 'WASM verifier not loaded; await WitnessVerifier.create() or WitnessVerifier.fetch() first');
    }
    return core;
}
function throwErr(result) {
    throw new VerificationError(result.err.reason, result.err.message);
}
/**
 * Local verifier pinned to a caller-supplied trust anchor.
 *
 * The gateway's answer is never trusted for the verdict: every `verify*`
 * method runs client-side against `witness-core` semantics via WASM.
 */
export class WitnessVerifier {
    network;
    peers;
    /** Pinned trust anchor. Peers required for cross-anchor (Federated) verification. */
    constructor(network, peers = []) {
        this.network = network;
        this.peers = peers;
    }
    /**
     * Async constructor: loads the WASM module and returns a ready verifier.
     */
    static async create(network, peers = []) {
        await loadWitnessCore();
        return new WitnessVerifier(network, peers);
    }
    /**
     * Explicit TOFU convenience: fetches the home network config (and each
     * cross-anchor peer's config) from the gateway, then loads the WASM module.
     */
    static async fetch(client) {
        const network = await client.network();
        const peers = [];
        for (const peer of network.federation?.peer_networks ?? []) {
            try {
                peers.push(await client.networkFrom(peer.gateway));
            }
            catch {
                // Unreachable peer configs are skipped; cross-anchors from them will
                // simply be reported unverified.
            }
        }
        return WitnessVerifier.create(network, peers);
    }
    /** The pinned home-network config. */
    networkConfig() {
        return this.network;
    }
    /** The pinned peer configs (for cross-anchor verification). */
    peerConfigs() {
        return this.peers;
    }
    /**
     * Verify a threshold-signed attestation against the pinned network.
     *
     * Returns the number of valid signatures. Throws `VerificationError` with a
     * machine-readable `reason` (sub-threshold, duplicate-signer, unknown-witness,
     * bad-signature, ambiguous-signature-encoding).
     */
    verifyAttestation(signed) {
        const result = getCore().verifySignedAttestation(JSON.stringify(signed), JSON.stringify(this.network));
        if ('err' in result)
            throwErr(result);
        return result.ok;
    }
    /**
     * Verify a self-contained `ProofBundle`.
     *
     * Returns a `ProofBundleVerification` describing the highest level achieved
     * (none/basic/batched/federated). Throws only if the home network's threshold
     * signature is invalid; other layers are reported per-layer.
     */
    verifyBundle(bundle) {
        const result = getCore().verifyProofBundle(JSON.stringify(bundle), JSON.stringify(this.network), JSON.stringify(this.peers));
        if ('err' in result)
            throwErr(result);
        return result.ok;
    }
    /**
     * Verify a signed tree head against the pinned network.
     *
     * Returns the number of valid signatures. Throws `VerificationError` on
     * failure.
     */
    verifySth(sth) {
        const result = getCore().verifySignedTreeHead(JSON.stringify(sth), JSON.stringify(this.network));
        if ('err' in result)
            throwErr(result);
        return result.ok;
    }
    /**
     * Verify a log consistency proof between two signed tree heads.
     *
     * Both STHs are verified individually, then RFC 9162 consistency is applied.
     * Throws `VerificationError` on failure.
     */
    verifyConsistency(proof) {
        const result = getCore().verifyLogConsistency(JSON.stringify(proof), JSON.stringify(this.network));
        if ('err' in result)
            throwErr(result);
    }
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
    verifyLogInclusion(proof, leafHex) {
        this.verifySth(proof.sth);
        if (proof.tree_size !== proof.sth.tree_head.tree_size) {
            throw new VerificationError('index-size-mismatch', `proof tree_size ${proof.tree_size} does not match STH tree_size ${proof.sth.tree_head.tree_size}`);
        }
        const result = getCore().verifyInclusion(leafHex, proof.leaf_index, proof.tree_size, JSON.stringify(proof.audit_path), proof.sth.tree_head.root_hash);
        if ('err' in result)
            throwErr(result);
        if (!result.ok) {
            throw new VerificationError('bad-signature', 'inclusion proof failed');
        }
    }
}
