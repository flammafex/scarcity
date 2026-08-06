export type WasmResult<T> = {
    ok: T;
} | {
    err: {
        reason: string;
        message: string;
    };
};
/** The typed WASM verification surface. */
export interface WitnessCoreModule {
    verifySignedAttestation(signedJson: string, configJson: string): WasmResult<number>;
    verifySignedTreeHead(sthJson: string, configJson: string): WasmResult<number>;
    verifyLogConsistency(proofJson: string, configJson: string): WasmResult<true>;
    verifyProofBundle(bundleJson: string, networkJson: string, peersJson: string): WasmResult<unknown>;
    verifySignatureBls(attestationJson: string, sigHex: string, pkHex: string): WasmResult<true>;
    verifyAggregatedSignatureBls(attestationJson: string, aggSigHex: string, pksJson: string): WasmResult<true>;
    verifyInclusion(leafHex: string, leafIndex: number, treeSize: number, siblingsJson: string, rootHex: string): WasmResult<boolean>;
    verifyConsistency(first: number, second: number, firstHashHex: string, secondHashHex: string, proofJson: string): WasmResult<boolean>;
    attestationToBytes(attestationJson: string): WasmResult<string>;
    merkleTreeHash(leavesJson: string): WasmResult<string>;
    treeHeadDigest(treeHeadJson: string): WasmResult<string>;
    decodeAttestationSignatures(json: string): WasmResult<unknown>;
}
/**
 * Load (once) and return the typed WASM verification module.
 *
 * The module is cached after the first load. Callers that need to guarantee
 * the module is ready before use should `await loadWitnessCore()`.
 */
export declare function loadWitnessCore(): Promise<WitnessCoreModule>;
/**
 * Synchronously return the already-loaded WASM module, or `null` if it has
 * not been loaded yet. Used by the synchronous `WitnessVerifier` methods.
 */
export declare function getLoadedModule(): WitnessCoreModule | null;
