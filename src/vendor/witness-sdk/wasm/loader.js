// WASM module loader for the `@witness/sdk` local verifier.
//
// Loads `witness_core_wasm.wasm` (the compiled `witness-core` verification
// surface — the single trust root, spec §4.3 Path A) and wraps its
// `#[no_mangle]` extern "C" exports in a typed, ergonomic API.
//
// Works in Node 18+ (via `node:fs`) and browsers (via `fetch`). The `.wasm`
// binary is checked in next to this file and copied to `dist/wasm/` on build.
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function bytes(s) {
    return { kind: 'bytes', data: encoder.encode(s) };
}
function u64(value) {
    return { kind: 'u64', value };
}
let cachedInstance = null;
let cachedModule = null;
async function loadWasmBytes() {
    const url = new URL('./witness_core_wasm.wasm', import.meta.url);
    // Node 18+: `readFileSync` accepts a file URL.
    try {
        const { readFileSync } = await import('node:fs');
        return readFileSync(url);
    }
    catch {
        // Browser: fetch the module URL.
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`failed to fetch wasm module: ${res.status}`);
        }
        return new Uint8Array(await res.arrayBuffer());
    }
}
async function getInstance() {
    if (cachedInstance)
        return cachedInstance;
    const bytes = await loadWasmBytes();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    cachedInstance = instance;
    return instance;
}
function invoke(exports, fnName, args) {
    const { memory, alloc, dealloc, result_ptr, result_len } = exports;
    const ptrs = [];
    try {
        const callArgs = [];
        for (const arg of args) {
            if (arg.kind === 'u64') {
                callArgs.push(BigInt(arg.value));
            }
            else {
                const ptr = alloc(arg.data.length);
                new Uint8Array(memory.buffer, ptr, arg.data.length).set(arg.data);
                ptrs.push(ptr);
                callArgs.push(ptr, arg.data.length);
            }
        }
        const fn = exports[fnName];
        fn(...callArgs);
        const len = result_len();
        const ptr = result_ptr();
        const text = decoder.decode(new Uint8Array(memory.buffer, ptr, len));
        return JSON.parse(text);
    }
    finally {
        for (const ptr of ptrs) {
            dealloc(ptr, 0);
        }
    }
}
/**
 * Load (once) and return the typed WASM verification module.
 *
 * The module is cached after the first load. Callers that need to guarantee
 * the module is ready before use should `await loadWitnessCore()`.
 */
export async function loadWitnessCore() {
    if (cachedModule)
        return cachedModule;
    const instance = await getInstance();
    const exports = instance.exports;
    const module = {
        verifySignedAttestation(signedJson, configJson) {
            return invoke(exports, 'verify_signed_attestation', [
                bytes(signedJson),
                bytes(configJson),
            ]);
        },
        verifySignedTreeHead(sthJson, configJson) {
            return invoke(exports, 'verify_signed_tree_head', [
                bytes(sthJson),
                bytes(configJson),
            ]);
        },
        verifyLogConsistency(proofJson, configJson) {
            return invoke(exports, 'verify_log_consistency', [
                bytes(proofJson),
                bytes(configJson),
            ]);
        },
        verifyProofBundle(bundleJson, networkJson, peersJson) {
            return invoke(exports, 'verify_proof_bundle', [
                bytes(bundleJson),
                bytes(networkJson),
                bytes(peersJson),
            ]);
        },
        verifySignatureBls(attestationJson, sigHex, pkHex) {
            return invoke(exports, 'verify_signature_bls', [
                bytes(attestationJson),
                bytes(sigHex),
                bytes(pkHex),
            ]);
        },
        verifyAggregatedSignatureBls(attestationJson, aggSigHex, pksJson) {
            return invoke(exports, 'verify_aggregated_signature_bls', [
                bytes(attestationJson),
                bytes(aggSigHex),
                bytes(pksJson),
            ]);
        },
        verifyInclusion(leafHex, leafIndex, treeSize, siblingsJson, rootHex) {
            return invoke(exports, 'verify_inclusion', [
                bytes(leafHex),
                u64(leafIndex),
                u64(treeSize),
                bytes(siblingsJson),
                bytes(rootHex),
            ]);
        },
        verifyConsistency(first, second, firstHashHex, secondHashHex, proofJson) {
            return invoke(exports, 'verify_consistency', [
                u64(first),
                u64(second),
                bytes(firstHashHex),
                bytes(secondHashHex),
                bytes(proofJson),
            ]);
        },
        attestationToBytes(attestationJson) {
            return invoke(exports, 'attestation_to_bytes', [
                bytes(attestationJson),
            ]);
        },
        merkleTreeHash(leavesJson) {
            return invoke(exports, 'merkle_tree_hash', [
                bytes(leavesJson),
            ]);
        },
        treeHeadDigest(treeHeadJson) {
            return invoke(exports, 'tree_head_digest', [
                bytes(treeHeadJson),
            ]);
        },
        decodeAttestationSignatures(json) {
            return invoke(exports, 'decode_attestation_signatures', [
                bytes(json),
            ]);
        },
    };
    cachedModule = module;
    return module;
}
/**
 * Synchronously return the already-loaded WASM module, or `null` if it has
 * not been loaded yet. Used by the synchronous `WitnessVerifier` methods.
 */
export function getLoadedModule() {
    return cachedModule;
}
