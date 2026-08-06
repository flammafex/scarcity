/**
 * Configuration for the Freebird client
 */
interface ClientConfig {
    /** The base URL of the issuer (e.g. "https://issuer.example.com") */
    issuerUrl: string;
    /** The base URL of the verifier (e.g. "https://verifier.example.com") */
    verifierUrl?: string;
    /** Optional verifier scope override when verifierUrl is unavailable. */
    verifierId?: string;
    /** Optional audience override when verifierUrl is unavailable. */
    audience?: string;
    /**
     * Optional TTL (ms) for the cached `/.well-known/keys` discovery metadata.
     *
     * When unset, the TTL is derived from the metadata's `epoch_duration_sec`
     * (i.e. the cache expires when the current epoch advances). Set this to
     * override the epoch-derived TTL, e.g. to poll for key rotation more
     * aggressively than once per epoch.
     */
    keyCacheTtlMs?: number;
    /**
     * Optional persistent store for issued tokens.
     *
     * When provided, consumers can persist and reload tokens across sessions
     * without hand-rolling storage. See {@link TokenStore} and the
     * `MemoryTokenStore`/`StorageTokenStore` implementations.
     */
    tokenStore?: TokenStore;
    /**
     * Optional Proof-of-Work difficulty (leading zero bits) to mine when the
     * issuer requires PoW Sybil resistance.
     *
     * When unset, PoW is disabled unless the issuer publishes a PoW requirement
     * in `/.well-known/issuer` (the `sybil` field), which takes precedence over
     * this config. The issuance methods mine a request-bound `proof_of_work`
     * proof automatically when PoW is required.
     */
    powDifficulty?: number;
    /**
     * Optional custom `fetch` implementation used for all outbound HTTP.
     *
     * When provided, every request the client makes (discovery, issuance,
     * verification, exchange, graph-issuance) is routed through this function
     * instead of the global `fetch`. This lets consumers route traffic through a
     * proxy (e.g. Tor/SOCKS5) for network-level privacy. Defaults to the global
     * `fetch` when unset.
     */
    fetch?: typeof fetch;
}
/**
 * Represents the .well-known/issuer metadata
 */
interface IssuerMetadata {
    issuer_id: string;
    voprf: {
        suite: string;
        kid: string;
        pubkey: string;
    };
    public?: {
        token_type: string;
        token_key_id: string;
        rfc9474_variant: string;
        modulus_bits: number;
        spend_policy: string;
    };
    /**
     * Issuer-published Sybil resistance requirements. Absent on issuers that do
     * not publish them. Mirrors `SybilConfigSummary` in
     * `issuer/src/routes/admin/types.rs`.
     */
    sybil?: SybilConfigSummary;
}
/**
 * Issuer-published Sybil resistance requirements (sanitized — no secrets).
 * Mirrors `SybilConfigSummary` in `issuer/src/routes/admin/types.rs`.
 */
interface SybilConfigSummary {
    /** Current Sybil resistance mode (e.g. `"pow"`, `"proof_of_work"`, `"none"`). */
    mode: string;
    /** Human-readable description of the mode. */
    mode_description: string;
    /** Mode-specific settings (untagged; shape depends on `mode`). */
    settings: SybilModeSettings;
    /** Combined-mode mechanisms (only when `mode` is `"combined"`). */
    combined_mechanisms?: string[] | null;
    /** Combined-mode type (only when `mode` is `"combined"`). */
    combined_mode_type?: string | null;
    /** Combined threshold (only for `"combined"` + `"threshold"`). */
    combined_threshold?: number | null;
}
/**
 * Mode-specific Sybil settings. The wire shape is untagged and depends on
 * `SybilConfigSummary.mode`; the SDK only reads `difficulty` for PoW.
 */
type SybilModeSettings = {
    difficulty: number;
} | {
    interval: string;
    interval_secs: number;
} | {
    invites_per_user: number;
    cooldown: string;
    cooldown_secs: number;
    expires: string;
    expires_secs: number;
    new_user_wait: string;
    new_user_wait_secs: number;
    persistence_path: string;
    bootstrap_users_configured: boolean;
} | {
    levels: TrustLevelSummary[];
    persistence_path: string;
} | {
    min_score: number;
    persistence_path: string;
} | {
    required_vouchers: number;
    cooldown: string;
    cooldown_secs: number;
    expires: string;
    expires_secs: number;
    new_user_wait: string;
    new_user_wait_secs: number;
    persistence_path: string;
} | {
    max_proof_age?: string | null;
    max_proof_age_secs?: number | null;
} | Record<string, never>;
/** Summary of a progressive-trust level. Mirrors `TrustLevelSummary`. */
interface TrustLevelSummary {
    min_age: string;
    min_age_secs: number;
    max_tokens: number;
    cooldown: string;
    cooldown_secs: number;
}
interface PublicKeyInfo {
    token_key_id: string;
    token_type: string;
    rfc9474_variant: string;
    modulus_bits: number;
    pubkey_spki_b64: string;
    issuer_id: string;
    valid_from: number;
    valid_until: number;
    audience?: string;
    spend_policy: string;
    max_uses?: number;
}
/** A source or output position in the immutable exchange rule. */
interface ExchangeSlot {
    descriptor_id: string;
    keyset_id: string;
    slot_id: string;
    quantity: number;
}
interface ExchangeRequestSource {
    slot: ExchangeSlot;
    /** Base64url-encoded V5 public bearer source artifact. */
    artifact: string;
}
interface ExchangeRequestOutput {
    slot: ExchangeSlot;
    /** Base64url-encoded RFC 9474 blinded target message. */
    blinded_value: string;
}
/** Exact JSON body accepted by POST /v2/public/exchange. */
interface ExchangeRequest {
    version: 2;
    /** Public, non-secret 16-byte operation identifier (canonical base64url). */
    public_operation_id: string;
    graph_id: string;
    transition_id: string;
    source_keyset_id: string;
    target_keyset_id: string;
    sources: ExchangeRequestSource[];
    outputs: ExchangeRequestOutput[];
}
interface ExchangeResultOutput {
    slot: ExchangeSlot;
    blinded_value: string;
    /** Base64url-encoded RFC 9474 blind signature. */
    blind_signature: string;
}
interface ExchangeResult {
    version: 2;
    public_operation_id: string;
    graph_id: string;
    transition_id: string;
    source_keyset_id: string;
    target_keyset_id: string;
    outputs: ExchangeResultOutput[];
    result_digest: string;
}
interface ExchangeReceipt {
    version: 2;
    public_operation_id: string;
    graph_id: string;
    transition_id: string;
    source_keyset_id: string;
    target_keyset_id: string;
    result_digest: string;
    created_at: number;
    expires_at: number;
    receipt_key_id: string;
    signature: string;
}
/** Exact stored success JSON returned by POST and status lookup. */
interface ExchangeSuccessResponse {
    result: ExchangeResult;
    receipt: ExchangeReceipt;
}
interface ExchangeReceiptKeyInfo {
    key_id: string;
    algorithm: 'Ed25519';
    purpose: 'exchange_receipt_active' | 'exchange_receipt_retained';
    public_key_b64: string;
    valid_from: number;
    valid_until: number;
}
interface ExchangeTargetKeysetInfo {
    keyset_id: string;
    /** Canonical ordered descriptor membership. */
    descriptor_ids: string[];
}
interface ExchangeDescriptorInfo {
    descriptor_id: string;
    profile_id: string;
    issuer_id: string;
    token_key_id: string;
    pubkey_spki_b64: string;
    suite: string;
    valid_from: number;
    valid_until: number;
    audience?: string;
}
interface ExchangeTransitionSlotInfo {
    descriptor_id: string;
    slot_id: string;
    class: string;
    quantity: number;
}
type ExchangeAdmissionState = 'accepting_new' | 'recovery_only' | 'disabled';
interface ExchangeTransitionInfo {
    transition_id: string;
    source_keyset_id: string;
    target_keyset_id: string;
    source_slots: ExchangeTransitionSlotInfo[];
    output_slots: ExchangeTransitionSlotInfo[];
    budget_id: string;
    budget_limit: number;
    admission_state: ExchangeAdmissionState;
}
interface ExchangeGraphInfo {
    profile_id: 'freebird/public-bearer-exchange/v2';
    graph_id: string;
    descriptors: ExchangeDescriptorInfo[];
    keysets: ExchangeTargetKeysetInfo[];
    transitions: ExchangeTransitionInfo[];
}
/** All-or-nothing V2 exchange trust container from /.well-known/keys. */
interface ExchangeDiscoveryMetadata {
    active_graph: ExchangeGraphInfo;
    retained_graphs: ExchangeGraphInfo[];
    active_receipt_key: ExchangeReceiptKeyInfo;
    retained_receipt_keys: ExchangeReceiptKeyInfo[];
}
interface GraphIssuancePolicyInfo {
    issuance_policy_id: string;
    graph_id: string;
    keyset_id: string;
    descriptor_id: string;
    budget_id: string;
    budget_limit: number;
    quantity: number;
    admission_state: ExchangeAdmissionState;
    authorization_scheme: string;
    /** Published only for v4_local policies; binds the authorization namespace. */
    authorization_scope_digest_b64?: string;
}
interface GraphIssuanceDiscoveryMetadata {
    version: 2;
    policies: GraphIssuancePolicyInfo[];
    replay_authority: GraphIssuanceReplayAuthorityDiscovery;
}
interface GraphIssuanceReplayAuthorityDiscovery {
    authority_id: string;
    v4_scope_digest_tombstones: string[];
}
/** Exact V2 JSON body accepted by POST /v1/public/graph/issue. */
interface GraphIssuanceRequest {
    version: 2;
    public_operation_id: string;
    issuance_policy_id: string;
    graph_id: string;
    keyset_id: string;
    descriptor_id: string;
    blinded_message: string;
    authorization: string;
}
interface GraphIssuanceResult {
    version: 2;
    public_operation_id: string;
    issuance_policy_id: string;
    graph_id: string;
    keyset_id: string;
    descriptor_id: string;
    token_key_id: string;
    quantity: number;
    request_digest: string;
    blind_signature: string;
    result_digest: string;
}
/**
 * Exact persisted inputs needed to retry or observe an issuance operation.
 *
 * The nested request is retained verbatim, while the duplicated selectors and
 * digests make accidental recovery-context mutation detectable without
 * consulting issuer discovery. `blindingState` is intentionally opaque to the
 * SDK and is returned to the caller for finalization.
 */
interface GraphIssuanceRecoveryContext {
    request: GraphIssuanceRequest;
    requestDigest: string;
    publicOperationId: string;
    issuancePolicyId: string;
    graphId: string;
    keysetId: string;
    descriptorId: string;
    statusCapability: string;
    /** The token key selected by the fresh issuance operation. */
    expectedTokenKeyId: string;
    /** Caller-owned RFC 9474 blinding state; the SDK never interprets it. */
    blindingState: unknown;
}
type GraphIssuanceOutcome = {
    kind: 'committed';
    httpStatus: 200;
    response: GraphIssuanceResult;
    rawResponseBody: string;
    cacheControl: 'no-store';
} | {
    kind: 'error';
    httpStatus: 400 | 404 | 409 | 413 | 503;
    response: {
        error: string;
    };
    rawResponseBody: string;
    cacheControl: 'no-store';
};
interface ExchangeTransitionSelection {
    graph: ExchangeGraphInfo;
    transition: ExchangeTransitionInfo;
}
type ExchangeErrorCode = 'invalid_status_capability' | 'invalid_public_operation_id' | 'exchange_request_too_large' | 'exchange_unavailable' | 'invalid_exchange_request' | 'operation_conflict' | 'invalid_exchange' | 'unknown_operation' | 'status_unauthorized';
interface ExchangePendingResponse {
    error: 'exchange_retryable';
}
interface ExchangeErrorResponse {
    error: ExchangeErrorCode;
}
interface ExchangeHttpOutcome {
    /** The exact response text returned by the durable exchange record. */
    rawResponseBody: string;
    cacheControl: 'no-store';
}
interface ExchangeCommittedOutcome extends ExchangeHttpOutcome {
    kind: 'committed';
    httpStatus: 200;
    response: ExchangeSuccessResponse;
}
interface ExchangePendingOutcome extends ExchangeHttpOutcome {
    kind: 'pending';
    httpStatus: 202;
    response: ExchangePendingResponse;
    /** Retry-After delay in whole seconds. */
    retryAfter: number;
}
type ExchangeErrorOutcome = ExchangeHttpOutcome & ({
    kind: 'error';
    httpStatus: 400;
    response: {
        error: 'invalid_status_capability' | 'invalid_public_operation_id' | 'invalid_exchange_request' | 'invalid_exchange';
    };
} | {
    kind: 'error';
    httpStatus: 413;
    response: {
        error: 'exchange_request_too_large';
    };
} | {
    kind: 'error';
    httpStatus: 404;
    response: {
        error: 'unknown_operation';
    };
} | {
    kind: 'error';
    httpStatus: 409;
    response: {
        error: 'operation_conflict';
    };
} | {
    kind: 'error';
    httpStatus: 503;
    response: {
        error: 'exchange_unavailable';
    };
});
type ExchangeOutcome = ExchangeCommittedOutcome | ExchangePendingOutcome | ExchangeErrorOutcome;
interface KeyDiscoveryMetadata {
    issuer_id: string;
    current_epoch: number;
    valid_epochs: number[];
    epoch_duration_sec: number;
    voprf: {
        suite: string;
        kid: string;
        pubkey: string;
    };
    public: PublicKeyInfo[];
    /** Absent on legacy issuers that do not publish exchange metadata. */
    exchange?: ExchangeDiscoveryMetadata;
    /** Absent unless policy-authorized graph initial issuance is configured. */
    graph_issuance?: GraphIssuanceDiscoveryMetadata;
}
/**
 * Represents the .well-known/verifier metadata
 */
interface VerifierMetadata {
    verifier_id: string;
    audience: string;
    scope_digest_b64: string;
}
/**
 * A single vouch proof for Multi-Party Vouching
 */
interface VouchProof {
    voucher_id: string;
    vouchee_id: string;
    timestamp: number;
    signature: string;
    voucher_pubkey_b64: string;
}
/**
 * Supported Sybil resistance proof types.
 * Mirrors the enum in `common/src/api.rs`
 */
type SybilProof = {
    type: 'proof_of_work';
    nonce: number;
    input: string;
    timestamp: number;
} | {
    type: 'rate_limit';
    client_id: string;
    timestamp: number;
} | {
    type: 'invitation';
    code: string;
    signature: string;
} | {
    type: 'registered_user';
    user_id: string;
} | {
    type: 'web_authn';
    subject_hash: string;
    auth_proof: string;
    timestamp: number;
} | {
    type: 'progressive_trust';
    user_id_hash: string;
    first_seen: number;
    tokens_issued: number;
    last_issuance: number;
    hmac_proof: string;
} | {
    type: 'proof_of_diversity';
    user_id_hash: string;
    diversity_score: number;
    unique_networks: number;
    unique_devices: number;
    first_seen: number;
    hmac_proof: string;
} | {
    type: 'multi_party_vouching';
    vouchee_id_hash: string;
    vouches: VouchProof[];
    hmac_proof: string;
    timestamp: number;
} | {
    type: 'social_graph';
    /** Complete cred.presentation artifact encoded as a JSON string. */
    attestation: string;
    /** The presentation_signature field encoded as a hexadecimal string. */
    presentation: string;
} | {
    type: 'multi';
    proofs: SybilProof[];
} | {
    type: 'none';
};
/**
 * Request to issue a token (Client -> Issuer)
 */
interface IssueRequest {
    /** Base64url encoded blinded element */
    blinded_element_b64: string;
    /** Optional context string (unused in v1) */
    ctx_b64?: string;
    /** Sybil resistance proof if required */
    sybil_proof?: SybilProof;
}
/**
 * Response from token issuance (Issuer -> Client)
 */
interface IssueResponse {
    /** Base64url encoded VOPRF evaluation [VERSION|A|B|DLEQ_proof] (131 bytes) */
    token: string;
    /** Key ID used for issuance */
    kid: string;
    /** Issuer identifier */
    issuer_id: string;
    /** Sybil verification details (optional) */
    sybil_info?: {
        required: boolean;
        passed: boolean;
        cost: number;
    };
}
interface PublicIssueRequest {
    /** Base64url encoded RFC 9474 blinded message */
    blinded_msg_b64: string;
    /** Strict lowercase hex token key ID */
    token_key_id?: string;
    /** Sybil resistance proof if required */
    sybil_proof?: SybilProof;
}
interface PublicIssueResponse {
    /** Base64url encoded RFC 9474 blind signature */
    blind_signature_b64: string;
    /** Strict lowercase hex token key ID */
    token_key_id: string;
    /** Issuer identifier */
    issuer_id: string;
    /** Sybil verification details (optional) */
    sybil_info?: {
        required: boolean;
        passed: boolean;
        cost: number;
    };
}
/**
 * Exact JSON body accepted by POST /v1/oprf/issue/batch.
 * Mirrors `BatchIssueReq` in `common/src/api/issuance.rs`.
 */
interface BatchIssueReq {
    /** Base64url-encoded blinded VOPRF elements. */
    blinded_elements: string[];
    /** Optional context string (unused in v1). */
    ctx_b64?: string;
    /** Sybil resistance proof if required. */
    sybil_proof?: SybilProof;
}
/**
 * Per-token outcome of a V4 batch issuance. Mirrors the `TokenResult` enum in
 * `common/src/api/issuance.rs`, tagged on `status` with lowercase variant names.
 */
type TokenResult = {
    status: 'success';
    token: string;
    kid: string;
    issuer_id: string;
} | {
    status: 'error';
    message: string;
    code: string;
};
/**
 * Exact JSON body returned by POST /v1/oprf/issue/batch.
 * Mirrors `BatchIssueResp` in `common/src/api/issuance.rs`.
 */
interface BatchIssueResp {
    results: TokenResult[];
    successful: number;
    failed: number;
    processing_time_ms: number;
    throughput: number;
    sybil_info?: {
        required: boolean;
        passed: boolean;
        cost: number;
    };
}
/**
 * Exact JSON body accepted by POST /v1/public/issue/batch.
 * Mirrors `PublicBatchIssueReq` in `common/src/api/issuance.rs`.
 */
interface PublicBatchIssueReq {
    /** Base64url-encoded RFC 9474 blinded messages. */
    blinded_msgs: string[];
    /** Strict lowercase hex token key ID. */
    token_key_id?: string;
    /** Sybil resistance proof if required. */
    sybil_proof?: SybilProof;
}
/**
 * Exact JSON body returned by POST /v1/public/issue/batch.
 * Mirrors `PublicBatchIssueResp` in `common/src/api/issuance.rs`.
 */
interface PublicBatchIssueResp {
    /** Base64url-encoded RFC 9474 blind signatures, one per blinded message. */
    blind_signatures: string[];
    token_key_id: string;
    issuer_id: string;
    successful: number;
    failed: number;
    processing_time_ms: number;
    throughput: number;
    sybil_info?: {
        required: boolean;
        passed: boolean;
        cost: number;
    };
}
/**
 * Options for {@link FreebirdClient.issueTokens}.
 */
interface IssueTokensOptions {
    /** Sybil resistance proof if required. */
    sybilProof?: SybilProof;
    /** Optional context string (unused in v1). */
    ctxB64?: string;
}
/**
 * Options for {@link FreebirdClient.issuePublicTokens}.
 */
interface IssuePublicTokensOptions {
    /** Strict lowercase hex token key ID of the signing key. */
    tokenKeyId?: string;
    /** Sybil resistance proof if required. */
    sybilProof?: SybilProof;
    /** Issuer identifier embedded in each pass. */
    issuerId: string;
    /** Per-token 32-byte nonces, one per message, embedded in each pass. */
    nonces: Uint8Array[];
}
/**
 * A V5 public bearer pass: the wire format produced by
 * `voprf.buildPublicBearerPass` (and parsed by `voprf.parsePublicBearerPass`).
 */
type PublicBearerPass = Uint8Array;
/**
 * Opaque RFC 9474 blinding state held between blinding and unblinding.
 *
 * `inv` is the secret blinding inverse factor. It must never be persisted to
 * any store; `@cloudflare/blindrsa-ts` handles zeroization of key material.
 */
interface RsaBlindState {
    /** Secret blinding inverse factor. Never persist. */
    inv: Uint8Array;
    /** The RFC 9474 prepared message that was blinded. */
    prepared: Uint8Array;
    /** SPKI DER bytes of the RSA public key used for blinding. */
    publicKey: Uint8Array;
}
/**
 * Options for {@link FreebirdClient.issuePublicToken}.
 */
interface IssuePublicTokenOptions {
    /** 32-byte public bearer nonce embedded in the pass. */
    nonce: Uint8Array;
    /** Strict lowercase hex token key ID of the signing key. */
    tokenKeyId: string;
    /** Issuer identifier embedded in the pass. */
    issuerId: string;
    /** Sybil resistance proof if required. */
    sybilProof?: SybilProof;
}
/**
 * Internal state maintained between blinding and unblinding.
 * This must be kept secure on the client.
 */
interface BlindState {
    /** The random scalar 'r' used for blinding */
    r: bigint;
    /** The original hashed point H(input) */
    p: any;
}
/**
 * A complete, unblinded token ready for use.
 */
interface FreebirdToken {
    /** Base64url-encoded redemption token */
    tokenValue: string;
    /** The Issuer ID this token belongs to (extracted for convenience) */
    issuerId: string;
    /** Token wire version */
    version?: 4 | 5;
    /** V4 key ID used for issuance */
    kid?: string;
    /** V5 public bearer token key ID */
    tokenKeyId?: string;
    /**
     * Unix timestamp (seconds) at which the token expires, taken from
     * `PublicKeyInfo.valid_until`. Token stores use this to evict expired
     * tokens on `load`/`list`. Absent for tokens without a known expiry.
     */
    valid_until?: number;
}
/**
 * A persistent store for issued tokens.
 *
 * Implementations must evict expired tokens (those whose `valid_until` has
 * passed) on `load` and `list`. Tokens are keyed by their `tokenValue`.
 */
interface TokenStore {
    /** Persists a token, replacing any existing token with the same id. */
    save(token: FreebirdToken): Promise<void>;
    /**
     * Loads a token by id (its `tokenValue`). When `id` is omitted, returns the
     * most recently saved token, or `null` if the store is empty.
     */
    load(id?: string): Promise<FreebirdToken | null>;
    /** Lists all non-expired tokens. */
    list(): Promise<FreebirdToken[]>;
    /** Removes all tokens from the store. */
    clear(): Promise<void>;
}
/**
 * Exact JSON body accepted by POST /v1/verify and POST /v1/check.
 * Mirrors `VerifyReq` in `common/src/api/verification.rs`.
 */
interface VerifyReq {
    /** Base64url-encoded redemption token. */
    token_b64: string;
}
/**
 * Exact JSON body returned by POST /v1/verify and POST /v1/check.
 * Mirrors `VerifyResp` in `common/src/api/verification.rs`.
 */
interface VerifyResp {
    ok: boolean;
    /** Present only on error responses. */
    error?: string | null;
    /** Unix timestamp (seconds) at which the token was verified. */
    verified_at: number;
}
/** One token in a batch verification request. Mirrors `TokenToVerify`. */
interface TokenToVerify {
    token_b64: string;
}
/**
 * Exact JSON body accepted by POST /v1/verify/batch.
 * Mirrors `BatchVerifyReq` in `common/src/api/verification.rs`.
 */
interface BatchVerifyReq {
    tokens: TokenToVerify[];
}
/**
 * Per-token outcome of a batch verification. Mirrors the `VerifyResult` enum
 * in `common/src/api/verification.rs`, which is tagged on `status` with
 * lowercase variant names. `code` is one of `verification_failed`,
 * `replay_detected`, or `store_error`.
 */
type VerifyResult = {
    status: 'success';
    verified_at: number;
} | {
    status: 'error';
    message: string;
    code: string;
};
/**
 * Exact JSON body returned by POST /v1/verify/batch.
 * Mirrors `BatchVerifyResp` in `common/src/api/verification.rs`.
 */
interface BatchVerifyResp {
    results: VerifyResult[];
    successful: number;
    failed: number;
    processing_time_ms: number;
    throughput: number;
}

/** Options controlling a polling loop. */
interface PollOptions {
    /**
     * Minimum delay (ms) between status polls. Defaults to 1000ms. The server's
     * `retryAfter` (when present) is honored as a floor, so the actual delay is
     * `max(intervalMs, retryAfter * 1000)`.
     */
    intervalMs?: number;
    /** Overall cap (ms) for the polling loop. Defaults to 60000ms. */
    timeoutMs?: number;
    /** Cancels the polling loop. */
    signal?: AbortSignal;
}
/**
 * Polls a status fetcher until a terminal outcome is reached.
 *
 * `shouldRetry` decides whether an outcome is retryable (e.g. a pending
 * exchange or a retryable 503); `retryAfterOf` extracts the server-provided
 * retry delay (in whole seconds) from a retryable outcome, used as the floor
 * for the next poll. Throws {@link PollTimeoutError} if `timeoutMs` elapses
 * and {@link PollAbortedError} if `signal` is aborted.
 */
declare function pollUntilTerminal<T extends {
    kind: string;
}>(fetchStatus: () => Promise<T>, options: PollOptions, shouldRetry: (outcome: T) => boolean, retryAfterOf: (outcome: T) => number | undefined): Promise<T>;
/**
 * Polls an exchange status until it is committed or fails terminally.
 *
 * Retries while the outcome is `pending`, honoring the server's `retryAfter`
 * (in whole seconds) as the floor for the next poll.
 */
declare function pollExchangeStatus(fetchStatus: () => Promise<ExchangeOutcome>, options?: PollOptions): Promise<ExchangeOutcome>;
/**
 * Polls a graph issuance status until it is committed or fails terminally.
 *
 * Graph issuance has no `pending` state; the only retryable outcome is a 503
 * (`graph_issuance_unavailable`), which is retried on the configured interval.
 */
declare function pollGraphIssuanceStatus(fetchStatus: () => Promise<GraphIssuanceOutcome>, options?: PollOptions): Promise<GraphIssuanceOutcome>;

type SelectExchangeTransition = (graphId: string, transitionId: string) => Promise<ExchangeTransitionSelection>;

/**
 * Options for {@link exchangePasses}.
 */
interface ExchangePassesOptions {
    /**
     * Explicit public operation id. Defaults to a fresh {@link generateOperationId}.
     */
    publicOperationId?: string;
    /**
     * Messages to blind for each output slot, in `transition.output_slots` order.
     *
     * When omitted, a fresh 32-byte nonce is generated per output and the message
     * is built with the target descriptor's token key and issuer id, so the caller
     * writes no bespoke protocol code. Supply explicit messages when the caller
     * needs to retain the nonces (and blinding state) for later unblinding.
     */
    messages?: Uint8Array[];
}
/**
 * Generates a canonical base64url operation id for exactly 16 bytes, matching
 * `validateExchangeOperationId` / `isCanonicalBase64Url(…, 16)`.
 *
 * The value is drawn from a CSPRNG because it is a public, non-secret operation
 * identifier that must still be unguessable to avoid operation collisions.
 */
declare function generateOperationId(): string;
/**
 * Generates a canonical base64url status capability for exactly 32 bytes,
 * matching `validateStatusCapability` / `validateGraphStatusCapability`.
 *
 * The value is drawn from a CSPRNG because it is an unguessable capability
 * token that authorizes status lookups for an exchange operation.
 */
declare function generateStatusCapability(): string;
/**
 * Assembles a valid V2 `ExchangeRequest` from an explicit graph/transition
 * selection, filling `public_operation_id`, `graph_id`, `transition_id`,
 * `source_keyset_id`, `target_keyset_id`, `sources`, and blinded `outputs`.
 *
 * `sources` must carry one artifact per `transition.source_slots` entry, with
 * slots matching the transition's source slots and keyset. Each output slot is
 * blinded with the target descriptor's RSA public key.
 */
declare function exchangePasses(sources: ExchangeRequestSource[], transition: {
    graphId: string;
    transitionId: string;
}, opts: ExchangePassesOptions | undefined, selectTransition: SelectExchangeTransition): Promise<ExchangeRequest>;

declare class FreebirdClient {
    private state;
    constructor(config: ClientConfig);
    /**
     * The optional {@link TokenStore} configured for this client, or `undefined`
     * if none was provided.
     */
    get tokenStore(): TokenStore | undefined;
    /** Initializes the client by fetching the issuer's public key. */
    init(): Promise<void>;
    /** Issues a new anonymous V4 token. */
    issueToken(sybilProof?: SybilProof): Promise<FreebirdToken>;
    /**
     * Issues a batch of anonymous V4 tokens.
     *
     * `msgs` determines how many tokens to issue (one per element; the element
     * content is not part of the V4 input). Inputs larger than 10_000 are
     * chunked into multiple requests. If any token fails, a
     * {@link BatchIssuanceError} is thrown carrying the per-token outcomes and
     * the successfully finalized tokens.
     */
    issueTokens(msgs: Uint8Array[], opts?: IssueTokensOptions): Promise<FreebirdToken[]>;
    getKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata>;
    /**
     * Forces a fresh fetch of the issuer's `/.well-known/keys` discovery
     * metadata, bypassing the TTL-based cache. Useful for long-lived clients
     * that want to observe key rotation proactively.
     */
    refreshKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata>;
    /** Requests a V5 public bearer pass blind signature. */
    issuePublicBlindSignature(blindedMsg: Uint8Array | string, sybilProof?: SybilProof, tokenKeyId?: string): Promise<PublicIssueResponse>;
    /**
     * Issues a complete V5 public bearer pass in one call.
     *
     * `msg` is the message to be blindly signed (typically the output of
     * `crypto.buildPublicBearerMessage(nonce, tokenKeyId, issuerId)`). The
     * caller supplies the nonce, token key ID, and issuer ID via `opts`, which
     * are also embedded in the returned pass.
     *
     * The blinding factor is held only in memory for the duration of the call
     * and is never persisted.
     */
    issuePublicToken(msg: Uint8Array, opts: IssuePublicTokenOptions): Promise<PublicBearerPass>;
    /**
     * Issues a batch of V5 public bearer passes in one call.
     *
     * Each `msgs[i]` is the message to be blindly signed (typically the output of
     * `crypto.buildPublicBearerMessage(nonces[i], tokenKeyId, issuerId)`).
     * `opts.nonces[i]` and `opts.issuerId` are embedded in the returned pass.
     * Inputs larger than 10_000 are chunked into multiple requests.
     */
    issuePublicTokens(msgs: Uint8Array[], opts: IssuePublicTokensOptions): Promise<PublicBearerPass[]>;
    /**
     * Locally verifies the RSA-PSS signature of a V5 public bearer pass against
     * the given public key.
     *
     * NOTE: local verification checks only cryptographic validity. It does NOT
     * check spend status (whether the pass has already been used). Only the
     * verifier's `/v1/verify` endpoint enforces single-use replay protection.
     */
    verifyPublicBearerPassLocally(pass: PublicBearerPass, keyInfo: PublicKeyInfo): Promise<boolean>;
    /** Resolves an explicit immutable graph and transition selection. */
    selectExchangeTransition(graphId: string, transitionId: string): Promise<ExchangeTransitionSelection>;
    /** Starts or exactly retries a V2 public bearer exchange operation. */
    exchange(request: ExchangeRequest, statusCapability: string): Promise<ExchangeOutcome>;
    /** Looks up a V2 exchange operation. */
    getExchangeStatus(submittedRequest: ExchangeRequest, statusCapability: string): Promise<ExchangeOutcome>;
    getExchangeStatus(publicOperationId: string, statusCapability: string, submittedRequest: ExchangeRequest): Promise<ExchangeOutcome>;
    exchangeRequestDigest(request: ExchangeRequest): string;
    /** Generates a canonical 16-byte base64url exchange operation id. */
    generateOperationId(): string;
    /** Generates a canonical 32-byte base64url exchange status capability. */
    generateStatusCapability(): string;
    /**
     * Assembles a valid V2 `ExchangeRequest` from an explicit graph/transition
     * selection, blinding the output slots with the target descriptors' keys.
     */
    exchangePasses(sources: ExchangeRequestSource[], transition: {
        graphId: string;
        transitionId: string;
    }, opts?: ExchangePassesOptions): Promise<ExchangeRequest>;
    /** Resolves one current graph issuance policy. */
    selectGraphIssuancePolicy(policyId: string): Promise<GraphIssuancePolicyInfo>;
    /** Starts a fresh policy-authorized graph blind issuance operation. */
    issueGraphBlindSignature(request: GraphIssuanceRequest, statusCapability: string): Promise<GraphIssuanceOutcome>;
    /** Retries an already-created graph issuance operation. */
    retryGraphBlindSignature(context: GraphIssuanceRecoveryContext): Promise<GraphIssuanceOutcome>;
    /** Alias with the protocol name used by recovery callers. */
    retryGraphIssuance(context: GraphIssuanceRecoveryContext): Promise<GraphIssuanceOutcome>;
    /** Builds a complete context suitable for durable recovery. */
    createGraphIssuanceRecoveryContext(request: GraphIssuanceRequest, statusCapability: string, expectedTokenKeyId: string, blindingState: unknown): Promise<GraphIssuanceRecoveryContext>;
    /** Observes a graph issuance result using persisted recovery context. */
    getGraphIssuanceStatus(context: GraphIssuanceRecoveryContext): Promise<GraphIssuanceOutcome>;
    /**
     * Polls an exchange operation until it is committed or fails terminally.
     *
     * Retries while the status is `pending`, honoring the server's `retryAfter`
     * as the floor for the next poll. Throws {@link PollTimeoutError} on
     * `timeoutMs` and {@link PollAbortedError} on `signal` abort.
     */
    pollExchangeStatus(request: ExchangeRequest, statusCapability: string, options?: PollOptions): Promise<ExchangeOutcome>;
    /**
     * Polls a graph issuance operation until it is committed or fails
     * terminally. Retries on retryable 503 outcomes. Throws
     * {@link PollTimeoutError} on `timeoutMs` and {@link PollAbortedError} on
     * `signal` abort.
     */
    pollGraphIssuanceStatus(context: GraphIssuanceRecoveryContext, options?: PollOptions): Promise<GraphIssuanceOutcome>;
    graphIssuanceRequestDigest(request: GraphIssuanceRequest): string;
    graphIssuanceAuthorizationBindingDigest(request: GraphIssuanceRequest): string;
    /**
     * Verifies a token against the configured verifier, consuming it. Throws
     * typed errors on failure (see {@link verification.verifyToken}).
     */
    verifyToken(token: FreebirdToken): Promise<VerifyResp>;
    /**
     * Boolean convenience over {@link verifyToken}. Returns `false` for invalid
     * or replayed tokens; rethrows infrastructure errors (verifier unavailable,
     * rate limited, not configured).
     */
    verifyTokenValid(token: FreebirdToken): Promise<boolean>;
    /**
     * Checks token validity WITHOUT consuming it (distinct `/v1/check` endpoint).
     */
    checkToken(token: FreebirdToken): Promise<VerifyResp>;
    /** Verifies a batch of tokens in one request, consuming each. */
    verifyBatch(tokens: FreebirdToken[]): Promise<BatchVerifyResp>;
}

/**
 * Stable machine-readable failure codes carried by every {@link FreebirdError}.
 *
 * These are intentionally coarse and stable so consumers can branch on them
 * without depending on human-readable messages. Messages stay generic; detail
 * belongs in the `code` and server-side logs (never echoed to end users).
 */
type FreebirdErrorCode = 'discovery' | 'verification' | 'verifier_not_configured' | 'exchange' | 'graph_issuance' | 'issuance' | 'rate_limited' | 'verifier_unavailable' | 'invalid_token' | 'replayed_token' | 'poll';
/**
 * Base class for every typed error thrown by the SDK.
 *
 * Carries a stable {@link FreebirdErrorCode} and a generic, non-leaky message.
 */
declare class FreebirdError extends Error {
    readonly code: FreebirdErrorCode;
    constructor(code: FreebirdErrorCode, message: string);
}
/** Discovery metadata could not be fetched or failed validation. */
declare class DiscoveryError extends FreebirdError {
    constructor(message?: string);
}
/** A token could not be verified. */
declare class VerificationError extends FreebirdError {
    constructor(message?: string, code?: FreebirdErrorCode);
}
/** The client is not configured with a verifier endpoint. */
declare class VerifierNotConfiguredError extends FreebirdError {
    constructor(message?: string);
}
/** A V2 public bearer exchange operation failed. */
declare class ExchangeError extends FreebirdError {
    readonly outcome?: ExchangeOutcome;
    constructor(message?: string, outcome?: ExchangeOutcome);
}
/** A graph issuance operation failed. */
declare class GraphIssuanceError extends FreebirdError {
    readonly outcome?: GraphIssuanceOutcome;
    constructor(message?: string, outcome?: GraphIssuanceOutcome);
}
/** The server rate-limited the request; `retryAfter` is in whole seconds. */
declare class RateLimitedError extends FreebirdError {
    readonly retryAfter: number;
    constructor(retryAfter: number, message?: string);
}
/** The verifier is temporarily unavailable (retryable). */
declare class VerifierUnavailableError extends FreebirdError {
    constructor(message?: string);
}
/** The presented token is invalid (malformed or failed verification). */
declare class InvalidTokenError extends VerificationError {
    constructor(message?: string);
}
/** The presented token has already been used (replay detected). */
declare class ReplayedTokenError extends VerificationError {
    constructor(message?: string);
}
/** A polling operation failed (base class for poll-specific errors). */
declare class PollError extends FreebirdError {
    constructor(message?: string);
}
/** A polling operation exceeded its `timeoutMs` cap. */
declare class PollTimeoutError extends PollError {
    constructor(message?: string);
}
/** A polling operation was cancelled via its `AbortSignal`. */
declare class PollAbortedError extends PollError {
    constructor(message?: string);
}
/**
 * One or more tokens in a batch issuance failed.
 *
 * The successfully finalized tokens are carried on `tokens` (in input order,
 * with failures omitted) and the raw per-token outcomes on `results`, so
 * callers can see exactly which tokens failed and why without the failure
 * details being silently dropped.
 */
declare class BatchIssuanceError extends FreebirdError {
    readonly results: TokenResult[];
    readonly tokens: FreebirdToken[];
    readonly failed: number;
    constructor(results: TokenResult[], tokens: FreebirdToken[]);
}

/**
 * The stable id used to key tokens in a {@link TokenStore}: the redemption
 * token value, which is unique per issued token.
 */
declare function tokenId(token: FreebirdToken): string;
/**
 * An in-memory {@link TokenStore}. Useful for tests and short-lived sessions;
 * does not survive process restarts.
 */
declare class MemoryTokenStore implements TokenStore {
    private readonly tokens;
    save(token: FreebirdToken): Promise<void>;
    load(id?: string): Promise<FreebirdToken | null>;
    list(): Promise<FreebirdToken[]>;
    clear(): Promise<void>;
    private evict;
}
/** Options for {@link StorageTokenStore}. */
interface StorageTokenStoreOptions {
    /**
     * The storage key. In a browser this is the `localStorage` key; in Node it
     * is the filesystem path of the token file.
     */
    key: string;
}
/**
 * A durable {@link TokenStore} backed by `localStorage` in the browser and by
 * the filesystem in Node.
 *
 * Node writes follow the repo's security hygiene: the file is written to a
 * temporary sibling, `fsync`ed, and atomically renamed into place, with mode
 * `0o600` on Unix so token material is not world-readable.
 */
declare class StorageTokenStore implements TokenStore {
    private readonly key;
    private readonly useBrowser;
    constructor(options: StorageTokenStoreOptions);
    save(token: FreebirdToken): Promise<void>;
    load(id?: string): Promise<FreebirdToken | null>;
    list(): Promise<FreebirdToken[]>;
    clear(): Promise<void>;
    private readAll;
    private writeAll;
}

/**
 * Serializes a {@link GraphIssuanceRecoveryContext} to a documented JSON
 * envelope:
 *
 * ```json
 * {
 *   "version": 1,
 *   "type": "graph_issuance_recovery_context",
 *   "context": { ...GraphIssuanceRecoveryContext }
 * }
 * ```
 *
 * SECURITY: `blindingState` is opaque and caller-owned. It is included in the
 * round-trip so the context can be reconstructed in memory, but it may contain
 * secret RFC 9474 blinding material (`RsaBlindState.inv`). Do NOT persist this
 * serialization to a durable store; keep it in memory only. The token store
 * never stores recovery contexts.
 */
declare function serializeGraphIssuanceRecoveryContext(context: GraphIssuanceRecoveryContext): string;
/**
 * Deserializes a {@link GraphIssuanceRecoveryContext} produced by
 * {@link serializeGraphIssuanceRecoveryContext}. Validates the envelope and
 * the context shape. Throws {@link GraphIssuanceError} on malformed input.
 */
declare function deserializeGraphIssuanceRecoveryContext(serialized: string): GraphIssuanceRecoveryContext;

/** The `proof_of_work` {@link SybilProof} variant produced by the miner. */
type ProofOfWorkProof = Extract<SybilProof, {
    type: 'proof_of_work';
}>;
/**
 * Verifies that a (input, nonce, timestamp) triple satisfies `difficulty`
 * leading zero bits. Matches `ProofOfWork::verify_hash`.
 */
declare function verifyPow(input: string, nonce: number, timestamp: number, difficulty: number): boolean;
/**
 * Mines a `proof_of_work` {@link SybilProof} for the given request-binding
 * `input` at the given `difficulty` (leading zero bits).
 *
 * The loop is async and yields to the event loop every `yieldEvery`
 * iterations so a long mine does not block other work.
 */
declare function generateProofOfWork(input: string, difficulty: number, opts?: {
    timestamp?: number;
    yieldEvery?: number;
}): Promise<ProofOfWorkProof>;
/**
 * V4 single-issue request binding.
 * Matches `issue.rs`: `freebird:issue:v1:<issuer_id>:<blinded_element_b64>`.
 */
declare function buildIssueBinding(issuerId: string, blindedElementB64: string): string;
/**
 * V5 public single-issue request binding.
 * Matches `public_issue.rs`: `freebird:public-issue:v1:<issuer_id>:<blinded_msg_b64>`.
 */
declare function buildPublicIssueBinding(issuerId: string, blindedMsgB64: string): string;
/**
 * V4 renewal request binding.
 * Matches `issue.rs`: `freebird:renew:v1:<issuer_id>:<blinded_element_b64>`.
 */
declare function buildRenewBinding(issuerId: string, blindedElementB64: string): string;
/**
 * Batch request binding. Matches `batch_request_binding` in `batch_issue.rs`:
 * the SHA-256 of each element's little-endian u64 length followed by its bytes,
 * truncated to 16 bytes and base64url-encoded.
 *
 * `routeScope` is `"issue-batch"` (V4) or `"public-issue-batch"` (V5).
 */
declare function buildBatchBinding(routeScope: string, issuerId: string, blindedElements: string[]): string;

/**
 * Blinds the input for the VOPRF protocol.
 * Corresponds to Rust: Client::blind
 */
declare function blind(input: Uint8Array, context: Uint8Array): {
    blinded: Uint8Array;
    state: BlindState;
};
/**
 * Verifies the issuer's response, unblinds, and returns the 32-byte PRF output.
 * Corresponds to Rust: Client::finalize
 *
 * Returns the unblinded PRF output: SHA-256("VOPRF-P256-SHA256:Finalize" || ctx || W)
 * where W = B * r^(-1) is the unblinded evaluated point.
 */
declare function finalize(state: BlindState, tokenB64: string, issuerPubkeyB64: string, context: Uint8Array): Uint8Array;
/**
 * Builds the verifier/audience scope digest clients bind into V4 tokens.
 */
declare function buildScopeDigest(verifierId: string, audience: string): Uint8Array;
/**
 * Builds the public input that is blindly issued and privately re-evaluated.
 */
declare function buildPrivateTokenInput(issuerId: string, kid: string, nonce: Uint8Array, scopeDigest: Uint8Array): Uint8Array;
/**
 * Builds a V4 redemption token for wire transmission.
 * Format: [version(1) | nonce(32) | scope_digest(32) | kid_len(1) | kid(var) | issuer_id_len(1) | issuer_id(var) | authenticator(32)]
 */
declare function buildRedemptionToken(nonce: Uint8Array, scopeDigest: Uint8Array, kid: string, issuerId: string, authenticator: Uint8Array): Uint8Array;
/**
 * Parses a V4 redemption token from wire bytes.
 */
declare function parseRedemptionToken(bytes: Uint8Array): {
    nonce: Uint8Array;
    scopeDigest: Uint8Array;
    kid: string;
    issuerId: string;
    authenticator: Uint8Array;
};
/**
 * Computes the strict V5 token key ID: SHA-256(pubkey_spki).
 */
declare function tokenKeyIdFromSpki(pubkeySpki: Uint8Array): Uint8Array;
declare function tokenKeyIdToHex(tokenKeyId: Uint8Array): string;
declare function tokenKeyIdFromHex(tokenKeyIdHex: string): Uint8Array;
/**
 * Builds the canonical 48-byte V5 public bearer pass message digest.
 *
 * Pass this digest as the message to an RFC 9474
 * RSABSSA-SHA384-PSS-Deterministic blind-signature implementation.
 */
declare function buildPublicBearerMessage(nonce: Uint8Array, tokenKeyId: Uint8Array, issuerId: string): Uint8Array;
/**
 * Builds the V5 public bearer pass wire format.
 * Format: [version(1) | nonce(32) | token_key_id(32) | issuer_id_len(1) | issuer_id(var) | sig_len(2,BE) | signature(var)]
 */
declare function buildPublicBearerPass(nonce: Uint8Array, tokenKeyId: Uint8Array, issuerId: string, signature: Uint8Array): Uint8Array;
declare function parsePublicBearerPass(bytes: Uint8Array): {
    nonce: Uint8Array;
    tokenKeyId: Uint8Array;
    issuerId: string;
    signature: Uint8Array;
};

/** Build the raw V2 HMAC authorization transcript used by the issuer. */
declare function graphIssuanceHmacAuthorizationTranscriptV2(nonce: Uint8Array, policyId: string, authorizationBindingDigest: Uint8Array): Uint8Array;
/** Return the raw V2 HMAC-SHA256 tag. */
declare function graphIssuanceHmacAuthorizationTagV2(secret: Uint8Array, nonce: Uint8Array, policyId: string, authorizationBindingDigest: Uint8Array): Uint8Array;
/** Construct canonical `nonce_raw || tag_raw` authorization bytes. */
declare function buildGraphIssuanceHmacAuthorizationV2(secret: Uint8Array, nonce: Uint8Array, policyId: string, authorizationBindingDigest: Uint8Array): string;
/** Parse a canonical V2 authorization into its raw nonce and tag. */
declare function parseGraphIssuanceHmacAuthorizationV2(authorization: string): {
    nonce: Uint8Array;
    tag: Uint8Array;
};
/** Verify a V2 authorization and return its raw nonce. */
declare function verifyGraphIssuanceHmacAuthorizationV2(secret: Uint8Array, policyId: string, authorizationBindingDigest: Uint8Array, authorization: string): Uint8Array;
declare const hmacAuthorizationTranscriptV2: typeof graphIssuanceHmacAuthorizationTranscriptV2;
declare const hmacAuthorizationTagV2: typeof graphIssuanceHmacAuthorizationTagV2;
declare const buildHmacAuthorizationV2: typeof buildGraphIssuanceHmacAuthorizationV2;
declare const parseHmacAuthorizationV2: typeof parseGraphIssuanceHmacAuthorizationV2;
declare const verifyHmacAuthorizationV2: typeof verifyGraphIssuanceHmacAuthorizationV2;

/**
 * Blinds `msg` for RFC 9474 RSABSSA-SHA384-PSS-Deterministic signing.
 *
 * `publicKey` is the RSA public key as SPKI DER bytes. The returned `state`
 * holds the secret blinding inverse factor and must never be persisted to any
 * store; `@cloudflare/blindrsa-ts` handles zeroization of key material.
 */
declare function rsaBlind(publicKey: Uint8Array, msg: Uint8Array): Promise<{
    blinded: Uint8Array;
    state: RsaBlindState;
}>;
/**
 * Unblinds a blind signature produced by the issuer, returning the final
 * RSA-PSS signature over the original message.
 */
declare function rsaUnblind(state: RsaBlindState, blindSignature: Uint8Array): Promise<Uint8Array>;
/**
 * Verifies an RSA-PSS/SHA-384 signature over `msg` using the RSA public key
 * (SPKI DER bytes) via WebCrypto `subtle.verify`. Returns `true` only if the
 * signature is valid.
 */
declare function rsaVerify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): Promise<boolean>;

/**
 * Freebird SDK
 * Anonymous authentication using VOPRF (Verifiable Oblivious Pseudorandom Function).
 *
 * @module @freebird/sdk
 */

declare const crypto: {
    blind: typeof blind;
    finalize: typeof finalize;
    buildScopeDigest: typeof buildScopeDigest;
    buildPrivateTokenInput: typeof buildPrivateTokenInput;
    buildRedemptionToken: typeof buildRedemptionToken;
    parseRedemptionToken: typeof parseRedemptionToken;
    tokenKeyIdFromSpki: typeof tokenKeyIdFromSpki;
    tokenKeyIdToHex: typeof tokenKeyIdToHex;
    tokenKeyIdFromHex: typeof tokenKeyIdFromHex;
    buildPublicBearerMessage: typeof buildPublicBearerMessage;
    buildPublicBearerPass: typeof buildPublicBearerPass;
    parsePublicBearerPass: typeof parsePublicBearerPass;
    rsaBlind: typeof rsaBlind;
    rsaUnblind: typeof rsaUnblind;
    rsaVerify: typeof rsaVerify;
    graphIssuanceHmacAuthorizationTranscriptV2: typeof graphIssuanceHmacAuthorizationTranscriptV2;
    graphIssuanceHmacAuthorizationTagV2: typeof graphIssuanceHmacAuthorizationTagV2;
    buildGraphIssuanceHmacAuthorizationV2: typeof buildGraphIssuanceHmacAuthorizationV2;
    parseGraphIssuanceHmacAuthorizationV2: typeof parseGraphIssuanceHmacAuthorizationV2;
    verifyGraphIssuanceHmacAuthorizationV2: typeof verifyGraphIssuanceHmacAuthorizationV2;
    hmacAuthorizationTranscriptV2: typeof graphIssuanceHmacAuthorizationTranscriptV2;
    hmacAuthorizationTagV2: typeof graphIssuanceHmacAuthorizationTagV2;
    buildHmacAuthorizationV2: typeof buildGraphIssuanceHmacAuthorizationV2;
    parseHmacAuthorizationV2: typeof parseGraphIssuanceHmacAuthorizationV2;
    verifyHmacAuthorizationV2: typeof verifyGraphIssuanceHmacAuthorizationV2;
};

export { BatchIssuanceError, BatchIssueReq, BatchIssueResp, BatchVerifyReq, BatchVerifyResp, BlindState, ClientConfig, DiscoveryError, ExchangeCommittedOutcome, ExchangeDescriptorInfo, ExchangeDiscoveryMetadata, ExchangeError, ExchangeErrorCode, ExchangeErrorOutcome, ExchangeErrorResponse, ExchangeOutcome, ExchangePassesOptions, ExchangePendingOutcome, ExchangePendingResponse, ExchangeReceipt, ExchangeReceiptKeyInfo, ExchangeRequest, ExchangeRequestOutput, ExchangeRequestSource, ExchangeResult, ExchangeResultOutput, ExchangeSlot, ExchangeSuccessResponse, ExchangeTargetKeysetInfo, FreebirdClient, FreebirdError, FreebirdErrorCode, FreebirdToken, GraphIssuanceDiscoveryMetadata, GraphIssuanceError, GraphIssuanceOutcome, GraphIssuancePolicyInfo, GraphIssuanceRecoveryContext, GraphIssuanceReplayAuthorityDiscovery, GraphIssuanceRequest, GraphIssuanceResult, InvalidTokenError, IssuePublicTokenOptions, IssuePublicTokensOptions, IssueRequest, IssueResponse, IssueTokensOptions, IssuerMetadata, KeyDiscoveryMetadata, MemoryTokenStore, PollAbortedError, PollError, PollOptions, PollTimeoutError, PublicBatchIssueReq, PublicBatchIssueResp, PublicBearerPass, PublicIssueRequest, PublicIssueResponse, PublicKeyInfo, RateLimitedError, ReplayedTokenError, RsaBlindState, StorageTokenStore, StorageTokenStoreOptions, SybilConfigSummary, SybilModeSettings, SybilProof, TokenResult, TokenStore, TokenToVerify, TrustLevelSummary, VerificationError, VerifierMetadata, VerifierNotConfiguredError, VerifierUnavailableError, VerifyReq, VerifyResp, VerifyResult, buildBatchBinding, buildGraphIssuanceHmacAuthorizationV2, buildHmacAuthorizationV2, buildIssueBinding, buildPublicIssueBinding, buildRenewBinding, crypto, deserializeGraphIssuanceRecoveryContext, exchangePasses, generateOperationId, generateProofOfWork, generateStatusCapability, graphIssuanceHmacAuthorizationTagV2, graphIssuanceHmacAuthorizationTranscriptV2, hmacAuthorizationTagV2, hmacAuthorizationTranscriptV2, parseGraphIssuanceHmacAuthorizationV2, parseHmacAuthorizationV2, pollExchangeStatus, pollGraphIssuanceStatus, pollUntilTerminal, serializeGraphIssuanceRecoveryContext, tokenId, verifyGraphIssuanceHmacAuthorizationV2, verifyHmacAuthorizationV2, verifyPow };
