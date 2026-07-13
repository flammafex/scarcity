# Scarcity V2 Freebird admission contract

**Normative draft. Contract version: `scarcity/freebird-admission/v2`.**

Freebird retains its native V4 opaque credential and native authenticated
admission envelope. Scarcity adds no competing credential container.

## 1. Exact digest profile

Every digest uses the core's V2 canonical CBOR profile and exact function:

`H(label, bytes) = SHA-256(ASCII("scarcity/v2/" || label || "\0") || bytes)`.

`C(P)` is the canonical CBOR encoding of the explicitly named payload `P`.
There is no generic field-stripping operation. The core's decoder rules,
limits, map ordering, and byte representation apply without service exceptions;
the named projections below are authoritative.

The projections are exactly core's maps, including field names and array
ordering:

```text
TransactionCore = {
  spend_domain: bytes(32),
  inputs: [{ output_id: bytes(32), nullifier: bytes(32), owner_key_id: bytes(32) }],
  outputs: [TxOutput]
}
OperationCore = {
  transaction_core: TransactionCore,
  transaction_digest: bytes(32), owner_authorizations: [Authorization],
  final_note_proofs: [FinalNoteProof], operation_expiry: uint64
}
AdmissionRequestCore = {
  version: 2, federation_id: bytes(32), audience: ASCII text,
  scope: ASCII text, operation_digest: bytes(32), spend_domain: bytes(32),
  admission_policy_digest: bytes(32), request_expiry: uint64
}
```

`transaction_digest = H("transaction", C(TransactionCore))`,
`operation_digest = H("operation", C(OperationCore))`, and
`admission_digest = H("admission", C(AdmissionRequestCore))`. The embedded
`transaction_core` is not replaced by its digest. Inputs, final-note proofs,
owner authorizations, and issuer proofs use core's specified ordering.
Assertions, credentials, binding keys/signatures, redemption IDs, transport
fields, and retry keys are excluded. No digest is recursive; these bytes are
the core fixture bytes, not a service approximation.

## 2. Policy, scopes, and binding

The federation publishes exactly this core-aligned immutable policy payload:

```text
AdmissionPolicy = {
  authority_id: bytes(32), federation_id: bytes(32), policy_version: uint64,
  valid_from: uint64, valid_until: uint64,
  allowed_audiences: [ASCII text], scope_rules: [{scope: ASCII text,
    enabled: boolean}], issuer_key_epochs: [{issuer_id: bytes(32),
    first_epoch: uint64, last_epoch: uint64}],
  asset_ids: [bytes(32)], spend_domains: [bytes(32)],
  max_operation_bytes: uint64, max_inputs: uint16, max_outputs: uint16,
  replay_window: uint64
}
ValidationPolicy = {
  authority_id: bytes(32), federation_id: bytes(32), policy_version: uint64,
  valid_from: uint64, valid_until: uint64, spend_domain: bytes(32),
  accepted_asset_ids: [bytes(32)], max_inputs: uint16, max_outputs: uint16,
  expiry_policy_digests: [bytes(32)]
}
```

Arrays are sorted by canonical byte value with no duplicates. The exact
digests are `admission_policy_digest = H("admission-policy", C(AdmissionPolicy))`
and `validation_policy_digest = H("validation-policy", C(ValidationPolicy))`.
The native Ed25519 authority signature envelope is excluded from each named
payload. A policy is authoritative only for its authority, version, epoch, and
deterministic block/header-time validity interval.

`mint-request` is optional and issuer-configured. `spend` is mandatory when
the federation's AdmissionPolicy enables spend admission. Audience and scope
matching are exact; wildcard, prefix, stale, or issuer-audience substitution
is rejected. Bridges and unspecified scopes are rejected.

Each operation uses a fresh ephemeral Ed25519 binding key. The private key is
never sent or persisted. The client signs the canonical binding payload:
`"scarcity/v2/freebird-binding\0" || admission_digest || operation_digest ||
binding_public_key`. The native Freebird redemption envelope carries the
public key and signature. Reuse for another operation is invalid.

## 3. Redemption and signed assertion

The native Freebird redemption request carries the opaque V4 credential,
`AdmissionRequestCore`, `admission_digest`, ephemeral binding public key and
signature, and a stable retry key. Freebird atomically validates credential,
replay state, audience, scope, binding, policy authority/version/digest, issuer
epoch, and request expiry before reserving its single-use replay key.

Success returns the native Freebird authenticated assertion envelope. Its
signed payload contains exactly the public fields:

```text
{ version, verifier_id, federation_id, audience, scope,
  operation_digest, admission_digest, binding_public_key,
  admission_policy_digest, assertion_id, issued_at, expires_at,
  verifier_key_id }
```

The native Freebird verifier signature covers that payload. No new generic
Scarcity wrapper is introduced. Witness verifies the native envelope offline
against the configured verifier key epoch and policy object. It checks every
field, including both digests, binding, audience, scope, and expiry. At ABCI
commit processing, it compares `expires_at` with deterministic CometBFT block
time; local gateway clocks are irrelevant. An expired assertion is rejected
and cannot be made valid by retrying.

## 4. Authenticated reconciliation and recovery

Freebird/federation and Witness exchange only public digest IDs and native
artifacts over authenticated transport. The callback payload is the native
Witness finality artifact plus `{operation_digest, admission_digest,
assertion_id, status}`; the query request is `{operation_digest,
admission_digest, assertion_id}` and the response is the same authenticated
status/artifact. Status values are `accepted`, `committed`, `finalized`,
`rejected`, `conflict`, or `expired`.

The durable authorization state machine is:

| State | Meaning | Terminal mapping/action |
|---|---|---|
| `UNUSED` | No replay reservation | atomically enter `REDEEMING` |
| `REDEEMING` | Reservation/response transaction uncertain | recover by exact retry key; `AUTHORIZED` or `REJECTED` |
| `AUTHORIZED` | Assertion issued, no commit known | submit exact operation; `SUBMITTED` |
| `SUBMITTED` | Witness accepted or outcome unknown | authenticated query/callback; `COMMITTED`, `CONFLICT`, `REJECTED`, or `EXPIRED` |
| `COMMITTED` | CometBFT block and valid commit certificate observed | verify artifact; `FINALIZED` |
| `FINALIZED` | Native Witness artifact verified | terminal; credential remains consumed |
| `CONFLICT` | Nullifier/idempotency conflict | terminal; no replacement assertion |
| `REJECTED` | Deterministic admission/ABCI rejection | terminal; new operation may seek admission |
| `EXPIRED` | Commit time exceeded assertion/operation expiry | terminal; no late commit |

The same credential, exact digest tuple, binding key, and retry key returns the
same assertion or terminal result. A changed tuple returns `409
credential_conflict` and never consumes a new authorization. Witness `COMMITTED`
is not `FINALIZED` until its native artifact and commit certificate verify.
Freebird marks `FINALIZED` only from that verified artifact. A lost response is
queried, never guessed; a Freebird outage fails closed for new authorization.

Credentials, private assertion material, binding private keys, and retry
secrets MUST be absent from notes, receipts, FinalNotes, checkpoints, logs
shared with peers, and gossip. Public assertion fields may appear in the
Witness request solely for offline verification. Exact request relay and
metadata observation remain possible and are covered by the threat model.
