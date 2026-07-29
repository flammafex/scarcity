# Scarcity Genesis V1 — Phase-1 Initial-Issuance Contract

Status: authoritative for Phase-1 genesis. Normative terms **MUST**, **MUST
NOT**, **SHOULD**, and **MAY** are used as in RFC 2119.

This contract defines the initial-issuance operation for the
`scarcity/circulating-bearer/v1` class. It complements
`docs/scarcity-circulation-v1.md`; it does not revise, weaken, or replace that
document. A bearer accepted under this document is subsequently subject to
the circulation contract, including its graph, descriptor, vault, Witness,
HyperToken, and privacy rules. Circulation receipts remain governed by that
companion contract; genesis has no receipt object.

## 1. Pinned dependencies and fixed profile

The following dependency revisions are part of this contract:

| Dependency | Required pin | Phase-1 role |
|---|---:|---|
| Freebird v0.8.1 graph issuance, admission authorizer, and transition graph | `7aded788b9fc492b5b9ae3ca0f05a3d3f3c662a6` | Genesis graph-issuance operation, generic `v4_local` one-use admission, and subsequent E01/E10 circulation |
| Witness attestation jobs | `41c130f` | Post-acceptance evidence for circulation only |
| HyperToken safety APIs | `922ec01` | Non-monetary local/transport safety for circulation only |

A different revision is outside this contract until compatibility is reviewed
and this document is explicitly revised. The pins identify implementations;
they do not authorize a caller to add a wrapper endpoint, rename a Freebird
field, or substitute a direct V5 signing call.

The fixed Phase-1 genesis profile is:

| Item | Phase-1 value |
|---|---|
| Class | `scarcity/circulating-bearer/v1` |
| Graph keysets | exactly two role-neutral keysets, `K0` and `K1` |
| Circulation edges | exactly `E01: K0 → K1` and `E10: K1 → K0` |
| Initial output | exactly one artifact in `K0` per successful genesis operation |
| Initial-issuance budget | 100 artifacts for the graph-issuance budget |
| Graph-issuance admission | generic `v4_local`, one-use Freebird admission authorizer |
| Initial graph state | graph issuance `accepting_new`; E01 and E10 `disabled` |
| Genesis acceptance | a locally verified graph-issuance HTTP `200` |
| Witness and HyperToken | neither participates in genesis acceptance |
| Custody | local-only bootstrap; no recovery custody, replica, escrow, or backup |

`K0`, `K1`, `E01`, and `E10` are Scarcity labels. Their wire identities are
the canonical descriptor, keyset, transition, and graph identities produced by
the pinned Freebird implementation. The labels do not add fields to any
Freebird object.

The 100-artifact value is an issuer/graph lifetime charge budget, not a
per-user allowance, a renewable quota, a promise that 100 artifacts will be
committed, or permission to create another issuance edge. A fresh operation
consumes one unit atomically when it creates its durable committed operation
and result. There is no intermediate issuance state to refund. If the
response is lost after commit, an exact retry returns the same committed
result and does not charge a second unit.

## 2. Scope, non-goals, and authority boundaries

### 2.1 Scope

This contract specifies how the operator bootstraps the two-keyset graph and
how a holder of a valid one-use Freebird V4 admission obtains the first K0
bearer through Freebird graph issuance. It specifies the acceptance boundary,
replay protection, exact committed-result retry, lifecycle switch to
circulation, and the executable conformance gates for that operation.

The operation is intentionally one artifact, one class, one K0 target, and one
budget unit. It does not create K1 output and does not traverse E01 or E10.

### 2.2 Non-goals

Genesis does **not** define:

- a direct V5 issue endpoint, a V5 signing API, or a new bearer wire format;
- an exchange, source artifact, source slot, change output, or transition;
- a second graph, keyset, edge, denomination, quantity, or issuance class;
- dividend policy, civic-purpose policy, redemption, demurrage, or accounting;
- a Witness claim, timestamp, finality statement, or attestation job;
- a HyperToken action, relay message, public projection, balance, or history;
- wallet recovery, seed export, administrative restore, escrow, or custody; or
- an offline, fallback, or locally fabricated acceptance path.

Freebird admission establishes eligibility to attempt the operation. It does
not encode value, ownership, an amount, a wallet identity, a nullifier, or a
Scarcity policy decision. The generic graph-issuance runtime establishes the
operation's native result; the Scarcity bootstrap-manifest validator must
establish that it is the required K0-only, quantity-one, budget-100 operation.
Neither the admission authorizer nor a relay determines monetary policy.

### 2.3 Authority boundaries

1. **Pinned Freebird graph issuance** is authoritative for its generic
   graph-issuance request processing, one-use authorizer integration, durable
   committed operation/result behavior, and artifact signing. A Redis marker
   is coordination state for that authority; it is not an independent
   monetary authority. The pinned runtime is not asserted to enforce
   Scarcity's exact two-keyset, edge, K0-only, quantity-one, or budget-100
   profile.
2. **The generic `v4_local` authorizer** is authoritative only for validation
   and one-use consumption of the V4 admission credential. It MUST remain
   economy-blind and MUST NOT be used as a bearer, amount, ownership, or
   issuance-policy record.
3. **The Scarcity bootstrap-manifest validator and genesis client** are the
   Scarcity authorities for the profile and local wallet state. The validator
   MUST enforce the exact Phase-1 graph profile before the client begins. The
   client accepts only after independently verifying the complete
   graph-issuance HTTP `200` against its request and the pinned K0 descriptor.
   A successful HTTP status without verification is not acceptance.
4. **The operator** is authoritative for deployment configuration and the
   lifecycle gate. Operator acknowledgement proves the required disabled-first
   publication evidence; it cannot manufacture a Freebird result or make a
   failed HTTP response acceptable.
5. **Witness** has no genesis role. It MUST NOT be called to approve, order,
   timestamp, repair, or accept initial issuance. Its pinned attestation-job
   API begins only at the post-acceptance circulation boundary.
6. **HyperToken** has no genesis role. It MUST NOT receive a genesis request,
   artifact, operation identifier, admission credential, or wallet state, and it
   MUST NOT project any of them.
7. **The local wallet vault** is authoritative only for the recipient's
   secrets and accepted local record. Loss of the vault or its unlock key is
   loss of the local bearer. Freebird's committed operation/result record is
   not a recovery-custody service.

## 3. Genesis is a graph operation

### 3.1 Why it is not direct V5 issue

V5 is the public bearer cryptographic format used by the graph descriptors. A
direct V5 issue call would be only a signing primitive: it would not, by
itself, prove that the output was selected by this graph's K0 issuance policy,
consume a generic one-use V4 admission, charge the 100-artifact budget, or
produce the complete graph-issuance result. Therefore a V5 blind-signature
result, even if cryptographically valid, is not genesis acceptance.

Graph issuance MAY use the pinned implementation's V5 bearer machinery as an
internal output step. That does not turn it into direct V5 issue. The
authoritative operation is the pinned graph-issuance operation, with its graph
identity, K0 descriptor binding, `v4_local` admission, atomic budget charge, and
signed result. No caller may bypass that operation by invoking a V5 primitive.

### 3.2 Why it is not exchange

An exchange consumes one source artifact and applies an admitted transition
from one keyset to another. Genesis has no source artifact, no source slot, no
transition ID, and no K1 output. It is a graph issuance operation that creates
the first bearer under K0. It MUST NOT be encoded as E01, E10, a self-edge, or
an exchange with an omitted source.

The V4 admission is an authorization input to graph issuance, not an exchange
source and not money. Its one-use consumption is separate from any later
circulation source spend. Once a K0 bearer exists, its subsequent movement is
governed only by `docs/scarcity-circulation-v1.md` and the pinned transition
graph.

## 4. Bootstrap manifest and disabled-first publication

### 4.1 Required manifest

Before serving a genesis request, the operator MUST have one durable,
operator-reviewed bootstrap manifest containing, or unambiguously referencing,
all of the following deployment inputs:

1. **One shared graph runtime.** The graph runtime, graph identity, issuer
   identity, canonicalization rules, admission policy, budget state, and
   committed operation/result store MUST be one coherent Freebird runtime. A
   worker-local graph or worker-local replay database is not a conforming
   deployment.
2. **The K0 descriptor.** It MUST be the single descriptor assigned to K0 and
   the descriptor used by graph issuance for every initial artifact.
3. **The K1 descriptor.** It MUST be the single descriptor assigned to K1 and
   the descriptor used by subsequent E01 output.
4. **Both circulation transitions.** The graph MUST contain exactly E01 and
   E10, with their canonical source and target keyset identities, and both
   MUST initially be `disabled`. No other transition may be enabled or
   served.
5. **The graph-issuance policy.** It MUST be `accepting_new`, select K0 only,
   use the generic `v4_local` one-use Freebird admission authorizer, and have
   the graph issuance budget set to exactly 100 artifacts.
6. **Subsequent-circulation receipt configuration.** If the operator
   preprovisions the active and retained receipt-key configuration required by
   the circulation contract, it MUST record its deployment values and
   validity/retention policy before circulation. This is not a graph-issuance
   prerequisite: the V2 graph-issuance result has no receipt or receipt key, and
   genesis MUST NOT use or verify either.
7. **Redis configuration.** The shared Redis endpoint/cluster, database or
   namespace, TLS and ACL settings, durability/availability mode, and the
   pinned `v4_local`/operation-state configuration MUST be preprovisioned and
   tested. Every graph-issuance worker and every admission-authorizer worker
   MUST use the same replay authority.

The manifest is a deployment control record, not a replacement Freebird wire
object. Wire objects MUST be produced and parsed only through the APIs and
canonical encodings in Freebird `7aded788b9fc492b5b9ae3ca0f05a3d3f3c662a6`. In particular, this document does
not add JSON members, headers, route names, or alternate status values.

### 4.2 Disabled-first acknowledgement

The operator MUST publish the complete graph with E01 and E10 disabled before
either edge can accept fresh circulation. The operator then MUST durably
acknowledge that disabled publication and retain the evidence across restart.
The acknowledgement uses the existing disabled-publication evidence defined by
the circulation contract; it is not a new genesis wire type. Its evidence
MUST contain exactly:

- `version = "freebird/exchange-disabled-publication-ack/v1"`;
- `issuer_id` equal to the pinned issuer identity;
- `graph_id` equal to the canonical graph identity;
- `disabled_transition_ids` containing both and only the canonical E01 and
  E10 transition IDs;
- `acknowledged_admission_state = "disabled"`;
- a non-empty `operator` identity; and
- a nonzero `acknowledged_at_unix` timestamp.

The operator evidence and Freebird's durable disabled-publication markers MUST
refer to the same issuer and graph. A graph with accepting E01 or E10 but no
durable evidence is non-conforming. This evidence does not accept a genesis
request; it establishes the lifecycle precondition for later circulation.

### 4.3 Scarcity manifest validation before service

Freebird's generic graph-issuance runtime and `v4_local` authorizer are not
claimed to enforce the complete Scarcity profile, and this document does not
claim that a Scarcity validator already exists. A required Phase-1
Scarcity bootstrap-manifest validator MUST be implemented and MUST fail closed
before the genesis client begins. It MUST validate the canonical graph
relationships, exactly two keysets K0/K1, exactly E01 and E10, exactly one
descriptor per keyset, E01/E10 initially `disabled`, K0-only graph issuance,
quantity one, the exactly-100-artifact budget, `accepting_new` graph-issuance
policy using generic `v4_local`, and the shared Redis invariant. Restart MUST
NOT reset the budget, delete the global V4 spend markers, or cause a worker to
serve a different graph. This validator is a Scarcity bootstrap component,
not a new Freebird endpoint or a claim about existing code.

## 5. Generic `v4_local` admission and shared Redis replay

### 5.1 V4 credential and request boundary

The admission credential is the Freebird V4 private-verification redemption
token accepted by the pinned generic `v4_local` authorizer. The current V4
canonical byte layout is the Freebird-defined layout:

```text
version(0x04) || nonce(32) || scope_digest(32) ||
kid_len(1) || kid || issuer_id_len(1) || issuer_id || authenticator(32)
```

Its transport encoding, and the placement of that encoding in a graph-
issuance request, MUST be exactly what the pinned Freebird SDK defines. The
layout above is a description of the existing V4 credential, not a new
graph-issuance request schema. A caller MUST NOT add an amount, class value,
wallet ID, owner, source artifact, nullifier, or Scarcity identifier to the
Freebird admission payload.

For a fresh operation, `v4_local` MUST validate the credential's canonical
encoding, V4 version, issuer and key identifier, scope binding, authenticator,
and all authorizer policy checks before the operation can consume a budget
unit. The verifier configuration MUST bind the accepted issuer/key and
verifier/audience scope to the operator's configured values. A V5 bearer is
not a V4 admission credential.

### 5.2 Exact shared Redis invariant

The replay invariant is global to the issuer's V4 admission authority, not
local to a graph, transition, process, Redis client, wallet, or HTTP request:

> For every validated V4 credential `t`, the shared Redis state contains one
> and only one global spend marker for `t` if and only if `t` has been
> accepted/consumed by any `v4_local` authorization operation. The marker is
> keyed by Freebird's canonical scope-bound `nullifier_key_v4` derived from
> the validated V4 token, then by `v4_spend_key(nullifier)`; this contract
> specifies no byte formula for either Freebird-derived value. The marker is
> not scoped by graph ID, operation ID, wallet ID, or a time bucket. Its Redis
> TTL is permanently absent (`TTL = -1`). It MUST never expire, be deleted, or
> be replaced by a local cache.

The marker's value and physical namespace MUST use the pinned Freebird
`v4_local` key encoding. The scope-bound nullifier and no-expiry invariant
above are normative; this contract does not invent a Redis wire field or
authorize an operator-specific alternate key format. A token whose marker
exists is a replay everywhere in the shared authority, even when presented
with a new graph request, operation identifier, or output.

All workers that can verify or consume V4 credentials MUST use the same
strongly consistent write authority. A process-local set, per-worker Redis,
eventual replica, or graph-local marker is not a substitute. Redis loss,
partition, ambiguity, or inability to perform the atomic operation MUST fail
closed; it MUST NOT invoke a local or insecure fallback.

### 5.3 Atomic admission, charge, and committed result

The Phase-1 integration MUST require the pinned runtime to perform the
following as one atomic issuance commit for a fresh operation. Cryptographic
checks MAY occur before the transaction, but the final replay check, budget
charge, and committed operation/result state MUST be all-or-nothing.

1. Confirm that the Scarcity manifest validator has admitted the
   `accepting_new` graph-issuance policy, canonical K0 output, quantity one,
   and one budget unit remains.
2. Confirm that no global V4 spend marker exists for the validated credential's
   canonical scope-bound nullifier.
3. Confirm that no different request already owns the operation's idempotency
   identity.
4. Create the non-expiring global V4 spend marker, charge exactly one artifact,
   and durably create the operation in `committed` state with its result in the
   same atomic issuance decision.

If any precondition fails, none of those mutations may take effect. A
successful atomic decision consumes the admission credential and budget and
creates the durable committed result before the operation can be reported as
complete. If the HTTP response is lost after that decision, the exact same
operation can return its committed result; a different operation may not reuse
that V4 credential.

For an exact retry of an already committed operation, the runtime returns or
reconstructs the committed result without creating another marker or charging
another unit. There is no intermediate issuance operation state. A retry with
a changed credential, output, graph, K0 selector, request digest, or other
SDK-defined idempotency input is a conflict and MUST not consume a second
credential or budget unit.

The durable committed operation/result is retained by Freebird as required for
exact POST retry and status observation. That operational record is not a
wallet backup or a recovery-custody promise. The global V4 marker is permanent
even when ordinary committed-result/status retention ends.

## 6. Graph-issuance request, result, status, and acceptance

### 6.1 Native wire contract rule

The graph-issuance request, `GraphIssuanceResult` V2 result, status response,
capability transport, canonical encodings, and HTTP route are the exact types
and APIs provided by Freebird `7aded788b9fc492b5b9ae3ca0f05a3d3f3c662a6`. This document intentionally does not
reproduce or invent request/status field lists. Implementations MUST
import/use those native types, reject unknown or non-canonical fields as
required by that SDK, and MUST NOT create a Scarcity-specific wrapper that
changes the wire contract.

The V2 graph-issuance result contains only its selectors, `quantity`, request
digest, blind signature, and result digest. It has no receipt, receipt key,
receipt digest, or receipt signature. No graph-issuance acceptance rule may
require any of those absent values.

In this section, “operation identifier”, “status capability”, “request”, and
“result” refer to the corresponding existing SDK values. The terms describe
their required semantics and do not name additional fields.

### 6.2 Fresh request

For each fresh genesis attempt, the client MUST:

1. obtain a fresh unpredictable operation identifier and a separate fresh
   status capability using the SDK's required encoding and transport
   location;
2. prepare exactly one output for the canonical K0 descriptor, retaining any
   nonce, message, and blinding state locally as required by the V5 output
   machinery;
3. bind the request to the pinned graph and the canonical K0/keyset/descriptor
   selectors exposed by the SDK, without inferring or rewriting slot fields;
4. include the one-use V4 admission credential only in the SDK-defined
   admission location; and
5. durably persist the exact request identity, status capability, expected K0
   output binding, output nonce/blinding state, and preparation snapshot
   before submission.

The client MUST NOT reuse an operation identifier, status capability, output
nonce, or blinding state. Preparation is not issuance and creates no bearer.
The V4 credential MUST NOT be copied into logs, URLs, status queries, wallet
metadata, or HyperToken messages.

### 6.3 Result and genesis acceptance

Only a graph-issuance HTTP `200` with `Cache-Control: no-store` can be an
acceptance candidate. The client MUST reject any successful response without
the `no-store` directive. It MUST strictly parse the native
V2 graph-issuance result with unknown fields rejected and then perform these
checks in order:

1. validate the result selectors against the submitted request, require the
   fixed quantity-one binding, validate the request digest against the exact
   request, and validate the result digest against the canonical result;
2. perform RFC 9474 blind-signature unblinding and finalization using the
   locally retained blinding state;
3. verify the resulting V5 artifact under the pinned K0 descriptor and the
   `scarcity/circulating-bearer/v1` class; and
4. atomically commit the finalized artifact and the local record needed for
   subsequent circulation to the vault before deleting superseded blinding
   secrets.

This verified HTTP `200` followed by the atomic vault commit is genesis
acceptance. A status response, valid-looking V5 bytes, V4 verification
response, operator acknowledgement, Witness response, HyperToken result, or
any other status cannot substitute for it. No graph-issuance receipt is
involved.

### 6.4 Status capability and retries

The status capability is a separate bearer secret for the SDK's status
operation. It MUST be fresh, transmitted only where the SDK specifies, and
kept out of JSON fields or URLs unless the pinned SDK explicitly requires that
transport. A status request with a wrong, missing, or malformed capability
MUST NOT disclose operation state.

Status observation is not completion. The status GET only observes a durable
`committed` operation/result, or the native SDK's no-result/authorization
response; it never creates or advances an issuance operation and MUST NOT
itself accept genesis. An exact POST retry is the only way to return or
recreate the committed result and still requires the full result checks above.

Every Freebird `2xx` response for the graph-issuance POST or its status
operation MUST include `Cache-Control: no-store`; the client MUST reject a
`2xx` response that lacks it. A timeout, disconnect, `503`, or client/server
crash leaves only whether the atomic commit is visible to be determined. The
client MUST retain the exact request, capability, V4 operation identity, and
blinding state and MUST retry that exact POST; it MUST NOT offer the would-be
bearer as accepted money. The retry returns/recreates the committed result if
the atomic commit occurred and otherwise follows the fresh-request policy.

The idempotency rule is:

- the same operation identity plus the exact canonical request digest and all
  SDK-defined admission/output bindings identifies one operation;
- an exact repeated POST returns or recreates the same committed result when
  the atomic commit has occurred;
- a mutated request is a conflict and MUST NOT be treated as a new genesis
  attempt using the same V4 credential; and
- a committed operation, global V4 marker, or budget charge is not duplicated
  or refunded merely because the caller did not receive the response.

An HTTP `400`, `403`, or `409` is not acceptance. A definitive rejection may
return local preparation state only when the client and Freebird establish
that no committed operation or V4 marker was created. An uncertain result
MUST be resolved by the same exact POST and MUST NOT be regenerated with a new
operation. Failure of result parsing, selector/request/result-digest
validation, unblinding, or K0 artifact verification is a local acceptance
failure, not permission to spend another V4 credential against the same
attempted issuance.

## 7. Privacy, persistence, and no-custody rules

### 7.1 Freebird and application privacy

No graph-issuance component may place economic or wallet data in the V4
admission input or any Freebird policy field. In particular, it MUST NOT send
an amount, class-derived value, owner, wallet ID, bearer, nullifier, source
artifact, recipient identity, balance, purpose, or transaction lineage to the
V4 authorizer. `v4_local` sees an eligibility credential, not Scarcity money.

No component under Scarcity or HyperToken control may log, trace, metric-label,
broadcast, project, or place in a URL the V4 credential or any of its nonce,
scope digest, authenticator, operation request/result, output nonce, blinding
state, blinded value, finalized artifact, status capability, or vault record.
Routine logs MUST use non-identifying error codes and aggregate counters only.
Operation, graph, transition, key, and admission identifiers SHOULD be
treated as correlation handles and MUST NOT appear in routine logs.

Freebird necessarily receives the graph-issuance request and its network
metadata. This contract makes no network-layer anonymity claim. Witness and
HyperToken receive no genesis payload.

### 7.2 Persistence boundary

The local wallet MUST retain the output nonce/blinding state until a verified
HTTP `200` is durably accepted, and then retain the K0 bearer under the
circulation vault rules. The unlock key, bearer secrets, admission credential,
and blinding state MUST NOT be stored in Redis, telemetry, exports, sync
state, crash reports, backups, or public/browser state.

Freebird MAY durably retain the minimum native operation state required for
exact POST retry, committed-result delivery, and status observation. Redis
MUST retain the global V4 spend marker forever and MUST retain operation/replay
state only as required by the pinned SDK's committed-result semantics. Redis
is not a wallet vault, user recovery service, escrow, backup, or
administrative restore path.

No genesis acceptance is valid from a Redis marker alone. Conversely, deleting
an operation result or losing local wallet state does not delete or shorten the
global V4 spend marker. A lost local bearer is not recoverable through a new
genesis request.

## 8. Lifecycle switch to circulation

Genesis and circulation have an explicit operator-controlled handoff.

1. **Bootstrap.** Validate the manifest, publish the graph with E01 and E10
   disabled, durably record the exact disabled-publication acknowledgement,
   and verify shared Redis readiness. Graph issuance alone may be
   `accepting_new`; later circulation receipt configuration is outside genesis.
2. **Initial issuance.** Serve only the pinned graph-issuance operation, K0
   output, `v4_local` one-use admission, and the 100-artifact budget. Witness
   and HyperToken remain uninvolved.
3. **Close fresh issuance.** Disable fresh graph issuance. The policy and
   status path MUST retain durable `committed` operation/result records and
   exact POST retry for those records, but MUST create no new operation after
   disable. A request without a committed record MUST be rejected without
   consuming a credential or budget unit.
4. **Review committed results.** Reconcile every committed operation/result,
   permanent V4 marker, budget charge, accepted K0 artifact, and local
   operator evidence before declaring the handoff complete.
5. **Enable circulation.** Only after the operator has acknowledged the
   disabled-first evidence and completed the review may the operator publish
   E01 and E10 as `accepting_new`. The existing circulation startup gate and
   all of its discovery and validation rules then apply. Graph issuance remains
   closed to fresh requests; exact POST retry and status observation remain
   limited to already committed operation/results.

The lifecycle switch MUST NOT reset the 100-artifact budget, clear V4 markers,
reclassify a K0 genesis artifact as an exchange output, or enable an edge
because Witness or HyperToken reports success. If fresh issuance cannot be
closed while preserving exact recovery, the operator MUST keep E01 and E10
disabled.

## 9. Operator configuration versus frozen contract values

The following are frozen and MUST NOT be changed by deployment configuration:

- the class `scarcity/circulating-bearer/v1`;
- exactly K0 and K1, exactly E01 and E10, and the direction of each edge;
- one K0 artifact per successful genesis operation;
- the initial graph-issuance budget of exactly 100 artifacts;
- K0-only initial output;
- generic `v4_local` one-use admission and the global non-expiring replay
  invariant;
- disabled E01/E10 before the lifecycle switch;
- acceptance only on a verified graph-issuance HTTP `200` with `no-store`;
- no Witness or HyperToken genesis authority; and
- local-only custody with no recovery, escrow, replica, or backup.

The following remain operator policy or deployment configuration. They MUST be
recorded in the manifest and validated against the pinned SDK, but are not
new frozen constants in this document:

- issuer identity, issuer key material, VOPRF `kid`, verifier identity,
  audience/scope configuration, and key rotation schedule;
- the HTTPS origin, route/bindings, TLS policy, authentication between local
  components, request-size/concurrency/rate limits, and operational timeouts;
- canonical descriptor key material, descriptor validity/audience settings,
  active/retained receipt keys, receipt validity/retention, and key-rotation
  procedures for later circulation only, subject to the circulation contract;
- Redis endpoint or cluster, namespace/database, TLS, ACLs, durability,
  failover/consistency mode, monitoring, and backup policy for operational
  state (the V4 marker still MUST be non-expiring and globally shared);
- status/result retention, retry/backoff limits, maintenance windows, and
  operator review/sign-off procedure, provided they never delete committed
  results needed for exact POST retry or turn an uncertain result into
  acceptance; and
- whether and when post-acceptance Witness evidence is enabled for later
  circulation, and the HyperToken transport deployment, which have no genesis
  authority.

Configuration MUST NOT be used to raise the 100-artifact budget, make K1 an
initial target, enable an unacknowledged edge, scope replay protection to a
graph or operation, add a fallback mint, or create recovery custody.

## 10. Executable Phase-1 fixture gates

These are required future Phase-1 native-execution gates. This document does
not assert that the fixtures or Scarcity wallet/bootstrap-validator code are
currently checked in. Phase 1 MUST NOT be enabled until the responsible native
consumers execute the applicable future fixtures as conformance tests. At
minimum, the fixture set MUST include:

1. **Dependency and manifest vectors:** the four dependency pins, canonical
   graph identity, exactly one descriptor in each of K0 and K1, exactly E01
   and E10, both disabled, K0-only graph issuance, `accepting_new` policy,
   exactly 100 artifacts, and preprovisioned Redis configuration. Any receipt
   configuration for later circulation is outside these genesis vectors.
2. **Disabled-first startup vectors:** initial publication, exact
   disabled-publication evidence containing issuer ID, graph ID, only E01/E10
   IDs, operator, timestamp, restart persistence, refusal before evidence,
   and proof that acceptance of graph issuance does not enable circulation.
3. **V4 authorizer vectors:** valid canonical V4 credentials; wrong issuer,
   key, scope, authenticator, version, length, and encoding; one-use success;
   replay from concurrent workers; cross-graph replay; Redis unavailable or
   ambiguous; and atomic rollback when admission, budget, or operation
   preconditions fail. The expected vector MUST prove one global marker keyed
   by Freebird's `nullifier_key_v4` and `v4_spend_key(nullifier)`, and
   `TTL = -1` after restart and beyond ordinary operation/result retention.
4. **Genesis request/result vectors:** native SDK request and exact
   V2 graph-issuance result encodings, K0 selector/output binding, quantity-one
   binding, strict request/result-digest validation, RFC 9474 unblinding and
   finalization, K0 descriptor artifact verification, rejected unknown fields,
   HTTP `200` acceptance, missing `Cache-Control: no-store`, and valid-looking
   V5 output without a graph-issuance result.
5. **Capability and committed-result vectors:** fresh capability secrecy,
   wrong or missing capability, status observation without acceptance, timeout,
   disconnect, `503`, process crash before and after the atomic commit,
   committed-result return/recreation by exact POST, mutated-request conflict,
   no budget refund, and no second V4 marker.
6. **Budget and lifecycle vectors:** 100 charges, exhaustion at the configured
   boundary, no reset on restart, disabling fresh issuance while retaining
   committed-result retry/status observation, rejection of a new request
   without consumption, and enabling E01/E10 only after the acknowledgement
   and operator review gate.
7. **Authority-separation vectors:** verified graph-issuance `200` accepts
   with Witness unavailable and HyperToken absent; Witness, HyperToken,
   status, operator evidence, or a local V5 signature cannot accept a missing,
   non-`200`, malformed, or invalid graph-issuance result.
8. **Privacy and custody vectors:** no economic payload crosses the V4
   boundary; no secret or correlation handle appears in routine logs, URLs,
   telemetry, HyperToken state, or public projections; no wallet secret is in
   Redis; and no backup, seed, escrow, or administrative recovery path exists.

Every deterministic credential, nonce, capability, blinding value, key, or
Redis test value in a fixture MUST be labeled **TEST-ONLY**. Deterministic or
reused values are prohibited in production.

The future native Freebird graph-issuance consumer at
`7aded788b9fc492b5b9ae3ca0f05a3d3f3c662a6` MUST execute
the Freebird wire, authorizer, Redis, budget, and committed-result fixtures.
The future Scarcity genesis client and bootstrap-manifest validator MUST
execute the local preparation, profile validation, acceptance, vault, and
authority-separation fixtures. The future operator startup/lifecycle gate MUST
execute its publication and handoff fixtures. The pinned circulation, Witness,
and HyperToken consumers execute their own applicable post-genesis gates.

Fixtures do not become authoritative merely by being checked in. A fixture is
authoritative only when its responsible native consumer executes it as a
conformance test. JSON-shape assertions, generic scripts, mock-only checks,
or service availability tests do not establish this composition contract.

## 11. Phase-1 genesis acceptance criteria

Genesis conforms only if all of the following hold:

1. the pinned graph runtime passes the bootstrap manifest and disabled-first
   startup gate;
2. graph issuance is `accepting_new`, targets only K0, and has exactly 100
   artifact units remaining at initial bootstrap;
3. the request uses the native graph-issuance API and a valid, unused generic
   `v4_local` credential;
4. admission consumption, the global non-expiring V4 marker, one budget
   charge, and the durable committed operation/result are atomically
   coordinated in shared Redis/runtime state;
5. the response is HTTP `200` with `Cache-Control: no-store`, and every
   native result selector, quantity, request digest, result digest, blind
   signature, RFC 9474 finalization, and K0 artifact check succeeds;
6. the local wallet durably stores the accepted K0 artifact before exposing
   it as a bearer, with no custody or backup path;
7. Witness and HyperToken are not involved in the acceptance decision; and
8. the applicable native executable fixture gates pass, including the later
   close-and-switch review before E01/E10 are enabled.

Any failed item is non-conforming. There is no direct-V5, exchange, offline,
Witness-backed, HyperToken-backed, Redis-local, or insecure-fallback genesis
path.
