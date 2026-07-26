# Scarcity Circulation V1 — Phase-1 Composition Contract

Status: authoritative for Phase 1. Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as in RFC 2119.

This frozen contract composes exactly these dependency revisions:

| Dependency | Required pin |
|---|---|
| Freebird genesis-plus-circulation deployment | `29b9476` |
| Witness durable attestation-job API | `41c130f` |
| HyperToken strict dispatch/final projection | `922ec01` |

All three pins are required for the frozen Phase-1 contract. The Freebird `29b9476` deployment includes the V2 transition graph revision `f632348` plus graph issuance and admission authorization for a complete genesis-plus-circulation deployment. The circulation wire semantics originate with the Freebird V2 graph revision `f632348`; it is included in the single Freebird deployment pin, not a separate service pin. A different revision of any dependency is outside this contract until compatibility is reviewed and this contract is explicitly revised. The Witness pin has the legacy timestamp endpoint removed. This document defines Scarcity behavior; it does not change those services' wire formats.

## 1. Fixed profile

| Item | Phase-1 value |
|---|---|
| Circulation class | `scarcity/circulating-bearer/v1` |
| Freebird profile | `freebird/public-bearer-exchange/v2` |
| Keysets | exactly two role-neutral, one-descriptor keysets, `K0` and `K1` |
| Transitions | exactly `E01: K0 → K1` and `E10: K1 → K0` |
| Cardinality | exactly one source and one output per request and edge |
| Quantity | `1` on every source and output slot |
| Lifetime budget | `100` output units reserved per edge |
| Receipt lifetime | exactly 30 days (`2,592,000` seconds) |
| Transfer acceptance | a locally verified Freebird exchange POST HTTP `200` response |
| Witness | asynchronous evidence only |
| HyperToken | no monetary action and no public projection |
| Vault | encrypted, local-only, with no recovery or backup |

`K0`, `K1`, `E01`, and `E10` are contract labels, not additional Freebird fields. Their wire identities are the canonical `keyset_id` and `transition_id` values discovered below. Each edge has a distinct `budget_id`. The budget is issuer-wide lifetime reservation capacity, not a per-user, per-token, renewable, or committed-transfer guarantee. Source spend and one unit of edge budget are claimed atomically when a fresh operation is reserved, before result production; a `202` can therefore represent a spent source and charged budget. Pending or crashed work is not refunded. An exact recovery of the same reservation adds no charge, but an edge can yield fewer than 100 committed transfers.

## 2. Scope and non-goals

Phase 1 supports a single indivisible bearer moving alternately across two Freebird keysets. It specifies recipient-side blinding, one-source/one-output exchange, receipt verification and storage, and optional post-acceptance Witness evidence.

Phase 1 does **not** define denomination changes, multiple inputs or outputs, minting policy, redemption, vault/key recovery, backup, escrow, HTLCs, Scarcity nullifier gossip, public balances, transaction history, indexing, discovery through HyperToken, or a HyperToken action that creates, destroys, spends, transfers, or represents money. It does not make Witness a spend, ordering, finality, or acceptance authority.

## 3. Trust and authority boundaries

1. **Freebird issuer/exchange** is the sole authority for source validity, single spend, edge admission, edge lifetime budget, target blind signing, operation recovery, and signed exchange receipts.
2. **Validated Freebird discovery** is the sole source of graph, descriptor, keyset, transition, and receipt-verification-key metadata. The preparation snapshot pins graph, transition, keyset, and descriptor identities. A later, independently all-or-nothing validated snapshot from the same pinned origin and issuer may supply a rotated active or retained receipt key. Transport success alone is not authority.
3. **The recipient's Scarcity wallet** generates and retains the output nonce and blinding state, verifies the complete exchange POST `200` response, finalizes the target bearer, and makes the acceptance decision.
4. **Witness** only attests that a contract-defined hash was submitted to its network no later than the signed attestation time. It does not see or validate the receipt, cannot repair a failed Freebird exchange, and cannot cause acceptance.
5. **HyperToken** is neither a monetary authority nor a disclosure authority in Phase 1. Strict dispatch success does not imply a transfer, and no bearer, receipt, operation, vault state, Witness hash, or monetary derivative may enter an action payload, action result, history entry, state broadcast, describe response, welcome state, room state, or custom outbound projection.
6. **Local storage** is authoritative only for the wallet's secrets and state. Loss of the vault or its encryption key means loss of the bearer; no service is a recovery custodian.

## 4. Discovery, pinning, and validation

### 4.1 Wallet discovery

The client **MUST** fetch `GET /.well-known/keys` from an operator-pinned Freebird HTTPS origin (loopback test deployments may use HTTP). It **MUST** pin the expected origin and `issuer_id`, reject redirects to another origin, require the top-level `exchange` value, and validate that complete `ExchangeDiscoveryV2` container all-or-nothing before preparing an output.

Wallet validation is limited to publicly discoverable graph, descriptor, keyset, transition, admission-state, and receipt-key metadata. Freebird discovery does not expose disabled-publication acknowledgement records or durable publication markers, and wallets **MUST NOT** claim to validate that operator evidence through discovery.

Validation **MUST** include the current Freebird V2 canonical rules:

- the active graph has `profile_id = "freebird/public-bearer-exchange/v2"`, a canonical `graph_id`, canonical descriptor IDs, canonical ordered keyset IDs, and canonical transition IDs;
- descriptor `issuer_id` equals the pinned issuer; `token_key_id` matches the SHA-256 identity of `pubkey_spki_b64`; suite, audience, validity interval, and RSA public key are valid;
- the graph contains exactly two keysets mapped locally to `K0` and `K1`, exactly one descriptor in each keyset, and exactly two non-self transitions mapped to `E01` and `E10` by their source and target keyset IDs;
- each transition has exactly one `source_slots` entry and one `output_slots` entry; both have `class = "scarcity/circulating-bearer/v1"` and `quantity = 1`; each descriptor belongs to the referenced keyset;
- each transition has `budget_limit = 100`, a distinct non-empty `budget_id`, and `admission_state = "accepting_new"` before fresh use;
- `active_receipt_key` is Ed25519, has purpose `exchange_receipt_active`, has a canonical key ID, and covers the full 30-day receipt interval; retained receipt keys are validated identically with purpose `exchange_receipt_retained`;
- every retained graph and receipt key is canonical, unique, and internally consistent. A retained transition **MUST NOT** be treated as accepting fresh work.

The wallet **MUST** retain the exact validated preparation snapshot and its origin with every prepared operation. Discovery refresh cannot mutate its graph, transition, keyset, descriptor, selector, or output bindings. Receipt verification is the sole exception to same-snapshot use: the wallet **MAY** fetch a later snapshot from the same pinned origin and issuer, **MUST** validate that entire container independently, and **MAY** use its matching canonical `active_receipt_key` or `retained_receipt_keys` entry whose validity covers the receipt. The receipt key need not have been present in the preparation snapshot. The wallet must not splice an unvalidated key or replace any prepared graph binding.

### 4.2 Operator startup/restart gate

Before either transition may be enabled, the operator **MUST** first publish the graph with both E01 and E10 `disabled`, complete a successful durable disabled-publication acknowledgement, and only then publish them as `accepting_new`. On every startup and restart, the operator gate—not the wallet—must prove this history before Freebird serves either transition as accepting.

The operator evidence contains exactly `version = "freebird/exchange-disabled-publication-ack/v1"`, `issuer_id` equal to the pinned issuer ID, `graph_id` equal to the canonical graph ID, `disabled_transition_ids` containing both and only the E01 and E10 IDs, `acknowledged_admission_state = "disabled"`, a non-empty `operator` identity, and a nonzero `acknowledged_at_unix` timestamp. The acknowledgement record and Freebird's durable disabled-publication markers must survive restart. An accepting transition without this bootstrap evidence is non-conforming.

## 5. Recipient preparation

For a bearer in `Ki`, the recipient selects the only admitted edge `Ki → Kj` and, using the discovered output descriptor, performs the existing Freebird V5 public-bearer blind-RSA preparation. Recipient handoff is preparation data, not an `ExchangeRequestV2` and not a new service wire type:

1. Generate a fresh unpredictable 16-byte operation value and encode it as unpadded canonical base64url for `public_operation_id`.
2. Generate a separate fresh unpredictable 32-byte status capability and encode it as unpadded canonical base64url only in the single `exchange-status-capability` HTTP header.
3. Generate the fresh output nonce and blind the Freebird public-bearer message for the target descriptor. Keep the nonce, message, and blinding state secret in the vault; expose only the unpadded canonical base64url `blinded_value`.
4. Copy graph, transition, source-keyset, target-keyset, descriptor, slot, class, and quantity selectors from the pinned graph. Do not infer or rewrite slot IDs.
5. Atomically persist the operation ID, status capability, expected selectors, sole output slot and `blinded_value`, output nonce, message, blinding state, and preparation-snapshot reference before handoff.
6. Hand the sender only the values needed to construct and submit the request: operation ID, status capability, expected selectors, and sole output. The nonce, message, and blinding state never leave the recipient vault.

Operation values, status capabilities, output nonces, and blinding state **MUST NOT** be reused. Recipient preparation is not acceptance and creates no balance.

The sender adds the sole source slot and source `artifact`, constructs the full `ExchangeRequestV2`, and atomically persists that full request, status capability, and preparation-snapshot reference before POST. The sender **MUST** provide the recipient either the exact submitted request or an authenticated confirmation of its selectors and sole output. The recipient validates the response against its persisted expected selectors/output; if it receives the exact submitted request, it additionally verifies that request against those expectations. The recipient is not required to persist the sender's source artifact as part of its preparation record.

## 6. Freebird V2 request and accepted response

The request is `POST /v2/public/exchange`, with JSON matching Freebird's `ExchangeRequestV2` exactly and one `exchange-status-capability` header. Its fields are:

```text
version, public_operation_id, graph_id, transition_id,
source_keyset_id, target_keyset_id, sources, outputs
```

For this contract, `version` is `2`; `sources` contains exactly one `ExchangeSource { slot, artifact }`; `outputs` contains exactly one `ExchangeOutput { slot, blinded_value }`; and each `slot` contains only `descriptor_id`, `keyset_id`, `slot_id`, and `quantity`. `artifact` is the canonical unpadded-base64url Freebird V5 public bearer supplied by the current holder. Unknown fields are forbidden.

Every Freebird `2xx` response, including POST and status-GET `200` and `202`, **MUST** include the `Cache-Control: no-store` directive; the client **MUST** reject that response if the directive is absent. An HTTP `200` body contains exactly:

```text
{ "result": ExchangeResultV2, "receipt": ExchangeReceiptV2 }
```

`ExchangeResultV2` contains `version`, `public_operation_id`, `graph_id`, `transition_id`, `source_keyset_id`, `target_keyset_id`, `outputs`, and `result_digest`. Each result output contains `slot`, `blinded_value`, and `blind_signature`.

`ExchangeReceiptV2` contains `version`, `public_operation_id`, `graph_id`, `transition_id`, `source_keyset_id`, `target_keyset_id`, `result_digest`, `created_at`, `expires_at`, `receipt_key_id`, and `signature`. It contains neither a status capability nor a receipt-digest wire field. Clients compute the raw 32-byte receipt digest as `SHA256(DOMAIN_RECEIPT_V2 || canonical_payload)`, where `DOMAIN_RECEIPT_V2` is the bytes `freebird exchange receipt v2\0`.

Before acceptance, the recipient **MUST**:

1. require HTTP `200` with `Cache-Control: no-store`, parse both objects with unknown fields rejected, and validate their canonical Freebird V2 encodings;
2. require all selectors and the sole output slot and `blinded_value` to match the recipient's persisted expectations or, when supplied, the exact submitted request, which must itself match those expectations;
3. recompute `result_digest` using Freebird's V2 result domain and require the receipt to bind that result and all selectors;
4. require `expires_at - created_at = 2,592,000`, require the receipt to be currently within its validity interval, and require a receipt key from the preparation snapshot or a later independently validated snapshot under Section 4 to cover that interval;
5. compute the raw receipt digest, decode the 64-byte receipt signature, and verify Ed25519 over that digest using the validated active or retained key identified by `receipt_key_id`;
6. finalize the returned blind signature with the stored blinding state, construct the target Freebird V5 public bearer, and verify it against the pinned target descriptor; and
7. atomically store the new bearer, result, receipt, preparation and receipt-key discovery references, and pending Witness-evidence marker before deleting superseded recipient-side preparation secrets.

Only completion of all seven checks on a Freebird exchange POST HTTP `200` accepts the transfer. A status GET, Witness response, HyperToken dispatch outcome, locally plausible bearer, or any other HTTP status cannot substitute.

## 7. Canonical receipt-hash envelope

Witness receives only a SHA-256 hash, not a receipt. After Freebird acceptance, form this binary envelope:

```text
u32be(length(UTF8(class))) || UTF8(class) || receipt_digest_bytes
```

where `class` is exactly `scarcity/circulating-bearer/v1`, `u32be` is an unsigned four-byte big-endian length, and `receipt_digest_bytes` is the raw 32-byte value the client computes as `SHA256(DOMAIN_RECEIPT_V2 || canonical_payload)`. `ExchangeReceiptV2` has no receipt-digest field to decode; its `result_digest` is a different value. No JSON, whitespace, signature text, or HTTP bytes enter this envelope.

The Witness submission hash is `SHA-256(envelope)`, encoded as exactly 64 lowercase hexadecimal characters. The receipt signature is not duplicated in the envelope: prior receipt verification establishes that the validated Freebird key signed `receipt_digest_bytes`, while the stored receipt retains that signature.

## 8. Exact Witness POST/GET lifecycle

When Witness evidence is enabled, work starts only after Freebird acceptance and never blocks use of the new bearer. The wallet **MUST** have an operator-pinned expected `witness_network_id` before submission and must independently fetch and validate `GET /v1/network` against that expectation.

1. Submit `POST /v1/attestations` with JSON `{ "hash": "<64-lowercase-hex>" }`. Phase 1 omits `freebird_token`; a Witness deployment used here **MUST** permit hash-only submissions. The source type's only optional admission shape, when used outside this profile, is `"freebird_token": { "token_b64": "..." }`; it is not part of this composition.
2. The response is an `AttestationJobResponse` with `attestation`, `status`, `attempts`, and optional `signed_attestation`, `next_attempt_at`, and `last_error`. `attestation` contains exactly `hash`, `timestamp`, `network_id`, and `sequence`.
3. HTTP `202` means `status` is `pending` or `retryable`. Preserve the canonical tuple and poll no earlier than `next_attempt_at` when present.
4. Poll `GET /v1/attestations/:hash` using the same lowercase hash. An existing job returns HTTP `200` with its current snapshot; HTTP `404` means no job exists and permits repeating the identical POST; malformed hashes are HTTP `400`.
5. `status = "confirmed"` is evidence only when `signed_attestation` is present, repeats the exact canonical tuple, its hash equals the submitted hash, `signed_attestation.attestation.network_id == pinned NetworkConfig.id == expected witness_network_id`, and its threshold signatures verify locally against that pinned and validated `GET /v1/network` configuration.
6. `status = "failed"` is terminal for that Witness job and has no `signed_attestation`. Preserve the accepted Freebird transfer and record evidence failure locally. `pending` and `retryable` likewise never invalidate or delay the transfer.

Duplicate POSTs for a hash retrieve the same durable job and tuple. The gateway assigns `timestamp`, `network_id`, and `sequence`; clients must not propose them. The removed legacy timestamp endpoint **MUST NOT** be called. `POST /v1/verify` is not an authority for this composition; verification is local.

## 9. Vault boundary and state machines

The Phase-1 vault record envelope is frozen as this unknown-field-rejecting JSON object:

```text
{
  "version": "scarcity/vault-record/v1",
  "wallet_id": "<canonical unpadded base64url of 16 bytes>",
  "record_id": "<canonical unpadded base64url of 16 bytes>",
  "nonce": "<canonical unpadded base64url of 12 bytes>",
  "ciphertext": "<canonical unpadded base64url of ciphertext || 16-byte tag>"
}
```

`wallet_id` is generated once as 16 unpredictable bytes when the vault is created. Each `record_id` is a distinct 16-byte unpredictable identifier generated when that logical record is created and remains stable across its state transitions.

Each record **MUST** use AES-256-GCM and a fresh unpredictable 96-bit nonce generated with a cryptographically secure random source. A nonce **MUST NOT** repeat under one unlock key. The authenticated additional data is exactly:

```text
u32be(length(UTF8(version))) || UTF8(version) || wallet_id_bytes || record_id_bytes
```

The plaintext is the wallet's complete local record bytes, including its state. Envelope encoding is not itself encrypted, but version, wallet ID, and record ID are authenticated by AAD. Decryption rejects an unknown version, non-canonical encoding, wrong field length, duplicate/unknown field, wallet or record mismatch, or invalid GCM tag.

The **vault unlock-key boundary** is a separate local provider that releases exactly one 32-byte AES key to the wallet only after explicit unlock. That key is never stored in a vault envelope, synced, exported, backed up, logged, or sent to Freebird, Witness, or HyperToken; it is kept only in protected process memory while unlocked and cleared on lock or shutdown. Key enrollment and user authentication are platform responsibilities outside this wire profile, but they **MUST NOT** create a recovery, escrow, replica, or backup path.

Every state transition writes a newly encrypted envelope with a fresh nonce to local temporary storage, durably flushes it, atomically replaces the prior record, and durably flushes the containing directory before exposing the new state. Within one wallet, a transition touching multiple local records requires an equivalent atomic local transaction. The vault is excluded from sync, telemetry, browser/public state, filesystem indexing, cloud storage, exports, crash uploads, and backups. There is no seed phrase, recovery service, replica, or administrative restore path. Encryption at rest does not protect an unlocked or compromised device; Phase 1 makes no such claim. Secrets should be held in memory only while needed and cleared after transition.

Recipient states are:

```text
EMPTY → PREPARED → SUBMITTED_UNKNOWN → CURRENT
                                   ↘ REJECTED
CURRENT → EVIDENCE_PENDING → EVIDENCED
                           ↘ EVIDENCE_FAILED
```

- `PREPARED` atomically stores the preparation-snapshot reference, operation value, status capability, expected selectors/output, nonce, message, and blinding state.
- Once any POST may have reached Freebird, the state is `SUBMITTED_UNKNOWN`; the recipient **MUST NOT** discard or regenerate its operation, capability, expected selectors/output, nonce, or blinding state.
- `CURRENT` is entered only after Section 6 acceptance and atomic persistence of the finalized target bearer and receipt.
- Witness states are metadata on `CURRENT`; they do not change spendability.

The sender atomically stores the full submitted request. Its source moves `CURRENT → OFFERED → RESERVED_PENDING` on POST `202`, because reservation has already claimed the source and one unit of the edge budget; neither is refunded merely because work remains pending. A POST `200` moves it to `SPENT`. After timeout, disconnect, `503`, or crash it moves to `SPEND_UNKNOWN`, not back to `CURRENT`; it must not be offered or spent again. Recovery repeats the same canonical POST until POST `200`. If recovery is abandoned or becomes operationally impossible, the source remains permanently unavailable. A definitive rejection may return the source to `CURRENT` only when the client establishes that no reservation was created.

## 10. Retry and failure semantics

- The same `public_operation_id`, status capability, canonical Freebird V2 request digest, and exact decoded source `artifact` and output `blinded_value` bytes define one operation. Recovery POSTs **MUST** preserve all of them. JSON property order and insignificant whitespace are irrelevant; changing any digest-bound value or source/output bytes creates a conflict or different operation and risks loss.
- Freebird POST `202` (`exchange_retryable`, `Retry-After: 1`) means the operation is reserved or still recoverable: the source and one budget unit have already been claimed. Transport timeout, disconnect, `503`, or a client/server crash may also leave durable `Reserved` or `ResultReady` work. In every case, recovery **MUST** repeat the same canonical POST with the same single status-capability header. Only `process_or_recover_v2` on POST claims and advances recoverable work.
- `GET /v2/public/exchange/status?public_operation_id=<id>` is optional observation only and **MUST NOT** be described or used as completing recovery. With the same capability, GET `200` observes a committed response, `202` observes pending, `404` observes unknown, and `403` observes unauthorized. A successful GET must also carry `Cache-Control: no-store` or be rejected. After any GET observation, the client still repeats the recovery POST; only its verified `200` can accept and complete local recovery.
- POST `409` means operation conflict. POST `400` means invalid exchange. Treat either as a failed attempt, but never regenerate and resubmit against a source whose spend status is uncertain.
- A repeated canonical committed POST must yield the committed response; the client verifies it again rather than trusting cached or GET-observed acceptance.
- Failure of response parsing, canonical validation, selector binding, receipt signature, receipt lifetime, unblinding, or target-bearer verification is terminal for local acceptance and must retain diagnostic state without exposing secrets.
- Budget exhaustion or an edge leaving `accepting_new` forbids fresh exchange. Reservation charges are not refunded for pending work. This does not authorize another edge, quantity, class, graph, or fallback mint.
- Witness network, quorum, polling, validation, and terminal-job failures affect evidence only. They never roll back, repeat, or compensate a Freebird exchange.

## 11. Privacy and logging prohibitions

No component under Scarcity or HyperToken control may log, metric-label, trace, project, broadcast, or place in URLs: source artifacts, finalized bearers, output nonces, blinding state, blinded values, blind signatures, status capabilities, complete requests or responses, receipts, receipt digests, Witness envelope bytes, or vault records. Public operation IDs, graph/transition IDs, receipt key IDs, and Witness hashes also **MUST NOT** appear in routine logs because they are correlation handles. Errors use non-identifying codes and aggregate counters only.

Witness receives only its submission hash. HyperToken receives nothing from this protocol. Freebird necessarily receives the exchange request and Witness necessarily receives connection metadata; Phase 1 claims no network-layer anonymity and defines no public explorer or projection.

## 12. Graph lifecycle and key rotation

Descriptors, ordered keysets, transitions, and graphs are content-addressed. Changing descriptor key material or validity changes its descriptor ID, then its keyset ID, affected transition IDs, and graph ID. Rotation therefore requires a newly validated active graph; clients must never rewrite IDs in place.

Before rotation, the operator must provide an explicit migration plan for every outstanding bearer keyset. A graph made merely `recovery_only` can recover already reserved operations but cannot admit a new transfer from an outstanding bearer. Rotation **MUST NOT** strand such bearers, silently reset either 100-unit budget, reuse a `budget_id` for a different stable edge contract, or remove receipt keys needed during any unexpired 30-day receipt interval.

Admission-state-only revisions leave the stable transition contract and budget identity unchanged. `accepting_new` admits fresh and recovery work; `recovery_only` admits recovery only; `disabled` admits neither and is permitted only after pending references are gone. Retained graphs and receipt keys remain pinned for recovery/verification, never fresh selection.

## 13. Phase-1 executable fixture and vector gates

Phase 1 **MUST NOT** be enabled until the responsible native Phase-1 consumers parse and execute all applicable checked-in fixtures/vectors. The native Scarcity consumer executes wallet/protocol composition vectors; the pinned Freebird operator/startup path executes its non-public bootstrap gate vectors.

1. a complete public `/.well-known/keys` discovery and minimal graph fixture proving exactly one descriptor per K0/K1, E01/E10, class/quantity/cardinality, distinct 100-unit budgets, and active/retained receipt-key metadata, without pretending that discovery contains bootstrap acknowledgements;
2. an operator startup/restart and graph-lifecycle fixture proving initial disabled publication of both transitions, durable acknowledgement with all Section 4.2 evidence fields, refusal before acknowledgement, later `accepting_new`, restart persistence, admission-only revision, retained recovery, independently validated rotated active/retained receipt keys, migration without stranding bearers, budget non-reset, and rejection of a reused budget ID with a changed stable contract;
3. canonical descriptor, ordered keyset, transition stable-contract, and graph vectors with expected descriptor IDs, keyset IDs, E01/E10 transition IDs, and graph ID;
4. E01 and E10 request/result/receipt vectors proving canonical encodings, canonical request and result digests, raw computed receipt digest, selector/output binding, receipt signature verification, `Cache-Control: no-store`, and finalized target-bearer verification;
5. the custom receipt-hash envelope vector with class bytes, raw computed receipt-digest bytes, complete binary envelope, and expected lowercase Witness submission hash;
6. a Freebird crash/recovery matrix covering recipient handoff and sender persistence, fresh reservation, durable `Reserved`, `ResultReady`, and `Committed` states across POST `200`/`202`/`400`/`409`/`503`, timeout, disconnect, and process/restart crashes; it must prove source/budget claim at reservation, no pending-work refund, same-digest POST recovery, GET observation-only behavior, atomic local state changes, and rejection of wrong capabilities or mutated source/output bytes;
7. vault AEAD and crash-consistency vectors for every recipient and sender state, containing version, wallet ID, record ID, 256-bit key, 96-bit nonce, exact AAD, plaintext, ciphertext/tag, successful decrypt, rejection after tampering with every envelope/AAD/ciphertext component, atomic acceptance, secret clearing, unlock/lock behavior, and proof that export/backup paths are absent;
8. when Witness evidence is enabled, Witness lifecycle vectors for new and duplicate POST, GET `pending`, `retryable`, `confirmed`, `failed`, and missing jobs; canonical-tuple stability; exact `signed_attestation.attestation.network_id == pinned NetworkConfig.id == expected witness_network_id` binding; and accepted/rejected hash and threshold signatures;
9. Freebird/Witness authority-separation vectors proving that a verified exchange POST `200` accepts when Witness is disabled or unavailable, while Witness confirmation, status GET, or HyperToken dispatch cannot accept a non-`200` or invalid Freebird result; crashes and Witness retries must not roll back, repeat, or compensate a Freebird reservation; and
10. HyperToken non-disclosure vectors proving no monetary dispatch and no bearer, receipt, operation, vault state, Witness hash, or monetary derivative leaks through state/history, action results, broadcasts, describe/welcome/room state, custom messages, or any other public projection.

Any deterministic nonce, status capability, operation ID, output nonce, blinding value or randomness, AES-256 key, or AES-GCM nonce in these fixtures **MUST** be clearly labeled **TEST-ONLY**. Deterministic or reused values are prohibited in production; production randomness must come from a cryptographically secure random source as required by the relevant sections.

Fixtures do not become authoritative merely by being checked in. Each is authoritative only when its responsible native consumer executes it as a conformance test; JSON-shape assertions or generic scripts do not satisfy this gate, and service-only tests cannot establish Scarcity composition semantics.

## 14. Phase-1 acceptance criteria

A Phase-1 transfer conforms only if:

1. wallet discovery validates and pins exactly the public graph metadata and constants in Sections 1 and 4.1, including one descriptor per keyset;
2. the separate operator startup/restart gate in Section 4.2 proves disabled-first publication and durable acknowledgement before either transition accepts fresh work;
3. recipient preparation is fresh, local, durable, and bound to the selected edge;
4. the request has exactly one quantity-1 source and one quantity-1 output of the fixed class;
5. the exchange POST returns HTTP `200` with `Cache-Control: no-store` and every verification step in Section 6 succeeds;
6. vault transitions use the frozen AEAD profile atomically and ambiguous outcomes remain recoverable only by the same canonical POST;
7. if Witness evidence is enabled, it starts after acceptance, uses the Section 7 hash, binds the expected network identity, follows Section 8, and cannot affect acceptance;
8. no HyperToken monetary action or public projection occurs;
9. privacy, no-backup, reservation-budget, receipt-lifetime, and rotation rules are enforced; and
10. every applicable native executable gate in Section 13 passes.

Any failed item is non-conforming; there is no permissive, offline, Witness-backed, or HyperToken-backed fallback.

## 15. Deferred work

Phase 2 may add operator automation, UI, hardware-backed unlock providers, and audits. It may consider denomination or multi-party protocols only under a new versioned contract.

No Phase-1 behavior or fixture gate may be deferred to Phase 2. The Section 13 native-execution authority rule continues to apply to every future fixture: a fixture is not authoritative until the relevant native consumer executes it as a conformance test.
