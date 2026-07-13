# Scarcity V2 Core Protocol Contract

**Status:** normative clean-slate contract; not wire-compatible with V1. The
words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are requirements for V2.

## 1. Scope and vocabulary

V2 defines notes, transactions, ownership authorization, issuer provenance,
expiry, and deterministic nullifiers.  An issuer defines what may be
minted; the core proves the provenance of a note and conserves value in each
asset.  A mint credential is not a supply cap, balance, or consensus statement.

Freebird admission credentials authorize an operation at the federation
boundary.  They MUST NOT occur in a note, transaction, receipt, nullifier, or
gossip message.  Witness finality and admission are separate contracts; this
document does not make a timestamp API an atomic nullifier registry.

## 2. Encoding and decoding

Every hash input and signed message is a **V2 canonical CBOR** byte string. The
profile is RFC 8949 deterministic encoding with these additional rules:

* only unsigned/negative integers, byte strings, text strings, arrays, maps,
  booleans, and null are permitted; floating point, tags, indefinite lengths,
  duplicate map keys, and other simple values are forbidden;
* integers use the shortest representation; byte/text strings and arrays/maps
  use definite lengths;
* map keys are unique text strings and are sorted by the lexicographic order of
  their encoded CBOR bytes;
* protocol integers are non-negative unless a schema explicitly says
  otherwise; amounts are encoded as unsigned integers;
* text is valid UTF-8 and is compared as its encoded bytes, not after Unicode
  normalization; protocol identifiers use ASCII;
* a decoder MUST reject trailing bytes and MUST reject a value whose decoded
  representation is not re-encodable to the identical bytes.

The following are hard decoder limits (including nested values): maximum
message 1 MiB, maximum nesting depth 32, maximum map/array length 256,
maximum byte string 64 KiB, maximum text string 4 KiB, and maximum integer
value `2^64 - 1` in the tagless V2 CBOR profile. Amounts use the same unsigned
`uint64` bound; checked sums MUST be
accumulated in `uint128`. A transaction has at most 256 inputs and 256 outputs,
and MUST contain at least one output.
Implementations MUST fail closed when a limit is exceeded.  Limits apply before
expensive cryptographic work where possible.

Core payloads use the native, versioned envelopes of their sibling protocol
contracts (the Witness receipt envelope and the Freebird admission envelope),
not a new generic Scarcity wrapper. A core payload MUST identify its V2 schema
in its native envelope, and that envelope's exact fields and signature coverage
are authoritative. Unknown fields are rejected unless the native contract
explicitly defines an extension mechanism.

The final profile is the specified canonical-CBOR profile above; its fixture
consumer, rather than a library name, is normative. These limits are resolved.

## 3. Canonical economic identities and shared digests

The shared hash profile is exactly the service-contract profile:

`H(label, bytes) = SHA-256(ASCII("scarcity/v2/" || label || "\\0") || bytes)`.

Each named `EconomicIdentity` payload below has one exact field list. Its
canonical bytes are deterministic CBOR under Section 2, with signature
envelopes, receipts, proofs, transport fields, retry fields, and derived
identity fields excluded by the named projection. There is no generic field
stripping operation and no hashing of an envelope. Each sibling service uses
the same named projection and canonical bytes defined below.

* `AssetIdentity = {issuer, asset_code, unit, decimals, policy_digest,
  expiry_policy}`; `asset_id = H("asset", C(AssetIdentity))`.
* `PolicyIdentity` is the canonical unsigned `ExpiryPolicy`; its digest is
  `H("asset-policy", C(PolicyIdentity))`.
* `OutputIdentity = {transaction_id, output_index, output_commitment}`;
  `output_id = H("output", C(OutputIdentity))`.
* `MintIdentity = {keyset_id, output_commitment}`;
  `mint_transaction_id = H("mint-transaction", C(MintIdentity))`.
* `TransactionCore` and `OperationCore` are the complete named projections in
  Section 8; `transaction_digest = H("transaction", C(TransactionCore))` and
  `operation_digest = H("operation", C(OperationCore))`.
* `AdmissionRequestCore` is the complete named projection in Section 8;
  `admission_digest = H("admission", C(AdmissionRequestCore))`.
* `owner_key_id = H("owner-key", raw_ed25519_public_key)`.
* `nullifier = H("nullifier", C({spend_domain, output_id}))`.
* `output_leaf = H("output-leaf", C({output_index, output_id}))`.
* `output_node = H("output-node", left_hash || right_hash)`.
* A MintNote commitment is
  `H("output-commitment", C({keyset_id, owner_material, replay_nonce}))`;
  a transition commitment is
  `H("output-commitment", C(TransitionOutputCommitment))`.

`C(P)` means the canonical CBOR bytes of the explicitly named payload `P`, not
a generic field-stripping rule. All results are exactly 32 bytes; changing an
unsigned field changes its identity, while changing only a signature envelope
does not.

`TransitionOutputCommitment` is exactly
`{asset_id, amount, recipient_key, spend_domain, provenance:{kind:"transition"}}`.

## 4. Asset descriptor

An `AssetDescriptor` is:

```text
{ issuer: IssuerId,
  asset_code: ASCII text (1..64),
  unit: ASCII text (1..32),
  decimals: unsigned integer (0..38), policy_digest: bytes(32),
  expiry_policy: ExpiryPolicy, asset_id: bytes(32),
  issuer_signature: AuthoritySignature }
ExpiryPolicy = { epoch_seconds: uint64, max_lifetime_epochs: uint64,
  boundary: "exclusive" }
```

For a policy, `epoch(t) = floor(t / epoch_seconds)` and
`epoch_start(e) = e * epoch_seconds`; multiplication is checked uint64
arithmetic. `epoch_seconds` and `max_lifetime_epochs` are non-zero.

`IssuerId` is exactly 32 bytes, the SHA-256 identifier of the issuer namespace
record. `SpendDomain` and `policy_digest` are also exactly 32 bytes.
`policy_digest` MUST equal
`H("asset-policy", C(PolicyIdentity))`; `asset_id` MUST equal
`H("asset", C(AssetIdentity))`. The issuer signature authenticates the
descriptor and policy for federation admission. `asset_code` is unique within
the issuer namespace; `unit` and `decimals` describe display only and MUST NOT
alter integer amounts.

The descriptor and its expiry policy are immutable. Any policy, issuer, code,
unit, or decimal change MUST create a new descriptor and therefore a new
`asset_id`; a registry MUST NOT mutate an existing descriptor in place.

The authority signature is a native authority-key-record envelope. Its
algorithm and key-record lifecycle are governed by the key section below.

## 5. Fixed RSA keysets and mint provenance

An issuer publishes a non-recursive `RSAKeyset` record. It contains identifiers
and scalar parameters, never nested asset descriptors, policy objects, or other
key records:

```text
{ issuer_id: IssuerId, keyset_id: bytes(32), asset_id: bytes(32),
  spend_domain: SpendDomain, denomination: uint64,
  issuance_epoch: uint64, expiry_epoch: uint64,
  modulus: bytes(384), public_exponent: 65537,
  suite: "RSABSSA-SHA384-PSS-Randomized",
  authority_key_id: bytes(32), authority_signature: Ed25519Signature }
```

`RSAKeysetIdentity` is the same map without `keyset_id` and
`authority_signature`; it is the named unsigned keyset payload.

`keyset_id = H("rsa-keyset", C(RSAKeysetIdentity))`. The keyset's
`asset_id`, sole `spend_domain`, exact denomination, issuance epoch, and expiry
epoch are public and immutable. `modulus` is a fixed 3072-bit RSA modulus;
`public_exponent` and `suite` are fixed literals. A keyset is valid only during
its issuance epoch and its credential expires at the exclusive end of
`expiry_epoch`. Keysets are not supply caps.

`issuance_epoch < expiry_epoch` and
`expiry_epoch - issuance_epoch <= asset.expiry_policy.max_lifetime_epochs`.
The keyset's fixed expiry epoch is the expiry used by its MintNotes.

An issuer creates a mint credential for one complete, directly spendable
initial output. There is exactly one RFC 9474 blinded signature input:

```text
MintSignatureInput = {
  keyset_id: bytes(32), asset_id: bytes(32), spend_domain: bytes(32),
  denomination: uint64, issuance_epoch: uint64, expiry_epoch: uint64,
  blinded_payload: { owner_material: bytes(32), replay_nonce: bytes(32) }
}
```

The `blinded_payload` contains only owner material and nonce. The public keyset
supplies every other field. The credential's signature envelope is RFC 9474
RSABSSA with SHA-384 and randomized PSS encoding over the canonical
`MintSignatureInput`; it
therefore covers the complete directly spendable initial output, including its
sole domain and replay nonce. The envelope is carried as `MintProvenance`;
it is not part of unsigned payload identity or output-id derivation. The
credential proves mint provenance, not a supply cap or balance. Issuer quota
accounting and replay prevention are external issuer state; the core MUST NOT
infer quota from a credential.

Blind issuance MUST use this RFC 9474 RSABSSA input and native issuance
envelope. The issuer does not learn the blinded owner material or resulting
output identity; the wallet verifies and unblinds before constructing the
output. The 32-byte nonce is committed data only: its freshness or uniqueness
is not a core-validity claim and MUST NOT be inferred while it is blinded.

The issuer key used by RSABSSA is an authority key record. Quota, replay-store,
and credential redemption behavior are external policy and service contracts.

## 6. Keys, roles, rotation, and revocation

Authority keys are Ed25519. A non-recursive `AuthorityKeyRecord` is exactly:

```text
{ namespace_id: bytes(32), role: ASCII text, public_key: bytes(32),
  not_before_epoch: uint64, not_after_epoch: uint64,
  predecessor_id: bytes(32) | null, key_id: bytes(32),
  root_signature: Ed25519Signature }
```

`authority_key_id = H("authority-key", C(AuthorityKeyIdentity))`.
The record binds that id to one 32-byte public key, role, issuer/federation
namespace, start/end epochs, predecessor id, and status. Roles are
`issuer-authority`, `issuer-revoke`,
`federation-authority`, and `witness-authority`; records do not represent
wallet owners. The record is signed by the offline authority root in the
native authority envelope. Rotation is prospective: a new record is effective
only at its start epoch and preserves the predecessor; historical signatures
remain valid under the recorded history.

Revocation is also prospective. A compromise/revocation record affects
signatures in its declared interval and later, never an already valid
historical mint or finality receipt. Verifiers MUST retain the append-only key
history and the root signature needed to establish the record at the relevant
epoch.

Owner keys are different: `recipient_key` is a raw 32-byte Ed25519 public key,
not a key-record reference. Its `owner_key_id` is exactly
`H("owner-key", recipient_key)`. Owner authorization is an Ed25519 signature
of the 32-byte authorization challenge, encoded as exactly 64 signature bytes;
the public key is taken from the referenced SpendableNote and MUST hash to the
declared owner key id. Owner keys have no authority-record rotation or
revocation semantics; one-time generation is wallet policy.

RSA mint keys are only the modulus in the fixed `RSAKeyset`; they are not
Ed25519 authority keys and are never reused for owner, Witness, or Freebird
signatures. `KeyId` for authority records and `keyset_id` for RSA keysets are
32-byte values with the equations above.

`Ed25519PublicKey` is exactly 32 raw bytes and `Ed25519Signature` exactly 64
raw bytes. `KeyId` is exactly
`H("authority-key", C(AuthorityKeyIdentity))`.
The federation/issuer root key is a published Ed25519 key; its append-only
history signs every authority record and rotation/revocation record. A record's
start epoch is prospective, revocation is prospective, and verifiers retain
the history needed to validate old records and receipts. This history is
authoritative; no local key directory may override it.

## 7. Outputs, final notes, and provenance

`SpendableNote = MintNote | FinalNote`. Both forms expose the same asset,
uint64 amount, raw Ed25519 owner key, sole spend domain, output commitment,
output id, and deterministic expiry.

A `TxOutput` is the pre-finalization output payload:

```text
{ asset_id: bytes(32), amount: uint64, recipient_key: bytes(32),
  spend_domain: SpendDomain,
  output_commitment: bytes(32),
  provenance: MintProvenance | TransitionProvenance }
MintProvenance = { kind: "mint", keyset_id: bytes(32),
  credential_payload: MintSignatureInput,
  signature_envelope: NativeMintSignatureEnvelope }
TransitionProvenance = { kind: "transition" }
```

`output_commitment` is an unsigned 32-byte commitment to the output's economic
payload and owner key. The output id is **exactly**
`H("output", C({transaction_id, output_index, output_commitment}))`; no
receipt, signature, source lineage, or other field is
included. A mint uses its deterministic `mint_transaction_id` and index zero;
a transition uses the transaction digest and its canonical output index. A mint
output has exactly one `MintProvenance`; a transition output has no source-lineage
field. After finalization, transition provenance is the authenticated pair
`(receipt_id, inclusion_proof.leaf_index)`, while conservation is checked
against transaction inputs.

`MintNote` is directly spendable without a zero-input Witness transfer:

```text
{ kind: "mint", asset_id: bytes(32), amount: uint64,
  recipient_key: bytes(32), spend_domain: SpendDomain,
  output_commitment: bytes(32), mint_transaction_id: bytes(32),
  output_index: 0, output_id: bytes(32),
  issued_at: uint64, expires_at: uint64,
  keyset_id: bytes(32), mint_credential: MintProvenance }
```

Its `output_commitment` is derived from the fixed keyset id and the two-field
blinded payload. `mint_transaction_id = H("mint-transaction", C({keyset_id,
output_commitment}))`, and its expiry is the exclusive end of the
keyset's `expiry_epoch` under the asset's immutable epoch length. Direct mint
validation checks the RSA suite/keyset binding, denomination, owner key, domain,
and these deterministic ids/times. The nonce is committed data only; no
freshness or uniqueness check is part of core validation. `issued_at` is exactly
the start of `issuance_epoch`;
`expires_at` is exactly the start of `expiry_epoch`, and validity is
`issued_at <= header_time < expires_at`. No request arrival time or
zero-input Witness operation supplies mint time.
`recipient_key` MUST equal the credential's `owner_material`, and the keyset's
asset, denomination, domain, and expiry epoch MUST equal the MintNote fields.
Consequently every MintNote amount is exactly its keyset denomination;
transitions may split or merge denominations but remain subject to exact
uint128 conservation.

After Witness commit, the output becomes a `FinalNote`:

```text
{ output: TxOutput, output_id: bytes(32),
  committed_at: uint64, expires_at: uint64,
  receipt: WitnessReceipt, inclusion_proof: InclusionProof }
```

For a transition, `committed_at` is the deterministic CometBFT commit time and
`expires_at` is the start of the epoch
`epoch(committed_at) + max_lifetime_epochs`, with checked uint64 arithmetic.

`output_id` MUST equal the output's id. `committed_at` MUST be the authenticated
Witness commit time in `receipt`; `expires_at` MUST be deterministically
derived from `committed_at` and the `AssetDescriptor.expiry_policy`. A FinalNote
is spendable only with a valid receipt and an inclusion proof that binds this
output id and its index to the committed transaction. The receipt MUST
authenticate the transaction id, exactly one spend domain, ordered output ids,
commit time, and finality. The inclusion proof MUST verify membership of this
output id at this output index under the receipt's committed root. A recipient one-time key
is bound by the output-id commitment and later owner authorization. Reusing a recipient key is wallet
policy, not an additional cryptographic validity rule.

Raw Ed25519 owner keys, owner-key IDs, authority keys, rotation, prospective
revocation, and historical verification are resolved above. Witness retains its
native `witness.signed_finality` envelope; core treats that envelope as opaque
but requires its signed body to cover the transaction/operation/admission
digests, spend domain, output root, policy digests, state roots, deterministic
commit time, block commit certificate, validator epoch, nullifiers, and
signer set. Core MUST NOT invent a competing receipt envelope or include it in
an unsigned identity.

### Output Merkle tree

Each transaction has an output Merkle tree independent of its receipt and of
receipt fields. Outputs are ordered by their canonical transaction output index
(`0, 1, ...`) and MUST NOT be reordered by output id. For output index `i`,
`leaf_i = H("output-leaf", C({output_index: i, output_id}))`. An internal node is
`H("output-node", left_hash || right_hash)`. For an odd number of children, the final
child is duplicated at that level. For zero children the root is the fixed
`H("output-empty", empty-byte-string)`; V2 transactions reject zero outputs,
but this value makes the tree function total.

The tree root is committed by the Witness transaction finalization, but leaves
are not hashes of receipts and do not contain receipt ids, timestamps, or
signatures. An `InclusionProof` is the native-independent payload:

```text
{ leaf_index: uint, siblings: [bytes(32)] }
```

`leaf_index` MUST equal the transaction output index. `siblings` are ordered
from leaf level to root level; each level's left/right position is determined
by the index bit at that level. A proof MUST have exactly the tree height and
MUST reconstruct the receipt-committed root. The proof is carried alongside,
but is not included in, the output leaf or output id.

## 8. Transactions and authorization

The canonical unsigned projections are shared verbatim with Freebird and
Witness. They are maps with exactly these fields and array ordering:

```text
TransactionCore = {
  spend_domain: bytes(32),
  inputs: [{ output_id: bytes(32), nullifier: bytes(32), owner_key_id: bytes(32) }],
  outputs: [TxOutput]
}
FinalNoteProof = { spendable_note: SpendableNote, tx_output: TxOutput,
  output_id: bytes(32), provenance_proof: MintProvenanceProof |
    WitnessFinalityProof }
MintProvenanceProof = { mint_credential: MintProvenance }
WitnessFinalityProof = { receipt: NativeWitnessReceipt,
  inclusion_proof: InclusionProof }
OperationCore = {
  transaction_core: TransactionCore, transaction_digest: bytes(32),
  owner_authorizations: [Authorization], final_note_proofs: [FinalNoteProof],
  operation_expiry: uint64
}
AdmissionRequestCore = {
  version: uint64, federation_id: bytes(32), audience: ASCII text,
  scope: ASCII text, operation_digest: bytes(32), spend_domain: bytes(32),
  admission_policy_digest: bytes(32), request_expiry: uint64
}
```

`transaction_digest`, `operation_digest`, and `admission_digest` are exactly
the H invocations in Section 3. `transaction_core` is embedded as a payload,
not replaced by its digest; only the scalar digest references avoid recursion.
`final_note_proofs` is sorted by the corresponding input `output_id`, and
`owner_authorizations` is in the same canonical input order. Each proof carries
the complete SpendableNote and complete `TxOutput`, so its output id, domain,
amount, provenance, recipient key, and expiry are independently recomputable.
The proof's `output_id` MUST equal the recomputed id; its note and output MUST
agree field-for-field. The validator MUST derive every input asset/amount and
output asset/amount from these payloads, then perform conservation; no bare
output-id lookup is a substitute. None of these projections contains a
Freebird credential, assertion, binding private key, transport/retry field, or
signature envelope.

The complete submitted transaction carries the core plus its authorization and
native proof envelopes:

```text
{ spend_domain: SpendDomain, inputs: [Input], outputs: [TxOutput],
  authorizations: [Authorization] }
Input  = { note: SpendableNote, nullifier: bytes(32), authorization_ref: uint }
Authorization = { input_index: uint, owner_key_id: bytes(32),
  challenge: bytes(32), signature: bytes(64) }
```

Every transaction has one authenticated `spend_domain`, and every output and
input SpendableNote MUST carry that same domain. A transaction with a cross-domain
input or output MUST be rejected; no implicit bridge
or domain conversion exists in V2 base. `transaction_digest` is exactly
`H("transaction", C(TransactionCore))`; `TransactionCore` is the
field-by-field projection above and contains no authorization or signature
envelope, while each
authorization challenge is `H("authorization", C({
transaction_digest, input_index, spend_domain, owner_key_id }))`. Every input has exactly one authorization,
and every authorization references exactly one input. Inputs MUST be sorted by
their referenced `output_id` in lexicographic byte order; authorizations MUST
appear in the same input order and `input_index` is that canonical position.
Outputs are indexed by their array position. Input output ids, nullifiers, and
output ids MUST be unique within a transaction. An empty output array is
invalid.

Inputs are proof-carrying: a supplied MintNote MUST carry its valid mint
credential, while a supplied FinalNote MUST carry its Witness receipt and
inclusion proof; each validates independently. A node MUST NOT silently resolve a
bare output id from local state. An implementation using state resolution instead
MUST expose that resolution as an authenticated, versioned Witness proof with
the same output-id, receipt, and inclusion guarantees; otherwise it is not V2
compatible.

An authorization proves control of the input SpendableNote's recipient key and
binds the entire transaction through its transaction id. It does not prove
issuer provenance; mint or transition provenance is independently checked.

Transaction id coverage, input/auth ordering, and Ed25519 authorization
encoding are resolved above. The native Witness receipt envelope remains
authoritative for finalization fields not present in this payload.

## 9. Spend domains and nullifiers

`SpendDomain` identifies one finality/uniqueness domain and is authenticated by
the federation on each committed output. A nullifier is exactly:
`H("nullifier", C({spend_domain, output_id}))`.
The same output MUST yield the same nullifier in the same domain. A verifier
MUST reject a transaction whose input SpendableNote domain differs from the
transaction/output domain, or whose nullifier is not this exact derivation.
Cross-domain spends are invalid, not a new nullifier namespace for the same
output.

Finalization requires atomic registration of all transaction nullifiers: either
all are newly recorded and the transaction receives a receipt, or none are
recorded. A repeated identical transaction may be idempotent; a different
transaction presenting any recorded nullifier MUST produce conflict evidence.
Those registry and receipt rules belong to the Witness contract, not gossip.

`SpendDomain` is exactly 32 bytes. It is a federation-issued identifier for
one finality namespace; it is not an issuer or asset identifier.
Bridge and conditional-spend semantics are deferred to a later contract.

## 10. Conservation, expiry, and demurrage

For every asset independently, a valid transaction satisfies exact integer
conservation:

`sum_uint128(input amount(asset)) = sum_uint128(output amount(asset))`.

There is no cross-asset conversion, rounding, implicit fee, or negative amount.
Each amount is a `uint64`; each side is accumulated with checked `uint128`
arithmetic and MUST be rejected on overflow. Every spendable note, mint
denomination, input amount, and output amount MUST be greater than zero. A fee or burn requires an explicit
output/account type in a future version; it MUST NOT be silently inferred.

At validation time a FinalNote is spendable exactly when
`committed_at <= header_time < expires_at`. `committed_at` is the
authenticated Witness commit time; `expires_at` is the start of the epoch
`epoch(committed_at) + max_lifetime_epochs` from the immutable authenticated
asset expiry policy, with checked `uint64` time arithmetic. The expiry boundary
is exclusive. V2 base has **no
demurrage**; an asset descriptor MUST NOT reduce amounts through an implicit
demurrage rule.

CometBFT's committed block header time is federation time. All validators use
that deterministic header time for assertion validity, policy intervals, and
expiry; request-arrival time and local wall clocks MUST NOT participate in
validation. A block with a non-monotonic or otherwise invalid header time is
rejected by the CometBFT/Witness contract. Demurrage is excluded from V2 base.

## 11. Association policy versus cryptographic validity

The policy payloads are immutable, authenticated native records, matching the
service contracts:

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

`admission_policy_digest = H("admission-policy", C(AdmissionPolicy))`;
`validation_policy_digest = H("validation-policy", C(ValidationPolicy))`.
`AdmissionRequestCore.admission_policy_digest` MUST use the former, while the
Witness receipt commits both digests separately. Arrays are sorted
by their canonical byte values and contain no duplicates. Policy records are
signed by their respective Ed25519 authority and are immutable; a change
creates a new digest and must be committed at a new federation epoch.

Cryptographic validity means correct canonical decoding, schema/version,
signatures/proofs, hash bindings, issuer key status, note provenance,
nullifier derivation, time rules, and per-asset arithmetic. Association policy
is separate: examples include requiring an asset to be admitted by a
federation, allowing only particular issuers or domains, enforcing issuer
supply accounting, rate limits, or requiring a Freebird `spend` admission.

`validation_policy_digest` authenticates deterministic Witness/core validation
rules; `admission_policy_digest` authenticates the separate Freebird admission
profile. They are distinct 32-byte digests, both appear in their respective
native artifacts, and neither may stand in for the other.

Policy rejection MUST NOT be represented as a cryptographic failure, and a
cryptographically valid note is not automatically admitted to every federation.
Policy data MUST be authenticated by the policy authority and versioned when it
affects a finality decision.

## 12. Error categories

Errors are machine-readable categories, never ambiguous boolean failures:

* `decode-limit` — malformed CBOR, forbidden type, duplicate key, trailing
  bytes, or a decoder limit violation;
* `schema` — missing, extra, wrong-type, out-of-range, or non-canonical field;
* `hash-binding` — an id, commitment, challenge, or inclusion binding mismatch;
* `key` — unknown, wrong-role, expired, or revoked key;
* `provenance` — invalid issuer credential, asset mismatch, or note mismatch;
* `authorization` — missing/duplicate input authorization or invalid ownership;
* `nullifier` — incorrect derivation, duplicate in request, or registry conflict;
* `arithmetic` — overflow, negative value, cross-asset mismatch, or
  conservation failure;
* `time` — not-yet-valid, expired, clock/skew, or expiry-policy failure;
* `policy` — association/admission/supply-policy rejection;
* `finality` — unavailable, malformed, or non-matching federation receipt.

Implementations MAY include diagnostic details, but MUST NOT leak owner secrets
or blind-issuance material. Error details are not consensus inputs.

## 13. Fixture gate

Fixtures MUST cover canonical bytes and limits, every domain-separated digest,
asset substitution, mint versus transition provenance, output-id mutation,
receipt/inclusion mutation, key rotation/revocation, one-time recipient
authorization, authorization/domain substitution, proof-carrying inputs,
cross-domain rejection, exact arithmetic edges, Witness-derived expiry,
policy/validity separation, and registry transitions. No V2-base demurrage
fixture is permitted.

Core fixtures are not blocked by an unresolved core contract choice. Native
Witness and Freebird envelopes remain opaque and must continue to conform to
their signed sibling contracts; their envelope bytes are not Scarcity economic
identities. Fixture vectors MUST include MintNote direct validation, keyset
binding, issuance/expiry epochs, all three shared digests, output-id derivation,
Merkle odd/empty cases, transition receipt/index provenance, policy-digest
separation, and prospective key-history verification.
