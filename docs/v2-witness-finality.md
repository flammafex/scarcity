# Scarcity V2 Witness finality contract

**Normative draft. Contract version: `scarcity/witness-finality/v2`.**

Witness uses a CometBFT sidecar and deterministic ABCI application. It retains
the native Witness signed-artifact and threshold-signature envelopes; no new
Scarcity receipt container competes with them. There is no gateway-local
finality and no pre-consensus finality.

## 1. Canonical input and policy authority

Witness uses the core's exact V2 profile and `H(label, bytes) =
SHA-256(ASCII("scarcity/v2/" || label || "\0") || bytes)`, with `C(P)` and
canonical CBOR exactly as core specifies. `TransactionCore`,
`transaction_digest`, `OperationCore`, `operation_digest`, and
`AdmissionRequestCore`/`admission_digest` are exactly the nonrecursive
equations in the Freebird contract; Witness MUST reject any byte or digest
mismatch.

The request carries the exact `TransactionCore`/`OperationCore` projections,
public owner authorizations, and public `FinalNoteProof` values (prior native
receipt, output index, and independent output-tree inclusion proof). It carries
the native signed Freebird assertion, but no credential, private assertion
material, binding private key, or owner secret.

Witness validates the signed `AdmissionPolicy` authority envelope and its
`admission_policy_digest`, and separately validates the signed
`ValidationPolicy` object and `validation_policy_digest`. Their canonical
unsigned payloads are exactly core's:

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

The arrays/maps use the core CBOR profile and the policy contract's prescribed
ordering; unknown fields are rejected. Their digests are
`H("admission-policy", C(AdmissionPolicy))` and
`H("validation-policy", C(ValidationPolicy))`. Each object is authenticated
by its native authority-key-record signature envelope (not part of the named
payload) and
is accepted only for the configured authority, version, key epoch, and
deterministic block/header-time interval. Both digests are committed in the
final artifact.

## 2. ABCI validation and committed transition

The deterministic ABCI application verifies canonical bytes, all digest
equations, one spend domain, issuer provenance, owner signatures, FinalNote
lineage, exact conservation, output proofs, nullifiers, policies, and the
native Freebird assertion. Assertion expiry is checked against the deterministic
CometBFT block/header time at application commit, never against a local clock
or gateway arrival time.

The application atomically applies all inputs and outputs. A failed proof,
policy, assertion, expiry, or any nullifier CAS conflict rejects the complete
transaction; no input is recorded. Nullifiers are `H("nullifier",
C({spend_domain, output_id}))`. Output leaves and the independent Merkle tree
follow core's `output-leaf`, `output-node`, and `output-empty` rules and never
depend on a receipt ID.

CometBFT `CheckTx`, proposal validation, prevotes, precommits, locks, and ABCI
success before block commit are not finality. Finality requires all of:

1. a successful deterministic ABCI `DeliverTx` result (`code = 0`, with the
   canonical operation digest and resulting app/state roots) included at a
   specific transaction index in a committed CometBFT block;
2. a canonical transaction-inclusion proof for that index and the committed
   block data; and
3. a verified CometBFT commit certificate binding the block/header hash,
   app hash, height, chain/network ID, validator-set epoch, and voting-power
   quorum.

The successful ABCI proof is the canonical map
`{code: 0, tx_hash: bytes(32), tx_index: uint32, operation_digest: bytes(32),
prior_state_root: bytes(32), result_state_root: bytes(32)}` returned by the
application and authenticated by inclusion at `tx_index`; a failed or absent
response cannot produce a receipt. The transaction proof is
`{tx_index: uint32, leaf: bytes(32), siblings: [bytes(32)]}`, where the block's
native transaction root and ordered transaction list determine left/right
positions. The exact native CometBFT header/commit encoding is retained; the
proof MUST bind chain/network ID, height, app hash, block hash, and tx hash.
A gateway merely relays these values.

## 3. State roots and consensus failure

The application state root before the transaction is `prior_state_root`; the
post-transition deterministic root is `result_state_root`. State is a sorted
map of `(key, value)` bytes. `key = H("state-key", C({spend_domain,
nullifier}))`; a nullifier value is `C({operation_digest, block_height,
tx_index, output_root})`. Leaves are `H("state-leaf", key ||
H("state-value", value))`, internal nodes are `H("state-node", left ||
right)`, sorted lexicographically by key, with odd nodes duplicated and empty
root `H("state-empty", empty-byte-string)`. The block app hash MUST equal the
committed result of the ABCI application, and the receipt's state-root
transition MUST be proven by the committed block. `output_root` is
the independent ordered output Merkle root from core. State roots MUST cover
the nullifier registry, policy/key epochs, and application state required to
replay the transition; they MUST NOT include mutable receipt signatures.

For validator voting power `W`, CometBFT's configured Byzantine-safe quorum
(normally `>2W/3`) is required. Proposer/leader failure causes CometBFT round
change; quorum loss or partition halts commits and finality. A minority cannot
finalize or invent header time. CometBFT validator-set changes are committed
ABCI transitions: the block records the set ID/epoch and voting-power map used
for its certificate, and the new set becomes active only at its specified
height. Historical receipts use their historical set.

Recovery replays durable blocks, verifies app hashes and commit certificates,
restores state roots, and catches up to a committed quorum before voting.
Uncommitted proposal/lock state may be discarded or reproposed; committed
nullifiers and roots never roll back.

## 4. Operation-specific native receipt

After block commit, Witness emits its native `witness.signed_finality` artifact
with the configured native multisig or BLS envelope. Its signed body is
operation-specific and covers version, chain/network, spend domain, block
height, transaction index, block/header hash, app hash, transaction/operation/
admission digests, sorted nullifiers, `output_root`, separate
`admission_policy_digest` and `validation_policy_digest`, `prior_state_root`,
`result_state_root`, committed header time/expiry result, validator epoch,
signer IDs/bitmap, and voting power. The artifact also carries the CometBFT
commit certificate and transaction inclusion proof in the native Witness
envelope/fields.

Normatively, the native receipt envelope bytes are deterministic CBOR of the
map `{contract_version: "witness/v2", artifact_type: "witness.signed_finality",
receipt: ReceiptBody, signatures: NativeSignatureSet}` using the core profile.
`ReceiptBody` is the complete signed body above, and signatures cover
`H("receipt", C(ReceiptBody))` plus the native Witness signature domain. The
`receipt_id` is exactly `H("receipt", C(ReceiptBody))`; it is not a leaf input,
does not contain a signature, and is the ID used by FinalNote provenance.
`NativeSignatureSet` retains Witness's native multisig/aggregate fields,
signer IDs/bitmap, suite, proof-of-possession and config epoch. No competing
Scarcity wrapper is permitted.

Verifiers check the native signature, certificate quorum and epoch, header/app
hash binding, transaction proof, ABCI-success evidence, all roots, digests,
nullifiers, policies, and deterministic time. Same operation digest and exact
inputs returns the identical artifact. Changed inputs return `409
idempotency_conflict`; another operation sharing a committed nullifier returns
`409 nullifier_conflict`; invalid input/assertion is `400/401/403`, expiry
`422`, and no quorum `503`.

Authenticated callbacks/queries to Freebird use public operation/admission/
assertion IDs and this native artifact only. V1 `/v1/timestamp` remains
observation-only and cannot establish V2 finality.
