# Scarcity V2 threat and failure model

**Normative draft for the V2 Freebird and Witness service contracts.**

## 1. Assumptions and trust roots

V2 uses the core's deterministic CBOR profile, decoder limits, named `C(P)` projections,
and exact `H(label, bytes)` function. A permissioned CometBFT validator set,
Freebird verifier key epoch, issuer authority records, and policy authority
records are published trust roots. BFT safety holds only while Byzantine
voting power remains below the configured fault bound and validator keys/
software follow the contract. RFC 9474 RSABSSA blind issuance assumes the
selected RSA-PSS security, correct randomized encoding, sound implementation,
key secrecy, and correct issuer verification; it is not a supply cap or a
consensus proof.

## 2. Assets and required properties

Protected assets are issuer provenance, owner authorization, output and domain
identity, exact conservation, nullifier uniqueness, admission single-use,
policy integrity, and Witness finality/state roots. A final spend requires a
committed CometBFT block, successful deterministic ABCI result, transaction
index/inclusion proof, header/app-hash binding, voting-power certificate, and
native Witness artifact. All inputs transition atomically. Admission and
validation policy digests are separate and both receipt-bound.

## 3. Threats and limits

**Credential theft and front-running.** A copied opaque credential cannot be
substituted for a different operation because admission and operation digests,
fresh ephemeral binding, audience/scope, persistent replay, and signed
assertion checks are required. Exact request relay remains possible: an
observer can relay the same public request or race delivery, and this contract
does not provide sender authentication or network anonymity beyond the
Freebird design. Binding possession and Witness idempotency determine whether
the exact operation succeeds; metadata/timing may still link activity.

**Freebird collusion or metadata leakage.** A colluding issuer/verifier may
correlate issuance, redemption, IP/Tor/relay metadata, timing, scope, or policy
use, and may issue or admit more credentials than intended. VOPRF privacy does
not hide network metadata or malicious service-side logs. Batching/relays are
operational mitigations, not protocol guarantees. A Freebird verifier can
deny service; it cannot make an invalid Witness operation final without the
Witness quorum.

**Issuer inflation.** An issuer can inflate its own asset supply or quota. The
mint credential proves provenance for a complete initial output, not an issuer
balance, global supply cap, or honest monetary policy. Federation policy may
reject issuers/assets, but V2 does not make an issuer honest.

**Forged service output.** Gateway responses, Freebird responses, V1
timestamps, ABCI `CheckTx`, votes, locks, or pre-commit observations are not
finality. Verification requires the committed block/header/app hash,
successful ABCI result, transaction inclusion proof, CometBFT voting-power
certificate, and native Witness artifact. Historical validator epochs and
policy/key versions are checked.

**Malicious client/validator.** Deterministic ABCI validation checks public
FinalNote proofs, provenance, owner signatures, conservation, domain,
nullifiers, policy objects, assertion signature, and commit-time expiry. A
malicious validator below the BFT bound may censor or withhold votes, causing
unavailability, but cannot finalize conflicting/invalid state. A malicious
client cannot provide private credentials or keys through public proofs.

**Cross-domain and substitution attacks.** Domain is in the unsigned payload,
output identity, nullifier, admission request, and receipt. Nullifier
derivation and independent output Merkle proofs reject cross-domain and
receipt-derived output substitution. Bridges/HTLCs are out of scope.

**Crash, partition, and recovery.** Freebird durable states reconcile using
authenticated digest callbacks/queries. CometBFT replay and app hashes restore
committed state; quorum loss halts finality. Recovery never releases a consumed
credential or rolls back a committed nullifier. An unknown response is queried
by digest, not retried as a new operation.

**Policy and key lifecycle failure.** Unknown, stale, revoked, mismatched, or
unauthorized admission/validation policy objects and key epochs fail closed.
Authority signature envelopes authenticate policy objects; their signatures
are not silently included in unsigned identity equations.

## 4. Privacy, availability, and out of scope

Public transaction proofs, FinalNote proofs, output roots, state roots,
receipts, and exact request relays can reveal timing, graph, and network
metadata. Credentials, private assertions, binding private keys, owner secrets,
and transport secrets MUST remain absent from notes, receipts, checkpoints,
gossip, and public artifacts.

Issuer or Freebird outage prevents new admission; Witness quorum loss prevents
finality. These are fail-closed availability failures, not permission to use
fallbacks or V1 timestamps. The model does not tolerate compromise of the BFT
fault bound, trust roots, honest-client secrets, or deterministic ABCI
execution. It does not promise censorship resistance, traffic-analysis
resistance, perfect Freebird unlinkability, issuer honesty, or bridge/HTLC
semantics.
