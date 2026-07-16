# Scarcity cash-kernel contract blueprint

**Status:** Approved project-owner blueprint
**Authority:** `docs/scarcity-decisions.md` is the only authority.
`docs/scarcity-synthesis-matrix.md` is evidence only.

## Scope and non-goals

The cash kernel defines the native civic Scarbuck unit, citizen claims,
issuance, bearer notes, spending, reissuance, change, demurrage, finality, and
the accounting boundaries needed for a first federation.

It does not define bridge or HTLC money, cross-federation transfers, offline
finality, generic assets, or smart contracts.

Scarcity is a semantic evolution from V1, not a total rewrite. It is Sophia’s
citizen-cash alternative to Cashu and Fedimint.

Freebird establishes mandatory, anonymous, economy-blind citizenship and
eligibility. Witness supplies time and finality authority. HyperToken provides
local-first wallet state; universal relays provide transport only. None of
Freebird, Witness, or a relay determines monetary policy. No Freebird-visible
payload may include economic data.

## Approved policy recorded by this draft

- The unit is a native civic currency.
- Primary issuance is an equal, deterministic, anonymous citizen dividend.
- Secondary issuance is bounded civic issuance, threshold-authorized only for
  enumerated public purposes, including procurement and initial merchant
  liquidity.
- Permanent demurrage burns reduce supply, are irreversible, and are never
  automatically replaced or redirected. Separately authorized dividend or
  civic issuance may offset aggregate contraction only as new, classified
  issuance; it never reverses a burn.
- The polity establishes demand by accepting Scarbucks for its defined civic
  obligations, dues, fees, and services.
- Prestige is excluded from the first deployment; a later governance role
  requires separate approval.

## Required lifecycle boundaries

1. **Citizen claim:** Freebird eligibility is presented without economic
   information. Witness finality is required before a claim becomes a
   spendable bearer note. At most one claim may be issued per authorized
   entitlement interval under the approved dividend rule; interval parameters
   remain blocked.
2. **Civic issuance:** A request identifies an enumerated public purpose and
   passes the approved threshold authorization and cap checks. It is auditable
   as civic issuance and cannot silently become dividend issuance.
3. **Spend, reissue, and change:** A spend consumes an input note only after
   Witness finality. Reissuance creates successor notes and change preserves
   aggregate value, subject to demurrage. A rejected or conflicted attempt
   does not consume a note.
4. **Permanent burn:** Demurrage is recorded as an irreversible burn event
   against the affected note/value. It has no policy-side credit or
   redirection and is never automatically replaced. Separately authorized,
   classified dividend or civic issuance may offset aggregate contraction as
   new issuance and never reverses a burn.
5. **Witness finality:** Submission, retry, finalization, and conflict
   outcomes are distinct states. Retries are idempotent; a conflict cannot be
   resolved by a wallet or relay and leaves the competing result subject to
   the Witness authority boundary.
6. **Wallet recovery:** Local wallet state is recoverable from user-controlled
   recovery material and replayable finalized records. Local state cannot
   establish issuance or spend finality. Bearer ownership and recovery control
   remain subject to the unresolved ownership construction.
7. **Privacy and collusion:** Bearer privacy and anonymous eligibility are
   separate claims. The deployment must state metadata leakage and collusion
   assumptions for Freebird, Witness, wallets, and relays; no component may
   infer policy authority from observing transport or eligibility traffic.

## Accounting contract

For each defined accounting interval:

`outstanding_end = outstanding_start + dividend_issuance + civic_issuance - permanent_burns`

Spend, reissue, change, civic acceptance, and finalized transfers are value
reclassifications and must net to zero in this equation. Any retirement of
accepted funds must be an explicit permanent-burn event. The implementation
must provide non-duplicated aggregate issuance and burn records, conservation
across note transitions, deterministic replay of finalized state, and exact
aggregate reconciliation. The required audit granularity is unresolved and
must not impose public or linkable per-note lineage.

## Acceptance criteria for the draft

- No economic field crosses the Freebird boundary.
- Every issuance is classified as dividend or authorized civic issuance.
- Every spend has one unambiguous finalized outcome, with retries and
  conflicts safely represented.
- Permanent burns are irreversible, have no policy-side credit or redirection,
  and are never automatically replaced; separately authorized, classified
  dividend or civic issuance may offset aggregate contraction as new issuance
  and never reverses a burn.
- Wallet recovery cannot promote unfinalized data to money or finality.
- Aggregate accounting reconciles exactly, while leaving numeric parameters
  unspecified.
- Relay transport cannot authorize issuance, spending, policy, or finality.
- The first deployment contains no Prestige governance role or bridge/HTLC
  money.

## Blocked owner decisions before normative schemas/vectors

- bearer ownership construction and transfer versus blinded reissue;
- exact note and certificate canonical schema;
- demurrage rate, epoch, rounding, and age origin;
- claim proof and nullifier design;
- issuer and finality threshold topology;
- issuance audit granularity;
- privacy/collusion assumptions and relay deployment profile;
- the civic acceptance set;
- dividend schedule;
- civic issuance caps;
- first federation deployment;
- recovery and key-management policy; and
- issuer and key lifecycle.
