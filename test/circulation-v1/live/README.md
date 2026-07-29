# Circulation-v1 live vertical slice

This runner exercises the native Phase-1 composition against already-running
Freebird and Witness services. It does **not** provision services, start
containers, create Redis databases, write wallet/config files, or use the
legacy adapters.

The runner uses `MemoryVaultBackend` for both wallets. Secrets remain in
process memory and are never printed. The runner intentionally emits only
phase labels and redacted failure messages.

## Operational prerequisites

Before running this check, operators must provide:

- one shared Redis instance for the Freebird issuer/verifier deployment;
- a verifier-owned replay-authority probe context registered in that verifier's
  spend-store (the issuer has no public challenge-registration endpoint);
- the disabled-first bootstrap acknowledgement and the operator-approved
  switch to the accepting K0/K1 graph;
- the native Phase-1 V4 admission policy, with one-use redemption credentials;
- the pinned K0 graph issuance policy and the E01/E10 exchange edges;
- a local three-node Witness network with a stable NetworkConfig identity;
- 30-day receipt validity (`2_592_000` seconds), `Cache-Control: no-store` on
  successful JSON responses, and no public projection of receipt/artifact or
  status-capability data.

Discovery must expose exactly the two directed edges used here. The native
bootstrap validator requires the E01 and E10 edge budgets to be `100`; this
runner performs one committed quantity-1 exchange on each edge, then submits
only deliberate idempotent or consumed-source replays to prove that no second
artifact or budget charge is created.

The runner talks only to the pinned Freebird discovery endpoint,
`POST /v1/public/graph/issue`, its matching
`GET /v1/public/graph/issue/status?public_operation_id=...` status route,
`POST /v1/public/graph/replay-authority/probe`, `POST /v2/public/exchange`, and Witness `/v1/network` plus
`/v1/attestations`. It must not be pointed at the removed legacy graph
issuance routes, a legacy timestamp endpoint, HyperToken, a public explorer,
or a projection service.

## Required environment

All variables below are required; there are no defaults.

| Variable | Format |
| --- | --- |
| `SCARCITY_LIVE_FREEBIRD_ORIGIN` | HTTPS origin, or loopback HTTP origin; no path/query/fragment |
| `SCARCITY_LIVE_WITNESS_ORIGIN` | HTTPS origin, or loopback HTTP origin; no path/query/fragment |
| `SCARCITY_LIVE_ISSUER_ID` | Issuer identity pinned in discovery |
| `SCARCITY_LIVE_REPLAY_AUTHORITY_ID` | Canonical base64url, exactly 32 bytes; must match discovery |
| `SCARCITY_LIVE_REPLAY_AUTHORITY_PROBE_ID` | Canonical base64url, exactly 32 bytes; verifier-registered probe ID |
| `SCARCITY_LIVE_REPLAY_AUTHORITY_CHALLENGE` | Canonical base64url, exactly 32 bytes; pre-registered verifier challenge |
| `SCARCITY_LIVE_WITNESS_NETWORK_ID` | Expected Witness `NetworkConfig.id` |
| `SCARCITY_LIVE_V4_ADMISSION` | One-use canonical base64url V4 redemption token |
| `SCARCITY_LIVE_WALLET_A_ID` | Canonical base64url, exactly 16 bytes |
| `SCARCITY_LIVE_WALLET_B_ID` | Canonical base64url, exactly 16 bytes |
| `SCARCITY_LIVE_WALLET_A_UNLOCK_KEY` | Canonical base64url, exactly 32 bytes |
| `SCARCITY_LIVE_WALLET_B_UNLOCK_KEY` | Canonical base64url, exactly 32 bytes |
| `SCARCITY_LIVE_GRAPH_ID` | 64 lowercase hexadecimal characters |
| `SCARCITY_LIVE_E01_TRANSITION_ID` | 64 lowercase hexadecimal characters; K0 → K1 |
| `SCARCITY_LIVE_E10_TRANSITION_ID` | 64 lowercase hexadecimal characters; K1 → K0 |
| `SCARCITY_LIVE_POLL_INTERVAL_MS` | Positive integer milliseconds |
| `SCARCITY_LIVE_MAX_POLL_ATTEMPTS` | Positive integer |

Use shell environment injection or a secret manager. Do not add a `.env`
file, put these values in a repository script, or paste them into logs.

## Run

```sh
npm run build && node dist/test/circulation-v1/live/run-live.js
```

The equivalent package shortcut is:

```sh
npm run test:circulation-v1:live
```

The command is deliberately not runnable without explicit service origins,
pins, credentials, wallet unlock keys, expected graph/transition IDs, and
polling limits.

## Assertions

The run performs this bounded sequence:

1. Fetches and validates pinned Freebird discovery and the configured graph.
2. Verifies one issuer replay-authority probe using the supplied verifier-registered
   challenge/probe context; it never generates or registers local challenge material.
3. Fetches Witness network configuration and requires three nodes.
4. Creates two in-memory wallets and issues one K0 artifact to wallet A using
   the supplied V4 credential.
4. Repeats the committed graph-issuance POST with the exact canonical request
   and header-only capability, requiring the identical result and unchanged
   local artifact state.
5. Completes E01 (A K0 → B K1) and proves the exact original exchange POST is
   idempotent. It then submits a fresh operation with a fresh capability and
   valid distinct output but the already-consumed source, requiring definitive
   Freebird rejection and no local state change.
6. Completes E10 (B K1 → A K0), then submits only the computed receipt-envelope hash to Witness, polls the
   durable attestation job, and verifies the returned threshold signature,
   receipt hash, and network binding.
7. Verifies spent-source transitions, final K0/K1 ownership state, and that
   replaying either spent source fails.

No status capability, receipt, bearer artifact, request body, attestation, or
service response is printed by the runner.
