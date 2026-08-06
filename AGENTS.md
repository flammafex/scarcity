# AGENTS.md

Guidance for Codex / AI agents working in this repository. Read this before making changes.

## What this is

Scarcity is a Chaumian e-cash protocol: privacy-preserving bearer tokens with double-spend
prevention via nullifier gossip + threshold-signed timestamps. No blockchain, no mining.
Research prototype (v0.5.0). Node.js 20+, TypeScript ESM.

External services (Freebird, Witness, HyperToken) are **not in this repo** — they run as
separate containers/processes. The code here is the Scarcity core + CLI + web wallet + explorer.

## Repo layout

```
src/
  index.ts              Public API barrel (exports ScarbuckToken, adapters, types)
  token.ts              Core: mint/transfer/split/merge/multi-party/HTLC (largest, ~1000 lines)
  gossip.ts             NullifierGossip: P2P nullifier set, peer scoring, pruning
  validator.ts          TransferValidator: tiered validation + confidence scoring
  crypto.ts             SHA-256, nullifiers, constant-time compare, PoW
  ownership.ts          OwnershipProof (Schnorr-style, binds secret→nullifier)
  bridge.ts             FederationBridge (cross-federation transfers)
  constants.ts          DEFAULT_TOKEN_VALIDITY_MS (~576 days demurrage window)
  types.ts              Core interfaces + adapter contracts
  integrations/
    freebird.ts         V4 VOPRF admission tokens (has insecure fallback)
    witness.ts          Ed25519 multisig + BLS12-381 aggregated sigs (most complex, ~870 lines)
    hypertoken.ts       P2P peer mgmt, rate limiting, serialization
  circulation-v1/       Hand-written Freebird V2 exchange + graph-issuance subsystem (see below)
  vendor/               Vendored (not npm) Freebird VOPRF + HyperToken P2P stack
  cli/                  `scar` CLI: index.ts entry, commands/, config.ts, wallet.ts, infrastructure.ts
  web/                  Web wallet: server.ts (Express :3000) + public/ (vanilla JS, PWA)
  explorer/             Nullscape Explorer: server.ts (Express + WS :3001), database.ts (SQLite)
test/
  integration/          10 numbered suites (01-basic … 10-live-services)
  helpers/test-utils.ts Custom TestRunner + TestConfig
  run-integration-tests.ts  Orchestrates all suites
docker-compose.yaml     Full stack incl. external services
.forgejo/workflows/    CI
```

## Freebird integration surfaces

There are **four parallel, intentionally separate** Freebird surfaces in this repo. A Freebird
compatibility review MUST cover all four — missing one is a known failure mode (the
`circulation-v1/` subsystem was once overlooked for exactly this reason).

| Surface | Location | What it implements | Consumed by |
|---|---|---|---|
| Legacy adapter | `src/integrations/freebird.ts` | V4/V5 VOPRF admission tokens (shells the vendored SDK `FreebirdClient`) | Core protocol (`token.ts`, `validator.ts`), CLI, `test/integration/*` |
| Circulation V2 | `src/circulation-v1/` | Hand-written Freebird V2 public-bearer exchange + V2 graph-issuance (canonical digests, replay-authority, Witness envelope) | `src/index.ts` (exported as `circulationV1`), `test/circulation-v1/*` |
| Vendored SDK crypto | `src/vendor/freebird/` | `voprf.ts` / `p256.ts` snapshot of the Freebird SDK crypto layer | `src/integrations/freebird.ts` (legacy), `test/integration/08-crypto-correctness.test.ts` |
| Vendored Freebird SDK | `src/vendor/freebird-sdk/` | Bundled `@freebird/sdk` v0.2.0 (client + `crypto` namespace) | `src/integrations/freebird.ts`, `src/circulation-v1/canonical.ts` (framing/HMAC), `test/circulation-v1/*` |

Rules:
- `circulation-v1/canonical.ts` delegates the **V4/V5 framing and graph-issuance HMAC** bloc to the
  vendored `@freebird/sdk` `crypto` namespace (byte-identical; enforced by the framing/HMAC parity
  gate in `test/circulation-v1/foundation.test.ts`). The **V2 exchange/graph-issuance digests,
  replay-authority proof, and Witness envelope** stay hand-written — the SDK's public `crypto`
  namespace does not export them.
- `circulation-v1/` does **not** import the vendored `voprf.ts` — the V4/V5 framing is delegated to
  `src/vendor/freebird-sdk/` instead. Line-number references to `src/vendor/freebird/voprf.ts` in
  `canonical.ts` comments can drift after a vendor sync.
- After any change to `src/vendor/freebird-sdk/`, re-verify the `circulation-v1` vectors
  (`npm run test:circulation-v1`) — the framing/HMAC parity gate and the retained-digest parity
  tripwire (via `FreebirdClient` instance methods) both run there.
- The independent cross-check is now **frozen Rust-derived vectors + live runs**, not "two
  implementations": the retained V2 digests are pinned by `test:circulation-v1:live` and the
  framing/HMAC parity gate pins the vendored SDK to the same bytes. Do not vendor the SDK's
  `graph_issuance.ts` to replace the retained digest core in `canonical.ts`.

## Setup / run / test / build

```bash
npm install                 # native modules (better-sqlite3, @roamhq/wrtc) need build tools
npm run build               # tsc + copy static assets → dist/   (REQUIRED before running anything)
npm run dev                 # tsc --watch
npm run web                 # build + web wallet on http://localhost:3000
npm run explorer            # build + explorer on http://localhost:3001
npm test                    # build + integration suite (fallback mode if services down)
npm run test:live           # build + live-service tests (requires all infra running)
npm run test:basic          # single suite (also :double-spend, :degradation, :phase3)
npm run clean               # rm -rf dist
docker compose up --build --abort-on-container-exit   # full stack incl. tests
```

CLI (after `npm run build`): `./dist/src/cli/index.js <command>` or `npm install -g .` then `scar`.

## Lint

`npm run lint` runs `eslint src/` but **eslint is not installed and has no config** — the script
currently fails. Do not rely on linting. If you add eslint, also add config + devDependency.

## Coding conventions

- **ESM with `.js` import extensions** even for TS sources: `import { Crypto } from './crypto.js'`
  (Node16 module resolution). Always include the extension in new imports.
- `strict: true` TypeScript; prefer `readonly` fields and `interface` types.
- Adapter pattern: external services behind `AdmissionClient` / `WitnessClient` / `GossipNetwork`
  interfaces (see `src/types.ts`). Never call external services directly from core protocol code.
- Use `@noble/*` for crypto, not hand-rolled primitives. Use `Crypto.constantTimeEqual` for
  byte comparisons.
- JSDoc on public methods; keep section banners consistent with surrounding files.
- Vendored code lives under `src/vendor/` — treat as upstream, do not modify casually.
- Deprecation in progress: `freebird` config fields are being renamed to `auth` across
  `token.ts`/`validator.ts`. Prefer `auth`; keep `freebird` as a deprecated alias.

## Testing expectations

- **No unit test framework.** Tests are integration-level using a custom `TestRunner`
  (`test/helpers/test-utils.ts`). Follow the existing pattern when adding tests.
- `test/helpers/test-utils.ts` **auto-sets `SCARCITY_ALLOW_INSECURE_FALLBACK=true`**, so the
  default suite passes with no external services running (exercises fallback paths).
  **Green tests do NOT prove real-service correctness** — only `npm run test:live` does.
- New test files go in `test/integration/` with the next available `NN-name.test.ts` number,
  export a `runXxxTest` function, and register in `test/run-integration-tests.ts`.
- Always run `npm run build` before tests — the runner executes compiled JS from `dist/`.
- For crypto/protocol changes, prefer adding cases to `08-crypto-correctness.test.ts` or the
  relevant numbered suite rather than a new file.

## PR / review expectations

- Keep PRs scoped: one concern per PR. Don't mix refactors with behavior changes.
- Run `npm run build && npm test` before requesting review. Paste the summary in the PR.
- If your change touches external-service behavior, also run `npm run test:live` against
  `docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay`
  and note the result.
- Don't commit `dist/` (gitignored) or `node_modules/`.
- Don't update version numbers in `package.json`, `src/cli/index.ts`, or `src/web/server.ts`
  as part of an unrelated change — keep all three in sync (currently 0.5.0).
- Commit messages: short imperative subject, match the style in `git log --oneline`.

## Constraints — do NOT touch without asking

1. **Uncommitted working changes** may exist on `src/integrations/witness.ts`, `src/types.ts`,
   `test/integration/10-live-services.test.ts`. Check `git status` first; don't clobber in-progress work.
2. **Cryptographic primitives** in `src/crypto.ts`, `src/ownership.ts`, `src/vendor/freebird/`,
   and the signature handling in `src/integrations/witness.ts` — high blast radius. Flag for
   review before changing; never swap algorithms without explicit approval.
3. **HTLC two-phase nullifier logic** in `src/token.ts` (nullifier deliberately NOT published at
   lock time, only at claim/refund). A bug here = lost funds. Preserve the phase-1/phase-2 split.
4. **Demurrage constant** `DEFAULT_TOKEN_VALIDITY_MS` in `src/constants.ts` — must stay
   consistent across `NullifierGossip.maxNullifierAge`, `TransferValidator.maxTokenAge`, and
   `TOKEN_VALIDITY_MS` in `src/web/public/app.js`. Change all three together or none.
5. **Gossip pruning safety valve** (`src/gossip.ts` ~line 385) — the force-prune path has a
   documented theoretical double-spend risk; don't "fix" it without discussing the tradeoff.
6. **Insecure fallback paths** (`allowInsecureFallback` in freebird/witness adapters) — these
   exist for dev/testing. Don't remove them and don't make them default-on in production paths.
7. **`src/vendor/`** is vendored upstream code. Don't edit casually; if a fix is needed, note
   it's a local patch in the PR description.
8. **Port defaults are inconsistent across sources** (Witness: 8080 in config.ts vs 8083 in
   tests/README; HyperToken: 3000 in config.ts vs 5001 in tests/README). Don't "normalize" them
   without confirming which set is canonical — ask first.

## Definition of done

A change is complete when **all** of these hold:

- [ ] `npm run build` succeeds with no new TS errors.
- [ ] `npm test` passes (fallback mode). If the change affects external-service behavior,
      `npm run test:live` also passes against a running stack.
- [ ] New/changed behavior has test coverage in the appropriate `test/integration/` suite.
- [ ] No `console.log` left in production code paths unless matching existing style; warnings
      use `console.warn` with a `[Component]` prefix.
- [ ] Public API additions are exported from `src/index.ts` and have JSDoc.
- [ ] If any `readonly` field needed mutation, it's justified in the PR — avoid the
      `(this as any)` cast pattern unless strictly necessary; prefer a real mutator.
- [ ] If the demurrage window, port defaults, or version strings were touched, all
      inconsistent locations were updated together (see Constraints #4, #8).
- [ ] PR description includes the test summary output and notes any external-service testing.
- [ ] No secrets, `.env`, `dist/`, or `node_modules/` committed.
