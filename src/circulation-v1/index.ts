/**
 * Isolated Phase-1 circulation foundation (does not alter legacy protocol APIs).
 *
 * This is the hand-written Freebird V2 public-bearer exchange + V2 graph-issuance
 * subsystem. It is a SEPARATE Freebird surface from `src/integrations/freebird.ts`
 * (the legacy V4/V5 admission adapter) and from `src/vendor/freebird/` (vendored
 * SDK crypto). See AGENTS.md "Freebird integration surfaces" before changing any
 * of them. Exported from the package root as `circulationV1` (namespaced).
 */

export * from './types.js';
export * from './canonical.js';
export * from './blind-rsa.js';
export * from './bootstrap.js';
export * from './discovery.js';
export * from './freebird-client.js';
export * from './vault.js';
export * from './wallet.js';
export * from './witness-client.js';
