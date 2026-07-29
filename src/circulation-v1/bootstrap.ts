/** Scarcity-local validation of the frozen Phase-1 bootstrap profile. */

import {
  BoundaryValidationError,
  CIRCULATION_CLASS,
  EDGE_BUDGET_LIMIT,
  FREEBIRD_EXCHANGE_PROFILE,
  RECEIPT_LIFETIME_SECONDS,
  assertCanonicalSha256Hex,
  decodeCanonicalBase64Url,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  parseFreebirdV5Descriptor,
  parseGraphSlotSelector,
  type AdmissionState,
  type DisabledPublicationAcknowledgement,
  type ExchangeDiscoveryV2,
  type ExchangeGraphV2,
  type GraphIssuancePolicy,
  type GraphIssuanceDiscovery,
  type GraphKeysetV2,
  type GraphTransitionV2,
  type BootstrapManifest,
  type ReceiptVerificationKeyV2,
  type FreebirdDiscoveryDocumentV2,
  parseGraphIssuanceDiscovery,
} from './types.js';
import {
  canonicalDescriptorIdV2,
  canonicalDescriptorBytesV2,
  canonicalGraphIdV2,
  canonicalKeysetIdV2,
  canonicalTransitionIdV2,
  canonicalTransitionBytesV2,
} from './canonical.js';
import { validateRfc4055PssSpki } from './blind-rsa.js';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';

export interface BootstrapValidationOptions {
  /**
   * Genesis starts with disabled circulation edges.  A circulation discovery
   * snapshot normally uses accepting_new.  With no option, either lifecycle
   * state is accepted but both edges must use the same state.
   */
  readonly circulationState?: 'accepting_new' | 'disabled';
  /** Operator-pinned issuer identity for discovery validation. */
  readonly issuerId?: string;
  /** Optional exact identity checks supplied by the pinned Freebird codec. */
  readonly verifyDescriptorId?: (descriptor: unknown, descriptorId: string) => boolean;
  readonly verifyKeysetId?: (keyset: unknown, keysetId: string) => boolean;
  readonly verifyTransitionId?: (transition: unknown, transitionId: string) => boolean;
  readonly verifyGraphId?: (graph: unknown, graphId: string) => boolean;
}

function invalid(field: string, message: string): never {
  throw new BoundaryValidationError(`${field}: ${message}`);
}

function object(value: unknown, field: string): Record<string, unknown> {
  return (value !== null && typeof value === 'object' && !Array.isArray(value))
    ? value as Record<string, unknown>
    : invalid(field, 'expected an object');
}

function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], field: string): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) invalid(`${field}.${key}`, 'missing field');
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) invalid(`${field}.${key}`, 'unknown field');
  }
}

function text(value: unknown, field: string, min = 1, max = 4096): string {
  if (typeof value !== 'string' || value.length < min || value.length > max) invalid(field, 'invalid string');
  return value;
}

function integer(value: unknown, field: string, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) invalid(field, 'invalid integer');
  return value;
}

function id(value: unknown, field: string): string {
  return assertCanonicalSha256Hex(value, field);
}

function unique(values: readonly string[], field: string): void {
  if (new Set(values).size !== values.length) invalid(field, 'identities must be unique');
}

function parseReceiptKey(value: unknown, field: string, retained: boolean): ReceiptVerificationKeyV2 {
  const item = object(value, field);
  exact(item, ['key_id', 'algorithm', 'purpose', 'public_key_b64', 'valid_from', 'valid_until'], [], field);
  const keyId = id(item.key_id, `${field}.key_id`);
  const purpose = retained ? 'exchange_receipt_retained' : 'exchange_receipt_active';
  if (item.purpose !== purpose) invalid(`${field}.purpose`, `must be ${purpose}`);
  if (item.algorithm !== 'Ed25519') invalid(`${field}.algorithm`, 'must be Ed25519');
  const publicKey = decodeCanonicalBase64Url(item.public_key_b64, 32, `${field}.public_key_b64`);
  if (!ed25519.utils.isValidPublicKey(publicKey, false)) invalid(`${field}.public_key_b64`, 'invalid Ed25519 public key');
  const notBefore = integer(item.valid_from, `${field}.valid_from`, 1);
  const notAfter = integer(item.valid_until, `${field}.valid_until`, 1);
  if (notAfter <= notBefore || notAfter - notBefore < RECEIPT_LIFETIME_SECONDS) {
    invalid(`${field}.valid_until`, 'must cover a 30-day receipt interval');
  }
  if (encodeCanonicalLowerHex(sha256(publicKey)) !== keyId) invalid(`${field}.key_id`, 'does not identify public_key_b64');
  return {
    key_id: keyId,
    algorithm: 'Ed25519',
    purpose: purpose as ReceiptVerificationKeyV2['purpose'],
    public_key_b64: item.public_key_b64 as string,
    valid_from: notBefore,
    valid_until: notAfter,
  };
}

function parseClassSlot(value: unknown, field: string): GraphTransitionV2['source_slots'][number] {
  const item = object(value, field);
  exact(item, ['descriptor_id', 'slot_id', 'class', 'quantity'], [], field);
  if (item.class !== CIRCULATION_CLASS) invalid(`${field}.class`, 'wrong circulation class');
  const descriptorId = id(item.descriptor_id, `${field}.descriptor_id`);
  const slotId = text(item.slot_id, `${field}.slot_id`, 1, 128);
  if (!/^[\x00-\x7f]+$/.test(slotId)) invalid(`${field}.slot_id`, 'must be bounded ASCII');
  if (item.quantity !== 1) invalid(`${field}.quantity`, 'Phase-1 quantity must be 1');
  return { descriptor_id: descriptorId, slot_id: slotId, class: CIRCULATION_CLASS, quantity: 1 };
}

function parseKeyset(value: unknown, field: string): GraphKeysetV2 {
  const item = object(value, field);
  exact(item, ['keyset_id', 'descriptor_ids'], [], field);
  const keysetId = id(item.keyset_id, `${field}.keyset_id`);
  if (!Array.isArray(item.descriptor_ids) || item.descriptor_ids.length !== 1) {
    invalid(`${field}.descriptor_ids`, 'each keyset must contain exactly one descriptor');
  }
  const descriptorId = id(item.descriptor_ids[0], `${field}.descriptor_ids[0]`);
  return { keyset_id: keysetId, descriptor_ids: [descriptorId] };
}

function parseTransition(value: unknown, field: string): GraphTransitionV2 {
  const item = object(value, field);
  exact(item, ['transition_id', 'source_keyset_id', 'target_keyset_id', 'source_slots', 'output_slots', 'budget_id', 'budget_limit', 'admission_state'], [], field);
  const transitionId = id(item.transition_id, `${field}.transition_id`);
  const sourceKeysetId = id(item.source_keyset_id, `${field}.source_keyset_id`);
  const targetKeysetId = id(item.target_keyset_id, `${field}.target_keyset_id`);
  if (sourceKeysetId === targetKeysetId) invalid(`${field}.target_keyset_id`, 'transition must not be self-directed');
  if (!Array.isArray(item.source_slots) || item.source_slots.length !== 1) invalid(`${field}.source_slots`, 'must contain exactly one slot');
  if (!Array.isArray(item.output_slots) || item.output_slots.length !== 1) invalid(`${field}.output_slots`, 'must contain exactly one slot');
  const sourceSlot = parseClassSlot(item.source_slots[0], `${field}.source_slots[0]`);
  const outputSlot = parseClassSlot(item.output_slots[0], `${field}.output_slots[0]`);
  if (typeof item.budget_id !== 'string' || item.budget_id.length === 0 || item.budget_id.length > 4096) invalid(`${field}.budget_id`, 'must be non-empty');
  if (item.budget_limit !== EDGE_BUDGET_LIMIT) invalid(`${field}.budget_limit`, 'must be 100');
  if (item.admission_state !== 'accepting_new' && item.admission_state !== 'recovery_only' && item.admission_state !== 'disabled') {
    invalid(`${field}.admission_state`, 'invalid admission state');
  }
  return {
    transition_id: transitionId,
    source_keyset_id: sourceKeysetId,
    target_keyset_id: targetKeysetId,
    source_slots: [sourceSlot],
    output_slots: [outputSlot],
    budget_id: item.budget_id,
    budget_limit: EDGE_BUDGET_LIMIT,
    admission_state: item.admission_state as AdmissionState,
  };
}

function parseGraph(
  value: unknown,
  field: string,
  issuerId: string,
  retained: boolean,
  options: BootstrapValidationOptions,
): ExchangeGraphV2 {
  const item = object(value, field);
  exact(item, ['profile_id', 'graph_id', 'descriptors', 'keysets', 'transitions'], [], field);
  if (item.profile_id !== FREEBIRD_EXCHANGE_PROFILE) invalid(`${field}.profile_id`, 'wrong Freebird exchange profile');
  const graphId = id(item.graph_id, `${field}.graph_id`);
  if (!Array.isArray(item.descriptors) || item.descriptors.length !== 2) invalid(`${field}.descriptors`, 'must contain exactly two descriptors');
  if (!Array.isArray(item.keysets) || item.keysets.length !== 2) invalid(`${field}.keysets`, 'must contain exactly two keysets');
  if (!Array.isArray(item.transitions) || item.transitions.length !== 2) invalid(`${field}.transitions`, 'must contain exactly two transitions');
  const descriptors = item.descriptors.map((entry, index) => parseFreebirdV5Descriptor(entry, `${field}.descriptors[${index}]`)) as [ExchangeGraphV2['descriptors'][number], ExchangeGraphV2['descriptors'][number]];
  const keysets = item.keysets.map((entry, index) => parseKeyset(entry, `${field}.keysets[${index}]`)) as [GraphKeysetV2, GraphKeysetV2];
  const transitions = item.transitions.map((entry, index) => parseTransition(entry, `${field}.transitions[${index}]`)) as [GraphTransitionV2, GraphTransitionV2];
  unique(descriptors.map((entry) => entry.descriptor_id), `${field}.descriptors`);
  unique(descriptors.map((entry) => entry.token_key_id), `${field}.descriptors.token_key_id`);
  unique(keysets.map((entry) => entry.keyset_id), `${field}.keysets`);
  unique(transitions.map((entry) => entry.transition_id), `${field}.transitions`);
  for (const [index, descriptor] of descriptors.entries()) {
    if (descriptor.issuer_id !== issuerId) invalid(`${field}.descriptors[${index}].issuer_id`, 'does not match pinned issuer');
    try {
      validateRfc4055PssSpki(decodeCanonicalBase64Url(descriptor.pubkey_spki_b64, undefined, `${field}.descriptors[${index}].pubkey_spki_b64`));
    } catch (error) {
      invalid(`${field}.descriptors[${index}].pubkey_spki_b64`, error instanceof Error ? error.message : 'invalid RFC 4055 SPKI');
    }
    if (canonicalDescriptorIdV2(descriptor) !== descriptor.descriptor_id) invalid(`${field}.descriptors[${index}].descriptor_id`, 'non-canonical descriptor identity');
    if (options.verifyDescriptorId && !options.verifyDescriptorId(item.descriptors[index], descriptor.descriptor_id)) {
      invalid(`${field}.descriptors[${index}].descriptor_id`, 'identity verification failed');
    }
  }
  for (const [index, keyset] of keysets.entries()) {
    if (canonicalKeysetIdV2(keyset.descriptor_ids) !== keyset.keyset_id) invalid(`${field}.keysets[${index}].keyset_id`, 'non-canonical keyset identity');
    if (options.verifyKeysetId && !options.verifyKeysetId(item.keysets[index], keyset.keyset_id)) {
      invalid(`${field}.keysets[${index}].keyset_id`, 'identity verification failed');
    }
    if (!descriptors.some((descriptor) => descriptor.descriptor_id === keyset.descriptor_ids[0])) {
      invalid(`${field}.keysets[${index}].descriptor_ids[0]`, 'descriptor is not in graph');
    }
  }
  const memberships = new Set<string>();
  for (const keyset of keysets) {
    const descriptorId = keyset.descriptor_ids[0];
    if (memberships.has(descriptorId)) invalid(`${field}.keysets`, 'a descriptor may belong to only one keyset');
    memberships.add(descriptorId);
  }
  if (memberships.size !== descriptors.length) invalid(`${field}.keysets`, 'every descriptor must be published exactly once');
  for (const [index, transition] of transitions.entries()) {
    if (canonicalTransitionIdV2(transition) !== transition.transition_id) invalid(`${field}.transitions[${index}].transition_id`, 'non-canonical transition identity');
    if (options.verifyTransitionId && !options.verifyTransitionId(item.transitions[index], transition.transition_id)) {
      invalid(`${field}.transitions[${index}].transition_id`, 'identity verification failed');
    }
    if (!keysets.some((keyset) => keyset.keyset_id === transition.source_keyset_id)) invalid(`${field}.transitions[${index}].source_keyset_id`, 'unknown keyset');
    if (!keysets.some((keyset) => keyset.keyset_id === transition.target_keyset_id)) invalid(`${field}.transitions[${index}].target_keyset_id`, 'unknown keyset');
    if (!keysets.find((keyset) => keyset.keyset_id === transition.source_keyset_id)?.descriptor_ids.includes(transition.source_slots[0].descriptor_id)) {
      invalid(`${field}.transitions[${index}].source_slots[0].descriptor_id`, 'descriptor is not in source keyset');
    }
    if (!keysets.find((keyset) => keyset.keyset_id === transition.target_keyset_id)?.descriptor_ids.includes(transition.output_slots[0].descriptor_id)) {
      invalid(`${field}.transitions[${index}].output_slots[0].descriptor_id`, 'descriptor is not in target keyset');
    }
    if (retained && transition.admission_state === 'accepting_new') invalid(`${field}.transitions[${index}].admission_state`, 'retained transitions cannot accept fresh work');
    if (!retained && options.circulationState && transition.admission_state !== options.circulationState) {
      invalid(`${field}.transitions[${index}].admission_state`, `must be ${options.circulationState}`);
    }
  }
  const keysetIds = keysets.map((entry) => entry.keyset_id);
  const edgePairs = transitions.map((entry) => `${entry.source_keyset_id}->${entry.target_keyset_id}`);
  if (edgePairs.length !== 2 || !edgePairs.includes(`${keysetIds[0]}->${keysetIds[1]}`) || !edgePairs.includes(`${keysetIds[1]}->${keysetIds[0]}`)) {
    invalid(`${field}.transitions`, 'must contain exactly one edge in each direction');
  }
  const normalizedGraph = { profile_id: FREEBIRD_EXCHANGE_PROFILE, graph_id: graphId, descriptors, keysets, transitions };
  if (canonicalGraphIdV2(normalizedGraph) !== graphId) invalid(`${field}.graph_id`, 'non-canonical graph identity');
  if (options.verifyGraphId && !options.verifyGraphId(item, graphId)) invalid(`${field}.graph_id`, 'identity verification failed');
  return normalizedGraph;
}

function parseDiscovery(
  value: unknown,
  options: BootstrapValidationOptions,
): FreebirdDiscoveryDocumentV2 {
  const root = object(value, 'discovery');
  exact(root, ['exchange'], ['graph_issuance'], 'discovery');
  const exchange = object(root.exchange, 'discovery.exchange');
  exact(exchange, ['active_graph', 'retained_graphs', 'active_receipt_key', 'retained_receipt_keys'], [], 'discovery.exchange');
  const rawGraph = object(exchange.active_graph, 'discovery.exchange.active_graph');
  const rawDescriptors = rawGraph.descriptors;
  if (!Array.isArray(rawDescriptors) || rawDescriptors.length === 0) invalid('discovery.exchange.active_graph.descriptors', 'missing issuer identity');
  const firstDescriptor = object(rawDescriptors[0], 'discovery.exchange.active_graph.descriptors[0]');
  const issuerId = options.issuerId ?? text(firstDescriptor.issuer_id, 'discovery.exchange.active_graph.descriptors[0].issuer_id');
  const activeGraph = parseGraph(exchange.active_graph, 'discovery.exchange.active_graph', issuerId, false, options);
  if (!Array.isArray(exchange.retained_graphs)) invalid('discovery.exchange.retained_graphs', 'must be an array');
  const retainedGraphs = exchange.retained_graphs.map((entry, index) => parseGraph(entry, `discovery.exchange.retained_graphs[${index}]`, issuerId, true, options));
  const activeReceiptKey = parseReceiptKey(exchange.active_receipt_key, 'discovery.exchange.active_receipt_key', false);
  if (!Array.isArray(exchange.retained_receipt_keys)) invalid('discovery.exchange.retained_receipt_keys', 'must be an array');
  const retainedReceiptKeys = exchange.retained_receipt_keys.map((entry, index) => parseReceiptKey(entry, `discovery.exchange.retained_receipt_keys[${index}]`, true));
  unique([activeGraph.graph_id, ...retainedGraphs.map((graph) => graph.graph_id)], 'discovery.exchange graphs');
  unique([activeReceiptKey.key_id, ...retainedReceiptKeys.map((key) => key.key_id)], 'discovery.exchange receipt keys');
  const descriptorContracts = new Map<string, string>();
  const budgetContracts = new Map<string, string>();
  for (const graph of [activeGraph, ...retainedGraphs]) {
    for (const descriptor of graph.descriptors) {
      const contract = encodeCanonicalLowerHex(canonicalDescriptorBytesV2(descriptor));
      const previous = descriptorContracts.get(descriptor.token_key_id);
      if (previous !== undefined && previous !== contract) invalid('discovery.exchange descriptors', 'conflicting reused token-key metadata');
      descriptorContracts.set(descriptor.token_key_id, contract);
    }
    for (const transition of graph.transitions) {
      const contract = encodeCanonicalLowerHex(canonicalTransitionBytesV2(transition));
      const previous = budgetContracts.get(transition.budget_id);
      if (previous !== undefined && previous !== contract) invalid('discovery.exchange transitions', 'budget ID was reused for a changed stable contract');
      budgetContracts.set(transition.budget_id, contract);
    }
  }
  const graphIssuance = root.graph_issuance === undefined ? undefined : parseGraphIssuanceDiscovery(root.graph_issuance);
  return {
    exchange: { active_graph: activeGraph, retained_graphs: retainedGraphs, active_receipt_key: activeReceiptKey, retained_receipt_keys: retainedReceiptKeys },
    ...(graphIssuance === undefined ? {} : { graph_issuance: graphIssuance }),
  };
}

function parseGraphIssuancePolicy(value: unknown, graph: ExchangeGraphV2, discovery: GraphIssuanceDiscovery, field: string): GraphIssuancePolicy {
  const item = object(value, field);
  exact(item, ['issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'budget_id', 'budget_limit', 'quantity', 'admission_state', 'authorization_scheme', 'authorization_scope_digest_b64'], [], field);
  const policyId = text(item.issuance_policy_id, `${field}.issuance_policy_id`, 1, 128);
  if (!/^[\x00-\x7f]+$/.test(policyId)) invalid(`${field}.issuance_policy_id`, 'must be bounded ASCII');
  const outputKeysetId = id(item.keyset_id, `${field}.keyset_id`);
  const outputDescriptorId = id(item.descriptor_id, `${field}.descriptor_id`);
  const policyGraphId = id(item.graph_id, `${field}.graph_id`);
  const budgetId = text(item.budget_id, `${field}.budget_id`, 1, 128);
  if (!/^[\x00-\x7f]+$/.test(budgetId)) invalid(`${field}.budget_id`, 'must be bounded ASCII');
  if (policyGraphId !== graph.graph_id) invalid(`${field}.graph_id`, 'must reference active graph');
  if (item.admission_state !== 'accepting_new') invalid(`${field}.admission_state`, 'genesis issuance must be accepting_new');
  if (item.authorization_scheme !== 'v4_local') invalid(`${field}.authorization_scheme`, 'must be v4_local');
  if (item.quantity !== 1) invalid(`${field}.quantity`, 'must be 1');
  if (item.budget_limit !== EDGE_BUDGET_LIMIT) invalid(`${field}.budget_limit`, 'must be 100');
  if (!graph.keysets.some((keyset) => keyset.keyset_id === outputKeysetId)) invalid(`${field}.keyset_id`, 'unknown keyset');
  const outputKeyset = graph.keysets.find((keyset) => keyset.keyset_id === outputKeysetId)!;
  if (outputKeyset.keyset_id !== graph.keysets[0].keyset_id) invalid(`${field}.keyset_id`, 'genesis output must target K0');
  if (outputKeyset.descriptor_ids[0] !== outputDescriptorId) invalid(`${field}.descriptor_id`, 'must be K0 descriptor');
  const scope = encodeCanonicalBase64Url(decodeCanonicalBase64Url(item.authorization_scope_digest_b64, 32, `${field}.authorization_scope_digest_b64`));
  if (!discovery.replay_authority.v4_scope_digest_tombstones.includes(scope)) invalid(`${field}.authorization_scope_digest_b64`, 'must be retained by replay authority');
  const published = discovery.policies.find((candidate) => candidate.issuance_policy_id === policyId);
  if (published === undefined || published.graph_id !== policyGraphId || published.keyset_id !== outputKeysetId || published.descriptor_id !== outputDescriptorId || published.budget_id !== budgetId || published.budget_limit !== EDGE_BUDGET_LIMIT || published.quantity !== 1 || published.admission_state !== 'accepting_new' || published.authorization_scheme !== 'v4_local' || published.authorization_scope_digest_b64 !== scope) invalid(field, 'does not match published V2 policy');
  if (graph.descriptors.find((descriptor) => descriptor.descriptor_id === outputDescriptorId)?.token_key_id === undefined) invalid(`${field}.descriptor_id`, 'K0 descriptor token key is missing');
  return {
    issuance_policy_id: policyId,
    graph_id: policyGraphId,
    keyset_id: outputKeysetId,
    descriptor_id: outputDescriptorId,
    budget_id: budgetId,
    budget_limit: EDGE_BUDGET_LIMIT,
    quantity: 1,
    admission_state: 'accepting_new',
    authorization_scheme: 'v4_local',
    authorization_scope_digest_b64: scope,
  };
}

function parseAcknowledgement(value: unknown, issuerId: string, graphId: string, transitionIds: readonly string[]): DisabledPublicationAcknowledgement {
  const item = object(value, 'disabled_publication_ack');
  exact(item, ['version', 'issuer_id', 'graph_id', 'disabled_transition_ids', 'acknowledged_admission_state', 'operator', 'acknowledged_at_unix'], [], 'disabled_publication_ack');
  if (item.version !== 'freebird/exchange-disabled-publication-ack/v1') invalid('disabled_publication_ack.version', 'wrong version');
  if (item.issuer_id !== issuerId) invalid('disabled_publication_ack.issuer_id', 'issuer mismatch');
  if (item.graph_id !== graphId) invalid('disabled_publication_ack.graph_id', 'graph mismatch');
  if (!Array.isArray(item.disabled_transition_ids) || item.disabled_transition_ids.length !== 2) invalid('disabled_publication_ack.disabled_transition_ids', 'must contain exactly two IDs');
  const ids = item.disabled_transition_ids.map((entry, index) => id(entry, `disabled_publication_ack.disabled_transition_ids[${index}]`));
  if (new Set(ids).size !== 2 || !ids.every((entry) => transitionIds.includes(entry))) invalid('disabled_publication_ack.disabled_transition_ids', 'must contain exactly E01 and E10');
  if (item.acknowledged_admission_state !== 'disabled') invalid('disabled_publication_ack.acknowledged_admission_state', 'must be disabled');
  text(item.operator, 'disabled_publication_ack.operator');
  integer(item.acknowledged_at_unix, 'disabled_publication_ack.acknowledged_at_unix', 1);
  return item as unknown as DisabledPublicationAcknowledgement;
}

/** Parse and validate a complete public discovery snapshot. */
export function validateDiscoverySnapshot(value: unknown, options: BootstrapValidationOptions = {}): ExchangeDiscoveryV2 {
  return parseDiscovery(value, { ...options, circulationState: options.circulationState ?? 'accepting_new' }).exchange;
}

/** Validate the V2 graph-issuance policy/replay-authority container. */
export function validateGraphIssuanceDiscoverySnapshot(
  value: unknown,
  exchange: ExchangeDiscoveryV2,
): GraphIssuanceDiscovery {
  const discovery = parseGraphIssuanceDiscovery(value);
  const graphs = [exchange.active_graph, ...exchange.retained_graphs];
  for (const policy of discovery.policies) {
    const graph = graphs.find((candidate) => candidate.graph_id === policy.graph_id);
    if (graph === undefined) invalid(`graph issuance discovery policy ${policy.issuance_policy_id}`, 'unknown graph');
    const keyset = graph.keysets.find((candidate) => candidate.keyset_id === policy.keyset_id);
    if (keyset === undefined || !keyset.descriptor_ids.includes(policy.descriptor_id)) invalid(`graph issuance discovery policy ${policy.issuance_policy_id}`, 'unknown descriptor/keyset binding');
    if (policy.admission_state === 'accepting_new' && graph.graph_id !== exchange.active_graph.graph_id) invalid(`graph issuance discovery policy ${policy.issuance_policy_id}`, 'retained graph cannot accept new issuance');
  }
  return discovery;
}

/** Enforce Freebird's permanent replay-authority and append-only scope rules. */
export function validateGraphIssuanceDiscoveryUpdate(
  exchange: ExchangeDiscoveryV2,
  previous: unknown | undefined,
  next: unknown | undefined,
): GraphIssuanceDiscovery | undefined {
  if (next === undefined) {
    if (previous !== undefined) invalid('graph issuance discovery', 'replay authority container cannot be removed');
    return undefined;
  }
  const parsedNext = validateGraphIssuanceDiscoverySnapshot(next, exchange);
  if (previous === undefined) return parsedNext;
  const parsedPrevious = parseGraphIssuanceDiscovery(previous);
  if (parsedPrevious.replay_authority.authority_id !== parsedNext.replay_authority.authority_id) invalid('graph issuance discovery.replay_authority.authority_id', 'authority identity changed');
  const retained = new Set(parsedNext.replay_authority.v4_scope_digest_tombstones);
  for (const scope of parsedPrevious.replay_authority.v4_scope_digest_tombstones) {
    if (!retained.has(scope)) invalid('graph issuance discovery.replay_authority.v4_scope_digest_tombstones', 'tombstones are not append-only');
  }
  return parsedNext;
}

/**
 * Validate Scarcity's fixed bootstrap profile.  Freebird's generic graph and
 * v4_local runtime are not claimed to enforce any of these Scarcity rules.
 */
export function validateBootstrapManifest(
  value: unknown,
  options: BootstrapValidationOptions = {},
): BootstrapManifest {
  const root = object(value, 'bootstrap manifest');
  exact(root, ['version', 'issuer_id', 'discovery', 'graph_issuance', 'disabled_publication_ack'], [], 'bootstrap manifest');
  if (root.version !== 'scarcity/bootstrap-manifest/v2') invalid('bootstrap manifest.version', 'wrong version');
  const issuerId = text(root.issuer_id, 'bootstrap manifest.issuer_id');
  const discovery = parseDiscovery(root.discovery, { ...options, issuerId });
  if (discovery.graph_issuance === undefined) invalid('bootstrap manifest.discovery.graph_issuance', 'V2 graph issuance discovery is required');
  const activeGraph = discovery.exchange.active_graph;
  const transitionIds = activeGraph.transitions.map((transition) => transition.transition_id);
  const graphIssuance = parseGraphIssuancePolicy(root.graph_issuance, activeGraph, discovery.graph_issuance, 'bootstrap manifest.graph_issuance');
  const acknowledgement = parseAcknowledgement(root.disabled_publication_ack, issuerId, activeGraph.graph_id, transitionIds);
  if (activeGraph.transitions.some((transition) => transition.admission_state !== 'disabled')) {
    // The acknowledgement is the lifecycle prerequisite; accepting discovery
    // is valid only when callers explicitly validate a post-switch snapshot.
    if (options.circulationState !== 'accepting_new') invalid('bootstrap manifest.discovery.exchange.active_graph.transitions', 'must be disabled before the lifecycle switch');
  }
  return {
    version: 'scarcity/bootstrap-manifest/v2',
    issuer_id: issuerId,
    discovery,
    graph_issuance: graphIssuance,
    disabled_publication_ack: acknowledgement,
  };
}

/** A useful fixed-profile assertion for already parsed snapshots. */
export function assertFixedCirculationProfile(
  discovery: FreebirdDiscoveryDocumentV2,
  options: BootstrapValidationOptions = {},
): ExchangeDiscoveryV2 {
  return validateDiscoverySnapshot(discovery, { ...options, circulationState: options.circulationState ?? 'accepting_new' });
}
