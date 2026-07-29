/**
 * Private Phase-1 wallet orchestration.
 *
 * This module is intentionally a composition layer.  It owns no network
 * protocol, no public projection, and no custody policy; it only joins the
 * pinned discovery snapshot, the native Freebird client, the V5 blind-RSA
 * adapter, and the encrypted local vault.
 */

import { randomBytes as systemRandomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import {
  BoundaryValidationError,
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  parseExchangeAcceptedResponseV2,
  parseExchangeRequestV2,
  parseExchangeResultV2,
  parseGraphIssuanceRequest,
  parseGraphIssuanceResult,
  parseGraphSlotSelector,
  type CanonicalBase64Url,
  type ExchangeAcceptedResponseV2,
  type ExchangeOutputV2,
  type ExchangeRequestV2,
  type ExchangeResultV2,
  type FreebirdV5DescriptorV2,
  type GraphIssuanceRequest,
  type GraphIssuanceResult,
  type GraphIssuancePolicy,
  type GraphIssuanceRecoveryContext,
  type GraphSlotSelectorV2,
  RECEIPT_LIFETIME_SECONDS,
} from './types.js';
import {
  FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER,
  FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER,
  canonicalExchangeRequestDigestV2,
  canonicalGraphIssuanceRequestDigest,
  computeExchangeReceiptDigest,
  decodeV4RedemptionTokenBase64,
  encodeV5BearerArtifactBase64,
  verifyExchangeResultDigest,
  verifyGraphIssuanceRequestDigest,
  verifyGraphIssuanceResultDigest,
} from './canonical.js';
import {
  blindV5Message,
  finalizeV5Message,
  importRsaPssSpki,
  verifyV5Signature,
  type V5BlindPreparationRecord,
} from './blind-rsa.js';
import {
  validateDiscoverySnapshot,
} from './bootstrap.js';
import {
  assertPinnedFreebirdOrigin,
  type ValidatedFreebirdDiscovery,
} from './discovery.js';
import {
  type FreebirdCommittedOutcome,
  type FreebirdHttpClient,
  type FreebirdPostOutcome,
} from './freebird-client.js';
import {
  LocalVault,
  type ArtifactVaultRecord,
  type GenesisIssuanceVaultRecord,
  type PreparedReceiveVaultRecord,
  type PreparedSendVaultRecord,
  type VaultRecord,
} from './vault.js';

export class CirculationWalletError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CirculationWalletError';
  }
}

/** The minimal native Freebird dependency required by the wallet. */
export interface WalletFreebirdClient {
  readonly issueGraphIssuance: FreebirdHttpClient['issueGraphIssuance'];
  readonly recoverGraphIssuance: FreebirdHttpClient['recoverGraphIssuance'];
  readonly getGraphIssuanceStatus: FreebirdHttpClient['getGraphIssuanceStatus'];
  readonly processOrRecoverV2: FreebirdHttpClient['processOrRecoverV2'];
  readonly observeExchangeStatus: FreebirdHttpClient['observeExchangeStatus'];
}

export interface WalletDiscoverySource {
  readonly fetch: () => Promise<ValidatedFreebirdDiscovery>;
}

export interface CirculationWalletOptions {
  readonly vault: LocalVault;
  readonly discovery: ValidatedFreebirdDiscovery;
  readonly issuerId: string;
  readonly freebird: WalletFreebirdClient;
  /** TEST-ONLY deterministic source; production uses node:crypto. */
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly nowUnixSeconds?: () => number;
}

export interface OpenCirculationWalletOptions extends Omit<CirculationWalletOptions, 'discovery'> {
  readonly discovery: ValidatedFreebirdDiscovery | WalletDiscoverySource;
}

export interface GenesisPreparation {
  readonly record_id: CanonicalBase64Url;
  readonly operation_id: CanonicalBase64Url;
  readonly issuance_policy_id: string;
  readonly graph_id: string;
  readonly keyset_id: string;
  readonly descriptor_id: string;
}

/** Public offer data.  Vault secrets and the status capability are excluded. */
export interface RecipientTransferOffer {
  readonly version: 1;
  readonly offer_id: CanonicalBase64Url;
  readonly operation_id: CanonicalBase64Url;
  readonly graph_id: string;
  readonly transition_id: string;
  readonly source_keyset_id: string;
  readonly target_keyset_id: string;
  readonly source: GraphSlotSelectorV2;
  readonly output: ExchangeOutputV2;
}

export interface SendTransferInput {
  readonly offer: RecipientTransferOffer;
  /** Supplied through the private handoff channel, never through the offer. */
  readonly status_capability: string;
  readonly source_record_id?: string;
}

export interface ExactRecoveryExpectation {
  readonly request?: unknown;
  readonly status_capability?: string;
}

export interface TransferAcceptanceHandoff {
  readonly request: ExchangeRequestV2;
  readonly committed: FreebirdCommittedOutcome<ExchangeAcceptedResponseV2>;
}

export type WalletOperationState =
  | 'prepared'
  | 'submitted_unknown'
  | 'current'
  | 'rejected'
  | 'offered'
  | 'reserved_pending'
  | 'spend_unknown'
  | 'spent';

export type WalletOutcomeKind = 'committed' | 'retryable' | 'rejected' | 'conflict' | 'ambiguous';

/** Safe status data; it intentionally contains no request, receipt, artifact, or capability. */
export interface WalletOperationStatus {
  readonly kind: WalletOutcomeKind;
  readonly record_id: CanonicalBase64Url;
  readonly operation_id: CanonicalBase64Url;
  readonly state: WalletOperationState;
  readonly error_code?: string;
}

interface TransitionBinding {
  readonly transition_id: string;
  readonly graph_id: string;
  readonly source_keyset_id: string;
  readonly target_keyset_id: string;
  readonly source: GraphSlotSelectorV2;
  readonly output: GraphSlotSelectorV2;
  readonly source_class: string;
  readonly output_class: string;
}

interface WalletCommittedExchange {
  readonly request: ExchangeRequestV2;
  readonly response: ExchangeAcceptedResponseV2;
}

function fail(message: string): never {
  throw new CirculationWalletError(message);
}

function bytes(length: number, source: (length: number) => Uint8Array): Uint8Array {
  const value = source(length);
  if (!(value instanceof Uint8Array) || value.length !== length) fail(`random source: expected ${length} bytes`);
  return value.slice();
}

function defaultRandom(length: number): Uint8Array {
  return new Uint8Array(systemRandomBytes(length));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function equalBase64(left: string, right: string, field: string): void {
  const leftBytes = decodeCanonicalBase64Url(left, undefined, field);
  const rightBytes = decodeCanonicalBase64Url(right, undefined, field);
  if (!equalBytes(leftBytes, rightBytes)) fail(`${field}: does not match`);
}

function equalText(left: string, right: string, field: string): void {
  if (left !== right) fail(`${field}: does not match`);
}

function isRecord(value: VaultRecord, recordType: VaultRecord['record_type']): boolean {
  return value.record_type === recordType;
}

function outcomeKind(outcome: FreebirdPostOutcome<unknown>): WalletOutcomeKind {
  return outcome.kind;
}

function resultFromCommitted(outcome: FreebirdPostOutcome<unknown>): ExchangeAcceptedResponseV2 {
  if (outcome.kind !== 'committed' || outcome.observed || outcome.status !== 200) fail('committed POST result required');
  return parseExchangeAcceptedResponseV2(outcome.value);
}

function assertDescriptorBinding(descriptor: FreebirdV5DescriptorV2, descriptorId: string): void {
  if (descriptor.descriptor_id !== descriptorId) fail('descriptor binding mismatch');
}

function artifactFromFinalized(descriptor: FreebirdV5DescriptorV2, envelope: { readonly nonce: string; readonly token_key_id: string; readonly issuer_id: string; readonly signature: string }): CanonicalBase64Url {
  const nonce = decodeCanonicalBase64Url(envelope.nonce, 32, 'artifact.nonce');
  const tokenKeyId = decodeCanonicalLowerHex(envelope.token_key_id, 32, 'artifact.token_key_id');
  const signature = decodeCanonicalBase64Url(envelope.signature, undefined, 'artifact.signature');
  equalText(envelope.token_key_id, descriptor.token_key_id, 'artifact.token_key_id');
  equalText(envelope.issuer_id, descriptor.issuer_id, 'artifact.issuer_id');
  return encodeV5BearerArtifactBase64(nonce, tokenKeyId, descriptor.issuer_id, signature);
}

function status(recordId: CanonicalBase64Url, operationId: CanonicalBase64Url, state: WalletOperationState, kind: WalletOutcomeKind, errorCode?: string): WalletOperationStatus {
  return { kind, record_id: recordId, operation_id: operationId, state, ...(errorCode === undefined ? {} : { error_code: errorCode }) };
}

export class CirculationWallet {
  readonly vault: LocalVault;
  readonly discovery: ValidatedFreebirdDiscovery;
  readonly freebird: WalletFreebirdClient;
  private readonly randomBytes: (length: number) => Uint8Array;
  private readonly nowUnixSeconds: () => number;

  constructor(options: CirculationWalletOptions) {
    this.vault = options.vault;
    this.discovery = validatePinnedDiscovery(options.discovery, options.issuerId);
    this.freebird = options.freebird;
    this.randomBytes = options.randomBytes ?? defaultRandom;
    this.nowUnixSeconds = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Load a discovery source and validate it before constructing the wallet. */
  static async open(options: OpenCirculationWalletOptions): Promise<CirculationWallet> {
    const discovery = 'fetch' in options.discovery ? await options.discovery.fetch() : options.discovery;
    return new CirculationWallet({ ...options, discovery });
  }

  private activeGraph(): ValidatedFreebirdDiscovery['exchange']['active_graph'] {
    return this.discovery.exchange.active_graph;
  }

  private snapshotRef(kind: 'genesis' | 'receive' | 'send'): string {
    return `${this.discovery.origin}|${kind}|${this.activeGraph().graph_id}`;
  }

  private descriptor(descriptorId: string): FreebirdV5DescriptorV2 {
    const graphs = [this.discovery.exchange.active_graph, ...this.discovery.exchange.retained_graphs];
    const descriptor = graphs.flatMap((graph) => graph.descriptors).find((candidate) => candidate.descriptor_id === descriptorId);
    if (descriptor === undefined) fail('descriptor is not in the pinned graph');
    return descriptor;
  }

  private transition(transitionId: string): TransitionBinding {
    const graph = this.activeGraph();
    const transition = graph.transitions.find((candidate) => candidate.transition_id === transitionId);
    if (transition === undefined) fail('transition is not in the pinned graph');
    if (transition.admission_state !== 'accepting_new') fail('transition is not accepting fresh work');
    const sourceKeyset = graph.keysets.find((keyset) => keyset.keyset_id === transition.source_keyset_id);
    const targetKeyset = graph.keysets.find((keyset) => keyset.keyset_id === transition.target_keyset_id);
    if (sourceKeyset === undefined || targetKeyset === undefined) fail('transition keyset is not in the pinned graph');
    const source = {
      descriptor_id: transition.source_slots[0].descriptor_id,
      keyset_id: transition.source_keyset_id,
      slot_id: transition.source_slots[0].slot_id,
      quantity: transition.source_slots[0].quantity,
    } as GraphSlotSelectorV2;
    const output = {
      descriptor_id: transition.output_slots[0].descriptor_id,
      keyset_id: transition.target_keyset_id,
      slot_id: transition.output_slots[0].slot_id,
      quantity: transition.output_slots[0].quantity,
    } as GraphSlotSelectorV2;
    this.descriptor(source.descriptor_id);
    this.descriptor(output.descriptor_id);
    return {
      transition_id: transition.transition_id,
      graph_id: graph.graph_id,
      source_keyset_id: transition.source_keyset_id,
      target_keyset_id: transition.target_keyset_id,
      source,
      output,
      source_class: transition.source_slots[0].class,
      output_class: transition.output_slots[0].class,
    };
  }

  private issuancePolicy(policyId?: string): { readonly policy: GraphIssuancePolicy; readonly descriptor: FreebirdV5DescriptorV2 } {
    const policies = this.discovery.graph_issuance?.policies;
    if (policies === undefined || policies.length === 0) fail('graph issuance policy is missing from pinned discovery');
    const discovered = policyId === undefined
      ? policies.length === 1 ? policies[0] : fail('issuance policy must be selected explicitly')
      : policies.find((candidate) => candidate.issuance_policy_id === policyId);
    if (discovered === undefined) fail('issuance policy is not in pinned discovery');
    const graph = this.activeGraph();
    const k0 = graph.keysets[0];
    if (
      discovered.graph_id !== graph.graph_id
      || discovered.keyset_id !== k0.keyset_id
      || discovered.descriptor_id !== k0.descriptor_ids[0]
      || discovered.budget_limit !== 100
      || discovered.quantity !== 1
      || discovered.admission_state !== 'accepting_new'
      || discovered.authorization_scheme !== 'v4_local'
      || discovered.authorization_scope_digest_b64 === undefined
    ) fail('graph issuance policy is not the fixed K0 profile');
    const descriptor = this.descriptor(discovered.descriptor_id);
    return {
      policy: {
        issuance_policy_id: discovered.issuance_policy_id,
        graph_id: discovered.graph_id,
        keyset_id: discovered.keyset_id,
        descriptor_id: discovered.descriptor_id,
        budget_id: discovered.budget_id,
        budget_limit: 100,
        quantity: 1,
        admission_state: 'accepting_new',
        authorization_scheme: 'v4_local',
        authorization_scope_digest_b64: discovered.authorization_scope_digest_b64,
      },
      descriptor,
    };
  }

  private async publicKey(descriptor: FreebirdV5DescriptorV2): Promise<CryptoKey> {
    return importRsaPssSpki(descriptor);
  }

  private async record(recordId: string): Promise<VaultRecord> {
    const value = await this.vault.getRecord(recordId);
    if (value === undefined) fail('vault operation record is missing');
    return value;
  }

  private async artifactRecords(): Promise<ReadonlyArray<[CanonicalBase64Url, ArtifactVaultRecord]>> {
    const records = await this.vault.listRecords();
    return [...records.entries()].filter((entry): entry is [CanonicalBase64Url, ArtifactVaultRecord] => entry[1].record_type === 'artifact');
  }

  /** Prepare one K0 graph-issuance request without exposing its secrets. */
  async prepareGenesis(input: { readonly authorization: string; readonly issuance_policy_id?: string }): Promise<GenesisPreparation> {
    const { policy, descriptor } = this.issuancePolicy(input.issuance_policy_id);
    const admission = decodeV4RedemptionTokenBase64(input.authorization);
    if (policy.authorization_scope_digest_b64 === undefined || !equalBytes(admission.scope_digest, decodeCanonicalBase64Url(policy.authorization_scope_digest_b64, 32, 'authorization_scope_digest_b64'))) fail('authorization scope does not match V2 policy');
    const operation = encodeCanonicalBase64Url(bytes(16, this.randomBytes));
    const capability = encodeCanonicalBase64Url(bytes(32, this.randomBytes));
    const nonce = bytes(32, this.randomBytes);
    const publicKey = await this.publicKey(descriptor);
    const preparation = await blindV5Message(descriptor, publicKey, nonce);
    try {
      const request = parseGraphIssuanceRequest({
        version: 2,
        public_operation_id: operation,
        issuance_policy_id: policy.issuance_policy_id,
        graph_id: policy.graph_id,
        keyset_id: policy.keyset_id,
        descriptor_id: policy.descriptor_id,
        blinded_message: preparation.blinded_value,
        authorization: input.authorization,
      });
      const created = await this.vault.createGenesisIssuance({
        operation_id: operation,
        status_capability: capability,
        preparation_snapshot_ref: this.snapshotRef('genesis'),
        request,
        expected_token_key_id: descriptor.token_key_id,
        output_nonce: preparation.nonce,
        message: preparation.message,
        blinding_state: preparation.blinding_state,
      });
      return {
        record_id: created.record_id,
        operation_id: operation,
        issuance_policy_id: policy.issuance_policy_id,
        graph_id: policy.graph_id,
        keyset_id: policy.keyset_id,
        descriptor_id: policy.descriptor_id,
      };
    } finally {
      nonce.fill(0);
      preparation.nonce.fill(0);
      preparation.message.fill(0);
      preparation.blinding_state.fill(0);
    }
  }

  /** Submit or recover the exact persisted genesis POST. */
  async submitGenesis(recordId: string): Promise<WalletOperationStatus> {
    const record = await this.record(recordId);
    if (!isRecord(record, 'genesis_issuance')) fail('record is not a genesis operation');
    const genesis = record as GenesisIssuanceVaultRecord;
    if (genesis.state === 'current') return status(recordId as CanonicalBase64Url, genesis.operation_id, 'current', 'committed');
    if (genesis.state === 'rejected') return status(recordId as CanonicalBase64Url, genesis.operation_id, 'rejected', 'rejected');
    const fresh = genesis.state === 'prepared';
    if (fresh) await this.vault.markGenesisSubmitted(recordId);
    const current = await this.record(recordId) as GenesisIssuanceVaultRecord;
    return this.performGenesis(recordId as CanonicalBase64Url, current, fresh);
  }

  async recoverGenesis(recordId: string, expected?: ExactRecoveryExpectation): Promise<WalletOperationStatus> {
    if (expected !== undefined) await this.assertGenesisRecovery(recordId, expected);
    return this.submitGenesis(recordId);
  }

  private async assertGenesisRecovery(recordId: string, expected: ExactRecoveryExpectation): Promise<void> {
    const record = await this.record(recordId);
    if (!isRecord(record, 'genesis_issuance')) fail('record is not a genesis operation');
    const genesis = record as GenesisIssuanceVaultRecord;
    if (expected.status_capability !== undefined) equalBase64(expected.status_capability, genesis.status_capability ?? '', 'genesis.status_capability');
    if (expected.request !== undefined) {
      const request = parseGraphIssuanceRequest(expected.request);
      equalBase64(encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(request)), encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(genesis.request)), 'genesis.request_digest');
    }
  }

  private async performGenesis(recordId: CanonicalBase64Url, record: GenesisIssuanceVaultRecord, fresh = false): Promise<WalletOperationStatus> {
    if (record.status_capability === null) fail('genesis status capability is unavailable');
    let outcome: FreebirdPostOutcome<GraphIssuanceResult>;
    const recovery: GraphIssuanceRecoveryContext = {
      request: record.request,
      requestDigest: encodeCanonicalBase64Url(canonicalGraphIssuanceRequestDigest(record.request)),
      publicOperationId: record.operation_id,
      issuancePolicyId: record.request.issuance_policy_id,
      graphId: record.request.graph_id,
      keysetId: record.request.keyset_id,
      descriptorId: record.request.descriptor_id,
      statusCapability: record.status_capability,
      expectedTokenKeyId: record.expected_token_key_id,
      blindingState: record.blinding_state,
    };
    try {
      outcome = fresh
        ? await this.freebird.issueGraphIssuance(record.request, record.status_capability)
        : await this.freebird.recoverGraphIssuance(recovery);
    } catch {
      return status(recordId, record.operation_id, 'submitted_unknown', 'ambiguous', 'transport_failure');
    }
    if (outcome.kind !== 'committed') {
      return status(recordId, record.operation_id, 'submitted_unknown', outcomeKind(outcome as FreebirdPostOutcome<unknown>), 'error' in outcome ? outcome.error.code : undefined);
    }
    let artifact: CanonicalBase64Url;
    try {
      artifact = await this.finalizeGenesisArtifact(record, outcome.value);
    } catch {
      await this.vault.terminalRejectGenesis(recordId, 'invalid_result');
      return status(recordId, record.operation_id, 'rejected', 'rejected', 'invalid_result');
    }
    await this.vault.finalizeGenesis(recordId, { artifact, result: outcome.value });
    return status(recordId, record.operation_id, 'current', 'committed');
  }

  private async finalizeGenesisArtifact(record: GenesisIssuanceVaultRecord, resultValue: GraphIssuanceResult): Promise<CanonicalBase64Url> {
    const result = parseGraphIssuanceResult(resultValue);
    const descriptor = this.descriptor(record.request.descriptor_id);
    equalBase64(record.operation_id, result.public_operation_id, 'genesis result.public_operation_id');
    equalText(record.request.issuance_policy_id, result.issuance_policy_id, 'genesis result.issuance_policy_id');
    equalText(record.request.graph_id, result.graph_id, 'genesis result.graph_id');
    equalText(record.request.keyset_id, result.keyset_id, 'genesis result.keyset_id');
    equalText(record.request.descriptor_id, result.descriptor_id, 'genesis result.descriptor_id');
    equalText(descriptor.token_key_id, result.token_key_id, 'genesis result.token_key_id');
    if (result.quantity !== 1) fail('genesis result.quantity: expected one');
    verifyGraphIssuanceRequestDigest(record.request, result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
    verifyGraphIssuanceResultDigest(result, FREEBIRD_GRAPH_ISSUANCE_CANONICAL_DIGEST_VERIFIER);
    if (record.output_nonce === null || record.message === null || record.blinding_state === null) fail('genesis preparation secrets are missing');
    const nonce = decodeCanonicalBase64Url(record.output_nonce, 32, 'genesis.output_nonce');
    const message = decodeCanonicalBase64Url(record.message, 48, 'genesis.message');
    const blindingState = decodeCanonicalBase64Url(record.blinding_state, undefined, 'genesis.blinding_state');
    const preparation: V5BlindPreparationRecord = {
      nonce,
      token_key_id: descriptor.token_key_id,
      issuer_id: descriptor.issuer_id,
      message,
      blinded_value: record.request.blinded_message,
      blinding_state: blindingState,
    };
    try {
      const publicKey = await this.publicKey(descriptor);
      const finalized = await finalizeV5Message(descriptor, publicKey, preparation, result.blind_signature);
      if (!await verifyV5Signature(descriptor, publicKey, preparation, finalized.signature)) fail('genesis artifact signature verification failed');
      return artifactFromFinalized(descriptor, finalized);
    } finally {
      nonce.fill(0);
      message.fill(0);
      blindingState.fill(0);
    }
  }

  /** Prepare a recipient-side offer for one explicitly selected graph edge. */
  async prepareTransferOffer(input: { readonly transition_id: string }): Promise<RecipientTransferOffer> {
    const binding = this.transition(input.transition_id);
    const descriptor = this.descriptor(binding.output.descriptor_id);
    const operation = encodeCanonicalBase64Url(bytes(16, this.randomBytes));
    const capability = encodeCanonicalBase64Url(bytes(32, this.randomBytes));
    const nonce = bytes(32, this.randomBytes);
    const publicKey = await this.publicKey(descriptor);
    const preparation = await blindV5Message(descriptor, publicKey, nonce);
    try {
      const output: ExchangeOutputV2 = { slot: binding.output, blinded_value: preparation.blinded_value };
      const created = await this.vault.createPreparedReceive({
        operation_id: operation,
        status_capability: capability,
        preparation_snapshot_ref: this.snapshotRef('receive'),
        graph_id: binding.graph_id,
        transition_id: binding.transition_id,
        source_keyset_id: binding.source_keyset_id,
        target_keyset_id: binding.target_keyset_id,
        expected_output: output,
        output_nonce: preparation.nonce,
        message: preparation.message,
        blinding_state: preparation.blinding_state,
      });
      return {
        version: 1,
        offer_id: created.record_id,
        operation_id: operation,
        graph_id: binding.graph_id,
        transition_id: binding.transition_id,
        source_keyset_id: binding.source_keyset_id,
        target_keyset_id: binding.target_keyset_id,
        source: binding.source,
        output,
      };
    } finally {
      nonce.fill(0);
      preparation.nonce.fill(0);
      preparation.message.fill(0);
      preparation.blinding_state.fill(0);
    }
  }

  async prepareRecipientOffer(input: { readonly transition_id: string }): Promise<RecipientTransferOffer> {
    return this.prepareTransferOffer(input);
  }

  /** Return only non-sensitive state for a local operation. */
  async getStatus(recordId: string): Promise<WalletOperationStatus> {
    const record = await this.record(recordId);
    if (!('operation_id' in record)) fail('record has no operation state');
    const kind: WalletOutcomeKind = record.state === 'current' || record.state === 'spent' ? 'committed' : record.state === 'rejected' ? 'rejected' : record.state === 'reserved_pending' || record.state === 'prepared' || record.state === 'offered' ? 'retryable' : 'ambiguous';
    return status(recordId as CanonicalBase64Url, record.operation_id, record.state, kind);
  }

  /** Submit a sender operation using the capability from the private handoff channel. */
  async sendTransfer(input: SendTransferInput): Promise<WalletOperationStatus> {
    decodeCanonicalBase64Url(input.status_capability, 32, 'status_capability');
    const binding = this.assertPublicOffer(input.offer);
    const source = await this.selectSource(binding, input.source_record_id);
    const request = parseExchangeRequestV2({
      version: 2,
      public_operation_id: input.offer.operation_id,
      graph_id: binding.graph_id,
      transition_id: binding.transition_id,
      source_keyset_id: binding.source_keyset_id,
      target_keyset_id: binding.target_keyset_id,
      sources: [{ slot: binding.source, artifact: source.record.artifact }],
      outputs: [input.offer.output],
    });
    const created = await this.vault.createPreparedAndReserveSend({
      operation_id: request.public_operation_id,
      status_capability: input.status_capability,
      preparation_snapshot_ref: this.snapshotRef('send'),
      request,
      source_record_id: source.recordId,
    });
    return this.performSend(created.record_id, await this.record(created.record_id) as PreparedSendVaultRecord);
  }

  async submitTransfer(input: SendTransferInput): Promise<WalletOperationStatus> {
    return this.sendTransfer(input);
  }

  async recoverSend(recordId: string, expected?: ExactRecoveryExpectation): Promise<WalletOperationStatus> {
    const record = await this.record(recordId);
    if (!isRecord(record, 'prepared_send')) fail('record is not a sender operation');
    const send = record as PreparedSendVaultRecord;
    if (expected !== undefined) {
      if (expected.status_capability !== undefined) equalBase64(expected.status_capability, send.status_capability ?? '', 'send.status_capability');
      if (expected.request !== undefined) {
        const request = parseExchangeRequestV2(expected.request);
        equalBase64(encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(request)), encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(send.request)), 'send.request_digest');
      }
    }
    if (send.state === 'spent') return status(recordId as CanonicalBase64Url, send.operation_id, 'spent', 'committed');
    if (send.state === 'rejected') return status(recordId as CanonicalBase64Url, send.operation_id, 'rejected', 'rejected');
    if (send.state === 'offered') await this.vault.reserveSource(send.source_record_id, recordId);
    const recovered = await this.record(recordId) as PreparedSendVaultRecord;
    return this.performSend(recordId as CanonicalBase64Url, recovered);
  }

  private async selectSource(binding: TransitionBinding, sourceRecordId?: string): Promise<{ readonly recordId: CanonicalBase64Url; readonly record: ArtifactVaultRecord }> {
    const candidates = (await this.artifactRecords()).filter((entry) => entry[1].state === 'current' && entry[1].keyset_id === binding.source_keyset_id && entry[1].descriptor_id === binding.source.descriptor_id);
    if (sourceRecordId !== undefined) {
      const selected = candidates.find((entry) => entry[0] === sourceRecordId);
      if (selected === undefined) fail('source artifact is not compatible with the explicit edge');
      return { recordId: selected[0], record: selected[1] };
    }
    if (candidates.length === 0) fail('no compatible current source artifact');
    return { recordId: candidates[0][0], record: candidates[0][1] };
  }

  private async performSend(recordId: CanonicalBase64Url, record: PreparedSendVaultRecord): Promise<WalletOperationStatus> {
    if (record.status_capability === null) fail('send status capability is unavailable');
    await this.assertSendReserved(record);
    let outcome: FreebirdPostOutcome<ExchangeAcceptedResponseV2>;
    try {
      outcome = await this.freebird.processOrRecoverV2(record.request, record.status_capability);
    } catch {
      if (record.state === 'reserved_pending') await this.vault.markSendSubmittedUnknown(recordId);
      return status(recordId, record.operation_id, 'spend_unknown', 'ambiguous', 'transport_failure');
    }
    if (outcome.kind === 'retryable') return status(recordId, record.operation_id, 'reserved_pending', 'retryable');
    if (outcome.kind !== 'committed') {
      if (record.state === 'reserved_pending') await this.vault.markSendSubmittedUnknown(recordId);
      return status(recordId, record.operation_id, 'spend_unknown', outcome.kind, 'error' in outcome ? outcome.error.code : undefined);
    }
    let response: ExchangeAcceptedResponseV2;
    try {
      response = resultFromCommitted(outcome as FreebirdPostOutcome<unknown>);
      this.assertCommittedExchange(record.request, response);
    } catch {
      await this.vault.terminalRejectSend(recordId, 'invalid_result');
      return status(recordId, record.operation_id, 'rejected', 'rejected', 'invalid_result');
    }
    await this.vault.finalizeSend(recordId, { result: response.result, receipt: response.receipt });
    return status(recordId, record.operation_id, 'spent', 'committed');
  }

  private async assertSendReserved(record: PreparedSendVaultRecord): Promise<void> {
    const records = await this.vault.listRecords();
    const source = records.get(record.source_record_id);
    if (source === undefined || source.record_type !== 'artifact' || source.state !== 'reserved' || source.reserved_by !== record.operation_id) {
      fail('send reservation invariant is not satisfied');
    }
    equalBase64(source.artifact, record.source_artifact, 'send.source_artifact');
    equalBase64(source.artifact, record.request.sources[0].artifact, 'send.request.sources[0].artifact');
  }

  /** Retrieve an explicit private handoff for the recipient after a committed POST. */
  async getTransferAcceptanceHandoff(recordId: string): Promise<TransferAcceptanceHandoff> {
    const record = await this.record(recordId);
    if (!isRecord(record, 'prepared_send')) fail('record is not a sender operation');
    const send = record as PreparedSendVaultRecord;
    if (send.state !== 'spent' || send.result === null) fail('sender operation is not committed');
    const requestDigest = encodeCanonicalBase64Url(canonicalExchangeRequestDigestV2(send.request));
    return {
      request: send.request,
      committed: { kind: 'committed', status: 200, value: send.result, request_digest: requestDigest, observed: false },
    };
  }

  /** Accept only a verified committed POST handoff; status GETs cannot accept. */
  async acceptTransfer(offer: RecipientTransferOffer, handoff: TransferAcceptanceHandoff): Promise<WalletOperationStatus> {
    const record = await this.record(offer.offer_id);
    if (!isRecord(record, 'prepared_receive')) fail('offer record is not a recipient operation');
    const receive = record as PreparedReceiveVaultRecord;
    if (receive.state === 'current') return status(offer.offer_id, receive.operation_id, 'current', 'committed');
    if (receive.state === 'rejected') return status(offer.offer_id, receive.operation_id, 'rejected', 'rejected');
    try {
      this.assertOffer(offer, receive);
      const request = parseExchangeRequestV2(handoff.request);
      this.assertOfferRequest(offer, receive, request);
      if (handoff.committed.kind !== 'committed' || handoff.committed.observed || handoff.committed.status !== 200) fail('committed POST handoff required');
      const response = parseExchangeAcceptedResponseV2(handoff.committed.value);
      this.assertCommittedExchange(request, response);
      const artifact = await this.finalizeReceiveArtifact(receive, response.result);
      await this.vault.finalizeReceive(offer.offer_id, { artifact, result: response.result, receipt: response.receipt });
      return status(offer.offer_id, receive.operation_id, 'current', 'committed');
    } catch (error) {
      if (error instanceof CirculationWalletError || error instanceof BoundaryValidationError) {
        await this.vault.terminalRejectReceive(offer.offer_id, 'invalid_offer_or_result');
        return status(offer.offer_id, receive.operation_id, 'rejected', 'rejected', 'invalid_offer_or_result');
      }
      throw error;
    }
  }

  async acceptRecipientTransfer(offer: RecipientTransferOffer, handoff: TransferAcceptanceHandoff): Promise<WalletOperationStatus> {
    return this.acceptTransfer(offer, handoff);
  }

  /** Recover a recipient operation through the same exact POST, never a new identity. */
  async recoverReceive(offer: RecipientTransferOffer, requestValue: unknown, expectedStatusCapability?: string): Promise<WalletOperationStatus> {
    const record = await this.record(offer.offer_id);
    if (!isRecord(record, 'prepared_receive')) fail('offer record is not a recipient operation');
    const receive = record as PreparedReceiveVaultRecord;
    if (receive.state === 'current') return status(offer.offer_id, receive.operation_id, 'current', 'committed');
    if (receive.state === 'rejected') return status(offer.offer_id, receive.operation_id, 'rejected', 'rejected');
    if (receive.status_capability === null) fail('receive status capability is unavailable');
    if (expectedStatusCapability !== undefined) equalBase64(expectedStatusCapability, receive.status_capability, 'receive.status_capability');
    const request = parseExchangeRequestV2(requestValue);
    this.assertOffer(offer, receive);
    this.assertOfferRequest(offer, receive, request);
    if (receive.state === 'prepared') await this.vault.markReceiveSubmitted(offer.offer_id);
    let outcome: FreebirdPostOutcome<ExchangeAcceptedResponseV2>;
    try {
      outcome = await this.freebird.processOrRecoverV2(request, receive.status_capability);
    } catch {
      return status(offer.offer_id, receive.operation_id, 'submitted_unknown', 'ambiguous', 'transport_failure');
    }
    if (outcome.kind === 'committed') {
      try {
        const response = resultFromCommitted(outcome as FreebirdPostOutcome<unknown>);
        this.assertCommittedExchange(request, response);
        const updated = await this.record(offer.offer_id) as PreparedReceiveVaultRecord;
        const artifact = await this.finalizeReceiveArtifact(updated, response.result);
        await this.vault.finalizeReceive(offer.offer_id, { artifact, result: response.result, receipt: response.receipt });
        return status(offer.offer_id, receive.operation_id, 'current', 'committed');
      } catch (error) {
        if (error instanceof CirculationWalletError || error instanceof BoundaryValidationError) {
          await this.vault.terminalRejectReceive(offer.offer_id, 'invalid_offer_or_result');
          return status(offer.offer_id, receive.operation_id, 'rejected', 'rejected', 'invalid_offer_or_result');
        }
        throw error;
      }
    }
    return status(offer.offer_id, receive.operation_id, 'submitted_unknown', outcome.kind, 'error' in outcome ? outcome.error.code : undefined);
  }

  private assertOffer(offer: RecipientTransferOffer, receive: PreparedReceiveVaultRecord): TransitionBinding {
    const binding = this.assertPublicOffer(offer);
    equalBase64(offer.operation_id, receive.operation_id, 'offer.operation_id');
    this.assertSelector(receive.expected_output.slot, binding.output, 'stored offer.output.slot');
    equalBase64(receive.expected_output.blinded_value, offer.output.blinded_value, 'offer.output.blinded_value');
    return binding;
  }

  private assertPublicOffer(offer: RecipientTransferOffer): TransitionBinding {
    if (offer.version !== 1 || offer.offer_id.length === 0) fail('invalid transfer offer');
    decodeCanonicalBase64Url(offer.offer_id, 16, 'offer.offer_id');
    decodeCanonicalBase64Url(offer.operation_id, 16, 'offer.operation_id');
    const binding = this.transition(offer.transition_id);
    equalText(binding.graph_id, offer.graph_id, 'offer.graph_id');
    equalText(binding.source_keyset_id, offer.source_keyset_id, 'offer.source_keyset_id');
    equalText(binding.target_keyset_id, offer.target_keyset_id, 'offer.target_keyset_id');
    equalText(binding.transition_id, offer.transition_id, 'offer.transition_id');
    this.assertSelector(offer.source, binding.source, 'offer.source');
    this.assertSelector(offer.output.slot, binding.output, 'offer.output.slot');
    return binding;
  }

  private assertOfferRequest(offer: RecipientTransferOffer, receive: PreparedReceiveVaultRecord, request: ExchangeRequestV2): void {
    equalBase64(request.public_operation_id, offer.operation_id, 'request.public_operation_id');
    equalText(request.graph_id, offer.graph_id, 'request.graph_id');
    equalText(request.transition_id, offer.transition_id, 'request.transition_id');
    equalText(request.source_keyset_id, offer.source_keyset_id, 'request.source_keyset_id');
    equalText(request.target_keyset_id, offer.target_keyset_id, 'request.target_keyset_id');
    this.assertSelector(request.sources[0].slot, offer.source, 'request.sources[0].slot');
    this.assertSelector(request.outputs[0].slot, receive.expected_output.slot, 'request.outputs[0].slot');
    equalBase64(request.outputs[0].blinded_value, receive.expected_output.blinded_value, 'request.outputs[0].blinded_value');
  }

  private assertSelector(actual: GraphSlotSelectorV2, expected: GraphSlotSelectorV2, field: string): void {
    parseGraphSlotSelector(actual, field);
    equalText(actual.descriptor_id, expected.descriptor_id, `${field}.descriptor_id`);
    equalText(actual.keyset_id, expected.keyset_id, `${field}.keyset_id`);
    equalText(actual.slot_id, expected.slot_id, `${field}.slot_id`);
    if (actual.quantity !== expected.quantity) fail(`${field}.quantity: does not match`);
  }

  private assertCommittedExchange(request: ExchangeRequestV2, response: ExchangeAcceptedResponseV2): void {
    const parsedRequest = parseExchangeRequestV2(request);
    const accepted = parseExchangeAcceptedResponseV2(response);
    const result = parseExchangeResultV2(accepted.result);
    equalBase64(parsedRequest.public_operation_id, result.public_operation_id, 'result.public_operation_id');
    equalText(parsedRequest.graph_id, result.graph_id, 'result.graph_id');
    equalText(parsedRequest.transition_id, result.transition_id, 'result.transition_id');
    equalText(parsedRequest.source_keyset_id, result.source_keyset_id, 'result.source_keyset_id');
    equalText(parsedRequest.target_keyset_id, result.target_keyset_id, 'result.target_keyset_id');
    this.assertSelector(result.outputs[0].slot, parsedRequest.outputs[0].slot, 'result.outputs[0].slot');
    equalBase64(result.outputs[0].blinded_value, parsedRequest.outputs[0].blinded_value, 'result.outputs[0].blinded_value');
    verifyExchangeResultDigest(result, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    equalBase64(accepted.receipt.public_operation_id, parsedRequest.public_operation_id, 'receipt.public_operation_id');
    equalText(accepted.receipt.graph_id, parsedRequest.graph_id, 'receipt.graph_id');
    equalText(accepted.receipt.transition_id, parsedRequest.transition_id, 'receipt.transition_id');
    equalText(accepted.receipt.source_keyset_id, parsedRequest.source_keyset_id, 'receipt.source_keyset_id');
    equalText(accepted.receipt.target_keyset_id, parsedRequest.target_keyset_id, 'receipt.target_keyset_id');
    equalBase64(accepted.receipt.result_digest, result.result_digest, 'receipt.result_digest');
    if (accepted.receipt.expires_at - accepted.receipt.created_at !== RECEIPT_LIFETIME_SECONDS) fail('receipt lifetime is not 30 days');
    const now = this.nowUnixSeconds();
    if (!Number.isSafeInteger(now) || accepted.receipt.created_at > now || accepted.receipt.expires_at < now) fail('receipt is outside its validity interval');
    const receiptKey = accepted.receipt.receipt_key_id === this.discovery.exchange.active_receipt_key.key_id
      ? this.discovery.exchange.active_receipt_key
      : this.discovery.exchange.retained_receipt_keys.find((key) => key.key_id === accepted.receipt.receipt_key_id);
    if (receiptKey === undefined) fail('receipt key is not in the pinned discovery');
    if (receiptKey.valid_from > accepted.receipt.created_at || receiptKey.valid_until < accepted.receipt.expires_at) fail('receipt key does not cover receipt interval');
    const receiptDigest = computeExchangeReceiptDigest(accepted.receipt, FREEBIRD_V2_CANONICAL_DIGEST_VERIFIER);
    const receiptSignature = decodeCanonicalBase64Url(accepted.receipt.signature, 64, 'receipt.signature');
    const receiptPublicKey = decodeCanonicalBase64Url(receiptKey.public_key_b64, 32, 'receipt key.public_key_b64');
    if (!ed25519.verify(receiptSignature, receiptDigest, receiptPublicKey)) fail('receipt signature verification failed');
  }

  private async finalizeReceiveArtifact(record: PreparedReceiveVaultRecord, resultValue: ExchangeResultV2): Promise<CanonicalBase64Url> {
    const result = parseExchangeResultV2(resultValue);
    const descriptor = this.descriptor(record.expected_output.slot.descriptor_id);
    assertDescriptorBinding(descriptor, result.outputs[0].slot.descriptor_id);
    if (record.output_nonce === null || record.message === null || record.blinding_state === null) fail('receive preparation secrets are missing');
    const nonce = decodeCanonicalBase64Url(record.output_nonce, 32, 'receive.output_nonce');
    const message = decodeCanonicalBase64Url(record.message, 48, 'receive.message');
    const blindingState = decodeCanonicalBase64Url(record.blinding_state, undefined, 'receive.blinding_state');
    const preparation: V5BlindPreparationRecord = {
      nonce,
      token_key_id: descriptor.token_key_id,
      issuer_id: descriptor.issuer_id,
      message,
      blinded_value: record.expected_output.blinded_value,
      blinding_state: blindingState,
    };
    try {
      const publicKey = await this.publicKey(descriptor);
      const finalized = await finalizeV5Message(descriptor, publicKey, preparation, result.outputs[0].blind_signature);
      if (!await verifyV5Signature(descriptor, publicKey, preparation, finalized.signature)) fail('receive artifact signature verification failed');
      return artifactFromFinalized(descriptor, finalized);
    } finally {
      nonce.fill(0);
      message.fill(0);
      blindingState.fill(0);
    }
  }
}

function validatePinnedDiscovery(value: ValidatedFreebirdDiscovery, issuerId: string): ValidatedFreebirdDiscovery {
  if (value === null || typeof value !== 'object' || typeof value.origin !== 'string') fail('validated discovery is required');
  assertPinnedFreebirdOrigin(value.origin);
  if (typeof issuerId !== 'string' || issuerId.length === 0) fail('issuer ID is required');
  const exchange = validateDiscoverySnapshot({ exchange: value.document.exchange }, { issuerId, circulationState: 'accepting_new' });
  if (exchange.active_graph.graph_id !== value.exchange.active_graph.graph_id) fail('discovery snapshot identity mismatch');
  return { ...value, exchange };
}
