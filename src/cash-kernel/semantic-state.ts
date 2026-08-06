/** Opaque in-memory semantic oracle; this is not a wire or cryptographic schema. */
export type CapabilityEvidence = { capabilityRef: string; requestReference: string; tainted?: boolean };
export type AuthorityEvidence = { evidenceReference: string; rawResultReference: string; normalizedResultReference: string; requestTuple: unknown; requestReference: string; resultReference: string; normalized: string };
export type OperationRequest = { reference: string; [field: string]: unknown };
export type BoundResult = { requestReference: string; resultReference: string; normalized: string };
export type RecoveryState = { reference: string; status: 'FINALIZED' | 'PENDING' | 'UNVERIFIED' };

export interface SemanticAuthority {
  verifyOpening(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyPriorValue(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyFreebird(evidence: CapabilityEvidence): BoundResult | 'tainted' | null;
  verifyDividendWitness(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyCivicWitness(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyBurnWitness(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifySpendWitness(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyRecovery(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyRelay(evidence: AuthorityEvidence): BoundResult;
}
export interface SemanticPolicy {
  verifyDividend(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
  verifyCivic(request: OperationRequest, evidence: AuthorityEvidence): BoundResult;
}

export class SemanticKernelError extends Error { constructor(readonly category: string) { super(category); } }
const fail = (category: string): never => { throw new SemanticKernelError(category); };
const integer = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n);
const positive = (n: unknown): n is number => integer(n) && n > 0;
const add = (a: number, b: number): number => { if (!integer(a) || !integer(b) || b < 0 || a > Number.MAX_SAFE_INTEGER - b) fail('accounting_overflow'); return a + b; };
const sub = (a: number, b: number): number => { if (!integer(a) || !integer(b) || b < 0 || b > a) fail('accounting_underflow'); return a - b; };
const equal = (a: unknown, b: unknown): boolean => {
  if (Object.is(a, b)) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((v, i) => equal(v, b[i]));
  const ak = Object.keys(a as object).sort(); const bk = Object.keys(b as object).sort();
  return equal(ak, bk) && ak.every((k) => equal((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
};
export const structuralEqual = equal;
const resultFor = (request: OperationRequest, result: BoundResult, category: string): BoundResult => { if (!result || result.requestReference !== request.reference) fail(category); return result; };

type Note = { status: 'AVAILABLE' | 'PENDING' | 'SPENT' | 'BURNED'; value: number; successor?: string };
type Use = { domain: string; kind: string; result: string; request: string };

/** The Oracle semantic state machine. Every transition is prepare-then-commit. */
export class SemanticCashKernel {
  private supply = 0;
  private opened = false;
  private openingSnapshot: unknown;
  private restored = 0;
  private readonly notes = new Map<string, Note>();
  private readonly claims = new Map<string, { request: OperationRequest; status: 'PENDING' | 'FINALIZED'; note: string }>();
  private readonly requests = new Map<string, OperationRequest>();
  private readonly uses: Use[] = [];
  private readonly relayReceipts: string[] = [];
  private readonly records: string[] = [];
  constructor(private readonly authority: SemanticAuthority, private readonly policy: SemanticPolicy) {}

  private freebird(evidence: CapabilityEvidence): BoundResult {
    const result = this.authority.verifyFreebird(evidence);
    if (result === 'tainted') fail('economically_tainted_capability');
    if (!result) fail('invalid_or_missing_citizenship_capability');
    return resultFor({ reference: evidence.requestReference }, result as BoundResult, 'invalid_or_missing_citizenship_capability');
  }
  private use(domain: string, kind: string, request: OperationRequest, result: BoundResult): 'new' | 'retry' {
    const prior = this.uses.find((u) => u.domain === domain && u.kind === kind && u.result === result.resultReference);
    if (prior && prior.request !== request.reference) fail(`${kind}_result_request_conflict`);
    if (prior) return 'retry';
    this.uses.push({ domain, kind, result: result.resultReference, request: request.reference }); return 'new';
  }
  private requestRetry(request: OperationRequest): 'new' | 'retry' {
    const prior = this.requests.get(request.reference);
    if (!prior) return 'new';
    if (equal(prior, request)) return 'retry';
    fail('changed_retry_payload_conflict');
    return 'new';
  }
  private remember(request: OperationRequest): void { this.requests.set(request.reference, structuredCopy(request)); }

  /** Verify and open an exact snapshot-backed supply state. */
  open(request: OperationRequest, evidence: AuthorityEvidence): 'new' | 'retry' {
    const result = resultFor(request, this.authority.verifyOpening(request, evidence), 'unverified_prior_state');
    const mode = this.requestRetry(request); if (mode === 'retry') return mode;
    if (this.opened || !integer(request.value) || request.value < 0) fail('unverified_prior_state');
    this.use('authority', 'opening', request, result); this.supply = request.value as number; this.openingSnapshot = structuredCopy(request.snapshot); this.opened = true; this.remember(request); this.records.push('prior_state_verified'); return 'new';
  }

  /** Restore one exact prior value after bound evidence verification. */
  restorePrior(request: OperationRequest, evidence: AuthorityEvidence): 'new' | 'retry' {
    const result = resultFor(request, this.authority.verifyPriorValue(request, evidence), 'unverified_prior_state');
    const mode = this.requestRetry(request); if (mode === 'retry') return mode;
    if (!this.opened || !positive(request.value) || request.status !== 'AVAILABLE' || !equal(request.snapshot, this.openingSnapshot) || this.notes.has(String(request.note)) || this.restored > this.supply - (request.value as number)) fail('unverified_prior_state');
    this.use('authority', 'prior', request, result); this.notes.set(String(request.note), { status: 'AVAILABLE', value: request.value as number }); this.restored += request.value as number; this.remember(request); return 'new';
  }

  /** Finalize an exact dividend claim and create its classified spendable note. */
  dividend(request: OperationRequest, capability: CapabilityEvidence, policyEvidence: AuthorityEvidence, witnessEvidence: AuthorityEvidence): 'new' | 'retry' {
    const fb = this.freebird(capability); const policy = resultFor(request, this.policy.verifyDividend(request, policyEvidence), 'dividend_policy_binding_conflict'); const witness = resultFor(request, this.authority.verifyDividendWitness(request, witnessEvidence), 'claim_witness_binding_conflict');
    const boundRequest = { ...request, policyResult: policy.resultReference, witnessResult: witness.resultReference, capabilityResult: fb.resultReference };
    const mode = this.requestRetry(boundRequest); if (mode === 'retry') return mode;
    const outputRef = String(request.outputRef ?? request.note); if (this.claims.has(String(request.slot))) fail('fixture_entitlement_slot_conflict'); if (!positive(request.amount) || !outputRef || this.notes.has(outputRef)) fail('invalid_dividend_claim');
    const next = add(this.supply, request.amount as number); this.use('policy', 'dividend', boundRequest, policy); this.use('witness', 'dividend', boundRequest, witness); this.use('freebird', 'dividend', boundRequest, fb); this.claims.set(String(request.slot), { request: structuredCopy(boundRequest), status: 'FINALIZED', note: outputRef }); this.notes.set(outputRef, { status: 'AVAILABLE', value: request.amount as number }); this.supply = next; this.remember(boundRequest); this.records.push('claim_finalized', `classified_dividend=${request.amount}`, 'spendable_note', 'Witness_finality', 'dividend_note_created'); return 'new';
  }

  /** Finalize classified civic issuance with exact policy and authority bindings. */
  civic(request: OperationRequest, capability: CapabilityEvidence, policyEvidence: AuthorityEvidence, witnessEvidence: AuthorityEvidence): 'new' | 'retry' {
    const fb = this.freebird(capability); const policy = resultFor(request, this.policy.verifyCivic(request, policyEvidence), 'civic_policy_binding_conflict'); const witness = resultFor(request, this.authority.verifyCivicWitness(request, witnessEvidence), 'civic_witness_binding_conflict');
    const boundRequest = { ...request, policyResult: policy.resultReference, witnessResult: witness.resultReference, capabilityResult: fb.resultReference };
    const mode = this.requestRetry(boundRequest); if (mode === 'retry') return mode;
    const outputRef = String(request.outputRef); if (!request.purpose || !positive(request.amount) || !outputRef || this.notes.has(outputRef)) fail('unclassified_issuance'); const next = add(this.supply, request.amount as number); this.use('policy', 'civic', boundRequest, policy); this.use('witness', 'civic', boundRequest, witness); this.use('freebird', 'civic', boundRequest, fb); this.supply = next; this.notes.set(outputRef, { status: 'AVAILABLE', value: request.amount as number }); this.remember(boundRequest); this.records.push(`classified_civic_issuance=${request.amount}`); return 'new';
  }

  /** Partially or fully burn an exact input, creating a unique successor only for a remainder. */
  burn(request: OperationRequest, witnessEvidence: AuthorityEvidence): 'new' | 'retry' {
    const witness = resultFor(request, this.authority.verifyBurnWitness(request, witnessEvidence), 'burn_witness_binding_conflict'); const boundRequest = { ...request, witnessResult: witness.resultReference }; const mode = this.requestRetry(boundRequest); if (mode === 'retry') return mode;
    const note = this.notes.get(String(request.input)); if (!note) throw new SemanticKernelError('accounting_underflow'); if (note.status !== 'AVAILABLE' || !positive(request.amount) || request.amount > note.value) fail('accounting_underflow'); const remainder = note.value - (request.amount as number); if ((remainder > 0) !== Boolean(request.successor)) fail(remainder > 0 ? 'successor_required' : 'successor_forbidden'); if (request.successor && this.notes.has(String(request.successor))) fail('successor_collision'); const next = sub(this.supply, request.amount as number); this.use('witness', 'burn', boundRequest, witness); note.status = 'BURNED'; this.supply = next; this.records.push(`permanent_burn=${request.amount}`); if (request.successor) { this.notes.set(String(request.successor), { status: 'AVAILABLE', value: remainder }); this.records.push('opaque_successor_created'); } this.remember(boundRequest); return 'new';
  }

  /** Finalize an exact spend with structural request identity and bound result use. */
  spend(request: OperationRequest, capability: CapabilityEvidence, witnessEvidence: AuthorityEvidence): 'new' | 'retry' {
    const fb = this.freebird(capability); const witness = resultFor(request, this.authority.verifySpendWitness(request, witnessEvidence), 'spend_not_finalized'); const boundRequest = { ...request, witnessResult: witness.resultReference, capabilityResult: fb.resultReference }; const mode = this.requestRetry(boundRequest); if (mode === 'retry') return mode;
    const note = this.notes.get(String(request.input)); if (!note) throw new SemanticKernelError('invalid_spend'); if (note.status !== 'AVAILABLE' || !positive(request.gross) || !integer(request.burn) || request.burn < 0 || request.burn > request.gross || request.output !== (request.gross as number) - request.burn) fail('invalid_spend'); const outputRef = String(request.outputRef); if (this.notes.has(outputRef) || !outputRef) fail('invalid_spend'); const next = sub(this.supply, request.burn as number); this.use('witness', 'spend', boundRequest, witness); this.use('freebird', 'spend', boundRequest, fb); note.status = 'PENDING'; this.records.push('spend_pending'); note.status = 'SPENT'; this.notes.set(outputRef, { status: 'AVAILABLE', value: request.output as number }); this.supply = next; this.remember(boundRequest); if ((request.burn as number) > 0) this.records.push(`permanent_burn=${request.burn}`); this.records.push(`gross=${request.gross}`, `outputs=${request.output}`, 'Witness_finality'); return 'new';
  }

  recover(request: OperationRequest, evidence: AuthorityEvidence): { authoritative: boolean; status: string } {
    const result = resultFor(request, this.authority.verifyRecovery(request, evidence), 'recovery_conflict'); const mode = this.requestRetry(request); if (mode === 'retry') return { authoritative: true, status: String(request.status) }; const authoritative = request.status === 'FINALIZED' && result.resultReference === String(request.finality); this.use('witness', 'recovery', request, result); this.remember(request); return { authoritative, status: String(request.status) };
  }
  relay(envelope: string, evidence: AuthorityEvidence): 'new' | 'retry' { const result = resultFor({ reference: evidence.requestReference }, this.authority.verifyRelay(evidence), 'forged_or_unverified_relay_message'); const prior = this.relayReceipts.find((ref) => ref === result.resultReference); if (prior) return 'retry'; this.relayReceipts.push(result.resultReference); this.records.push(`verified_finality=${result.resultReference}`); return 'new'; }
  rejectDeferred(): never { return fail('deferred_operation'); }
  observe(): unknown { return { opened: this.opened, supply: this.supply, notes: [...this.notes.entries()], claims: [...this.claims.entries()], requests: [...this.requests.entries()], uses: [...this.uses], relays: [...this.relayReceipts], records: [...this.records] }; }
}

const structuredCopy = <T>(value: T): T => {
  if (Array.isArray(value)) return value.map(structuredCopy) as T;
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value as object).map(([k, v]) => [k, structuredCopy(v)])) as T;
  return value;
};
