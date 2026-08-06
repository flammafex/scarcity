import { SemanticCashKernel, structuralEqual, type CapabilityEvidence, type AuthorityEvidence, type OperationRequest, type SemanticAuthority, type SemanticPolicy } from '../../../src/cash-kernel/semantic-state.js';

export class TableAuthority implements SemanticAuthority {
  private exact(request: OperationRequest, evidence: AuthorityEvidence, failure: string) { if (evidence.requestReference !== request.reference || !structuralEqual(evidence.requestTuple, request)) throw new Error(failure); return { requestReference: request.reference, resultReference: evidence.normalizedResultReference, normalized: evidence.normalizedResultReference }; }
  verifyOpening(request: OperationRequest, evidence: AuthorityEvidence) { return this.exact(request, evidence, 'unverified_prior_state'); }
  verifyPriorValue(request: OperationRequest, evidence: AuthorityEvidence) { return this.exact(request, evidence, 'unverified_prior_state'); }
  verifyFreebird(evidence: CapabilityEvidence) { if (evidence.tainted) return 'tainted' as const; if (evidence.capabilityRef !== 'CAP-A' && evidence.capabilityRef !== 'CAP-B') return null; return { requestReference: evidence.requestReference, resultReference: `FB-${evidence.capabilityRef}`, normalized: 'valid' }; }
  verifyDividendWitness(request: OperationRequest, evidence: AuthorityEvidence) { return this.exact(request, evidence, 'claim_witness_binding_conflict'); }
  verifyCivicWitness(request: OperationRequest, evidence: AuthorityEvidence) { if (evidence.resultReference === 'INVALID') throw new Error('issuance_not_finalized'); return this.exact(request, evidence, 'civic_witness_binding_conflict'); }
  verifyBurnWitness(request: OperationRequest, evidence: AuthorityEvidence) { return this.exact(request, evidence, 'burn_witness_binding_conflict'); }
  verifySpendWitness(request: OperationRequest, evidence: AuthorityEvidence) { return this.exact(request, evidence, 'spend_not_finalized'); }
  verifyRecovery(request: OperationRequest, evidence: AuthorityEvidence) { return this.exact(request, evidence, 'recovery_conflict'); }
  verifyRelay(evidence: AuthorityEvidence) { if (evidence.requestReference !== evidence.evidenceReference) throw new Error('forged_or_unverified_relay_message'); return { requestReference: evidence.requestReference, resultReference: evidence.resultReference, normalized: evidence.normalized }; }
}
export class TablePolicy implements SemanticPolicy {
  verifyDividend(request: OperationRequest, evidence: AuthorityEvidence) { if (evidence.requestReference !== request.reference) throw new Error('dividend_policy_binding_conflict'); return { requestReference: request.reference, resultReference: evidence.resultReference, normalized: evidence.normalized }; }
  verifyCivic(request: OperationRequest, evidence: AuthorityEvidence) { if (evidence.requestReference !== request.reference) throw new Error('civic_policy_binding_conflict'); if (request.purpose === 'OVER-CAP') throw new Error('civic_issuance_cap'); if (request.purpose === 'BAD-THRESHOLD') throw new Error('invalid_threshold'); if (!String(request.purpose).startsWith('CIVIC-')) throw new Error('unclassified_issuance'); return { requestReference: request.reference, resultReference: evidence.resultReference, normalized: evidence.normalized }; }
}
const requestTable = new Map<string, OperationRequest>();
export const evidence = (request: string | OperationRequest, resultReference = `RESULT-${typeof request === 'string' ? request : request.reference}`): AuthorityEvidence => { const requestReference = typeof request === 'string' ? request : request.reference; const requestTuple = typeof request === 'string' ? (requestTable.get(request) ?? { reference: request }) : request; return { evidenceReference: `EVIDENCE-${requestReference}`, rawResultReference: `RAW-${resultReference}`, normalizedResultReference: resultReference, requestReference, requestTuple, resultReference, normalized: resultReference }; };
export const capability = (requestReference: string, ref = 'CAP-A'): CapabilityEvidence => ({ capabilityRef: ref, requestReference });
export const request = (reference: string, fields: Record<string, unknown> = {}): OperationRequest => { const value = { reference, ...fields }; requestTable.set(reference, value); return value; };
export const makeKernel = (): SemanticCashKernel => new SemanticCashKernel(new TableAuthority(), new TablePolicy());
