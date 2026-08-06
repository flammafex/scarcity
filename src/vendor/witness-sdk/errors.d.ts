import type { AttestationJobStatus } from './types.generated.js';
/** Machine-readable error codes for the whole SDK. */
export type WitnessErrorCode = 'transport' | 'http' | 'not_found' | 'job_failed' | 'confirmation_timeout' | 'decode' | 'verification' | 'auth_required';
/** Machine-readable reason for a local verification failure (§6.3). */
export type VerificationFailureReason = 'sub-threshold' | 'duplicate-signer' | 'unknown-witness' | 'bad-signature' | 'index-size-mismatch' | 'ambiguous-signature-encoding';
/** Base class for all SDK errors. */
export declare class WitnessError extends Error {
    readonly code: WitnessErrorCode;
    constructor(code: WitnessErrorCode, message: string, options?: ErrorOptions);
}
/** A transport-level failure (connect, TLS, timeout, abort, etc.). */
export declare class TransportError extends WitnessError {
    constructor(message: string, options?: ErrorOptions);
}
/** The gateway returned a non-2xx status that is not a 404 on a read endpoint. */
export declare class HttpStatusError extends WitnessError {
    readonly status: number;
    readonly body: string;
    constructor(status: number, body: string);
}
/** The gateway returned 404 on a read endpoint (e.g. unknown attestation). */
export declare class NotFoundError extends WitnessError {
    constructor(body: string);
}
/** An attestation job reached the terminal `failed` state. */
export declare class JobFailedError extends WitnessError {
    readonly attempts: number;
    readonly lastError?: string;
    constructor(attempts: number, lastError?: string);
}
/** `waitForConfirmation` exceeded its timeout before the job reached a terminal state. */
export declare class ConfirmationTimeoutError extends WitnessError {
    readonly lastStatus: AttestationJobStatus;
    constructor(lastStatus: AttestationJobStatus);
}
/** The gateway returned a response that could not be decoded, or a protocol violation. */
export declare class DecodeError extends WitnessError {
    constructor(message: string);
}
/** Local verification failed (see `reason` for the machine-readable cause). */
export declare class VerificationError extends WitnessError {
    readonly reason: VerificationFailureReason;
    constructor(reason: VerificationFailureReason, message?: string);
}
/** WebSocket auth failed (close code 4001, or the token was wrong/absent). */
export declare class AuthRequiredError extends WitnessError {
    constructor(message?: string);
}
