// Typed error model for `@witness/sdk` (§6.5).
//
// Every gateway failure mode a consumer must branch on is mapped to a typed
// error class; consumers never string-match on error messages.
/** Base class for all SDK errors. */
export class WitnessError extends Error {
    code;
    constructor(code, message, options) {
        super(message, options);
        this.name = new.target.name;
        this.code = code;
    }
}
/** A transport-level failure (connect, TLS, timeout, abort, etc.). */
export class TransportError extends WitnessError {
    constructor(message, options) {
        super('transport', message, options);
    }
}
/** The gateway returned a non-2xx status that is not a 404 on a read endpoint. */
export class HttpStatusError extends WitnessError {
    status;
    body;
    constructor(status, body) {
        super('http', `gateway returned ${status}: ${body}`);
        this.status = status;
        this.body = body;
    }
}
/** The gateway returned 404 on a read endpoint (e.g. unknown attestation). */
export class NotFoundError extends WitnessError {
    constructor(body) {
        super('not_found', `not found: ${body}`);
    }
}
/** An attestation job reached the terminal `failed` state. */
export class JobFailedError extends WitnessError {
    attempts;
    lastError;
    constructor(attempts, lastError) {
        super('job_failed', `attestation job failed after ${attempts} attempt(s): ${lastError ?? 'unknown'}`);
        this.attempts = attempts;
        this.lastError = lastError;
    }
}
/** `waitForConfirmation` exceeded its timeout before the job reached a terminal state. */
export class ConfirmationTimeoutError extends WitnessError {
    lastStatus;
    constructor(lastStatus) {
        super('confirmation_timeout', `timed out waiting for confirmation; last status: ${lastStatus}`);
        this.lastStatus = lastStatus;
    }
}
/** The gateway returned a response that could not be decoded, or a protocol violation. */
export class DecodeError extends WitnessError {
    constructor(message) {
        super('decode', `failed to decode gateway response: ${message}`);
    }
}
/** Local verification failed (see `reason` for the machine-readable cause). */
export class VerificationError extends WitnessError {
    reason;
    constructor(reason, message) {
        super('verification', message ?? `verification failed: ${reason}`);
        this.reason = reason;
    }
}
/** WebSocket auth failed (close code 4001, or the token was wrong/absent). */
export class AuthRequiredError extends WitnessError {
    constructor(message = 'authentication required') {
        super('auth_required', message);
    }
}
