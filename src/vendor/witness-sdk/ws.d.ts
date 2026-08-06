import type { AttestationEvent } from './types.generated.js';
import { WitnessError } from './errors.js';
/** Options for [`subscribeEvents`]. */
export type SubscribeOptions = {
    /** Optional bearer token for the auth handshake. */
    token?: string;
    /** Abort signal; aborting closes the subscription. */
    signal?: AbortSignal;
    /** Reconnect policy. Default: infinite retries with exponential backoff + jitter. */
    reconnect?: {
        maxRetries?: number;
        baseDelayMs?: number;
    };
    /** Called for each decoded `AttestationEvent`. */
    onEvent: (ev: AttestationEvent) => void;
    /** Called for non-fatal errors (decode failures, transport errors, auth failures). */
    onError?: (err: WitnessError) => void;
};
/** Handle returned by [`subscribeEvents`]; call `close()` to stop. */
export interface EventsSubscription {
    close(): void;
}
/**
 * Subscribe to attestation events over WebSocket.
 *
 * If `token` is supplied, performs the first-message auth handshake. A close
 * code of 4001 raises `AuthRequiredError` (no auto-retry). Other unexpected
 * closes are retried per the reconnect policy.
 */
export declare function subscribeEvents(gatewayUrl: string, opts: SubscribeOptions): EventsSubscription;
