/**
 * Scarcity Protocol Constants
 *
 * Central location for configurable defaults.
 */

/**
 * Default token validity window in milliseconds.
 *
 * Tokens expire after this period if not transferred.
 * This implements "lazy demurrage" - tokens must circulate to remain valid.
 *
 * Default: ~576 days (approximately 1.58 years)
 * Formula: 24 * 24 * 24 * 3600 * 1000 = 49,766,400,000 ms
 *
 * This value should be consistent across:
 * - NullifierGossip (maxNullifierAge)
 * - TransferValidator (maxTokenAge)
 * - Web wallet (TOKEN_VALIDITY_MS in app.js)
 *
 * To change: Pass custom values to NullifierGossip and TransferValidator constructors.
 */
export const DEFAULT_TOKEN_VALIDITY_MS = 24 * 24 * 24 * 3600 * 1000;

/**
 * Default token validity in days (for display purposes)
 */
export const DEFAULT_TOKEN_VALIDITY_DAYS = Math.floor(DEFAULT_TOKEN_VALIDITY_MS / (24 * 3600 * 1000));

/**
 * Warning threshold: show expiry warning when less than this many days remain
 */
export const DEFAULT_EXPIRY_WARNING_DAYS = 90;
