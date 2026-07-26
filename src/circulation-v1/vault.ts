/**
 * Encrypted, local-only Phase-1 wallet vault.
 *
 * This module deliberately has no password handling, key derivation, export,
 * backup, recovery, network, or service integration.  The caller supplies a
 * 32-byte AES key after performing its own unlock ceremony.
 */

import { createCipheriv, createDecipheriv, randomBytes as systemRandomBytes } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, unlink } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { basename, join, resolve } from 'node:path';
import {
  decodeCanonicalBase64Url,
  decodeCanonicalLowerHex,
  encodeCanonicalBase64Url,
  parseExchangeAcceptedResponseV2,
  parseExchangeReceiptV2,
  parseExchangeRequestV2,
  parseExchangeResultV2,
  parseGraphIssuanceRequestV1,
  parseGraphIssuanceResultV1,
  parseGraphSlotSelector,
  parseV5BearerArtifactEnvelope,
  type CanonicalBase64Url,
  type CanonicalSha256Hex,
  type ExchangeAcceptedResponseV2,
  type ExchangeOutputV2,
  type ExchangeReceiptV2,
  type ExchangeRequestV2,
  type ExchangeResultV2,
  type GraphIssuanceRequestV1,
  type GraphIssuanceResultV1,
  type GraphSlotSelectorV2,
} from './types.js';
import { decodeV5BearerArtifactBase64 } from './canonical.js';

export const VAULT_RECORD_VERSION = 'scarcity/vault-record/v1' as const;
export const VAULT_TRANSACTION_VERSION = 'scarcity/vault-transaction/v1' as const;
export const VAULT_LOCK_FILE = 'vault.lock' as const;
const VAULT_METADATA_VERSION = 'scarcity/vault/v1' as const;
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const RECORD_ID_BYTES = 16;
const WALLET_ID_BYTES = 16;
const OPERATION_ID_BYTES = 16;
const STATUS_CAPABILITY_BYTES = 32;
const MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES;

interface NativeFsExtensions {
  readonly waitForLock: (fd: number, offset?: number, length?: number, options?: { readonly shared?: boolean }) => Promise<void>;
  readonly unlock: (fd: number, offset?: number, length?: number) => void;
}

const nativeFsExtensions = createRequire(import.meta.url)('fs-native-extensions') as NativeFsExtensions;

export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultError';
  }
}

export class VaultValidationError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'VaultValidationError';
  }
}

/** Deliberately generic: callers cannot distinguish a wrong key from a bad tag. */
export class VaultAuthenticationError extends VaultError {
  constructor() {
    super('vault authentication failed');
    this.name = 'VaultAuthenticationError';
  }
}

export class VaultStateError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'VaultStateError';
  }
}

export class VaultPersistenceError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'VaultPersistenceError';
  }
}

/** Native advisory-lock acquisition/release failure. */
export class VaultLockError extends VaultStateError {
  constructor(message: string) {
    super(message);
    this.name = 'VaultLockError';
  }
}

export type VaultFailureStage =
  | 'metadata:before-temp-write'
  | 'metadata:after-temp-write'
  | 'metadata:before-fsync'
  | 'metadata:after-fsync'
  | 'metadata:before-rename'
  | 'metadata:after-rename'
  | 'metadata:before-directory-fsync'
  | 'metadata:after-directory-fsync'
  | 'transaction:before-temp-write'
  | 'transaction:after-temp-write'
  | 'transaction:before-fsync'
  | 'transaction:after-fsync'
  | 'transaction:before-rename'
  | 'transaction:after-rename'
  | 'transaction:before-directory-fsync'
  | 'transaction:after-directory-fsync'
  | 'transaction-clear:before-directory-fsync'
  | 'transaction-clear:after-directory-fsync'
  | 'record:before-temp-write'
  | 'record:after-temp-write'
  | 'record:before-fsync'
  | 'record:after-fsync'
  | 'record:before-rename'
  | 'record:after-rename'
  | 'record:before-directory-fsync'
  | 'record:after-directory-fsync'
  | 'record-delete:before-directory-fsync'
  | 'record-delete:after-directory-fsync'
  | 'lock:before-directory-fsync'
  | 'lock:after-directory-fsync';

export type VaultFailureHook = (stage: VaultFailureStage) => void | Promise<void>;

export interface VaultEnvelope {
  readonly version: typeof VAULT_RECORD_VERSION;
  readonly wallet_id: CanonicalBase64Url;
  readonly record_id: CanonicalBase64Url;
  readonly nonce: CanonicalBase64Url;
  readonly ciphertext: CanonicalBase64Url;
}

export type ArtifactState = 'current' | 'reserved' | 'spent';
export type ReceiveState = 'prepared' | 'submitted_unknown' | 'current' | 'rejected';
export type SendState = 'offered' | 'reserved_pending' | 'spend_unknown' | 'spent' | 'rejected';
export type GenesisState = 'prepared' | 'submitted_unknown' | 'current' | 'rejected';

export interface ArtifactVaultRecord {
  readonly version: 1;
  readonly record_type: 'artifact';
  readonly state: ArtifactState;
  readonly artifact: CanonicalBase64Url;
  readonly keyset_id: CanonicalSha256Hex;
  readonly descriptor_id: CanonicalSha256Hex;
  readonly reserved_by: CanonicalBase64Url | null;
}

export interface PreparedReceiveVaultRecord {
  readonly version: 1;
  readonly record_type: 'prepared_receive';
  readonly state: ReceiveState;
  readonly operation_id: CanonicalBase64Url;
  readonly status_capability: CanonicalBase64Url | null;
  readonly preparation_snapshot_ref: string;
  readonly graph_id: CanonicalSha256Hex;
  readonly transition_id: CanonicalSha256Hex;
  readonly source_keyset_id: CanonicalSha256Hex;
  readonly target_keyset_id: CanonicalSha256Hex;
  readonly expected_output: ExchangeOutputV2;
  readonly output_nonce: CanonicalBase64Url | null;
  readonly message: CanonicalBase64Url | null;
  readonly blinding_state: CanonicalBase64Url | null;
  readonly finalized_artifact: CanonicalBase64Url | null;
  readonly result: ExchangeResultV2 | null;
  readonly receipt: ExchangeReceiptV2 | null;
  readonly artifact_record_id: CanonicalBase64Url | null;
  readonly rejection_code: string | null;
}

export interface PreparedSendVaultRecord {
  readonly version: 1;
  readonly record_type: 'prepared_send';
  readonly state: SendState;
  readonly operation_id: CanonicalBase64Url;
  readonly status_capability: CanonicalBase64Url | null;
  readonly preparation_snapshot_ref: string;
  readonly source_record_id: CanonicalBase64Url;
  readonly source_artifact: CanonicalBase64Url;
  readonly request: ExchangeRequestV2;
  readonly result: ExchangeAcceptedResponseV2 | null;
  readonly finalized_artifact: CanonicalBase64Url | null;
  readonly output_record_id: CanonicalBase64Url | null;
  readonly rejection_code: string | null;
}

export interface GenesisIssuanceVaultRecord {
  readonly version: 1;
  readonly record_type: 'genesis_issuance';
  readonly state: GenesisState;
  readonly operation_id: CanonicalBase64Url;
  readonly status_capability: CanonicalBase64Url | null;
  readonly preparation_snapshot_ref: string;
  readonly request: GraphIssuanceRequestV1;
  readonly output_nonce: CanonicalBase64Url | null;
  readonly message: CanonicalBase64Url | null;
  readonly blinding_state: CanonicalBase64Url | null;
  readonly result: GraphIssuanceResultV1 | null;
  readonly finalized_artifact: CanonicalBase64Url | null;
  readonly artifact_record_id: CanonicalBase64Url | null;
  readonly rejection_code: string | null;
}

export type VaultRecord =
  | ArtifactVaultRecord
  | PreparedReceiveVaultRecord
  | PreparedSendVaultRecord
  | GenesisIssuanceVaultRecord;

export interface VaultStorageBackend {
  /** Process-local lock key used in addition to the filesystem lock. */
  readonly lockKey: string;
  /** Filesystem backends use native descriptor locking; memory backends serialize locally. */
  readonly processLocalLocking?: boolean;
  acquireLock(): Promise<VaultLockLease>;
  readWalletId(): Promise<string | undefined>;
  writeWalletId(walletId: string): Promise<void>;
  listRecordEnvelopes(): Promise<ReadonlyMap<string, string>>;
  writeRecordEnvelope(recordId: string, envelope: string): Promise<void>;
  deleteRecordEnvelope(recordId: string): Promise<void>;
  readTransactionEnvelope(): Promise<string | undefined>;
  writeTransactionEnvelope(envelope: string): Promise<void>;
  clearTransactionEnvelope(): Promise<void>;
}

export interface VaultLockLease {
  readonly descriptor: number;
  release(): Promise<void>;
}

export interface FilesystemVaultBackendOptions {
  readonly failureHook?: VaultFailureHook;
}

let memoryBackendSequence = 0;

/** In-memory backend for deterministic, service-free tests. */
export class MemoryVaultBackend implements VaultStorageBackend {
  public readonly lockKey: string;
  public readonly processLocalLocking = true;
  private walletId: string | undefined;
  private readonly records = new Map<string, string>();
  private transactionEnvelope: string | undefined;

  constructor(lockKey?: string) {
    memoryBackendSequence += 1;
    this.lockKey = lockKey ?? `memory-vault-${memoryBackendSequence}`;
  }

  async acquireLock(): Promise<VaultLockLease> {
    return {
      descriptor: -1,
      release: async () => undefined,
    };
  }

  async readWalletId(): Promise<string | undefined> {
    return this.walletId;
  }

  async writeWalletId(walletId: string): Promise<void> {
    if (this.walletId !== undefined && this.walletId !== JSON.stringify({ version: VAULT_METADATA_VERSION, wallet_id: walletId })) {
      throw new VaultPersistenceError('vault wallet identity already exists');
    }
    this.walletId = JSON.stringify({ version: VAULT_METADATA_VERSION, wallet_id: walletId });
  }

  async listRecordEnvelopes(): Promise<ReadonlyMap<string, string>> {
    return new Map(this.records);
  }

  async writeRecordEnvelope(recordId: string, envelope: string): Promise<void> {
    this.records.set(recordId, envelope);
  }

  async deleteRecordEnvelope(recordId: string): Promise<void> {
    this.records.delete(recordId);
  }

  async readTransactionEnvelope(): Promise<string | undefined> {
    return this.transactionEnvelope;
  }

  async writeTransactionEnvelope(envelope: string): Promise<void> {
    this.transactionEnvelope = envelope;
  }

  async clearTransactionEnvelope(): Promise<void> {
    this.transactionEnvelope = undefined;
  }
}

/**
 * Filesystem backend. Only encrypted envelopes and non-secret vault metadata
 * are ever written to temporary files.
 */
export class FilesystemVaultBackend implements VaultStorageBackend {
  public readonly directory: string;
  public readonly lockKey: string;
  public readonly processLocalLocking = false;
  public readonly lockFilePath: string;
  private readonly recordsDirectory: string;
  private readonly transactionPath: string;
  private readonly metadataPath: string;
  private readonly failureHook?: VaultFailureHook;

  constructor(directory: string, options: FilesystemVaultBackendOptions = {}) {
    if (typeof directory !== 'string' || directory.length === 0) {
      throw new VaultValidationError('directory: expected a non-empty path');
    }
    this.directory = resolve(directory);
    this.recordsDirectory = join(this.directory, 'records');
    this.transactionPath = join(this.directory, 'transaction.json');
    this.metadataPath = join(this.directory, 'vault.json');
    this.lockFilePath = join(this.directory, VAULT_LOCK_FILE);
    this.lockKey = `filesystem-vault-${this.directory}`;
    this.failureHook = options.failureHook;
  }

  private async ensureLayout(): Promise<void> {
    await mkdir(this.recordsDirectory, { recursive: true, mode: 0o700 });
  }

  private async invoke(stage: VaultFailureStage): Promise<void> {
    await this.failureHook?.(stage);
  }

  /**
   * Open the permanent sidecar and hold its native advisory exclusive lock.
   * This is intentionally for cooperating processes on a local filesystem;
   * NFS and other network-filesystem lock semantics are not supported.
   * Kernel descriptor release after process death is the crash recovery path.
   */
  async acquireLock(): Promise<VaultLockLease> {
    try {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
    } catch (error) {
      throw new VaultLockError(`unable to prepare advisory vault lock directory: ${error instanceof Error ? error.message : 'mkdir failed'}`);
    }
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(this.lockFilePath, 'a+', 0o600);
    } catch (error) {
      throw new VaultLockError(`unable to open advisory vault lock: ${error instanceof Error ? error.message : 'open failed'}`);
    }
    try {
      const stats = await handle.stat();
      if ((stats.mode & 0o077) !== 0) throw new VaultLockError('advisory vault lock sidecar permissions are not restrictive');
      if (stats.size !== 0) throw new VaultLockError('advisory vault lock sidecar must remain empty');
      await nativeFsExtensions.waitForLock(handle.fd, 0, 0, { shared: false });
      await handle.sync();
      await this.syncDirectory(this.directory, 'lock:before-directory-fsync', 'lock:after-directory-fsync');
    } catch (error) {
      try { await handle.close(); } catch { /* preserve the original failure */ }
      if (error instanceof VaultLockError) throw error;
      throw new VaultLockError(`unable to acquire advisory vault lock: ${error instanceof Error ? error.message : 'lock failed'}`);
    }

    let released = false;
    return {
      descriptor: handle.fd,
      release: async () => {
        if (released) return;
        released = true;
        try {
          nativeFsExtensions.unlock(handle.fd);
        } finally {
          await handle.close();
        }
      },
    };
  }

  private recordPath(recordId: string): string {
    const checked = encodedBytes(recordId, 'record_id', RECORD_ID_BYTES, RECORD_ID_BYTES);
    return join(this.recordsDirectory, `${checked}.json`);
  }

  private async syncDirectory(directory: string, before: VaultFailureStage, after: VaultFailureStage): Promise<void> {
    await this.invoke(before);
    try {
      const handle = await open(directory, 'r');
      try {
        await handle.sync();
      } finally {
        await handle.close();
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      // Directory fsync is not available on every supported filesystem.
      if (code !== 'EINVAL' && code !== 'ENOTSUP' && code !== 'EOPNOTSUPP' && code !== 'EBADF' && code !== 'EPERM') {
        throw error;
      }
    }
    await this.invoke(after);
  }

  private async atomicWrite(
    target: string,
    contents: string,
    prefix: 'metadata' | 'transaction' | 'record',
    directory: string,
  ): Promise<void> {
    const temporary = `${target}.${process.pid}.${systemRandomBytes(12).toString('hex')}.tmp`;
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    let renamed = false;
    try {
      await this.invoke(`${prefix}:before-temp-write`);
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(contents, 'utf8');
      await this.invoke(`${prefix}:after-temp-write`);
      await this.invoke(`${prefix}:before-fsync`);
      await handle.sync();
      await this.invoke(`${prefix}:after-fsync`);
      await handle.close();
      handle = undefined;
      await this.invoke(`${prefix}:before-rename`);
      await rename(temporary, target);
      renamed = true;
      await this.invoke(`${prefix}:after-rename`);
      await this.syncDirectory(directory, `${prefix}:before-directory-fsync`, `${prefix}:after-directory-fsync`);
    } catch (error) {
      if (handle !== undefined) {
        try {
          await handle.close();
        } catch {
          // Preserve the injected or filesystem failure.
        }
      }
      if (!renamed) {
        try {
          await unlink(temporary);
        } catch (cleanupError) {
          if ((cleanupError as NodeJS.ErrnoException).code !== 'ENOENT') {
            // There is no safe plaintext cleanup fallback; the temp contains
            // only the encrypted envelope and remains private mode 0600.
          }
        }
      }
      throw error;
    }
  }

  private async readOptional(path: string): Promise<string | undefined> {
    try {
      return await readFile(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    }
  }

  async readWalletId(): Promise<string | undefined> {
    await this.ensureLayout();
    return this.readOptional(this.metadataPath);
  }

  async writeWalletId(walletId: string): Promise<void> {
    await this.ensureLayout();
    const contents = JSON.stringify({ version: VAULT_METADATA_VERSION, wallet_id: walletId });
    const existing = await this.readOptional(this.metadataPath);
    if (existing !== undefined && existing !== contents) throw new VaultPersistenceError('vault wallet identity already exists');
    if (existing === contents) return;
    await this.atomicWrite(this.metadataPath, contents, 'metadata', this.directory);
  }

  async listRecordEnvelopes(): Promise<ReadonlyMap<string, string>> {
    await this.ensureLayout();
    const result = new Map<string, string>();
    for (const entry of await readdir(this.recordsDirectory, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
      const recordId = basename(entry.name, '.json');
      result.set(recordId, await readFile(join(this.recordsDirectory, entry.name), 'utf8'));
    }
    return result;
  }

  async writeRecordEnvelope(recordId: string, envelope: string): Promise<void> {
    await this.ensureLayout();
    await this.atomicWrite(this.recordPath(recordId), envelope, 'record', this.recordsDirectory);
  }

  async deleteRecordEnvelope(recordId: string): Promise<void> {
    await this.ensureLayout();
    try {
      await unlink(this.recordPath(recordId));
      await this.syncDirectory(this.recordsDirectory, 'record-delete:before-directory-fsync', 'record-delete:after-directory-fsync');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }

  async readTransactionEnvelope(): Promise<string | undefined> {
    await this.ensureLayout();
    return this.readOptional(this.transactionPath);
  }

  async writeTransactionEnvelope(envelope: string): Promise<void> {
    await this.ensureLayout();
    await this.atomicWrite(this.transactionPath, envelope, 'transaction', this.directory);
  }

  async clearTransactionEnvelope(): Promise<void> {
    await this.ensureLayout();
    try {
      await unlink(this.transactionPath);
      await this.syncDirectory(this.directory, 'transaction-clear:before-directory-fsync', 'transaction-clear:after-directory-fsync');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
}

// These aliases make the boundary names explicit without adding a public
// barrel dependency to the isolated circulation-v1 foundation.
export { FilesystemVaultBackend as FileVaultBackend };
export { MemoryVaultBackend as InMemoryVaultBackend };

type RandomSource = (length: number) => Uint8Array;

export interface VaultCreateOptions {
  readonly backend?: VaultStorageBackend;
  readonly directory?: string;
  readonly unlockKey?: Uint8Array;
  /** TEST-ONLY deterministic source; production uses node:crypto. */
  readonly randomBytes?: RandomSource;
  readonly failureHook?: VaultFailureHook;
}

export interface VaultOpenOptions {
  readonly backend?: VaultStorageBackend;
  readonly directory?: string;
  readonly unlockKey?: Uint8Array;
  /** TEST-ONLY deterministic source; production uses node:crypto. */
  readonly randomBytes?: RandomSource;
}

export interface ReceivePreparationInput {
  readonly operation_id?: string;
  readonly status_capability?: string;
  readonly preparation_snapshot_ref: string;
  readonly graph_id: string;
  readonly transition_id: string;
  readonly source_keyset_id: string;
  readonly target_keyset_id: string;
  readonly expected_output: ExchangeOutputV2;
  readonly output_nonce: Uint8Array;
  readonly message: Uint8Array;
  readonly blinding_state: Uint8Array;
}

export interface ReceiveHandoff {
  readonly operation_id: CanonicalBase64Url;
  readonly status_capability: CanonicalBase64Url;
  readonly graph_id: CanonicalSha256Hex;
  readonly transition_id: CanonicalSha256Hex;
  readonly source_keyset_id: CanonicalSha256Hex;
  readonly target_keyset_id: CanonicalSha256Hex;
  readonly output: ExchangeOutputV2;
}

export interface SendPreparationInput {
  readonly operation_id?: string;
  readonly status_capability?: string;
  readonly preparation_snapshot_ref: string;
  readonly request: ExchangeRequestV2;
  readonly source_record_id: string;
}

export interface SendHandoff {
  readonly operation_id: CanonicalBase64Url;
  readonly status_capability: CanonicalBase64Url;
  readonly request: ExchangeRequestV2;
}

export interface GenesisPreparationInput {
  readonly operation_id?: string;
  readonly status_capability?: string;
  readonly preparation_snapshot_ref: string;
  readonly request: GraphIssuanceRequestV1;
  readonly output_nonce: Uint8Array;
  readonly message: Uint8Array;
  readonly blinding_state: Uint8Array;
}

export interface GenesisHandoff {
  readonly operation_id: CanonicalBase64Url;
  readonly status_capability: CanonicalBase64Url;
  readonly request: GraphIssuanceRequestV1;
}

export interface FinalizeReceiveInput {
  readonly artifact: string;
  readonly result: ExchangeResultV2;
  readonly receipt: ExchangeReceiptV2;
}

export interface FinalizeGenesisInput {
  readonly artifact: string;
  readonly result: GraphIssuanceResultV1;
}

export interface FinalizeSendInput {
  readonly result: ExchangeResultV2;
  readonly receipt: ExchangeReceiptV2;
  readonly finalized_artifact?: string;
}

interface TransactionEntry {
  readonly record_id: CanonicalBase64Url;
  readonly envelope: string | null;
}

interface TransactionPlaintext {
  readonly version: typeof VAULT_TRANSACTION_VERSION;
  readonly transaction_id: CanonicalBase64Url;
  readonly entries: readonly TransactionEntry[];
}

const processLocks = new Map<string, Promise<void>>();

async function withProcessLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = processLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolveRelease) => { release = resolveRelease; });
  processLocks.set(key, current);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (processLocks.get(key) === current) processLocks.delete(key);
  }
}

async function withBackendLock<T>(backend: VaultStorageBackend, operation: () => Promise<T>): Promise<T> {
  const lease = await backend.acquireLock();
  try {
    return await operation();
  } finally {
    await lease.release();
  }
}

async function withBackendSerialization<T>(backend: VaultStorageBackend, operation: () => Promise<T>): Promise<T> {
  if (backend.processLocalLocking === false) return operation();
  return withProcessLock(backend.lockKey, operation);
}

function fail(field: string, message: string): never {
  throw new VaultValidationError(`${field}: ${message}`);
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(field, 'expected an object');
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], field: string): void {
  const requiredSet = new Set(required);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${field}.${key}`, 'missing field');
  }
  for (const key of Object.keys(value)) {
    if (!requiredSet.has(key)) fail(`${field}.${key}`, 'unknown field');
  }
}

function text(value: unknown, field: string, min = 1, max = 4096): string {
  if (typeof value !== 'string' || value.length < min || value.length > max) fail(field, 'invalid string');
  return value;
}

function decodeBoundedCanonicalBase64Url(value: unknown, field: string, expected: number | undefined, max: number): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || value.length > max * 2 + 8 || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    fail(field, 'invalid canonical base64url');
  }
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = globalThis.atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytes.length === 0 || bytes.length > max) fail(field, 'invalid byte length');
    if (expected !== undefined && bytes.length !== expected) fail(field, `expected ${expected} bytes`);
    if (encodeCanonicalBase64Url(bytes) !== value) fail(field, 'non-canonical base64url encoding');
    return bytes;
  } catch (error) {
    if (error instanceof VaultValidationError) throw error;
    fail(field, 'invalid canonical base64url');
  }
}

function boundedBytes(value: unknown, field: string, expected?: number, max = MAX_PLAINTEXT_BYTES): Uint8Array {
  return decodeBoundedCanonicalBase64Url(value, field, expected, max);
}

function suppliedBytes(value: Uint8Array, field: string, expected: number | undefined, max: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > max || (expected !== undefined && value.length !== expected)) {
    fail(field, expected === undefined ? 'invalid byte length' : `expected ${expected} bytes`);
  }
  return value.slice();
}

function id(value: unknown, field: string, bytes = 32): CanonicalSha256Hex {
  decodeCanonicalLowerHex(value, bytes, field);
  return value as CanonicalSha256Hex;
}

function encodedBytes(value: unknown, field: string, expected?: number, max = MAX_PLAINTEXT_BYTES): CanonicalBase64Url {
  return encodeCanonicalBase64Url(boundedBytes(value, field, expected, max));
}

function operationId(value: unknown, field: string): CanonicalBase64Url {
  return encodedBytes(value, field, OPERATION_ID_BYTES, OPERATION_ID_BYTES);
}

function capability(value: unknown, field: string): CanonicalBase64Url {
  return encodedBytes(value, field, STATUS_CAPABILITY_BYTES, STATUS_CAPABILITY_BYTES);
}

function recordId(value: unknown, field: string): CanonicalBase64Url {
  return encodedBytes(value, field, RECORD_ID_BYTES, RECORD_ID_BYTES);
}

function snapshotRef(value: unknown, field: string): string {
  return text(value, field, 1, 4096);
}

function equalText(left: string, right: string, field: string): void {
  if (left !== right) fail(field, 'does not match');
}

function equalBase64(left: string, right: string, field: string): void {
  const a = decodeCanonicalBase64Url(left, undefined, field);
  const b = decodeCanonicalBase64Url(right, undefined, field);
  if (a.length !== b.length || a.some((byte, index) => byte !== b[index])) fail(field, 'does not match');
}

function validateArtifact(value: unknown, field: string): CanonicalBase64Url {
  const artifact = encodedBytes(value, field, undefined, 16 * 1024);
  try {
    parseV5BearerArtifactEnvelope(decodeV5BearerArtifactBase64(artifact));
  } catch {
    fail(field, 'invalid Freebird V5 artifact');
  }
  return artifact;
}

function validateExpectedOutput(value: unknown, field: string): ExchangeOutputV2 {
  const output = object(value, field);
  exactKeys(output, ['slot', 'blinded_value'], field);
  const slot = parseGraphSlotSelector(output.slot, `${field}.slot`);
  const blinded = encodedBytes(output.blinded_value, `${field}.blinded_value`, undefined, 16 * 1024);
  return { slot, blinded_value: blinded };
}

function validateExchangeRequest(value: unknown, field: string): ExchangeRequestV2 {
  try {
    return parseExchangeRequestV2(value);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : 'invalid exchange request');
  }
}

function validateExchangeResult(value: unknown, field: string): ExchangeResultV2 {
  try {
    return parseExchangeResultV2(value);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : 'invalid exchange result');
  }
}

function validateReceipt(value: unknown, field: string): ExchangeReceiptV2 {
  try {
    return parseExchangeReceiptV2(value);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : 'invalid exchange receipt');
  }
}

function validateAcceptedResponse(value: unknown, field: string): ExchangeAcceptedResponseV2 {
  try {
    return parseExchangeAcceptedResponseV2(value);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : 'invalid exchange response');
  }
}

function validateGenesisRequest(value: unknown, field: string): GraphIssuanceRequestV1 {
  try {
    return parseGraphIssuanceRequestV1(value);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : 'invalid graph issuance request');
  }
}

function validateGenesisResult(value: unknown, field: string): GraphIssuanceResultV1 {
  try {
    return parseGraphIssuanceResultV1(value);
  } catch (error) {
    fail(field, error instanceof Error ? error.message : 'invalid graph issuance result');
  }
}

function validateArtifactRecord(value: unknown, field: string): ArtifactVaultRecord {
  const item = object(value, field);
  exactKeys(item, ['version', 'record_type', 'state', 'artifact', 'keyset_id', 'descriptor_id', 'reserved_by'], field);
  if (item.version !== 1 || item.record_type !== 'artifact') fail(field, 'wrong record type or version');
  if (item.state !== 'current' && item.state !== 'reserved' && item.state !== 'spent') fail(`${field}.state`, 'invalid artifact state');
  const artifact = validateArtifact(item.artifact, `${field}.artifact`);
  const keysetId = id(item.keyset_id, `${field}.keyset_id`);
  const descriptorId = id(item.descriptor_id, `${field}.descriptor_id`);
  const reservedBy = item.reserved_by === null ? null : recordId(item.reserved_by, `${field}.reserved_by`);
  if (item.state === 'reserved' && reservedBy === null) fail(`${field}.reserved_by`, 'required for reserved artifact');
  if (item.state !== 'reserved' && reservedBy !== null) fail(`${field}.reserved_by`, 'must be null unless reserved');
  return { version: 1, record_type: 'artifact', state: item.state, artifact, keyset_id: keysetId, descriptor_id: descriptorId, reserved_by: reservedBy };
}

function validateReceiveRecord(value: unknown, field: string): PreparedReceiveVaultRecord {
  const item = object(value, field);
  exactKeys(item, ['version', 'record_type', 'state', 'operation_id', 'status_capability', 'preparation_snapshot_ref', 'graph_id', 'transition_id', 'source_keyset_id', 'target_keyset_id', 'expected_output', 'output_nonce', 'message', 'blinding_state', 'finalized_artifact', 'result', 'receipt', 'artifact_record_id', 'rejection_code'], field);
  if (item.version !== 1 || item.record_type !== 'prepared_receive') fail(field, 'wrong record type or version');
  if (item.state !== 'prepared' && item.state !== 'submitted_unknown' && item.state !== 'current' && item.state !== 'rejected') fail(`${field}.state`, 'invalid receive state');
  const state = item.state as ReceiveState;
  const operation = operationId(item.operation_id, `${field}.operation_id`);
  const status = item.status_capability === null ? null : capability(item.status_capability, `${field}.status_capability`);
  const snapshot = snapshotRef(item.preparation_snapshot_ref, `${field}.preparation_snapshot_ref`);
  const graphId = id(item.graph_id, `${field}.graph_id`);
  const transitionId = id(item.transition_id, `${field}.transition_id`);
  const sourceKeysetId = id(item.source_keyset_id, `${field}.source_keyset_id`);
  const targetKeysetId = id(item.target_keyset_id, `${field}.target_keyset_id`);
  const expectedOutput = validateExpectedOutput(item.expected_output, `${field}.expected_output`);
  const nonce = item.output_nonce === null ? null : encodedBytes(item.output_nonce, `${field}.output_nonce`, 32, 32);
  const message = item.message === null ? null : encodedBytes(item.message, `${field}.message`, 48, 48);
  const blinding = item.blinding_state === null ? null : encodedBytes(item.blinding_state, `${field}.blinding_state`, undefined, 16 * 1024);
  const artifact = item.finalized_artifact === null ? null : validateArtifact(item.finalized_artifact, `${field}.finalized_artifact`);
  const result = item.result === null ? null : validateExchangeResult(item.result, `${field}.result`);
  const receipt = item.receipt === null ? null : validateReceipt(item.receipt, `${field}.receipt`);
  const artifactRecord = item.artifact_record_id === null ? null : recordId(item.artifact_record_id, `${field}.artifact_record_id`);
  const rejection = item.rejection_code === null ? null : text(item.rejection_code, `${field}.rejection_code`, 1, 128);
  if (state === 'current') {
    if (status !== null || nonce !== null || message !== null || blinding !== null || artifact === null || result === null || receipt === null || artifactRecord === null || rejection !== null) fail(field, 'current receive record is incomplete');
  } else {
    if (nonce === null || message === null || blinding === null || status === null || artifact !== null || result !== null || receipt !== null || artifactRecord !== null) fail(field, 'pending receive record is incomplete');
    if (state === 'rejected' && rejection === null) fail(`${field}.rejection_code`, 'required for rejected record');
    if (state !== 'rejected' && rejection !== null) fail(`${field}.rejection_code`, 'must be null before rejection');
  }
  return { version: 1, record_type: 'prepared_receive', state, operation_id: operation, status_capability: status, preparation_snapshot_ref: snapshot, graph_id: graphId, transition_id: transitionId, source_keyset_id: sourceKeysetId, target_keyset_id: targetKeysetId, expected_output: expectedOutput, output_nonce: nonce, message, blinding_state: blinding, finalized_artifact: artifact, result, receipt, artifact_record_id: artifactRecord, rejection_code: rejection };
}

function validateSendRecord(value: unknown, field: string): PreparedSendVaultRecord {
  const item = object(value, field);
  exactKeys(item, ['version', 'record_type', 'state', 'operation_id', 'status_capability', 'preparation_snapshot_ref', 'source_record_id', 'source_artifact', 'request', 'result', 'finalized_artifact', 'output_record_id', 'rejection_code'], field);
  if (item.version !== 1 || item.record_type !== 'prepared_send') fail(field, 'wrong record type or version');
  if (item.state !== 'offered' && item.state !== 'reserved_pending' && item.state !== 'spend_unknown' && item.state !== 'spent' && item.state !== 'rejected') fail(`${field}.state`, 'invalid send state');
  const state = item.state as SendState;
  const operation = operationId(item.operation_id, `${field}.operation_id`);
  const status = item.status_capability === null ? null : capability(item.status_capability, `${field}.status_capability`);
  const snapshot = snapshotRef(item.preparation_snapshot_ref, `${field}.preparation_snapshot_ref`);
  const sourceRecord = recordId(item.source_record_id, `${field}.source_record_id`);
  const sourceArtifact = validateArtifact(item.source_artifact, `${field}.source_artifact`);
  const request = validateExchangeRequest(item.request, `${field}.request`);
  const result = item.result === null ? null : validateAcceptedResponse(item.result, `${field}.result`);
  const finalized = item.finalized_artifact === null ? null : validateArtifact(item.finalized_artifact, `${field}.finalized_artifact`);
  const outputRecord = item.output_record_id === null ? null : recordId(item.output_record_id, `${field}.output_record_id`);
  const rejection = item.rejection_code === null ? null : text(item.rejection_code, `${field}.rejection_code`, 1, 128);
  equalBase64(sourceArtifact, request.sources[0].artifact, `${field}.source_artifact`);
  if (state === 'spent') {
    if (status !== null || result === null || finalized !== null && outputRecord === null || rejection !== null) fail(field, 'spent send record is incomplete');
  } else {
    if (result !== null || finalized !== null || outputRecord !== null) fail(field, 'pending send record is incomplete');
    if (state === 'rejected') {
      if (rejection === null) fail(`${field}.rejection_code`, 'required for rejected record');
    } else if (rejection !== null) {
      fail(`${field}.rejection_code`, 'must be null before rejection');
    }
    if ((state === 'offered' || state === 'reserved_pending' || state === 'spend_unknown') && status === null) fail(`${field}.status_capability`, 'required for recoverable send');
  }
  return { version: 1, record_type: 'prepared_send', state, operation_id: operation, status_capability: status, preparation_snapshot_ref: snapshot, source_record_id: sourceRecord, source_artifact: sourceArtifact, request, result, finalized_artifact: finalized, output_record_id: outputRecord, rejection_code: rejection };
}

function validateGenesisRecord(value: unknown, field: string): GenesisIssuanceVaultRecord {
  const item = object(value, field);
  exactKeys(item, ['version', 'record_type', 'state', 'operation_id', 'status_capability', 'preparation_snapshot_ref', 'request', 'output_nonce', 'message', 'blinding_state', 'result', 'finalized_artifact', 'artifact_record_id', 'rejection_code'], field);
  if (item.version !== 1 || item.record_type !== 'genesis_issuance') fail(field, 'wrong record type or version');
  if (item.state !== 'prepared' && item.state !== 'submitted_unknown' && item.state !== 'current' && item.state !== 'rejected') fail(`${field}.state`, 'invalid genesis state');
  const state = item.state as GenesisState;
  const operation = operationId(item.operation_id, `${field}.operation_id`);
  const status = item.status_capability === null ? null : capability(item.status_capability, `${field}.status_capability`);
  const snapshot = snapshotRef(item.preparation_snapshot_ref, `${field}.preparation_snapshot_ref`);
  const request = validateGenesisRequest(item.request, `${field}.request`);
  const nonce = item.output_nonce === null ? null : encodedBytes(item.output_nonce, `${field}.output_nonce`, 32, 32);
  const message = item.message === null ? null : encodedBytes(item.message, `${field}.message`, 48, 48);
  const blinding = item.blinding_state === null ? null : encodedBytes(item.blinding_state, `${field}.blinding_state`, undefined, 16 * 1024);
  const result = item.result === null ? null : validateGenesisResult(item.result, `${field}.result`);
  const artifact = item.finalized_artifact === null ? null : validateArtifact(item.finalized_artifact, `${field}.finalized_artifact`);
  const artifactRecord = item.artifact_record_id === null ? null : recordId(item.artifact_record_id, `${field}.artifact_record_id`);
  const rejection = item.rejection_code === null ? null : text(item.rejection_code, `${field}.rejection_code`, 1, 128);
  if (state === 'current') {
    if (status !== null || nonce !== null || message !== null || blinding !== null || result === null || artifact === null || artifactRecord === null || rejection !== null) fail(field, 'current genesis record is incomplete');
  } else {
    if (nonce === null || message === null || blinding === null || status === null || result !== null || artifact !== null || artifactRecord !== null) fail(field, 'pending genesis record is incomplete');
    if (state === 'rejected' && rejection === null) fail(`${field}.rejection_code`, 'required for rejected record');
    if (state !== 'rejected' && rejection !== null) fail(`${field}.rejection_code`, 'must be null before rejection');
  }
  return { version: 1, record_type: 'genesis_issuance', state, operation_id: operation, status_capability: status, preparation_snapshot_ref: snapshot, request, output_nonce: nonce, message, blinding_state: blinding, result, finalized_artifact: artifact, artifact_record_id: artifactRecord, rejection_code: rejection };
}

function validateRecord(value: unknown, field = 'record'): VaultRecord {
  const item = object(value, field);
  if (item.record_type === 'artifact') return validateArtifactRecord(item, field);
  if (item.record_type === 'prepared_receive') return validateReceiveRecord(item, field);
  if (item.record_type === 'prepared_send') return validateSendRecord(item, field);
  if (item.record_type === 'genesis_issuance') return validateGenesisRecord(item, field);
  fail(`${field}.record_type`, 'unknown record type');
}

function parseStrictJson(textValue: string, field: string): unknown {
  if (textValue.length > MAX_PLAINTEXT_BYTES * 2) fail(field, 'JSON is too large');
  let index = 0;
  const whitespace = (): void => { while (index < textValue.length && /\s/.test(textValue[index])) index += 1; };
  const stringToken = (): string => {
    const start = index;
    if (textValue[index] !== '"') fail(field, 'invalid JSON string');
    index += 1;
    while (index < textValue.length) {
      const character = textValue[index++];
      if (character === '\\') {
        if (index >= textValue.length) fail(field, 'invalid JSON escape');
        index += 1;
      } else if (character === '"') {
        try { return JSON.parse(textValue.slice(start, index)) as string; } catch { fail(field, 'invalid JSON string'); }
      } else if (character < ' ') {
        fail(field, 'invalid JSON string');
      }
    }
    fail(field, 'unterminated JSON string');
  };
  const scan = (): void => {
    whitespace();
    const character = textValue[index];
    if (character === '"') { stringToken(); return; }
    if (character === '{') {
      index += 1;
      whitespace();
      const keys = new Set<string>();
      if (textValue[index] === '}') { index += 1; return; }
      while (index < textValue.length) {
        whitespace();
        const key = stringToken();
        if (keys.has(key)) fail(`${field}.${key}`, 'duplicate field');
        keys.add(key);
        whitespace();
        if (textValue[index++] !== ':') fail(field, 'invalid JSON object');
        scan();
        whitespace();
        const separator = textValue[index++];
        if (separator === '}') return;
        if (separator !== ',') fail(field, 'invalid JSON object');
      }
      fail(field, 'unterminated JSON object');
    }
    if (character === '[') {
      index += 1;
      whitespace();
      if (textValue[index] === ']') { index += 1; return; }
      while (index < textValue.length) {
        scan();
        whitespace();
        const separator = textValue[index++];
        if (separator === ']') return;
        if (separator !== ',') fail(field, 'invalid JSON array');
      }
      fail(field, 'unterminated JSON array');
    }
    const start = index;
    while (index < textValue.length && !/[\s,\]}]/.test(textValue[index])) index += 1;
    if (start === index) fail(field, 'invalid JSON value');
  };
  scan();
  whitespace();
  if (index !== textValue.length) fail(field, 'trailing JSON data');
  try {
    return JSON.parse(textValue) as unknown;
  } catch {
    fail(field, 'invalid JSON');
  }
}

function assertCanonicalEnvelope(value: unknown, field = 'envelope'): VaultEnvelope {
  const item = object(value, field);
  exactKeys(item, ['version', 'wallet_id', 'record_id', 'nonce', 'ciphertext'], field);
  if (item.version !== VAULT_RECORD_VERSION) fail(`${field}.version`, 'unsupported vault format');
  const wallet = encodedBytes(item.wallet_id, `${field}.wallet_id`, WALLET_ID_BYTES, WALLET_ID_BYTES);
  const record = encodedBytes(item.record_id, `${field}.record_id`, RECORD_ID_BYTES, RECORD_ID_BYTES);
  const nonce = encodedBytes(item.nonce, `${field}.nonce`, GCM_NONCE_BYTES, GCM_NONCE_BYTES);
  const ciphertext = encodedBytes(item.ciphertext, `${field}.ciphertext`, undefined, MAX_CIPHERTEXT_BYTES);
  if (ciphertext.length < GCM_TAG_BYTES) fail(`${field}.ciphertext`, 'missing GCM tag');
  return { version: VAULT_RECORD_VERSION, wallet_id: wallet, record_id: record, nonce, ciphertext };
}

function parseEnvelope(textValue: string): VaultEnvelope {
  return assertCanonicalEnvelope(parseStrictJson(textValue, 'envelope'));
}

function u32be(value: number): Uint8Array {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function aad(version: string, walletId: Uint8Array, recordIdBytes: Uint8Array): Uint8Array {
  const versionBytes = new TextEncoder().encode(version);
  return Uint8Array.from([...u32be(versionBytes.length), ...versionBytes, ...walletId, ...recordIdBytes]);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function bytesFromRandom(source: RandomSource, length: number): Uint8Array {
  const bytes = source(length);
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new VaultValidationError(`random source: expected ${length} bytes`);
  }
  return bytes.slice();
}

export class LocalVault {
  private readonly backend: VaultStorageBackend;
  private readonly walletIdBytes: Uint8Array;
  private readonly randomSource: RandomSource;
  private unlockKey: Buffer | undefined;
  private records = new Map<string, VaultRecord>();
  private usedNonces = new Set<string>();

  private constructor(backend: VaultStorageBackend, walletId: Uint8Array, randomSource: RandomSource) {
    this.backend = backend;
    this.walletIdBytes = walletId.slice();
    this.randomSource = randomSource;
  }

  /** Create a new vault identity; no unlock key is persisted. */
  static async create(options: VaultCreateOptions = {}): Promise<LocalVault> {
    const backend = options.backend ?? new FilesystemVaultBackend(options.directory ?? fail('directory', 'required'), { failureHook: options.failureHook });
    const randomSource = options.randomBytes ?? ((length: number) => new Uint8Array(systemRandomBytes(length)));
    const vault = await withBackendSerialization(backend, async () => withBackendLock(backend, async () => {
      if (await backend.readWalletId() !== undefined) throw new VaultStateError('vault already exists');
      const walletId = bytesFromRandom(randomSource, WALLET_ID_BYTES);
      const walletIdText = encodeCanonicalBase64Url(walletId);
      await backend.writeWalletId(walletIdText);
      return new LocalVault(backend, walletId, randomSource);
    }));
    if (options.unlockKey !== undefined) await vault.unlock(options.unlockKey);
    return vault;
  }

  /** Open an existing vault identity; the caller must explicitly unlock it. */
  static async open(options: VaultOpenOptions): Promise<LocalVault> {
    const backend = options.backend ?? new FilesystemVaultBackend(options.directory ?? fail('directory', 'required'));
    const randomSource = options.randomBytes ?? ((length: number) => new Uint8Array(systemRandomBytes(length)));
    const rawMetadata = await withBackendLock(backend, () => backend.readWalletId());
    if (rawMetadata === undefined) throw new VaultStateError('vault does not exist');
    const metadata = parseStrictJson(rawMetadata, 'vault metadata');
    const item = object(metadata, 'vault metadata');
    exactKeys(item, ['version', 'wallet_id'], 'vault metadata');
    if (item.version !== VAULT_METADATA_VERSION) fail('vault metadata.version', 'unsupported vault format');
    const walletId = boundedBytes(item.wallet_id, 'vault metadata.wallet_id', WALLET_ID_BYTES, WALLET_ID_BYTES);
    const vault = new LocalVault(backend, walletId, randomSource);
    if (options.unlockKey !== undefined) await vault.unlock(options.unlockKey);
    return vault;
  }

  get wallet_id(): CanonicalBase64Url {
    return encodeCanonicalBase64Url(this.walletIdBytes);
  }

  get isUnlocked(): boolean {
    return this.unlockKey !== undefined;
  }

  /** Release exactly one caller-provided 32-byte AES key to this vault. */
  async unlock(key: Uint8Array): Promise<void> {
    if (!(key instanceof Uint8Array) || key.length !== AES_KEY_BYTES) throw new VaultValidationError('unlock key: expected exactly 32 bytes');
    const candidate = Buffer.from(key);
    try {
      await withBackendSerialization(this.backend, async () => withBackendLock(this.backend, async () => {
        if (this.unlockKey !== undefined) throw new VaultStateError('vault is already unlocked');
        this.unlockKey = candidate;
        try {
          await this.recoverLocked();
          await this.reloadLocked();
        } catch (error) {
          this.clearKeyAndRecords();
          throw error;
        }
      }));
    } catch (error) {
      candidate.fill(0);
      throw error;
    }
  }

  /** Clear unlocked state from this process. */
  async lock(): Promise<void> {
    await withBackendSerialization(this.backend, async () => withBackendLock(this.backend, async () => { this.clearKeyAndRecords(); }));
  }

  async close(): Promise<void> {
    await this.lock();
  }

  private clearKeyAndRecords(): void {
    this.unlockKey?.fill(0);
    this.unlockKey = undefined;
    this.records.clear();
  }

  private requireKey(): Buffer {
    if (this.unlockKey === undefined) throw new VaultStateError('vault is locked');
    return this.unlockKey;
  }

  private async access<T>(operation: () => Promise<T>): Promise<T> {
    return withBackendSerialization(this.backend, async () => {
      this.requireKey();
      return withBackendLock(this.backend, async () => {
        await this.recoverLocked();
        await this.reloadLocked();
        return operation();
      });
    });
  }

  private async reloadLocked(): Promise<void> {
    const entries = await this.backend.listRecordEnvelopes();
    const next = new Map<string, VaultRecord>();
    const nonces = new Set(this.usedNonces);
    for (const [fileRecordId, rawEnvelope] of entries) {
      const expectedId = recordId(fileRecordId, `record filename ${fileRecordId}`);
      const envelope = parseEnvelope(rawEnvelope);
      if (envelope.record_id !== expectedId) throw new VaultAuthenticationError();
      const plaintext = this.decryptEnvelope(envelope, expectedId);
      const parsed = parseStrictJson(plaintext, 'record plaintext');
      const record = validateRecord(parsed);
      if (next.has(expectedId)) throw new VaultValidationError('duplicate record identifier');
      next.set(expectedId, record);
      nonces.add(envelope.nonce);
    }
    this.records = next;
    this.usedNonces = nonces;
  }

  private async recoverLocked(): Promise<void> {
    const rawJournal = await this.backend.readTransactionEnvelope();
    if (rawJournal === undefined) return;
    const journalEnvelope = parseEnvelope(rawJournal);
    const transactionId = recordId(journalEnvelope.record_id, 'transaction.record_id');
    const plaintext = this.decryptEnvelope(journalEnvelope, transactionId);
    const parsed = parseStrictJson(plaintext, 'transaction plaintext');
    const journal = this.parseTransaction(parsed);
    const existing = await this.backend.listRecordEnvelopes();
    for (const entry of journal.entries) {
      const current = existing.get(entry.record_id);
      if (entry.envelope === null) {
        if (current !== undefined) await this.backend.deleteRecordEnvelope(entry.record_id);
      } else {
        const envelope = parseEnvelope(entry.envelope);
        if (envelope.record_id !== entry.record_id) throw new VaultAuthenticationError();
        const decrypted = this.decryptEnvelope(envelope, entry.record_id);
        validateRecord(parseStrictJson(decrypted, 'transaction record plaintext'));
        if (current !== entry.envelope) await this.backend.writeRecordEnvelope(entry.record_id, entry.envelope);
      }
    }
    await this.backend.clearTransactionEnvelope();
  }

  private parseTransaction(value: unknown): TransactionPlaintext {
    const item = object(value, 'transaction');
    exactKeys(item, ['version', 'transaction_id', 'entries'], 'transaction');
    if (item.version !== VAULT_TRANSACTION_VERSION) fail('transaction.version', 'unsupported transaction format');
    const transactionId = recordId(item.transaction_id, 'transaction.transaction_id');
    if (!Array.isArray(item.entries) || item.entries.length === 0 || item.entries.length > 4096) fail('transaction.entries', 'invalid entry count');
    const seen = new Set<string>();
    const entries = item.entries.map((valueEntry, index) => {
      const entry = object(valueEntry, `transaction.entries[${index}]`);
      exactKeys(entry, ['record_id', 'envelope'], `transaction.entries[${index}]`);
      const idValue = recordId(entry.record_id, `transaction.entries[${index}].record_id`);
      if (seen.has(idValue)) fail(`transaction.entries[${index}].record_id`, 'duplicate record identifier');
      seen.add(idValue);
      if (entry.envelope !== null) text(entry.envelope, `transaction.entries[${index}].envelope`, 1, MAX_CIPHERTEXT_BYTES * 2);
      return { record_id: idValue, envelope: entry.envelope as string | null };
    });
    return { version: VAULT_TRANSACTION_VERSION, transaction_id: transactionId, entries };
  }

  private newId(working: ReadonlyMap<string, VaultRecord>): CanonicalBase64Url {
    for (let attempt = 0; attempt < 128; attempt += 1) {
      const value = encodeCanonicalBase64Url(bytesFromRandom(this.randomSource, RECORD_ID_BYTES));
      if (!working.has(value)) return value;
    }
    throw new VaultStateError('unable to generate a unique record identifier');
  }

  private newOperationId(working: ReadonlyMap<string, VaultRecord>): CanonicalBase64Url {
    for (let attempt = 0; attempt < 128; attempt += 1) {
      const value = encodeCanonicalBase64Url(bytesFromRandom(this.randomSource, OPERATION_ID_BYTES));
      if ([...working.values()].every((record) => !('operation_id' in record) || record.operation_id !== value)) return value;
    }
    throw new VaultStateError('unable to generate a unique operation identifier');
  }

  private ensureOperationUnique(working: ReadonlyMap<string, VaultRecord>, value: CanonicalBase64Url): void {
    for (const record of working.values()) {
      if ('operation_id' in record && record.operation_id === value) throw new VaultStateError('operation identifier is already in use');
    }
  }

  private ensureCapabilityUnique(working: ReadonlyMap<string, VaultRecord>, value: CanonicalBase64Url): void {
    for (const record of working.values()) {
      if ('status_capability' in record && record.status_capability === value) throw new VaultStateError('status capability is already in use');
    }
  }

  private ensureOutputNonceUnique(working: ReadonlyMap<string, VaultRecord>, value: CanonicalBase64Url): void {
    for (const record of working.values()) {
      if ((record.record_type === 'prepared_receive' || record.record_type === 'genesis_issuance') && record.output_nonce !== null && record.output_nonce === value) {
        throw new VaultStateError('output nonce is already in use');
      }
      if (record.record_type === 'artifact' && decodeV5BearerArtifactBase64(record.artifact).nonce === value) {
        throw new VaultStateError('output nonce is already in use');
      }
    }
  }

  private newCapability(working: ReadonlyMap<string, VaultRecord>): CanonicalBase64Url {
    for (let attempt = 0; attempt < 128; attempt += 1) {
      const value = encodeCanonicalBase64Url(bytesFromRandom(this.randomSource, STATUS_CAPABILITY_BYTES));
      if ([...working.values()].every((record) => !('status_capability' in record) || record.status_capability !== value)) return value;
    }
    throw new VaultStateError('unable to generate a unique status capability');
  }

  private newNonce(): CanonicalBase64Url {
    for (let attempt = 0; attempt < 128; attempt += 1) {
      const nonce = encodeCanonicalBase64Url(bytesFromRandom(this.randomSource, GCM_NONCE_BYTES));
      if (!this.usedNonces.has(nonce)) {
        this.usedNonces.add(nonce);
        return nonce;
      }
    }
    throw new VaultStateError('unable to generate a fresh AES-GCM nonce');
  }

  private encryptPlaintext(plaintext: string, recordIdText: CanonicalBase64Url, transaction = false): string {
    const key = this.requireKey();
    const plaintextBytes = new TextEncoder().encode(plaintext);
    if (plaintextBytes.length === 0 || plaintextBytes.length > MAX_PLAINTEXT_BYTES) fail('plaintext', 'invalid size');
    const nonceText = this.newNonce();
    const nonce = decodeCanonicalBase64Url(nonceText, GCM_NONCE_BYTES, 'nonce');
    const recordBytes = decodeCanonicalBase64Url(recordIdText, RECORD_ID_BYTES, 'record_id');
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(aad(VAULT_RECORD_VERSION, this.walletIdBytes, recordBytes));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintextBytes)), cipher.final(), cipher.getAuthTag()]);
    if (ciphertext.length > MAX_CIPHERTEXT_BYTES) fail('ciphertext', 'too large');
    const envelope: VaultEnvelope = { version: VAULT_RECORD_VERSION, wallet_id: this.wallet_id, record_id: recordIdText, nonce: nonceText, ciphertext: encodeCanonicalBase64Url(ciphertext) };
    // `transaction` is intentionally unused in the wire shape. It documents
    // that the journal uses the same authenticated record envelope format.
    void transaction;
    return JSON.stringify(envelope);
  }

  private decryptEnvelope(envelope: VaultEnvelope, expectedRecordId: string): string {
    if (envelope.wallet_id !== this.wallet_id || envelope.record_id !== expectedRecordId) throw new VaultAuthenticationError();
    const key = this.requireKey();
    const nonce = decodeCanonicalBase64Url(envelope.nonce, GCM_NONCE_BYTES, 'envelope.nonce');
    const ciphertext = boundedBytes(envelope.ciphertext, 'envelope.ciphertext', undefined, MAX_CIPHERTEXT_BYTES);
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAAD(aad(envelope.version, this.walletIdBytes, decodeCanonicalBase64Url(expectedRecordId, RECORD_ID_BYTES, 'record_id')));
      decipher.setAuthTag(Buffer.from(ciphertext.slice(-GCM_TAG_BYTES)));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext.slice(0, -GCM_TAG_BYTES))), decipher.final()]);
      if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new VaultValidationError('plaintext: too large');
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
      } catch {
        throw new VaultValidationError('plaintext: invalid UTF-8');
      }
    } catch (error) {
      if (error instanceof VaultValidationError) throw error;
      throw new VaultAuthenticationError();
    }
  }

  private async commitWorking(working: Map<string, VaultRecord>): Promise<void> {
    const entries: TransactionEntry[] = [];
    const allIds = new Set([...this.records.keys(), ...working.keys()]);
    for (const idValue of allIds) {
      const previous = this.records.get(idValue);
      const next = working.get(idValue);
      if (next === undefined) {
        if (previous !== undefined) entries.push({ record_id: idValue, envelope: null });
      } else if (previous === undefined || JSON.stringify(previous) !== JSON.stringify(next)) {
        entries.push({ record_id: idValue, envelope: this.encryptPlaintext(JSON.stringify(next), idValue) });
      }
    }
    if (entries.length === 0) return;
    const transactionId = this.newId(working);
    const journal: TransactionPlaintext = { version: VAULT_TRANSACTION_VERSION, transaction_id: transactionId, entries };
    const journalEnvelope = this.encryptPlaintext(JSON.stringify(journal), transactionId, true);
    await this.backend.writeTransactionEnvelope(journalEnvelope);
    try {
      for (const entry of entries) {
        if (entry.envelope === null) await this.backend.deleteRecordEnvelope(entry.record_id);
        else await this.backend.writeRecordEnvelope(entry.record_id, entry.envelope);
      }
      await this.backend.clearTransactionEnvelope();
    } catch (error) {
      // The durable encrypted journal is intentionally retained. The next
      // access recovers the complete post-transaction set before exposing it.
      throw error;
    }
    this.records = new Map([...working.entries()].map(([key, value]) => [key, clone(value)]));
  }

  private async mutate<T>(operation: (working: Map<string, VaultRecord>) => Promise<{ value: T; changed?: boolean }> | { value: T; changed?: boolean }): Promise<T> {
    return this.access(async () => {
      const working = new Map([...this.records.entries()].map(([key, value]) => [key, clone(value)]));
      const result = await operation(working);
      if (result.changed !== false) await this.commitWorking(working);
      return result.value;
    });
  }

  async listRecords(): Promise<ReadonlyMap<CanonicalBase64Url, VaultRecord>> {
    return this.access(async () => new Map([...this.records.entries()].map(([key, value]) => [key, clone(value)])));
  }

  async getRecord(recordIdValue: string): Promise<VaultRecord | undefined> {
    const checkedId = recordId(recordIdValue, 'record_id');
    return this.access(async () => {
      const value = this.records.get(checkedId);
      return value === undefined ? undefined : clone(value);
    });
  }

  /** Store a verified canonical Freebird V5 artifact as a current artifact. */
  async storeArtifact(input: { readonly artifact: string; readonly keyset_id: string; readonly descriptor_id: string }): Promise<CanonicalBase64Url> {
    const artifact = validateArtifact(input.artifact, 'artifact');
    const keysetId = id(input.keyset_id, 'keyset_id');
    const descriptorId = id(input.descriptor_id, 'descriptor_id');
    return this.mutate((working) => {
      const recordIdValue = this.newId(working);
      working.set(recordIdValue, { version: 1, record_type: 'artifact', state: 'current', artifact, keyset_id: keysetId, descriptor_id: descriptorId, reserved_by: null });
      return { value: recordIdValue };
    });
  }

  async createArtifact(input: { readonly artifact: string; readonly keyset_id: string; readonly descriptor_id: string }): Promise<CanonicalBase64Url> {
    return this.storeArtifact(input);
  }

  async createPreparedReceive(input: ReceivePreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: ReceiveHandoff }> {
    const snapshot = snapshotRef(input.preparation_snapshot_ref, 'preparation_snapshot_ref');
    const graphId = id(input.graph_id, 'graph_id');
    const transitionId = id(input.transition_id, 'transition_id');
    const sourceKeysetId = id(input.source_keyset_id, 'source_keyset_id');
    const targetKeysetId = id(input.target_keyset_id, 'target_keyset_id');
    const expectedOutput = validateExpectedOutput(input.expected_output, 'expected_output');
    equalText(expectedOutput.slot.keyset_id, targetKeysetId, 'expected_output.slot.keyset_id');
    const nonce = encodeCanonicalBase64Url(suppliedBytes(input.output_nonce, 'output_nonce', 32, 32));
    const message = encodeCanonicalBase64Url(suppliedBytes(input.message, 'message', 48, 48));
    const blindingState = encodeCanonicalBase64Url(suppliedBytes(input.blinding_state, 'blinding_state', undefined, 16 * 1024));
    return this.mutate((working) => {
      const op = input.operation_id === undefined ? this.newOperationId(working) : operationId(input.operation_id, 'operation_id');
      const status = input.status_capability === undefined ? this.newCapability(working) : capability(input.status_capability, 'status_capability');
      this.ensureOperationUnique(working, op);
      this.ensureCapabilityUnique(working, status);
      this.ensureOutputNonceUnique(working, nonce);
      const recordIdValue = this.newId(working);
      working.set(recordIdValue, { version: 1, record_type: 'prepared_receive', state: 'prepared', operation_id: op, status_capability: status, preparation_snapshot_ref: snapshot, graph_id: graphId, transition_id: transitionId, source_keyset_id: sourceKeysetId, target_keyset_id: targetKeysetId, expected_output: expectedOutput, output_nonce: nonce, message, blinding_state: blindingState, finalized_artifact: null, result: null, receipt: null, artifact_record_id: null, rejection_code: null });
      return { value: { record_id: recordIdValue, handoff: { operation_id: op, status_capability: status, graph_id: graphId, transition_id: transitionId, source_keyset_id: sourceKeysetId, target_keyset_id: targetKeysetId, output: clone(expectedOutput) } } };
    });
  }

  async createPreparedSend(input: SendPreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: SendHandoff }> {
    const snapshot = snapshotRef(input.preparation_snapshot_ref, 'preparation_snapshot_ref');
    const request = validateExchangeRequest(input.request, 'request');
    const sourceRecordId = recordId(input.source_record_id, 'source_record_id');
    return this.mutate((working) => {
      const source = working.get(sourceRecordId);
      if (source === undefined || source.record_type !== 'artifact') throw new VaultStateError('source artifact does not exist');
      if (source.state !== 'current') throw new VaultStateError('source artifact is not current');
      equalBase64(source.artifact, request.sources[0].artifact, 'request.sources[0].artifact');
      equalText(source.keyset_id, request.sources[0].slot.keyset_id, 'request.sources[0].slot.keyset_id');
      equalText(source.descriptor_id, request.sources[0].slot.descriptor_id, 'request.sources[0].slot.descriptor_id');
      const op = input.operation_id === undefined ? request.public_operation_id : operationId(input.operation_id, 'operation_id');
      equalBase64(op, request.public_operation_id, 'request.public_operation_id');
      const status = input.status_capability === undefined ? this.newCapability(working) : capability(input.status_capability, 'status_capability');
      this.ensureOperationUnique(working, op);
      this.ensureCapabilityUnique(working, status);
      const recordIdValue = this.newId(working);
      working.set(recordIdValue, { version: 1, record_type: 'prepared_send', state: 'offered', operation_id: op, status_capability: status, preparation_snapshot_ref: snapshot, source_record_id: sourceRecordId, source_artifact: source.artifact, request, result: null, finalized_artifact: null, output_record_id: null, rejection_code: null });
      return { value: { record_id: recordIdValue, handoff: { operation_id: op, status_capability: status, request: clone(request) } } };
    });
  }

  /**
   * Atomically persist a prepared send and reserve its source artifact.
   *
   * This is the only conforming fresh-send transition: both records are
   * written by one vault mutation/journal so a crash cannot expose an
   * offered send while its source is still current.
   */
  async createPreparedAndReserveSend(input: SendPreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: SendHandoff }> {
    const snapshot = snapshotRef(input.preparation_snapshot_ref, 'preparation_snapshot_ref');
    const request = validateExchangeRequest(input.request, 'request');
    const sourceRecordId = recordId(input.source_record_id, 'source_record_id');
    return this.mutate((working) => {
      const source = working.get(sourceRecordId);
      if (source === undefined || source.record_type !== 'artifact' || source.state !== 'current') throw new VaultStateError('source artifact is not current');
      equalBase64(source.artifact, request.sources[0].artifact, 'request.sources[0].artifact');
      equalText(source.keyset_id, request.sources[0].slot.keyset_id, 'request.sources[0].slot.keyset_id');
      equalText(source.descriptor_id, request.sources[0].slot.descriptor_id, 'request.sources[0].slot.descriptor_id');
      const operation = input.operation_id === undefined ? request.public_operation_id : operationId(input.operation_id, 'operation_id');
      equalBase64(operation, request.public_operation_id, 'request.public_operation_id');
      const capabilityValue = input.status_capability === undefined ? this.newCapability(working) : capability(input.status_capability, 'status_capability');
      this.ensureOperationUnique(working, operation);
      this.ensureCapabilityUnique(working, capabilityValue);
      const recordIdValue = this.newId(working);
      working.set(sourceRecordId, { ...source, state: 'reserved', reserved_by: operation });
      working.set(recordIdValue, { version: 1, record_type: 'prepared_send', state: 'reserved_pending', operation_id: operation, status_capability: capabilityValue, preparation_snapshot_ref: snapshot, source_record_id: sourceRecordId, source_artifact: source.artifact, request, result: null, finalized_artifact: null, output_record_id: null, rejection_code: null });
      return { value: { record_id: recordIdValue, handoff: { operation_id: operation, status_capability: capabilityValue, request: clone(request) } } };
    });
  }

  async createGenesisIssuance(input: GenesisPreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: GenesisHandoff }> {
    const snapshot = snapshotRef(input.preparation_snapshot_ref, 'preparation_snapshot_ref');
    const request = validateGenesisRequest(input.request, 'request');
    const nonce = encodeCanonicalBase64Url(suppliedBytes(input.output_nonce, 'output_nonce', 32, 32));
    const message = encodeCanonicalBase64Url(suppliedBytes(input.message, 'message', 48, 48));
    const blindingState = encodeCanonicalBase64Url(suppliedBytes(input.blinding_state, 'blinding_state', undefined, 16 * 1024));
    return this.mutate((working) => {
      const op = input.operation_id === undefined ? request.public_operation_id : operationId(input.operation_id, 'operation_id');
      equalBase64(op, request.public_operation_id, 'request.public_operation_id');
      const status = input.status_capability === undefined ? this.newCapability(working) : capability(input.status_capability, 'status_capability');
      this.ensureOperationUnique(working, op);
      this.ensureCapabilityUnique(working, status);
      this.ensureOutputNonceUnique(working, nonce);
      const recordIdValue = this.newId(working);
      working.set(recordIdValue, { version: 1, record_type: 'genesis_issuance', state: 'prepared', operation_id: op, status_capability: status, preparation_snapshot_ref: snapshot, request, output_nonce: nonce, message, blinding_state: blindingState, result: null, finalized_artifact: null, artifact_record_id: null, rejection_code: null });
      return { value: { record_id: recordIdValue, handoff: { operation_id: op, status_capability: status, request: clone(request) } } };
    });
  }

  async markReceiveSubmitted(recordIdValue: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'prepared_receive' || value.state !== 'prepared') throw new VaultStateError('receive operation is not prepared');
      working.set(checked, { ...value, state: 'submitted_unknown' });
      return { value: undefined };
    });
  }

  async markGenesisSubmitted(recordIdValue: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'genesis_issuance' || value.state !== 'prepared') throw new VaultStateError('genesis operation is not prepared');
      working.set(checked, { ...value, state: 'submitted_unknown' });
      return { value: undefined };
    });
  }

  /** Atomically claim the source artifact and advance its send operation. */
  async reserveSource(sourceRecordIdValue: string, sendRecordIdValue: string): Promise<void> {
    const sourceId = recordId(sourceRecordIdValue, 'source_record_id');
    const sendId = recordId(sendRecordIdValue, 'send_record_id');
    await this.mutate((working) => {
      const source = working.get(sourceId);
      const send = working.get(sendId);
      if (source === undefined || source.record_type !== 'artifact' || source.state !== 'current') throw new VaultStateError('source artifact is not current');
      if (send === undefined || send.record_type !== 'prepared_send' || send.state !== 'offered') throw new VaultStateError('send operation is not offered');
      if (send.source_record_id !== sourceId) throw new VaultStateError('send source binding mismatch');
      working.set(sourceId, { ...source, state: 'reserved', reserved_by: send.operation_id });
      working.set(sendId, { ...send, state: 'reserved_pending' });
      return { value: undefined };
    });
  }

  async markSendSubmittedUnknown(sendRecordIdValue: string): Promise<void> {
    const sendId = recordId(sendRecordIdValue, 'send_record_id');
    await this.mutate((working) => {
      const send = working.get(sendId);
      if (send === undefined || send.record_type !== 'prepared_send' || send.state !== 'reserved_pending') throw new VaultStateError('send operation is not reserved');
      working.set(sendId, { ...send, state: 'spend_unknown' });
      return { value: undefined };
    });
  }

  /** Definitive source spend; only an already reserved source may be spent. */
  async spendReservedSource(sourceRecordIdValue: string, operationIdValue: string): Promise<void> {
    const sourceId = recordId(sourceRecordIdValue, 'source_record_id');
    const operation = operationId(operationIdValue, 'operation_id');
    await this.mutate((working) => {
      const source = working.get(sourceId);
      if (source === undefined || source.record_type !== 'artifact' || source.state !== 'reserved' || source.reserved_by === null || source.reserved_by !== operation) throw new VaultStateError('source artifact is not reserved by this operation');
      working.set(sourceId, { ...source, state: 'spent', reserved_by: null });
      return { value: undefined };
    });
  }

  async finalizeReceive(receiveRecordIdValue: string, input: FinalizeReceiveInput): Promise<CanonicalBase64Url> {
    const receiveId = recordId(receiveRecordIdValue, 'receive_record_id');
    const artifact = validateArtifact(input.artifact, 'artifact');
    const result = validateExchangeResult(input.result, 'result');
    const receipt = validateReceipt(input.receipt, 'receipt');
    return this.mutate((working) => {
      const receive = working.get(receiveId);
      if (receive === undefined || receive.record_type !== 'prepared_receive') throw new VaultStateError('receive operation is not recoverable');
      if (receive.state === 'current') {
        if (receive.artifact_record_id !== null && receive.finalized_artifact === artifact && receive.result?.result_digest === result.result_digest && receive.receipt?.signature === receipt.signature) return { value: receive.artifact_record_id, changed: false };
        throw new VaultStateError('receive operation is already finalized');
      }
      if (receive.state !== 'prepared' && receive.state !== 'submitted_unknown') throw new VaultStateError('receive operation is not recoverable');
      equalBase64(receive.operation_id, result.public_operation_id, 'result.public_operation_id');
      equalText(receive.graph_id, result.graph_id, 'result.graph_id');
      equalText(receive.transition_id, result.transition_id, 'result.transition_id');
      equalText(receive.source_keyset_id, result.source_keyset_id, 'result.source_keyset_id');
      equalText(receive.target_keyset_id, result.target_keyset_id, 'result.target_keyset_id');
      const output = result.outputs[0];
      equalText(receive.expected_output.slot.descriptor_id, output.slot.descriptor_id, 'result.outputs[0].slot.descriptor_id');
      equalText(receive.expected_output.slot.keyset_id, output.slot.keyset_id, 'result.outputs[0].slot.keyset_id');
      equalText(receive.expected_output.slot.slot_id, output.slot.slot_id, 'result.outputs[0].slot.slot_id');
      equalBase64(receive.expected_output.blinded_value, output.blinded_value, 'result.outputs[0].blinded_value');
      equalBase64(receive.operation_id, receipt.public_operation_id, 'receipt.public_operation_id');
      equalText(receive.graph_id, receipt.graph_id, 'receipt.graph_id');
      equalText(receive.transition_id, receipt.transition_id, 'receipt.transition_id');
      equalText(receive.source_keyset_id, receipt.source_keyset_id, 'receipt.source_keyset_id');
      equalText(receive.target_keyset_id, receipt.target_keyset_id, 'receipt.target_keyset_id');
      const parsedArtifact = decodeV5BearerArtifactBase64(artifact);
      if (receive.output_nonce === null) throw new VaultStateError('receive output nonce is missing');
      equalBase64(receive.output_nonce, parsedArtifact.nonce, 'artifact.nonce');
      const artifactId = this.newId(working);
      const artifactRecord: ArtifactVaultRecord = { version: 1, record_type: 'artifact', state: 'current', artifact, keyset_id: receive.target_keyset_id, descriptor_id: receive.expected_output.slot.descriptor_id, reserved_by: null };
      working.set(artifactId, artifactRecord);
      working.set(receiveId, { ...receive, state: 'current', status_capability: null, output_nonce: null, message: null, blinding_state: null, finalized_artifact: artifact, result, receipt, artifact_record_id: artifactId, rejection_code: null });
      return { value: artifactId };
    });
  }

  async finalizeGenesis(genesisRecordIdValue: string, input: FinalizeGenesisInput): Promise<CanonicalBase64Url> {
    const genesisId = recordId(genesisRecordIdValue, 'genesis_record_id');
    const artifact = validateArtifact(input.artifact, 'artifact');
    const result = validateGenesisResult(input.result, 'result');
    return this.mutate((working) => {
      const genesis = working.get(genesisId);
      if (genesis === undefined || genesis.record_type !== 'genesis_issuance') throw new VaultStateError('genesis operation is not recoverable');
      if (genesis.state === 'current') {
        if (genesis.artifact_record_id !== null && genesis.finalized_artifact === artifact && genesis.result?.result_digest === result.result_digest) return { value: genesis.artifact_record_id, changed: false };
        throw new VaultStateError('genesis operation is already finalized');
      }
      if (genesis.state !== 'prepared' && genesis.state !== 'submitted_unknown') throw new VaultStateError('genesis operation is not recoverable');
      equalBase64(genesis.operation_id, result.public_operation_id, 'result.public_operation_id');
      equalText(genesis.request.issuance_policy_id, result.issuance_policy_id, 'result.issuance_policy_id');
      equalText(genesis.request.graph_id, result.graph_id, 'result.graph_id');
      equalText(genesis.request.keyset_id, result.keyset_id, 'result.keyset_id');
      equalText(genesis.request.descriptor_id, result.descriptor_id, 'result.descriptor_id');
      if (result.quantity !== 1) throw new VaultStateError('genesis result quantity is not one');
      const parsedArtifact = decodeV5BearerArtifactBase64(artifact);
      if (genesis.output_nonce === null) throw new VaultStateError('genesis output nonce is missing');
      equalBase64(genesis.output_nonce, parsedArtifact.nonce, 'artifact.nonce');
      equalText(result.token_key_id, parsedArtifact.token_key_id, 'artifact.token_key_id');
      const artifactId = this.newId(working);
      const artifactRecord: ArtifactVaultRecord = { version: 1, record_type: 'artifact', state: 'current', artifact, keyset_id: genesis.request.keyset_id, descriptor_id: genesis.request.descriptor_id, reserved_by: null };
      working.set(artifactId, artifactRecord);
      working.set(genesisId, { ...genesis, state: 'current', status_capability: null, output_nonce: null, message: null, blinding_state: null, result, finalized_artifact: artifact, artifact_record_id: artifactId, rejection_code: null });
      return { value: artifactId };
    });
  }

  /** Atomically spend a reserved source and advance its accepted send result. */
  async finalizeSend(sendRecordIdValue: string, input: FinalizeSendInput): Promise<CanonicalBase64Url | undefined> {
    const sendId = recordId(sendRecordIdValue, 'send_record_id');
    const result = validateExchangeResult(input.result, 'result');
    const receipt = validateReceipt(input.receipt, 'receipt');
    const finalized = input.finalized_artifact === undefined ? undefined : validateArtifact(input.finalized_artifact, 'finalized_artifact');
    return this.mutate((working) => {
      const send = working.get(sendId);
      if (send === undefined || send.record_type !== 'prepared_send') throw new VaultStateError('send operation is not recoverable');
      if (send.state === 'spent') {
        if (send.result?.result.result_digest === result.result_digest && send.result.receipt.signature === receipt.signature && send.finalized_artifact === (finalized ?? null)) return { value: send.output_record_id ?? undefined, changed: false };
        throw new VaultStateError('send operation is already finalized');
      }
      if (send.state !== 'reserved_pending' && send.state !== 'spend_unknown') throw new VaultStateError('send operation is not recoverable');
      const source = working.get(send.source_record_id);
      if (source === undefined || source.record_type !== 'artifact' || source.state !== 'reserved' || source.reserved_by !== send.operation_id) throw new VaultStateError('send source is not reserved');
      equalBase64(send.operation_id, result.public_operation_id, 'result.public_operation_id');
      equalBase64(send.operation_id, receipt.public_operation_id, 'receipt.public_operation_id');
      equalText(send.request.graph_id, result.graph_id, 'result.graph_id');
      equalText(send.request.transition_id, result.transition_id, 'result.transition_id');
      equalText(send.request.graph_id, receipt.graph_id, 'receipt.graph_id');
      equalText(send.request.transition_id, receipt.transition_id, 'receipt.transition_id');
      equalText(send.request.source_keyset_id, receipt.source_keyset_id, 'receipt.source_keyset_id');
      equalText(send.request.target_keyset_id, receipt.target_keyset_id, 'receipt.target_keyset_id');
      equalText(send.request.source_keyset_id, result.source_keyset_id, 'result.source_keyset_id');
      equalText(send.request.target_keyset_id, result.target_keyset_id, 'result.target_keyset_id');
      equalText(send.request.outputs[0].slot.descriptor_id, result.outputs[0].slot.descriptor_id, 'result.outputs[0].slot.descriptor_id');
      equalText(send.request.outputs[0].slot.keyset_id, result.outputs[0].slot.keyset_id, 'result.outputs[0].slot.keyset_id');
      equalText(send.request.outputs[0].slot.slot_id, result.outputs[0].slot.slot_id, 'result.outputs[0].slot.slot_id');
      equalBase64(send.request.outputs[0].blinded_value, result.outputs[0].blinded_value, 'result.outputs[0].blinded_value');
      let outputRecordId: CanonicalBase64Url | null = null;
      if (finalized !== undefined) {
        const outputArtifact = decodeV5BearerArtifactBase64(finalized);
        outputRecordId = this.newId(working);
        working.set(outputRecordId, { version: 1, record_type: 'artifact', state: 'current', artifact: finalized, keyset_id: send.request.target_keyset_id, descriptor_id: send.request.outputs[0].slot.descriptor_id, reserved_by: null });
        void outputArtifact;
      }
      working.set(send.source_record_id, { ...source, state: 'spent', reserved_by: null });
      working.set(sendId, { ...send, state: 'spent', status_capability: null, result: { result, receipt }, finalized_artifact: finalized ?? null, output_record_id: outputRecordId, rejection_code: null });
      return { value: outputRecordId ?? undefined };
    });
  }

  /** Compatibility spelling for callers that use the protocol's commit term. */
  async commitReceive(recordIdValue: string, input: FinalizeReceiveInput): Promise<CanonicalBase64Url> {
    return this.finalizeReceive(recordIdValue, input);
  }

  /** Compatibility spelling for callers that use the protocol's commit term. */
  async commitGenesis(recordIdValue: string, input: FinalizeGenesisInput): Promise<CanonicalBase64Url> {
    return this.finalizeGenesis(recordIdValue, input);
  }

  /** Compatibility spelling for callers that use the protocol's commit term. */
  async commitSend(recordIdValue: string, input: FinalizeSendInput): Promise<CanonicalBase64Url | undefined> {
    return this.finalizeSend(recordIdValue, input);
  }

  async prepareReceive(input: ReceivePreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: ReceiveHandoff }> {
    return this.createPreparedReceive(input);
  }

  async prepareSend(input: SendPreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: SendHandoff }> {
    return this.createPreparedSend(input);
  }

  async prepareGenesis(input: GenesisPreparationInput): Promise<{ readonly record_id: CanonicalBase64Url; readonly handoff: GenesisHandoff }> {
    return this.createGenesisIssuance(input);
  }

  async reserveSourceArtifact(sourceRecordIdValue: string, sendRecordIdValue: string): Promise<void> {
    return this.reserveSource(sourceRecordIdValue, sendRecordIdValue);
  }

  async rejectReceive(recordIdValue: string, code: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    const reason = text(code, 'rejection_code', 1, 128);
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'prepared_receive' || value.state !== 'prepared') throw new VaultStateError('only an unsubmitted receive may be rejected');
      working.set(checked, { ...value, state: 'rejected', rejection_code: reason });
      return { value: undefined };
    });
  }

  async rejectGenesis(recordIdValue: string, code: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    const reason = text(code, 'rejection_code', 1, 128);
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'genesis_issuance' || value.state !== 'prepared') throw new VaultStateError('only an unsubmitted genesis operation may be rejected');
      working.set(checked, { ...value, state: 'rejected', rejection_code: reason });
      return { value: undefined };
    });
  }

  /** Persist a terminal local genesis rejection without enabling recovery. */
  async terminalRejectGenesis(recordIdValue: string, code: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    const reason = text(code, 'rejection_code', 1, 128);
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'genesis_issuance') throw new VaultStateError('genesis operation is not rejectable');
      if (value.state === 'current') throw new VaultStateError('current genesis cannot be rejected');
      if (value.state === 'rejected' && value.rejection_code === reason) return { value: undefined, changed: false };
      if (value.state === 'rejected') throw new VaultStateError('genesis operation is already rejected');
      working.set(checked, { ...value, state: 'rejected', rejection_code: reason });
      return { value: undefined };
    });
  }

  async rejectSend(recordIdValue: string, code: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    const reason = text(code, 'rejection_code', 1, 128);
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'prepared_send' || value.state !== 'offered') throw new VaultStateError('only an unreserved send may be rejected');
      working.set(checked, { ...value, state: 'rejected', status_capability: null, rejection_code: reason });
      return { value: undefined };
    });
  }

  /** Persist a terminal local send rejection while leaving its source safe. */
  async terminalRejectSend(recordIdValue: string, code: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    const reason = text(code, 'rejection_code', 1, 128);
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'prepared_send') throw new VaultStateError('send operation is not rejectable');
      if (value.state === 'spent') throw new VaultStateError('spent send cannot be rejected');
      if (value.state === 'rejected' && value.rejection_code === reason) return { value: undefined, changed: false };
      if (value.state === 'rejected') throw new VaultStateError('send operation is already rejected');
      working.set(checked, { ...value, state: 'rejected', status_capability: null, rejection_code: reason });
      return { value: undefined };
    });
  }

  /** Persist a terminal local receive rejection without enabling recovery. */
  async terminalRejectReceive(recordIdValue: string, code: string): Promise<void> {
    const checked = recordId(recordIdValue, 'record_id');
    const reason = text(code, 'rejection_code', 1, 128);
    await this.mutate((working) => {
      const value = working.get(checked);
      if (value === undefined || value.record_type !== 'prepared_receive') throw new VaultStateError('receive operation is not rejectable');
      if (value.state === 'current') throw new VaultStateError('current receive cannot be rejected');
      if (value.state === 'rejected' && value.rejection_code === reason) return { value: undefined, changed: false };
      if (value.state === 'rejected') throw new VaultStateError('receive operation is already rejected');
      working.set(checked, { ...value, state: 'rejected', rejection_code: reason });
      return { value: undefined };
    });
  }
}

export { LocalVault as EncryptedLocalVault, LocalVault as Vault };
