/** TEST-ONLY encrypted local-vault conformance gates. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  decodeCanonicalBase64Url,
  encodeCanonicalBase64Url,
  encodeCanonicalLowerHex,
  encodeV5BearerArtifactBase64,
} from '../../src/circulation-v1/index.js';
import {
  FilesystemVaultBackend,
  VAULT_LOCK_FILE,
  LocalVault,
  MemoryVaultBackend,
  VaultAuthenticationError,
  VaultValidationError,
} from '../../src/circulation-v1/vault.js';
import type {
  ExchangeReceiptV2,
  ExchangeRequestV2,
  ExchangeResultV2,
  GraphIssuanceRequestV1,
  GraphIssuanceResultV1,
} from '../../src/circulation-v1/types.js';

// TEST-ONLY deterministic values. Production vault randomness is node:crypto.
const TEST_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const ID0 = encodeCanonicalLowerHex(Uint8Array.of(...new Uint8Array(32).fill(0x10)));
const ID1 = encodeCanonicalLowerHex(Uint8Array.of(...new Uint8Array(32).fill(0x11)));
const ID2 = encodeCanonicalLowerHex(Uint8Array.of(...new Uint8Array(32).fill(0x12)));
const ID3 = encodeCanonicalLowerHex(Uint8Array.of(...new Uint8Array(32).fill(0x13)));
const OP_SEND = encodeCanonicalBase64Url(new Uint8Array(16).fill(0x20));
const OP_RECEIVE = encodeCanonicalBase64Url(new Uint8Array(16).fill(0x21));
const OP_GENESIS = encodeCanonicalBase64Url(new Uint8Array(16).fill(0x22));
const BLINDED = encodeCanonicalBase64Url(new Uint8Array(48).fill(0x31));
const BLIND_SIGNATURE = encodeCanonicalBase64Url(new Uint8Array(256).fill(0x32));
const DIGEST = encodeCanonicalBase64Url(new Uint8Array(32).fill(0x33));
const RECEIPT_SIGNATURE = encodeCanonicalBase64Url(new Uint8Array(64).fill(0x34));

function testRandomSource(): (length: number) => Uint8Array {
  // TEST-ONLY deterministic CSPRNG substitute for the memory backend.
  let cursor = 0;
  return (length: number): Uint8Array => {
    const bytes = Uint8Array.from({ length }, (_, index) => (cursor + index + 1) & 0xff);
    cursor += length;
    return bytes;
  };
}

function artifact(nonceByte: number): string {
  return encodeV5BearerArtifactBase64(
    new Uint8Array(32).fill(nonceByte),
    new Uint8Array(32).fill(0x40),
    'issuer:test-only',
    new Uint8Array(64).fill(0x41),
  );
}

function request(sourceArtifact: string, operationId: string): ExchangeRequestV2 {
  return {
    version: 2,
    public_operation_id: operationId,
    graph_id: ID0,
    transition_id: ID1,
    source_keyset_id: ID2,
    target_keyset_id: ID3,
    sources: [{ slot: { descriptor_id: ID0, keyset_id: ID2, slot_id: 'input', quantity: 1 }, artifact: sourceArtifact }],
    outputs: [{ slot: { descriptor_id: ID1, keyset_id: ID3, slot_id: 'output', quantity: 1 }, blinded_value: BLINDED }],
  };
}

function resultFor(exchangeRequest: ExchangeRequestV2): ExchangeResultV2 {
  return {
    version: 2,
    public_operation_id: exchangeRequest.public_operation_id,
    graph_id: exchangeRequest.graph_id,
    transition_id: exchangeRequest.transition_id,
    source_keyset_id: exchangeRequest.source_keyset_id,
    target_keyset_id: exchangeRequest.target_keyset_id,
    outputs: [{ ...exchangeRequest.outputs[0], blind_signature: BLIND_SIGNATURE }],
    result_digest: DIGEST,
  };
}

function receiptFor(exchangeResult: ExchangeResultV2): ExchangeReceiptV2 {
  return {
    version: 2,
    public_operation_id: exchangeResult.public_operation_id,
    graph_id: exchangeResult.graph_id,
    transition_id: exchangeResult.transition_id,
    source_keyset_id: exchangeResult.source_keyset_id,
    target_keyset_id: exchangeResult.target_keyset_id,
    result_digest: exchangeResult.result_digest,
    created_at: 1_700_000_000,
    expires_at: 1_700_000_000 + 2_592_000,
    receipt_key_id: ID0,
    signature: RECEIPT_SIGNATURE,
  };
}

function genesisRequest(): GraphIssuanceRequestV1 {
  return {
    version: 1,
    public_operation_id: OP_GENESIS,
    issuance_policy_id: 'bootstrap-v1',
    graph_id: ID0,
    keyset_id: ID2,
    descriptor_id: ID1,
    blinded_message: BLINDED,
    authorization: encodeCanonicalBase64Url(new Uint8Array(96).fill(0x51)),
  };
}

function genesisResult(requestValue: GraphIssuanceRequestV1): GraphIssuanceResultV1 {
  return {
    version: 1,
    public_operation_id: requestValue.public_operation_id,
    issuance_policy_id: requestValue.issuance_policy_id,
    graph_id: requestValue.graph_id,
    keyset_id: requestValue.keyset_id,
    descriptor_id: requestValue.descriptor_id,
    token_key_id: encodeCanonicalLowerHex(new Uint8Array(32).fill(0x40)),
    quantity: 1,
    request_digest: DIGEST,
    blind_signature: BLIND_SIGNATURE,
    result_digest: DIGEST,
  };
}

async function testMemoryStateMachines(): Promise<void> {
  const vault = await LocalVault.create({
    backend: new MemoryVaultBackend(),
    unlockKey: TEST_KEY,
    randomBytes: testRandomSource(),
  });
  const sourceArtifact = artifact(0x42);
  const sourceId = await vault.storeArtifact({ artifact: sourceArtifact, keyset_id: ID2, descriptor_id: ID0 });
  const sendRequest = request(sourceArtifact, OP_SEND);
  const send = await vault.createPreparedSend({
    preparation_snapshot_ref: 'TEST-ONLY snapshot',
    request: sendRequest,
    source_record_id: sourceId,
    status_capability: encodeCanonicalBase64Url(new Uint8Array(32).fill(0x52)),
  });
  await vault.reserveSource(sourceId, send.record_id);
  assert.equal((await vault.getRecord(sourceId))?.state, 'reserved', 'source reservation is atomic');
  assert.equal((await vault.getRecord(send.record_id))?.state, 'reserved_pending');
  await vault.markSendSubmittedUnknown(send.record_id);
  await vault.finalizeSend(send.record_id, { result: resultFor(sendRequest), receipt: receiptFor(resultFor(sendRequest)) });
  assert.equal((await vault.getRecord(sourceId))?.state, 'spent', 'source spend is atomic with send advancement');
  assert.equal((await vault.getRecord(send.record_id))?.state, 'spent');

  const receiveRequest = request(sourceArtifact, OP_RECEIVE);
  const receive = await vault.createPreparedReceive({
    preparation_snapshot_ref: 'TEST-ONLY snapshot',
    operation_id: OP_RECEIVE,
    status_capability: encodeCanonicalBase64Url(new Uint8Array(32).fill(0x53)),
    graph_id: receiveRequest.graph_id,
    transition_id: receiveRequest.transition_id,
    source_keyset_id: receiveRequest.source_keyset_id,
    target_keyset_id: receiveRequest.target_keyset_id,
    expected_output: receiveRequest.outputs[0],
    output_nonce: new Uint8Array(32).fill(0x54),
    message: new Uint8Array(48).fill(0x55),
    blinding_state: new Uint8Array(256).fill(0x56),
  });
  await vault.markReceiveSubmitted(receive.record_id);
  const receiveResult = resultFor(receiveRequest);
  const receiveArtifactId = await vault.finalizeReceive(receive.record_id, {
    artifact: encodeV5BearerArtifactBase64(new Uint8Array(32).fill(0x54), new Uint8Array(32).fill(0x40), 'issuer:test-only', new Uint8Array(64).fill(0x57)),
    result: receiveResult,
    receipt: receiptFor(receiveResult),
  });
  assert.equal((await vault.getRecord(receive.record_id))?.state, 'current', 'receive operation advanced atomically');
  assert.equal((await vault.getRecord(receiveArtifactId))?.state, 'current', 'finalized artifact committed atomically');
  const receiveRecord = await vault.getRecord(receive.record_id);
  assert.equal(receiveRecord?.record_type, 'prepared_receive');
  if (receiveRecord?.record_type === 'prepared_receive') {
    assert.equal(receiveRecord.status_capability, null, 'status capability is cleared after acceptance');
    assert.equal(receiveRecord.blinding_state, null, 'opaque blind state is cleared after acceptance');
  }

  const genesisRequestValue = genesisRequest();
  const genesis = await vault.createGenesisIssuance({
    preparation_snapshot_ref: 'TEST-ONLY genesis snapshot',
    request: genesisRequestValue,
    output_nonce: new Uint8Array(32).fill(0x58),
    message: new Uint8Array(48).fill(0x59),
    blinding_state: new Uint8Array(256).fill(0x5a),
    status_capability: encodeCanonicalBase64Url(new Uint8Array(32).fill(0x5b)),
  });
  await vault.markGenesisSubmitted(genesis.record_id);
  const genesisArtifactId = await vault.finalizeGenesis(genesis.record_id, {
    artifact: encodeV5BearerArtifactBase64(new Uint8Array(32).fill(0x58), new Uint8Array(32).fill(0x40), 'issuer:test-only', new Uint8Array(64).fill(0x5c)),
    result: genesisResult(genesisRequestValue),
  });
  assert.equal((await vault.getRecord(genesis.record_id))?.state, 'current');
  assert.equal((await vault.getRecord(genesisArtifactId))?.state, 'current');
}

async function testFilesystemAuthenticationAndPrivacy(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'scarcity-vault-test-'));
  let vault: LocalVault | undefined;
  try {
    const backend = new FilesystemVaultBackend(directory);
    vault = await LocalVault.create({ backend, unlockKey: TEST_KEY });
    const secretArtifact = artifact(0x61);
    await vault.storeArtifact({ artifact: secretArtifact, keyset_id: ID2, descriptor_id: ID0 });
    const receive = await vault.createPreparedReceive({
      preparation_snapshot_ref: 'TEST-ONLY privacy snapshot',
      operation_id: OP_RECEIVE,
      status_capability: encodeCanonicalBase64Url(new Uint8Array(32).fill(0x62)),
      graph_id: ID0,
      transition_id: ID1,
      source_keyset_id: ID2,
      target_keyset_id: ID3,
      expected_output: request(secretArtifact, OP_RECEIVE).outputs[0],
      output_nonce: new Uint8Array(32).fill(0x63),
      message: new Uint8Array(48).fill(0x64),
      blinding_state: new Uint8Array(256).fill(0x65),
    });
    await vault.markReceiveSubmitted(receive.record_id);
    const recordFiles = (await readdir(join(directory, 'records'))).filter((name) => name.endsWith('.json'));
    assert.equal(recordFiles.length, 2);
    const recordPath = join(directory, 'records', recordFiles[1]);
    const original = await readFile(recordPath, 'utf8');
    const envelope = JSON.parse(original) as Record<string, string>;
    const secrets = [
      secretArtifact,
      encodeCanonicalBase64Url(new Uint8Array(32).fill(0x62)),
      encodeCanonicalBase64Url(new Uint8Array(32).fill(0x63)),
      encodeCanonicalBase64Url(new Uint8Array(48).fill(0x64)),
      encodeCanonicalBase64Url(new Uint8Array(256).fill(0x65)),
    ];
    for (const secret of secrets) assert.equal(original.includes(secret), false, 'persisted envelope contains no plaintext secret');

    await vault.lock();
    await assert.rejects(LocalVault.open({ backend, unlockKey: new Uint8Array(32).fill(0x7f) }), VaultAuthenticationError, 'wrong key fails generically');

    const tamperCases: Array<[string, (value: Record<string, string>) => void, typeof VaultAuthenticationError | typeof VaultValidationError]> = [
      ['ciphertext', (value) => { const bytes = decodeCanonicalBase64Url(value.ciphertext); bytes[0] ^= 1; value.ciphertext = encodeCanonicalBase64Url(bytes); }, VaultAuthenticationError],
      ['nonce', (value) => { const bytes = decodeCanonicalBase64Url(value.nonce); bytes[0] ^= 1; value.nonce = encodeCanonicalBase64Url(bytes); }, VaultAuthenticationError],
      ['AAD wallet', (value) => { value.wallet_id = encodeCanonicalBase64Url(new Uint8Array(16).fill(0x7e)); }, VaultAuthenticationError],
      ['AAD record', (value) => { value.record_id = encodeCanonicalBase64Url(new Uint8Array(16).fill(0x7d)); }, VaultAuthenticationError],
      ['version', (value) => { value.version = 'scarcity/vault-record/v0'; }, VaultValidationError],
      ['unknown envelope field', (value) => { value.extra = 'TEST-ONLY'; }, VaultValidationError],
    ];
    for (const [, mutate, expected] of tamperCases) {
      const changed = { ...envelope };
      mutate(changed);
      await writeFile(recordPath, JSON.stringify(changed), 'utf8');
      await assert.rejects(LocalVault.open({ backend, unlockKey: TEST_KEY }), expected);
      await writeFile(recordPath, original, 'utf8');
    }
    const duplicateField = original.replace(`,"record_id":`, `,"wallet_id":${JSON.stringify(envelope.wallet_id)},"record_id":`);
    await writeFile(recordPath, duplicateField, 'utf8');
    await assert.rejects(LocalVault.open({ backend, unlockKey: TEST_KEY }), VaultValidationError, 'duplicate envelope fields are rejected');
    await writeFile(recordPath, original, 'utf8');

    vault = await LocalVault.open({ backend, unlockKey: TEST_KEY });
    await assert.rejects(vault.getRecord('../path-traversal'), VaultValidationError, 'record path is validated before lookup');
    await assert.rejects(backend.writeRecordEnvelope('../path-traversal', original), VaultValidationError, 'backend rejects traversal record IDs');
    const secondArtifactId = await vault.storeArtifact({ artifact: artifact(0x66), keyset_id: ID2, descriptor_id: ID0 });
    const allFiles = (await readdir(join(directory, 'records'))).filter((name) => name.endsWith('.json'));
    const envelopes = await Promise.all(allFiles.map((name) => readFile(join(directory, 'records', name), 'utf8')));
    const nonces = envelopes.map((value) => (JSON.parse(value) as { nonce: string }).nonce);
    assert.equal(new Set(nonces).size, nonces.length, 'AES-GCM nonces are unique');
    assert.ok(secondArtifactId.length > 0);
  } finally {
    await vault?.lock();
    await rm(directory, { recursive: true, force: true });
  }
}

async function testCrashSafeAtomicTransaction(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'scarcity-vault-fault-'));
  let injectFailure = false;
  const failureHook = async (stage: string): Promise<void> => {
    if (injectFailure && stage === 'record:before-rename') {
      injectFailure = false;
      throw new Error('TEST-ONLY injected rename failure');
    }
  };
  let vault: LocalVault | undefined;
  try {
    const backend = new FilesystemVaultBackend(directory, { failureHook });
    vault = await LocalVault.create({ backend, unlockKey: TEST_KEY });
    const source = artifact(0x71);
    const sourceId = await vault.storeArtifact({ artifact: source, keyset_id: ID2, descriptor_id: ID0 });
    const sendRequest = request(source, OP_SEND);
    const send = await vault.createPreparedSend({ preparation_snapshot_ref: 'TEST-ONLY crash snapshot', request: sendRequest, source_record_id: sourceId });
    injectFailure = true;
    await assert.rejects(vault.reserveSource(sourceId, send.record_id), /TEST-ONLY injected rename failure/);
    const leftovers = await readdir(join(directory, 'records'));
    assert.equal(leftovers.some((name) => name.endsWith('.tmp')), false, 'no temporary plaintext file remains');
    const recoveredSource = await vault.getRecord(sourceId);
    const recoveredSend = await vault.getRecord(send.record_id);
    assert.equal(recoveredSource?.state, 'reserved', 'journal recovery commits the source reservation as one unit');
    assert.equal(recoveredSend?.state, 'reserved_pending', 'journal recovery advances the operation as one unit');
    assert.equal((await readdir(directory)).includes('transaction.json'), false, 'transaction journal is removed after recovery');
  } finally {
    await vault?.lock();
    await rm(directory, { recursive: true, force: true });
  }
}

async function lockFileExists(directory: string): Promise<boolean> {
  try {
    await readFile(join(directory, VAULT_LOCK_FILE), 'utf8');
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

async function recordSnapshot(directory: string): Promise<readonly string[]> {
  const names = (await readdir(join(directory, 'records'))).filter((name) => name.endsWith('.json')).sort();
  return Promise.all(names.map(async (name) => `${name}:${await readFile(join(directory, 'records', name), 'utf8')}`));
}

async function waitForChildLine(child: ReturnType<typeof spawn>, expected: string): Promise<void> {
  const stdout = child.stdout;
  if (stdout === null) throw new Error('child stdout is unavailable');
  await new Promise<void>((resolve, reject) => {
    let output = '';
    const onData = (chunk: Buffer): void => {
      output += chunk.toString('utf8');
      if (output.includes(expected)) {
        stdout.off('data', onData);
        resolve();
      }
    };
    stdout.on('data', onData);
    child.once('error', reject);
    child.once('exit', (code, signal) => reject(new Error(`lock-holder exited before ${expected} (${code ?? signal}): ${output}`)));
  });
}

async function testFilesystemLocking(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'scarcity-vault-lock-'));
  let first: LocalVault | undefined;
  let second: LocalVault | undefined;
  const children: Array<ReturnType<typeof spawn>> = [];
  const waitForPending = async (promise: Promise<unknown>, message: string): Promise<void> => {
    let settled = false;
    void promise.then(() => { settled = true; }, () => { settled = true; });
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(settled, false, message);
  };
  try {
    const firstBackend = new FilesystemVaultBackend(directory);
    first = await LocalVault.create({ backend: firstBackend, unlockKey: TEST_KEY });
    const sourceId = await first.storeArtifact({ artifact: artifact(0x81), keyset_id: ID2, descriptor_id: ID0 });
    assert.equal(await lockFileExists(directory), true, 'stable sidecar survives normal operations');
    assert.equal(await readFile(join(directory, VAULT_LOCK_FILE), 'utf8'), '', 'sidecar contains no vault plaintext');
    await first.lock();
    assert.equal(await lockFileExists(directory), true, 'sidecar survives normal unlock');
    assert.equal(await readFile(join(directory, VAULT_LOCK_FILE), 'utf8'), '', 'sidecar remains empty after unlock');
    await first.unlock(TEST_KEY);

    const secondBackend = new FilesystemVaultBackend(directory);
    second = await LocalVault.open({ backend: secondBackend, unlockKey: TEST_KEY });
    const beforeContention = await recordSnapshot(directory);

    // Two independent vault instances contend through a held native lease.
    const heldLease = await firstBackend.acquireLock();
    const pendingSecond = second.storeArtifact({ artifact: artifact(0x82), keyset_id: ID2, descriptor_id: ID0 });
    await waitForPending(pendingSecond, 'second vault cannot mutate while the native lock is held');
    assert.deepEqual(await recordSnapshot(directory), beforeContention, 'contention preserves authoritative records');
    await heldLease.release();
    await pendingSecond;
    assert.equal(await lockFileExists(directory), true, 'sidecar remains after native unlock');
    assert.equal(await readFile(join(directory, VAULT_LOCK_FILE), 'utf8'), '');
    assert.equal((await second.getRecord(sourceId))?.state, 'current');

    // A real independent process cannot mutate during the held lock, then the
    // same operation succeeds after the holder releases its descriptor.
    const child = spawn(process.execPath, [process.argv[1], '--vault-lock-holder', directory], { stdio: ['pipe', 'pipe', 'pipe'] });
    children.push(child);
    await waitForChildLine(child, 'ready');
    const childContentionSnapshot = await recordSnapshot(directory);
    const pendingChild = first.storeArtifact({ artifact: artifact(0x83), keyset_id: ID2, descriptor_id: ID0 });
    await waitForPending(pendingChild, 'parent cannot mutate during child-owned native lock');
    assert.deepEqual(await recordSnapshot(directory), childContentionSnapshot, 'child contention cannot overwrite state');
    const childExit = once(child, 'exit');
    child.stdin?.end('release\n');
    await childExit;
    await pendingChild;
    assert.equal(await lockFileExists(directory), true, 'child release preserves the stable sidecar');
    assert.equal(await readFile(join(directory, VAULT_LOCK_FILE), 'utf8'), '');
    assert.equal((await first.getRecord(sourceId))?.state, 'current');

    // A killed holder loses only its descriptor; the permanent sidecar is
    // reused and the next operation then completes after descriptor release.
    const crashChild = spawn(process.execPath, [process.argv[1], '--vault-lock-crash-holder', directory], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(crashChild);
    await waitForChildLine(crashChild, 'ready');
    const crashContentionSnapshot = await recordSnapshot(directory);
    assert.deepEqual(await recordSnapshot(directory), crashContentionSnapshot, 'crashed-holder contention preserves state before release');
    const crashExit = once(crashChild, 'exit');
    crashChild.kill('SIGKILL');
    await crashExit;
    const pendingCrash = second.storeArtifact({ artifact: artifact(0x84), keyset_id: ID2, descriptor_id: ID0 });
    await pendingCrash;
    assert.equal(await lockFileExists(directory), true, 'descriptor-close recovery retains the sidecar');
    assert.equal(await readFile(join(directory, VAULT_LOCK_FILE), 'utf8'), '', 'sidecar still contains no vault plaintext');
    assert.equal((await first.getRecord(sourceId))?.state, 'current');
  } finally {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        const childExit = once(child, 'exit');
        child.kill('SIGKILL');
        await childExit.catch(() => undefined);
      }
    }
    await first?.lock();
    await second?.lock();
    await rm(directory, { recursive: true, force: true });
  }
}

async function holdFilesystemLock(directory: string, crash = false): Promise<void> {
  const backend = new FilesystemVaultBackend(directory);
  const lease = await backend.acquireLock();
  process.stdout.write('ready\n');
  if (crash) {
    setInterval(() => undefined, 1000);
    await new Promise<void>(() => undefined);
  }
  await new Promise<void>((resolve, reject) => {
    process.stdin.once('data', () => resolve());
    process.stdin.once('error', reject);
    process.stdin.resume();
  });
  await lease.release();
  process.stdout.write('released\n');
}

async function main(): Promise<void> {
  await testMemoryStateMachines();
  await testFilesystemAuthenticationAndPrivacy();
  await testCrashSafeAtomicTransaction();
  await testFilesystemLocking();
  console.log('circulation-v1 vault: all deterministic tests passed');
}

if (process.argv[2] === '--vault-lock-holder') {
  await holdFilesystemLock(process.argv[3]);
} else if (process.argv[2] === '--vault-lock-crash-holder') {
  await holdFilesystemLock(process.argv[3], true);
} else {
  await main();
}
