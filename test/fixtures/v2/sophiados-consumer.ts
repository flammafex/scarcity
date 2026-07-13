/** Bounded native consumer for the committed SophiaDOS V2 publication. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { encode, rfc8949EncodeOptions } from 'cborg';
import { decodeRestricted } from './restricted-cbor.js';

const SOPHIA_COMMIT = 'eae340b8351699b74fe2c1a5cf8c65896e598474';
const SCARCITY_COMMIT = '317a7a755c8a00e56d1c89550ade7828ca0f062d';
const root = resolve(process.env.SOPHIADOS_DIR ?? resolve(process.cwd(), '../sophiados'));
const show = (path: string): Buffer => execFileSync('git', ['-C', root, 'show', `${SOPHIA_COMMIT}:${path}`]);
const json = (path: string): any => JSON.parse(show(path).toString('utf8'));
const sha = (value: Uint8Array | Buffer) => createHash('sha256').update(value).digest('hex');
const fromHex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'));
const toHex = (value: Uint8Array) => Buffer.from(value).toString('hex');
const cbor = (value: unknown) => encode(value, rfc8949EncodeOptions);
const hash = (label: string, value: Uint8Array) => new Uint8Array(createHash('sha256').update(Buffer.concat([Buffer.from(`scarcity/v2/${label}\0`), Buffer.from(value)])).digest());
const mapValue = (value: unknown, key: string): unknown => value instanceof Map ? value.get(key) : undefined;
const bytes = (value: unknown) => value instanceof Uint8Array ? value : fromHex(String(value));

function tree(ids: Uint8Array[]) {
  const leaves = ids.map((id, i) => hash('output-leaf', cbor({ output_index: i, output_id: id })));
  let level: Uint8Array[] = leaves as Uint8Array[];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(hash('output-node', Uint8Array.from([...level[i], ...(level[i + 1] ?? level[i])] )));
    level = next;
  }
  return level[0] ?? hash('output-empty', new Uint8Array());
}

function emitReport(manifest: any, detail: string, status: 'fail' | 'unsupported') {
  const report = { fixture_namespace: 'scarcity-v2', report_version: 1, consumer: 'scarcity-typescript-v2-native-consumer', manifest_version: manifest.manifest_version, source_pins: manifest.source_pins, results: [{ case_id: 'manifest-and-vector-checksums', status: 'pass', detail: `manifest_sha256=${sha(show('contracts/conformance/fixtures/scarcity-v2/manifest.json'))}` }, { case_id: 'capability-matrix', status: 'pass', detail: 'scarcity core transition hashes and Merkle values; RSABSSA, Freebird and Witness remain data_only' }, { case_id: 'core-known-answers', status, detail }] };
  const output = resolve(process.cwd(), 'dist-v2-fixtures/consumer-report.json'); mkdirSync(dirname(output), { recursive: true }); writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`); console.log(JSON.stringify(report));
}

function main() {
  try { execFileSync('git', ['-C', root, 'cat-file', '-e', `${SOPHIA_COMMIT}^{commit}`]); }
  catch { throw new Error(`SophiaDOS committed source unavailable at ${root} (${SOPHIA_COMMIT})`); }
  const manifestPath = 'contracts/conformance/fixtures/scarcity-v2/manifest.json';
  const manifest = json(manifestPath);
  if (manifest.fixture_namespace !== 'scarcity-v2') throw new Error('wrong SophiaDOS fixture namespace');
  for (const pin of manifest.source_pins) {
    if (pin.repo === 'scarcity' && pin.commit !== SCARCITY_COMMIT) throw new Error(`Scarcity source pin mismatch: ${pin.path}`);
    if (pin.repo === 'scarcity' && sha(Buffer.from(execFileSync('git', ['show', `${SCARCITY_COMMIT}:${pin.path}`]))) !== pin.sha256) throw new Error(`Scarcity source checksum mismatch: ${pin.path}`);
  }
  for (const [path, expected] of Object.entries(manifest.vector_checksums)) if (sha(show(`contracts/conformance/fixtures/scarcity-v2/${path}`)) !== expected) throw new Error(`SophiaDOS vector checksum mismatch: ${path}`);
  const known = json('contracts/conformance/fixtures/scarcity-v2/scarcity-core-known-answers.json');
  const positive = json('contracts/conformance/fixtures/scarcity-v2/positive.json');
  const capability = json('contracts/conformance/fixtures/scarcity-v2/capability-matrix.json');
  if (capability.fixture_namespace !== 'scarcity-v2' || !capability.capabilities.some((item: any) => item.consumer === 'scarcity')) throw new Error('Scarcity capability declaration missing');
  const transition = positive.cases.find((item: any) => item.id === 'core-transition-known-answer');
  if (!transition || transition.known_answer_ref !== 'scarcity-core-known-answers.json') throw new Error('transition known-answer reference missing');

  const canonical = known.canonical;
  let policy: unknown; let asset: unknown;
  try { policy = decodeRestricted(canonical.policy); asset = decodeRestricted(canonical.asset); }
  catch (error) { emitReport(manifest, `authoritative known-answer canonical input rejected: ${(error as Error).message}`, 'fail'); return; }
  if (toHex(hash('asset-policy', cbor(policy))) !== known.digests.policy) throw new Error('published policy digest mismatch');
  if (toHex(hash('asset', cbor(asset))) !== known.digests.asset_id) throw new Error('published asset identity mismatch');
  if (!Buffer.from(cbor(policy)).equals(fromHex(canonical.policy)) || !Buffer.from(cbor(asset)).equals(fromHex(canonical.asset))) throw new Error('published canonical bytes drifted');

  const domain = fromHex(transition.input.spend_domain);
  const source = { transaction_id: new Uint8Array(32).fill(0x12), output_index: 0, output_commitment: new Uint8Array(32).fill(0x13) };
  const inputOutputId = hash('output', cbor(source));
  const inputNullifier = hash('nullifier', cbor({ spend_domain: domain, output_id: inputOutputId }));
  const assetId = fromHex(known.digests.asset_id);
  const outputs = [7, 3, 1].map((amount, i) => { const recipient_key = new Uint8Array(32).fill([0x88, 0xaa, 0xcc][i]); const output_commitment = hash('output-commitment', cbor({ asset_id: assetId, amount, recipient_key, spend_domain: domain, provenance: { kind: 'transition' } })); return { asset_id: assetId, amount, recipient_key, spend_domain: domain, output_commitment, provenance: { kind: 'transition' } }; });
  const transaction = { spend_domain: domain, inputs: [{ output_id: inputOutputId, nullifier: inputNullifier, owner_key_id: new Uint8Array(32).fill(0x66) }], outputs };
  const transactionId = hash('transaction', cbor(transaction));
  if (toHex(transactionId) !== known.digests.transaction_id) throw new Error('published transaction digest mismatch');
  const outputIds = outputs.map((output, output_index) => hash('output', cbor({ transaction_id: transactionId, output_index, output_commitment: output.output_commitment })));
  const nullifiers = outputIds.map((output_id) => hash('nullifier', cbor({ spend_domain: domain, output_id })));
  known.outputs.forEach((expected: any, i: number) => { if (expected.output_index !== i || expected.output_id !== toHex(outputIds[i]) || expected.nullifier !== toHex(nullifiers[i])) throw new Error(`published output ${i} mismatch`); });
  if (toHex(tree([])) !== known.merkle['0'] || toHex(tree(outputIds.slice(0, 1))) !== known.merkle['1'] || toHex(tree(outputIds)) !== known.merkle['3']) throw new Error('published Merkle value mismatch');

  const negativeResults = Object.entries(known.canonical_negative_values).map(([caseId, value]) => { try { decodeRestricted(value as string); return { case_id: `canonical-${caseId}`, status: 'fail', detail: `accepted; expected ${known.canonical_negative[caseId]}` }; } catch (error) { const expected = known.canonical_negative[caseId]; const actual = (error as Error).message; return { case_id: `canonical-${caseId}`, status: actual === expected ? 'pass' : 'fail', detail: `category=${actual}` }; } });
  const report = { fixture_namespace: 'scarcity-v2', report_version: 1, consumer: 'scarcity-typescript-v2-native-consumer', manifest_version: manifest.manifest_version, source_pins: manifest.source_pins, results: [{ case_id: 'manifest-and-vector-checksums', status: 'pass', detail: `manifest_sha256=${sha(show(manifestPath))}` }, { case_id: 'capability-matrix', status: 'pass', detail: 'scarcity core transition hashes and Merkle values; RSABSSA, Freebird and Witness remain data_only' }, { case_id: 'core-known-answers', status: 'pass', detail: 'cborg restricted canonical bytes, hashes, outputs and Merkle values independently verified' }, ...negativeResults] };
  const output = resolve(process.cwd(), 'dist-v2-fixtures/consumer-report.json'); mkdirSync(dirname(output), { recursive: true }); writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`); console.log(JSON.stringify(report));
}

main();
