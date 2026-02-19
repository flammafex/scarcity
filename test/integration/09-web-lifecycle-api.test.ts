/**
 * Integration Test: Web API token lifecycle persistence invariants
 *
 * Validates that mint/transfer/split/merge operations preserve token state
 * correctly in local storage via the web wallet API.
 */

import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { createServer } from 'net';
import { WebWalletServer } from '../../src/web/server.js';
import { TestRunner } from '../helpers/test-utils.js';

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('Failed to allocate free port'));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

async function api<T = any>(baseUrl: string, path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {})
    },
    ...init
  });
  const data = await response.json();
  if (!response.ok || data.success === false) {
    throw new Error(`API ${path} failed: ${data?.error || response.statusText}`);
  }
  return data as T;
}

export async function runWebLifecycleApiTest(): Promise<void> {
  const runner = new TestRunner();
  const previousHome = process.env.HOME;
  const tempHome = await mkdtemp(join(tmpdir(), 'scarcity-web-test-'));
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let server: WebWalletServer | undefined;

  process.env.HOME = tempHome;
  process.env.SCARCITY_ALLOW_INSECURE_FALLBACK = 'true';

  try {
    console.log('\n' + '='.repeat(60));
    console.log('TEST SUITE: Web API Lifecycle');
    console.log('='.repeat(60) + '\n');

    await runner.run('start server and init infra', async () => {
      server = new WebWalletServer();
      await server.start(port);
      await api(baseUrl, '/api/init', { method: 'POST', body: '{}' });
      runner.assert(true, 'Server started and initialized');
    });

    let alicePubKey = '';
    let bobPubKey = '';
    let mintedTokenId = '';
    let splitTokenIds: string[] = [];
    let mergedTokenId = '';

    await runner.run('create wallets', async () => {
      const alice = await api<any>(baseUrl, '/api/wallets', {
        method: 'POST',
        body: JSON.stringify({ name: 'alice', setDefault: true })
      });
      const bob = await api<any>(baseUrl, '/api/wallets', {
        method: 'POST',
        body: JSON.stringify({ name: 'bob', setDefault: false })
      });
      alicePubKey = alice.data.publicKey;
      bobPubKey = bob.data.publicKey;
      runner.assert(alicePubKey.length > 0, 'Alice public key should exist');
      runner.assert(bobPubKey.length > 0, 'Bob public key should exist');
    });

    await runner.run('mint token persists unspent state', async () => {
      const mint = await api<any>(baseUrl, '/api/tokens/mint', {
        method: 'POST',
        body: JSON.stringify({ wallet: 'alice', amount: 100 })
      });
      mintedTokenId = mint.data.id;
      const tokens = await api<any>(baseUrl, '/api/tokens?wallet=alice');
      const minted = tokens.data.tokens.find((t: any) => t.id === mintedTokenId);
      runner.assert(!!minted, 'Minted token should exist');
      runner.assert(minted.spent === false, 'Minted token should be unspent');
      runner.assert(minted.amount === 100, 'Minted amount should be 100');
    });

    await runner.run('split marks source spent and creates two unspent children', async () => {
      const split = await api<any>(baseUrl, '/api/tokens/split', {
        method: 'POST',
        body: JSON.stringify({ tokenId: mintedTokenId, amounts: [40, 60], wallet: 'alice' })
      });
      splitTokenIds = split.data.tokens.map((t: any) => t.id);
      runner.assert(splitTokenIds.length === 2, 'Split should create exactly two tokens');

      const tokens = await api<any>(baseUrl, '/api/tokens?wallet=alice');
      const source = tokens.data.tokens.find((t: any) => t.id === mintedTokenId);
      const splitA = tokens.data.tokens.find((t: any) => t.id === splitTokenIds[0]);
      const splitB = tokens.data.tokens.find((t: any) => t.id === splitTokenIds[1]);

      runner.assert(source?.spent === true, 'Split source token should be spent');
      runner.assert(splitA?.spent === false, 'First split token should be unspent');
      runner.assert(splitB?.spent === false, 'Second split token should be unspent');
      runner.assert(splitA?.amount + splitB?.amount === 100, 'Split child amounts should sum to 100');
    });

    await runner.run('merge marks children spent and creates merged unspent token', async () => {
      const merge = await api<any>(baseUrl, '/api/tokens/merge', {
        method: 'POST',
        body: JSON.stringify({ tokenIds: splitTokenIds, wallet: 'alice' })
      });
      mergedTokenId = merge.data.id;
      const tokens = await api<any>(baseUrl, '/api/tokens?wallet=alice');
      const splitA = tokens.data.tokens.find((t: any) => t.id === splitTokenIds[0]);
      const splitB = tokens.data.tokens.find((t: any) => t.id === splitTokenIds[1]);
      const merged = tokens.data.tokens.find((t: any) => t.id === mergedTokenId);

      runner.assert(splitA?.spent === true, 'Merged source split A should be spent');
      runner.assert(splitB?.spent === true, 'Merged source split B should be spent');
      runner.assert(merged?.spent === false, 'Merged token should be unspent');
      runner.assert(merged?.amount === 100, 'Merged token amount should be 100');
    });

    await runner.run('transfer marks merged token spent and returns package', async () => {
      const transfer = await api<any>(baseUrl, '/api/tokens/transfer', {
        method: 'POST',
        body: JSON.stringify({
          tokenId: mergedTokenId,
          recipientPublicKey: bobPubKey,
          wallet: 'alice'
        })
      });
      runner.assert(transfer.data.transfer.tokenId === mergedTokenId, 'Transfer should reference merged token');
      runner.assert(typeof transfer.data.transfer.nullifier === 'string', 'Transfer should include nullifier hex');
      runner.assert(transfer.data.transfer.proof?.timestamp > 0, 'Transfer proof should include timestamp');

      const tokens = await api<any>(baseUrl, '/api/tokens?wallet=alice');
      const merged = tokens.data.tokens.find((t: any) => t.id === mergedTokenId);
      runner.assert(merged?.spent === true, 'Transferred token should be marked spent');
    });

    runner.printSummary();
    const summary = runner.getSummary();
    if (summary.failed > 0) {
      throw new Error(`${summary.failed} test(s) failed`);
    }
  } finally {
    try {
      if (server) {
        await server.stop();
      }
    } catch {
      // Ignore shutdown issues in test teardown
    }
    process.env.HOME = previousHome;
    await rm(tempHome, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runWebLifecycleApiTest()
    .then(() => {
      console.log('\n✅ Web lifecycle API tests passed!\n');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Test suite failed:', error.message);
      process.exit(1);
    });
}

