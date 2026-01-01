/**
 * Test utilities and helpers for Scarcity integration tests
 */

import { Crypto } from '../../src/crypto.js';
import type { PublicKey } from '../../src/types.js';

// Centralized test configuration with environment variable support
export const TestConfig = {
  freebird: {
    issuer: process.env.FREEBIRD_ISSUER_URL || 'http://localhost:8081',
    verifier: process.env.FREEBIRD_VERIFIER_URL || 'http://localhost:8082'
  },
  witness: {
    gateway: process.env.WITNESS_GATEWAY_URL || 'http://localhost:8080',
    // Secondary gateway for bridge tests (defaults to 5002 if not specified)
    gateway2: process.env.WITNESS_GATEWAY_2_URL || 'http://localhost:5002'
  },
  hypertoken: {
    relay: process.env.HYPERTOKEN_RELAY_URL || 'ws://localhost:3000'
  }
};

/**
 * Test result with timing information
 */
export interface TestResult {
  name: string;
  passed: boolean;
  duration: number;
  error?: string;
  details?: any;
}

/**
 * Simple test runner
 */
export class TestRunner {
  private results: TestResult[] = [];
  private currentTest: string = '';
  private startTime: number = 0;

  async run(name: string, testFn: () => Promise<void>): Promise<void> {
    this.currentTest = name;
    this.startTime = Date.now();

    try {
      await testFn();
      this.pass(name);
    } catch (error) {
      this.fail(name, error);
    }
  }

  private pass(name: string, details?: any): void {
    this.results.push({
      name,
      passed: true,
      duration: Date.now() - this.startTime,
      details
    });
    console.log(`✅ ${name} (${Date.now() - this.startTime}ms)`);
  }

  private fail(name: string, error: any): void {
    this.results.push({
      name,
      passed: false,
      duration: Date.now() - this.startTime,
      error: error?.message || String(error)
    });
    console.log(`❌ ${name} (${Date.now() - this.startTime}ms)`);
    console.log(`   Error: ${error?.message || error}`);
  }

  assert(condition: boolean, message: string): void {
    if (!condition) {
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  assertEquals(actual: any, expected: any, message?: string): void {
    if (actual !== expected) {
      throw new Error(
        message || `Expected ${expected}, got ${actual}`
      );
    }
  }

  assertGreaterThan(actual: number, threshold: number, message?: string): void {
    if (actual <= threshold) {
      throw new Error(
        message || `Expected ${actual} > ${threshold}`
      );
    }
  }

  assertBetween(value: number, min: number, max: number, message?: string): void {
    if (value < min || value > max) {
      throw new Error(
        message || `Expected ${value} to be between ${min} and ${max}`
      );
    }
  }

  getSummary() {
    const passed = this.results.filter(r => r.passed).length;
    const failed = this.results.filter(r => !r.passed).length;
    const total = this.results.length;

    return {
      total,
      passed,
      failed,
      passRate: total > 0 ? (passed / total) * 100 : 0,
      results: this.results
    };
  }

  printSummary(): void {
    console.log('\n' + '='.repeat(60));
    console.log('TEST SUMMARY');
    console.log('='.repeat(60));

    const summary = this.getSummary();

    console.log(`Total: ${summary.total}`);
    console.log(`Passed: ${summary.passed}`);
    console.log(`Failed: ${summary.failed}`);
    console.log(`Pass Rate: ${summary.passRate.toFixed(1)}%`);

    if (summary.failed > 0) {
      console.log('\nFailed Tests:');
      summary.results
        .filter(r => !r.passed)
        .forEach(r => console.log(`  - ${r.name}: ${r.error}`));
    }

    console.log('='.repeat(60));
  }
}

/**
 * Create test key pair
 */
export function createTestKeyPair(): { publicKey: PublicKey; secret: Uint8Array } {
  const secret = Crypto.randomBytes(32);
  const publicKey: PublicKey = {
    bytes: Crypto.hash(secret, 'PUBLIC_KEY')
  };
  return { publicKey, secret };
}

/**
 * Wait for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry an async operation with exponential backoff
 */
export async function retry<T>(
  operation: () => Promise<T>,
  maxAttempts: number = 3,
  delayMs: number = 1000
): Promise<T> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      if (attempt === maxAttempts) {
        throw error;
      }
      await sleep(delayMs * Math.pow(2, attempt - 1));
    }
  }
  throw new Error('Retry failed');
}

/**
 * Check if a service is available
 */
export async function checkService(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(5000)
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Service availability checker
 */
export async function checkServices() {
  console.log('\n🔍 Checking service availability...\n');

  const services = [
    { name: 'HyperToken Relay', url: TestConfig.hypertoken.relay, skip: true }, // WebSocket, can't easily check
    { name: 'Witness Gateway', url: `${TestConfig.witness.gateway}/v1/config` },
    { name: 'Freebird Issuer', url: `${TestConfig.freebird.issuer}/.well-known/issuer` },
    { name: 'Freebird Verifier', url: `${TestConfig.freebird.verifier}/.well-known/issuer` }
  ];

  const results: { [key: string]: boolean } = {};

  for (const service of services) {
    if (service.skip) {
      console.log(`⏭️  ${service.name}: (skipped)`);
      results[service.name] = false;
      continue;
    }

    const available = await checkService(service.url);
    results[service.name] = available;

    if (available) {
      console.log(`✅ ${service.name}: Available (${service.url})`);
    } else {
      console.log(`❌ ${service.name}: Not available (${service.url})`);
    }
  }

  console.log('\n💡 Tests will run in fallback mode for unavailable services\n');

  return results;
}