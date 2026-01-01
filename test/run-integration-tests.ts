/**
 * Integration Test Runner
 *
 * Runs all integration tests in sequence, checking service availability
 * and providing detailed results.
 */

import { checkServices } from './helpers/test-utils.js';
import { runBasicTransferTest } from './integration/01-basic-transfer.test.js';
import { runDoubleSpendTest } from './integration/02-double-spend.test.js';
import { runGracefulDegradationTest } from './integration/03-graceful-degradation.test.js';
import { runPhase3Tests } from './integration/04-phase3-features.test.js';
import { runPhase3CLITests } from './integration/05-phase3-cli.test.js';
import { runSpamMitigationTest } from './integration/06-spam-mitigation.test.js';
import { runSecurityHardeningTest } from './integration/07-security-hardening.test.js';
import { runCryptoCorrectnessTest } from './integration/08-crypto-correctness.test.js';

interface TestSuite {
  name: string;
  run: () => Promise<void>;
  requiresServices?: boolean;
}

const testSuites: TestSuite[] = [
  {
    name: 'Graceful Degradation',
    run: runGracefulDegradationTest,
    requiresServices: false
  },
  {
    name: 'Basic Token Transfer',
    run: runBasicTransferTest,
    requiresServices: false // Works in fallback mode
  },
  {
    name: 'Double-Spend Detection',
    run: runDoubleSpendTest,
    requiresServices: false // Works in fallback mode
  },
  {
    name: 'Phase 3 Advanced Features',
    run: runPhase3Tests,
    requiresServices: false // Works in fallback mode
  },
  {
    name: 'Phase 3 CLI Operations',
    run: runPhase3CLITests,
    requiresServices: false // Works in fallback mode
  },
  {
    name: 'Spam Mitigation (Security)',
    run: runSpamMitigationTest,
    requiresServices: false // Tests security features
  },
  {
    name: 'Security Hardening (Phase 1)',
    run: runSecurityHardeningTest,
    requiresServices: false // Tests multi-gateway, peer diversity, and subnet checks
  },
  {
    name: 'Cryptographic Correctness',
    run: runCryptoCorrectnessTest,
    requiresServices: false // Pure crypto tests, no external services
  }
];

async function main() {
  console.log('\n' + '█'.repeat(60));
  console.log('SCARCITY INTEGRATION TEST SUITE');
  console.log('█'.repeat(60));

  // Check service availability
  // Uses TestConfig from test-utils.ts to check configured URLs (env vars or defaults)
  const services = await checkServices();

  const results: { name: string; passed: boolean; error?: string }[] = [];
  let totalPassed = 0;
  let totalFailed = 0;

  // Run each test suite
  for (const suite of testSuites) {
    console.log('\n' + '━'.repeat(60));
    console.log(`Running: ${suite.name}`);
    console.log('━'.repeat(60));

    try {
      await suite.run();
      results.push({ name: suite.name, passed: true });
      totalPassed++;
    } catch (error: any) {
      results.push({
        name: suite.name,
        passed: false,
        error: error.message
      });
      totalFailed++;
      console.error(`\n❌ Test suite "${suite.name}" failed:`, error.message);
    }
  }

  // Print final summary
  console.log('\n' + '█'.repeat(60));
  console.log('FINAL RESULTS');
  console.log('█'.repeat(60));

  results.forEach(result => {
    if (result.passed) {
      console.log(`✅ ${result.name}`);
    } else {
      console.log(`❌ ${result.name}: ${result.error}`);
    }
  });

  console.log('\n' + '─'.repeat(60));
  console.log(`Total Suites: ${results.length}`);
  console.log(`Passed: ${totalPassed}`);
  console.log(`Failed: ${totalFailed}`);
  console.log(
    `Pass Rate: ${results.length > 0 ? ((totalPassed / results.length) * 100).toFixed(1) : 0}%`
  );
  console.log('─'.repeat(60));

  if (totalFailed > 0) {
    console.log('\n❌ Some tests failed\n');
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed!\n');
    process.exit(0);
  }
}

// Run tests
main().catch((error) => {
  console.error('\n💥 Fatal error running tests:', error);
  process.exit(1);
});