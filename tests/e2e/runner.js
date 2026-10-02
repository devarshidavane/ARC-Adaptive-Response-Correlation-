#!/usr/bin/env node
/**
 * ARC Tauri Desktop Migration & Threat Intelligence Dashboard
 * Comprehensive E2E Test Suite Runner (Tiers 1-4)
 *
 * Usage:
 *   node tests/e2e/runner.js [options]
 *
 * Options:
 *   --tier=<1|2|3|4>     Run tests only for the specified Tier
 *   --feature=<F1..F6>   Run tests only for the specified Feature
 *   --strict             Strict mode: fail on any PENDING milestone test
 *   --milestone=<M1..M5> Filter tests relevant up to the specified milestone
 *   --json               Output test results as structured JSON
 *   --summary            Print only summary table
 *   --help, -h           Show this help message
 *
 * Exit Codes:
 *   0: All tests passed (or passed + pending in progressive mode)
 *   1: One or more tests failed (or pending in strict mode)
 */

const path = require('path');
const { resolveProjectPaths } = require('./utils');
const { tier1Tests } = require('./tier1_feature_coverage');
const { tier2Tests } = require('./tier2_boundary_cases');
const { tier3Tests } = require('./tier3_cross_feature');
const { tier4Tests } = require('./tier4_real_world_scenarios');

// Parse CLI arguments
const args = process.argv.slice(2);
const options = {
  tier: null,
  feature: null,
  strict: false,
  milestone: null,
  json: false,
  summaryOnly: false,
  help: false
};

for (const arg of args) {
  if (arg === '--help' || arg === '-h') {
    options.help = true;
  } else if (arg === '--strict') {
    options.strict = true;
  } else if (arg === '--json') {
    options.json = true;
  } else if (arg === '--summary') {
    options.summaryOnly = true;
  } else if (arg.startsWith('--tier=')) {
    options.tier = parseInt(arg.split('=')[1], 10);
  } else if (arg.startsWith('--feature=')) {
    options.feature = arg.split('=')[1].toUpperCase();
  } else if (arg.startsWith('--milestone=')) {
    options.milestone = arg.split('=')[1].toUpperCase();
  }
}

if (options.help) {
  console.log(`
ARC E2E Test Runner (Tiers 1-4)
Requirement-Driven Opaque-Box Test Suite

Usage:
  node tests/e2e/runner.js [options]

Options:
  --tier=<1|2|3|4>      Run specific tier (Tier 1: Feature Coverage, Tier 2: Boundary, Tier 3: Pairwise, Tier 4: Real-World)
  --feature=<F1..F6>    Filter tests for specific feature (F1: Build, F2: Launch, F3: Graph, F4: Map Exclusion, F5: Alerts, F6: IPC)
  --milestone=<M1..M5>  Evaluate tests up to target milestone
  --strict              Enforce 100% PASS (treat PENDING milestone tests as FAIL)
  --json                Output results as JSON
  --summary             Output summary table only
  --help, -h            Display this help message
`);
  process.exit(0);
}

// Combine all test suites
const allTests = [
  ...tier1Tests,
  ...tier2Tests,
  ...tier3Tests,
  ...tier4Tests
];

// Apply filters
let filteredTests = allTests.filter(test => {
  if (options.tier && test.tier !== options.tier) return false;
  if (options.feature && !test.feature.includes(options.feature)) return false;
  return true;
});

// Setup context
const paths = resolveProjectPaths();
const context = {
  paths,
  strict: options.strict,
  milestone: options.milestone
};

async function main() {
  const startTime = Date.now();
  const results = [];

  if (!options.json && !options.summaryOnly) {
    console.log('='.repeat(80));
    console.log(' ARC Tauri Desktop Migration & Threat Intelligence Dashboard - E2E Suite');
    console.log('='.repeat(80));
    console.log(` Target Root:      ${paths.rootDir}`);
    console.log(` Mode:             ${options.strict ? 'STRICT (Zero Pending Allowed)' : 'PROGRESSIVE (Milestone-Aware)'}`);
    console.log(` Tests Selected:   ${filteredTests.length} / ${allTests.length}`);
    if (options.tier) console.log(` Tier Filter:      Tier ${options.tier}`);
    if (options.feature) console.log(` Feature Filter:   ${options.feature}`);
    console.log('-'.repeat(80));
  }

  for (const test of filteredTests) {
    const testStart = Date.now();
    let result;
    try {
      result = await test.run(context);
    } catch (err) {
      result = {
        status: 'FAIL',
        message: `Unexpected test runner error: ${err.message}`,
        details: { stack: err.stack }
      };
    }
    const testDuration = Date.now() - testStart;

    const testResult = {
      id: test.id,
      tier: test.tier,
      feature: test.feature,
      name: test.name,
      targetMilestone: test.targetMilestone || 'M1',
      status: result.status,
      message: result.message,
      durationMs: testDuration,
      details: result.details || null
    };

    results.push(testResult);

    if (!options.json && !options.summaryOnly) {
      const statusBadge =
        testResult.status === 'PASS'
          ? '\x1b[32m[PASS]\x1b[0m'
          : testResult.status === 'FAIL'
          ? '\x1b[31m[FAIL]\x1b[0m'
          : '\x1b[33m[PENDING]\x1b[0m';

      console.log(` ${statusBadge} ${test.id.padEnd(12)} [T${test.tier}][${test.feature.padEnd(5)}] ${test.name}`);
      if (testResult.status === 'FAIL' || (testResult.status === 'PENDING' && process.env.VERBOSE)) {
        console.log(`        \x1b[90m↳ ${testResult.message}\x1b[0m`);
      }
    }
  }

  const totalDuration = Date.now() - startTime;

  // Compute Statistics
  const total = results.length;
  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL').length;
  const pending = results.filter(r => r.status === 'PENDING').length;

  const tierStats = {
    1: { total: 0, pass: 0, fail: 0, pending: 0 },
    2: { total: 0, pass: 0, fail: 0, pending: 0 },
    3: { total: 0, pass: 0, fail: 0, pending: 0 },
    4: { total: 0, pass: 0, fail: 0, pending: 0 }
  };

  const featureStats = {
    F1: { total: 0, pass: 0, fail: 0, pending: 0 },
    F2: { total: 0, pass: 0, fail: 0, pending: 0 },
    F3: { total: 0, pass: 0, fail: 0, pending: 0 },
    F4: { total: 0, pass: 0, fail: 0, pending: 0 },
    F5: { total: 0, pass: 0, fail: 0, pending: 0 },
    F6: { total: 0, pass: 0, fail: 0, pending: 0 }
  };

  for (const r of results) {
    if (tierStats[r.tier]) {
      tierStats[r.tier].total++;
      if (r.status === 'PASS') tierStats[r.tier].pass++;
      else if (r.status === 'FAIL') tierStats[r.tier].fail++;
      else tierStats[r.tier].pending++;
    }

    for (const f of ['F1', 'F2', 'F3', 'F4', 'F5', 'F6']) {
      if (r.feature.includes(f)) {
        featureStats[f].total++;
        if (r.status === 'PASS') featureStats[f].pass++;
        else if (r.status === 'FAIL') featureStats[f].fail++;
        else featureStats[f].pending++;
      }
    }
  }

  if (options.json) {
    console.log(JSON.stringify({
      summary: {
        total,
        passed,
        failed,
        pending,
        durationMs: totalDuration,
        passRate: total > 0 ? ((passed / total) * 100).toFixed(1) + '%' : '0%'
      },
      tierStats,
      featureStats,
      results
    }, null, 2));
    process.exit(failed > 0 || (options.strict && pending > 0) ? 1 : 0);
  }

  // Print Summary Table
  console.log('\n' + '='.repeat(80));
  console.log(' E2E TEST EXECUTION SUMMARY');
  console.log('='.repeat(80));
  console.log(` Total Tests:   ${total}`);
  console.log(` Passed:        \x1b[32m${passed}\x1b[0m (${total > 0 ? ((passed / total) * 100).toFixed(1) : 0}%)`);
  console.log(` Failed:        \x1b[31m${failed}\x1b[0m`);
  console.log(` Pending Mstone:\x1b[33m${pending}\x1b[0m`);
  console.log(` Total Time:    ${(totalDuration / 1000).toFixed(2)}s`);
  console.log('-'.repeat(80));

  console.log(' Coverage by Tier:');
  console.log('   Tier 1 (Feature Coverage):        ' +
    `${tierStats[1].pass} Passed, ${tierStats[1].fail} Failed, ${tierStats[1].pending} Pending (${tierStats[1].total} Total)`);
  console.log('   Tier 2 (Boundary & Corner Cases): ' +
    `${tierStats[2].pass} Passed, ${tierStats[2].fail} Failed, ${tierStats[2].pending} Pending (${tierStats[2].total} Total)`);
  console.log('   Tier 3 (Cross-Feature Pairwise):  ' +
    `${tierStats[3].pass} Passed, ${tierStats[3].fail} Failed, ${tierStats[3].pending} Pending (${tierStats[3].total} Total)`);
  console.log('   Tier 4 (Real-World Scenarios):    ' +
    `${tierStats[4].pass} Passed, ${tierStats[4].fail} Failed, ${tierStats[4].pending} Pending (${tierStats[4].total} Total)`);
  console.log('-'.repeat(80));

  console.log(' Feature Breakdown:');
  for (const [feat, s] of Object.entries(featureStats)) {
    const featNames = {
      F1: 'Tauri Build & Compilation',
      F2: 'Desktop Launch Stability',
      F3: 'Topology Graph DOM Presence',
      F4: 'Negative Map Exclusion',
      F5: 'Live Alerts & Feeds UI',
      F6: 'Cross-Platform IPC Abstraction'
    };
    console.log(`   ${feat} (${featNames[feat].padEnd(32)}): ${s.pass} Pass / ${s.fail} Fail / ${s.pending} Pending (Total ${s.total})`);
  }
  console.log('='.repeat(80));

  if (failed > 0) {
    console.log('\x1b[31m>>> RESULT: FAILED - Detected implementation defects or regressions <<<\x1b[0m');
    process.exit(1);
  } else if (options.strict && pending > 0) {
    console.log('\x1b[31m>>> RESULT: FAILED (STRICT MODE) - Milestone prerequisites pending <<<\x1b[0m');
    process.exit(1);
  } else {
    console.log('\x1b[32m>>> RESULT: PASSED - All active requirements satisfied <<<\x1b[0m');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
