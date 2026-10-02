const fs = require('fs');
const path = require('path');

const files = [
  'tests/e2e/tier1_feature_coverage.js',
  'tests/e2e/tier2_boundary_cases.js',
  'tests/e2e/tier3_cross_feature.js',
  'tests/e2e/tier4_real_world_scenarios.js'
];

for (const rel of files) {
  const full = path.resolve(__dirname, '..', '..', '..', rel);
  console.log(`\n=== Auditing ${rel} ===`);
  const mod = require(full);
  const testList = Object.values(mod).find(Array.isArray);

  if (!testList) {
    console.log(`Could not find exported test array in ${rel}`);
    continue;
  }

  console.log(`Found ${testList.length} test cases.`);

  for (const t of testList) {
    const fnStr = t.run.toString();
    
    // Check if the function actually has assertion logic / checks
    const hasChecks = /readFileSafe|readJsonSafe|scanDirectory|findDesktopExecutable|exists|scanForForbiddenMapTerms|queryInDomOrSource|fs\.|execSync|spawn|Buffer|JSON\.parse|IndexOf|includes|match|test/i.test(fnStr);
    const hasFail = /status:\s*['"]FAIL['"]|status:\s*ctx\.strict/i.test(fnStr);
    const returnsPass = /status:\s*['"]PASS['"]/i.test(fnStr);

    if (!hasChecks) {
      console.warn(`[WARN - NO CHECKS] ${t.id} (${t.name})`);
    }
    if (!hasFail) {
      console.warn(`[WARN - NO FAIL PATH] ${t.id} (${t.name})`);
    }

    // Check if it immediately returns PASS unconditionally
    const trimmedBody = fnStr.replace(/async\s*run\s*\([^)]*\)\s*\{/, '').trim();
    if (trimmedBody.startsWith("return { status: 'PASS'") || trimmedBody.startsWith('return { status: "PASS"')) {
      console.error(`[CRITICAL - TAUTOLOGY] ${t.id} returns PASS immediately!`);
    }
  }
}
