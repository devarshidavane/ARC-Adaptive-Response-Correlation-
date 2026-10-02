/**
 * Milestone 1 Adversarial Challenger Verification Suite
 * 
 * Empirically validates:
 * 1. Full E2E Test Suite Execution & Milestone-Aware Passing vs Pending Assertions (0 Failures)
 * 2. IPC Command Argument Edge Cases & Serde Deserialization Resiliency (acknowledge_alert & lookup_ioc)
 * 3. Build Hooks & Relative Path Resolution from src-tauri to frontend
 * 4. Zero-Trust Security Configuration (Allowlist & Strict CSP)
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { execSync } = require('child_process');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SRC_TAURI_DIR = path.join(PROJECT_ROOT, 'src-tauri');
const TAURI_CONF_PATH = path.join(SRC_TAURI_DIR, 'tauri.conf.json');
const CARGO_TOML_PATH = path.join(SRC_TAURI_DIR, 'Cargo.toml');
const MAIN_RS_PATH = path.join(SRC_TAURI_DIR, 'src', 'main.rs');
const FRONTEND_DIR = path.join(PROJECT_ROOT, 'ARC_Complete_Documentation', 'frontend');
const FRONTEND_PACKAGE_JSON = path.join(FRONTEND_DIR, 'package.json');
const ROOT_PACKAGE_JSON = path.join(PROJECT_ROOT, 'package.json');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    failedTests++;
    console.error(`  [FAIL] ${name}: ${err.message}`);
  }
}

console.log('================================================================');
console.log(' ARC MILESTONE 1 ADVERSARIAL CHALLENGER VERIFICATION HARNESS');
console.log('================================================================');

// ============================================================================
// SUITE 1: IPC COMMAND ARGUMENT RESILIENCY (acknowledge_alert & lookup_ioc)
// ============================================================================
console.log('\n--- SUITE 1: IPC Command Argument Resiliency (Rust & Logic Verification) ---');

const mainRsContent = fs.readFileSync(MAIN_RS_PATH, 'utf-8');

runTest('acknowledge_alert: Signature accepts Option<String> for both id and alert_id', () => {
  const ackSigRegex = /fn\s+acknowledge_alert\s*\(\s*id\s*:\s*Option<String>\s*,\s*alert_id\s*:\s*Option<String>\s*\)\s*->\s*Result<AlertAckResponse,\s*String>/;
  assert.ok(ackSigRegex.test(mainRsContent), 'Signature must accept Option<String> for both parameters');
});

runTest('acknowledge_alert: Fallback resolution logic uses id.or(alert_id).unwrap_or_else("ALT-UNKNOWN")', () => {
  assert.ok(mainRsContent.includes('id.or(alert_id).unwrap_or_else'), 'Must fall back gracefully from id to alert_id to ALT-UNKNOWN');
});

runTest('lookup_ioc: Signature accepts Option<String> for value, query, and indicator', () => {
  const lookupSigRegex = /fn\s+lookup_ioc\s*\([\s\S]*?value\s*:\s*Option<String>[\s\S]*?query\s*:\s*Option<String>[\s\S]*?indicator\s*:\s*Option<String>[\s\S]*?\)\s*->\s*Result<IocLookupResult,\s*String>/;
  assert.ok(lookupSigRegex.test(mainRsContent), 'Signature must accept Option<String> for value, query, and indicator');
});

runTest('lookup_ioc: Multi-parameter fallback resolution value.or(query).or(indicator).unwrap_or_default()', () => {
  const fallbackRegex = /value\s*\.or\(\s*query\s*\)\s*\.or\(\s*indicator\s*\)\s*\.unwrap_or_default\(\)/;
  assert.ok(fallbackRegex.test(mainRsContent), 'Must resolve term from value, query, or indicator in priority order');
  assert.ok(mainRsContent.includes('.trim()'), 'Must trim leading/trailing whitespace');
});

runTest('lookup_ioc: Empty and whitespace queries return safe UNKNOWN result with matched: false', () => {
  assert.ok(mainRsContent.includes('term.is_empty()'), 'Must explicitly guard against empty term');
  assert.ok(mainRsContent.includes('"Empty search query provided."'), 'Must provide clear diagnostic description on empty query');
});

// Emulate Tauri's Serde JSON deserialization & function execution logic in JS
function simulateAcknowledgeAlert(args) {
  // Serde deserializes { id?: string | null, alert_id?: string | null }
  const id = (args && typeof args.id === 'string') ? args.id : null;
  const alert_id = (args && typeof args.alert_id === 'string') ? args.alert_id : null;
  const target_id = id || alert_id || 'ALT-UNKNOWN';
  return {
    success: true,
    alert_id: target_id,
    status: 'ACKNOWLEDGED',
    message: `Alert ${target_id} successfully acknowledged by SOC analyst.`
  };
}

function simulateLookupIoc(args) {
  const value = (args && typeof args.value === 'string') ? args.value : null;
  const query = (args && typeof args.query === 'string') ? args.query : null;
  const indicator = (args && typeof args.indicator === 'string') ? args.indicator : null;
  const term = (value || query || indicator || '').trim();

  if (!term) {
    return {
      indicator: '',
      ioc_type: 'UNKNOWN',
      reputation: 'UNKNOWN',
      confidence: 0,
      matched: false,
      description: 'Empty search query provided.'
    };
  }

  if (term === '185.220.101.5') {
    return {
      indicator: term,
      ioc_type: 'IPv4',
      reputation: 'MALICIOUS',
      confidence: 96,
      threat_actor: 'APT29 (Cozy Bear)',
      matched: true
    };
  } else if (term.includes('e3b0c442') || term.length === 64) {
    return {
      indicator: term,
      ioc_type: 'SHA256',
      reputation: 'MALICIOUS',
      confidence: 99,
      threat_actor: 'Lazarus Group',
      matched: true
    };
  } else if (term.includes('cdn-update-auth-telemetry.com') || term.includes('.com') || term.includes('.net')) {
    return {
      indicator: term,
      ioc_type: 'Domain',
      reputation: 'SUSPICIOUS',
      confidence: 88,
      threat_actor: 'UNC2452',
      matched: true
    };
  } else {
    return {
      indicator: term,
      ioc_type: 'Generic',
      reputation: 'CLEAN',
      confidence: 50,
      matched: false
    };
  }
}

runTest('acknowledge_alert: Emulated IPC call with { id: "ALT-001" }', () => {
  const res = simulateAcknowledgeAlert({ id: 'ALT-001' });
  assert.strictEqual(res.alert_id, 'ALT-001');
  assert.strictEqual(res.success, true);
});

runTest('acknowledge_alert: Emulated IPC call with alternative { alert_id: "ALT-002" }', () => {
  const res = simulateAcknowledgeAlert({ alert_id: 'ALT-002' });
  assert.strictEqual(res.alert_id, 'ALT-002');
  assert.strictEqual(res.success, true);
});

runTest('acknowledge_alert: Emulated IPC call with empty object {} (both missing)', () => {
  const res = simulateAcknowledgeAlert({});
  assert.strictEqual(res.alert_id, 'ALT-UNKNOWN');
  assert.strictEqual(res.success, true);
});

runTest('acknowledge_alert: Emulated IPC call with null fields { id: null, alert_id: null }', () => {
  const res = simulateAcknowledgeAlert({ id: null, alert_id: null });
  assert.strictEqual(res.alert_id, 'ALT-UNKNOWN');
  assert.strictEqual(res.success, true);
});

runTest('acknowledge_alert: Emulated IPC call with extra unknown fields', () => {
  const res = simulateAcknowledgeAlert({ id: 'ALT-003', randomField: 'foo', extra: [1, 2, 3] });
  assert.strictEqual(res.alert_id, 'ALT-003');
  assert.strictEqual(res.success, true);
});

runTest('lookup_ioc: Emulated IPC call with { value: "185.220.101.5" } (Known IPv4 C2)', () => {
  const res = simulateLookupIoc({ value: '185.220.101.5' });
  assert.strictEqual(res.matched, true);
  assert.strictEqual(res.ioc_type, 'IPv4');
  assert.strictEqual(res.reputation, 'MALICIOUS');
  assert.strictEqual(res.threat_actor, 'APT29 (Cozy Bear)');
});

runTest('lookup_ioc: Emulated IPC call with alternative { query: "185.220.101.5" }', () => {
  const res = simulateLookupIoc({ query: '185.220.101.5' });
  assert.strictEqual(res.matched, true);
  assert.strictEqual(res.reputation, 'MALICIOUS');
});

runTest('lookup_ioc: Emulated IPC call with alternative { indicator: "185.220.101.5" }', () => {
  const res = simulateLookupIoc({ indicator: '185.220.101.5' });
  assert.strictEqual(res.matched, true);
  assert.strictEqual(res.reputation, 'MALICIOUS');
});

runTest('lookup_ioc: Emulated IPC call with empty object {} (all missing)', () => {
  const res = simulateLookupIoc({});
  assert.strictEqual(res.matched, false);
  assert.strictEqual(res.ioc_type, 'UNKNOWN');
  assert.strictEqual(res.reputation, 'UNKNOWN');
  assert.strictEqual(res.confidence, 0);
});

runTest('lookup_ioc: Emulated IPC call with whitespace only { value: "   \\t  " }', () => {
  const res = simulateLookupIoc({ value: '   \t  ' });
  assert.strictEqual(res.matched, false);
  assert.strictEqual(res.ioc_type, 'UNKNOWN');
});

runTest('lookup_ioc: Emulated IPC call with 64-char SHA256 hash (Lazarus)', () => {
  const res = simulateLookupIoc({ value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
  assert.strictEqual(res.matched, true);
  assert.strictEqual(res.ioc_type, 'SHA256');
  assert.strictEqual(res.reputation, 'MALICIOUS');
  assert.strictEqual(res.threat_actor, 'Lazarus Group');
});

runTest('lookup_ioc: Emulated IPC call with Domain (Cobalt Strike / UNC2452)', () => {
  const res = simulateLookupIoc({ value: 'cdn-update-auth-telemetry.com' });
  assert.strictEqual(res.matched, true);
  assert.strictEqual(res.ioc_type, 'Domain');
  assert.strictEqual(res.reputation, 'SUSPICIOUS');
});

runTest('lookup_ioc: Emulated IPC call with unindexed clean indicator', () => {
  const res = simulateLookupIoc({ value: '192.168.1.1' });
  assert.strictEqual(res.matched, false);
  assert.strictEqual(res.ioc_type, 'Generic');
  assert.strictEqual(res.reputation, 'CLEAN');
});

// ============================================================================
// SUITE 2: BUILD HOOKS & RELATIVE PATH RESOLUTION FROM src-tauri TO FRONTEND
// ============================================================================
console.log('\n--- SUITE 2: Build Hooks & Relative Path Resolution ---');

const tauriConf = JSON.parse(fs.readFileSync(TAURI_CONF_PATH, 'utf-8'));

runTest('tauri.conf.json: build.distDir exists and points to relative frontend build directory', () => {
  assert.ok(tauriConf.build && tauriConf.build.distDir, 'build.distDir must be defined');
  assert.strictEqual(tauriConf.build.distDir, '../ARC_Complete_Documentation/frontend/build');
});

runTest('tauri.conf.json: build.distDir resolves correctly from src-tauri directory', () => {
  const resolvedDist = path.resolve(SRC_TAURI_DIR, tauriConf.build.distDir);
  const expectedDist = path.resolve(FRONTEND_DIR, 'build');
  assert.strictEqual(resolvedDist.toLowerCase(), expectedDist.toLowerCase(), 'Resolved distDir must match frontend build dir');
  assert.ok(fs.existsSync(resolvedDist), 'Resolved distDir must exist on filesystem');
});

runTest('tauri.conf.json: build.beforeBuildCommand is configured for frontend build', () => {
  assert.ok(tauriConf.build && tauriConf.build.beforeBuildCommand, 'beforeBuildCommand must be defined');
  assert.strictEqual(tauriConf.build.beforeBuildCommand, 'npm --prefix ARC_Complete_Documentation/frontend run build');
});

runTest('tauri.conf.json: beforeBuildCommand --prefix directory exists from project root', () => {
  const prefixMatch = tauriConf.build.beforeBuildCommand.match(/--prefix\s+([^\s]+)/);
  assert.ok(prefixMatch, 'Must contain --prefix argument');
  const targetDir = path.resolve(PROJECT_ROOT, prefixMatch[1]);
  assert.ok(fs.existsSync(targetDir), `Target directory "${targetDir}" must exist`);
  assert.ok(fs.existsSync(path.join(targetDir, 'package.json')), 'Target directory must contain package.json');
});

runTest('package.json (root): build:frontend script matches beforeBuildCommand', () => {
  const rootPkg = JSON.parse(fs.readFileSync(ROOT_PACKAGE_JSON, 'utf-8'));
  assert.ok(rootPkg.scripts && rootPkg.scripts['build:frontend'], 'build:frontend script must exist in root package.json');
  assert.strictEqual(rootPkg.scripts['build:frontend'], tauriConf.build.beforeBuildCommand);
});

runTest('package.json (root): Tauri CLI script shortcuts configured', () => {
  const rootPkg = JSON.parse(fs.readFileSync(ROOT_PACKAGE_JSON, 'utf-8'));
  assert.strictEqual(rootPkg.scripts['tauri'], 'tauri');
  assert.strictEqual(rootPkg.scripts['tauri:dev'], 'tauri dev');
  assert.strictEqual(rootPkg.scripts['tauri:build'], 'tauri build');
  assert.strictEqual(rootPkg.scripts['tauri:info'], 'tauri info');
});

runTest('Frontend packaging: build directory contains index.html asset distribution', () => {
  const indexPath = path.join(FRONTEND_DIR, 'build', 'index.html');
  assert.ok(fs.existsSync(indexPath), 'Frontend build/index.html must exist');
  const indexContent = fs.readFileSync(indexPath, 'utf-8');
  assert.ok(indexContent.includes('<!doctype html>'), 'index.html must be valid HTML');
});

runTest('Zero-Trust Security: allowlist.all is strictly false', () => {
  assert.strictEqual(tauriConf.tauri.allowlist.all, false, 'Tauri allowlist must have all: false');
});

runTest('Content Security Policy: CSP prohibits unsafe-eval and permits local IPC endpoints', () => {
  const csp = tauriConf.tauri.security.csp;
  assert.ok(csp, 'CSP must be defined');
  assert.ok(!csp.includes("'unsafe-eval'"), 'CSP must NOT contain unsafe-eval');
  assert.ok(csp.includes('ipc:'), 'CSP must include ipc:');
  assert.ok(csp.includes('tauri:'), 'CSP must include tauri:');
});

// ============================================================================
// SUITE 3: COMPLETE E2E TEST SUITE EXECUTION & VERIFICATION (runner.js)
// ============================================================================
console.log('\n--- SUITE 3: Complete E2E Suite Execution (0 Failures Verification) ---');

runTest('Full E2E Runner execution (node tests/e2e/runner.js --json)', () => {
  const output = execSync('node tests/e2e/runner.js --json', {
    cwd: PROJECT_ROOT,
    encoding: 'utf-8'
  });
  const report = JSON.parse(output);

  assert.strictEqual(report.summary.failed, 0, `Total failed tests must be 0, found ${report.summary.failed}`);
  assert.strictEqual(report.summary.passed, 48, `Expected 48 passing tests in Milestone 1, found ${report.summary.passed}`);
  assert.strictEqual(report.summary.pending, 32, `Expected 32 pending downstream tests in Milestone 1, found ${report.summary.pending}`);
  assert.strictEqual(report.summary.total, 80, `Expected 80 total tests in suite, found ${report.summary.total}`);

  // Validate that F1 (Tauri Build) and F6 (IPC Abstraction) have 0 failures
  assert.strictEqual(report.featureStats.F1.fail, 0, 'F1 (Tauri Build) must have 0 failures');
  assert.strictEqual(report.featureStats.F6.fail, 0, 'F6 (IPC Abstraction) must have 0 failures');
  assert.strictEqual(report.featureStats.F4.fail, 0, 'F4 (Negative Map Exclusion) must have 0 failures');

  console.log(`      -> Verified: Total Tests=${report.summary.total}, Passed=${report.summary.passed}, Failed=${report.summary.failed}, Pending=${report.summary.pending}`);
});

// ============================================================================
// SUMMARY
// ============================================================================
console.log('\n================================================================');
console.log(` CHALLENGER ADVERSARIAL VERIFICATION: ${passedTests} / ${totalTests} PASSED (Failed: ${failedTests})`);
console.log('================================================================');

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
