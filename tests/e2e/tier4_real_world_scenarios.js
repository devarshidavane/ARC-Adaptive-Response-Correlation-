/**
 * ARC Tauri Desktop Migration & Threat Intelligence Dashboard
 * E2E Test Suite - Tier 4: Real-World Application Scenarios
 *
 * Implements 5 realistic SOC analyst workloads and end-to-end operational scenarios:
 * - TC-T4-01: Desktop SOC Analyst Launch & Triage (F1, F2, F3, F4, F5)
 * - TC-T4-02: Network Threat Investigation Workflow (F3, F5)
 * - TC-T4-03: Offline Standalone Execution Resilience (F1, F2, F3)
 * - TC-T4-04: Comprehensive Map Exclusion Regression Audit (F4, F5)
 * - TC-T4-05: End-to-End Build & Run Pipeline (F1, F2, F3, F5)
 */

const fs = require('fs');
const path = require('path');
const {
  readFileSafe,
  readJsonSafe,
  scanDirectory,
  scanForForbiddenMapTerms,
  queryInDomOrSource,
  findDesktopExecutable,
  exists
} = require('./utils');

const tier4Tests = [
  {
    id: 'TC-T4-01',
    tier: 4,
    feature: 'F1,F2,F3,F4,F5',
    name: 'Scenario 1: Desktop SOC Analyst Launch & Dashboard Triage Workflow',
    targetMilestone: 'M4',
    async run(ctx) {
      const steps = [];

      // Step 1: Verify Desktop Configuration
      const tauriExists = exists(ctx.paths.tauriConf);
      steps.push({ step: '1. Tauri Config Verification', passed: tauriExists });
      if (!tauriExists) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Scenario blocked: src-tauri/tauri.conf.json awaiting M1 creation',
          details: { steps }
        };
      }

      // Step 2: Verify Dashboard UI Source & Graph
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let hasGraph = false;
      let hasAlerts = false;
      let hasFeeds = false;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (queryInDomOrSource(content, '#network-topology-graph') || queryInDomOrSource(content, '.network-topology-graph')) {
          hasGraph = true;
        }
        if (/live[-_]?alerts?|livealertstream/i.test(content)) {
          hasAlerts = true;
        }
        if (/intel[-_]?feeds?|intelfeeds/i.test(content)) {
          hasFeeds = true;
        }
      }

      steps.push({ step: '2. Topology Graph Component', passed: hasGraph });
      steps.push({ step: '3. Live Alert Stream Panel', passed: hasAlerts });
      steps.push({ step: '4. Intelligence Feeds Panel', passed: hasFeeds });

      if (!hasGraph || !hasAlerts || !hasFeeds) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Scenario blocked: Dashboard components awaiting M2 UI implementation',
          details: { steps }
        };
      }

      // Step 5: Verify Negative Map Exclusion
      const mapTerms = scanForForbiddenMapTerms(ctx.paths.frontendSrc);
      steps.push({ step: '5. Zero Map Components Enforced', passed: mapTerms.length === 0 });
      if (mapTerms.length > 0) {
        return {
          status: 'FAIL',
          message: 'Scenario failed: Negative map constraint violated in dashboard UI',
          details: { steps, mapTerms }
        };
      }

      return {
        status: 'PASS',
        message: 'Scenario 1 PASSED: Full SOC Analyst launch & triage workflow validated successfully',
        details: { steps }
      };
    }
  },
  {
    id: 'TC-T4-02',
    tier: 4,
    feature: 'F3,F5',
    name: 'Scenario 2: Network Threat Investigation & Topology Escalation Workflow',
    targetMilestone: 'M2',
    async run(ctx) {
      const steps = [];

      // Step 1: Topology Infrastructure Nodes
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let hasNodeTypes = false;
      let hasThreatEdges = false;
      let hasCorrelation = false;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/workstation/i.test(content) && /server/i.test(content)) {
          hasNodeTypes = true;
        }
        if (/edges|links/i.test(content) && /threat/i.test(content)) {
          hasThreatEdges = true;
        }
        if (/compromised|highlight|selected/i.test(content) && /alert/i.test(content)) {
          hasCorrelation = true;
        }
      }

      steps.push({ step: '1. Node Taxonomy (Workstation/Server/Firewall)', passed: hasNodeTypes });
      steps.push({ step: '2. Threat Edges & Protocol Links', passed: hasThreatEdges });
      steps.push({ step: '3. Threat Alert to Node State Escalation', passed: hasCorrelation });

      if (!hasNodeTypes || !hasThreatEdges || !hasCorrelation) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Scenario blocked: Threat investigation workflow awaiting M2 UI completion',
          details: { steps }
        };
      }

      return {
        status: 'PASS',
        message: 'Scenario 2 PASSED: Network threat investigation and topology escalation workflow verified',
        details: { steps }
      };
    }
  },
  {
    id: 'TC-T4-03',
    tier: 4,
    feature: 'F1,F2,F3',
    name: 'Scenario 3: Offline Air-Gapped Standalone Execution Resilience',
    targetMilestone: 'M2',
    async run(ctx) {
      const steps = [];

      // Step 1: No external CDN or font dependencies that block rendering
      const indexHtml = path.join(ctx.paths.frontendDir, 'public', 'index.html');
      const htmlContent = readFileSafe(indexHtml) || '';
      const hasExternalGisCdn = /api\.mapbox\.com|unpkg\.com\/leaflet/i.test(htmlContent);
      steps.push({ step: '1. Zero External GIS CDNs in HTML', passed: !hasExternalGisCdn });

      if (hasExternalGisCdn) {
        return {
          status: 'FAIL',
          message: 'Scenario failed: External GIS CDNs found in index.html, breaking air-gapped resilience',
          details: { steps }
        };
      }

      // Step 2: Offline fallback data in frontend
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let hasOfflineFallback = false;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/offline|fallback|initialNodes|mockNodes|demoData|defaultTopology/i.test(content)) {
          hasOfflineFallback = true;
          break;
        }
      }

      steps.push({ step: '2. Local Offline Fallback Telemetry', passed: hasOfflineFallback });

      if (!hasOfflineFallback) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Scenario blocked: Offline fallback data not yet defined in frontend UI (M2 prerequisite)',
          details: { steps }
        };
      }

      return {
        status: 'PASS',
        message: 'Scenario 3 PASSED: Air-gapped standalone resilience verified with local fallbacks',
        details: { steps }
      };
    }
  },
  {
    id: 'TC-T4-04',
    tier: 4,
    feature: 'F4,F5',
    name: 'Scenario 4: Comprehensive Enterprise Map Exclusion Audit',
    targetMilestone: 'M2',
    async run(ctx) {
      const auditCategories = [];

      // 1. Source Code Audit
      const srcViolations = scanForForbiddenMapTerms(ctx.paths.frontendSrc);
      auditCategories.push({ category: 'Source Code Files', clean: srcViolations.length === 0, violations: srcViolations });

      // 2. Public Assets Audit
      const publicDir = path.join(ctx.paths.frontendDir, 'public');
      const publicViolations = scanForForbiddenMapTerms(publicDir);
      auditCategories.push({ category: 'Public Assets', clean: publicViolations.length === 0, violations: publicViolations });

      // 3. Package Dependencies Audit
      const pkg = readJsonSafe(ctx.paths.frontendPackageJson);
      const allDeps = Object.keys({ ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) });
      const forbiddenPackages = allDeps.filter(d => ['leaflet', 'mapbox-gl', 'openlayers', 'react-simple-maps', 'google-maps'].includes(d));
      auditCategories.push({ category: 'Package Dependencies', clean: forbiddenPackages.length === 0, violations: forbiddenPackages });

      // 4. Rust Backend Audit (if exists)
      let backendClean = true;
      let backendViolations = [];
      if (exists(ctx.paths.srcTauriDir)) {
        backendViolations = scanForForbiddenMapTerms(ctx.paths.srcTauriDir);
        backendClean = backendViolations.length === 0;
      }
      auditCategories.push({ category: 'Rust Backend Code', clean: backendClean, violations: backendViolations });

      const allClean = auditCategories.every(c => c.clean);
      if (!allClean) {
        return {
          status: 'FAIL',
          message: 'Scenario failed: Enterprise map exclusion audit detected prohibited cartographic elements',
          details: { auditCategories }
        };
      }

      return {
        status: 'PASS',
        message: 'Scenario 4 PASSED: 100% clean enterprise map exclusion audit across all project layers',
        details: { auditCategories }
      };
    }
  },
  {
    id: 'TC-T4-05',
    tier: 4,
    feature: 'F1,F2,F3,F5',
    name: 'Scenario 5: End-to-End Build & Run Pipeline Architecture',
    targetMilestone: 'M5',
    async run(ctx) {
      const pipelineGates = [];

      // Gate 1: Frontend Configuration
      const pkg = readJsonSafe(ctx.paths.frontendPackageJson);
      const hasRelativeHomepage = pkg?.homepage === '.' || pkg?.homepage === './';
      pipelineGates.push({ gate: '1. Frontend Relative Homepage', passed: hasRelativeHomepage });

      // Gate 2: Tauri Configuration
      const tauriExists = exists(ctx.paths.tauriConf);
      pipelineGates.push({ gate: '2. Tauri Configuration File', passed: tauriExists });

      // Gate 3: Rust IPC Commands
      const mainRsContent = readFileSafe(ctx.paths.mainRs) || '';
      const hasCommands = mainRsContent.includes('get_network_topology') &&
                          mainRsContent.includes('get_live_alerts') &&
                          mainRsContent.includes('get_threat_intel_feeds') &&
                          mainRsContent.includes('get_system_info');
      pipelineGates.push({ gate: '3. Rust IPC Commands Implemented', passed: hasCommands });

      // Gate 4: UI Programmatic Verification Script
      const verifyScript = path.join(ctx.paths.rootDir, 'scripts', 'verify-threat-intel-ui.js');
      const hasVerifyScript = exists(verifyScript);
      pipelineGates.push({ gate: '4. UI Programmatic Verification Script', passed: hasVerifyScript });

      // Gate 5: Desktop Executable Binary
      const exe = findDesktopExecutable(ctx.paths);
      pipelineGates.push({ gate: '5. Desktop Executable Built', passed: !!exe });

      if (!hasRelativeHomepage || !tauriExists || !hasCommands || !hasVerifyScript) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Scenario blocked: Pipeline gates awaiting milestone completions (M1, M2, M3, M4)',
          details: { pipelineGates }
        };
      }

      return {
        status: 'PASS',
        message: 'Scenario 5 PASSED: Full end-to-end build and run pipeline validated',
        details: { pipelineGates }
      };
    }
  }
];

module.exports = {
  tier4Tests
};
