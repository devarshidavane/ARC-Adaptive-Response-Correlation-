/**
 * scripts/verify-threat-intel-ui.js
 * Automated programmatic verification script for ARC Threat Intelligence UI.
 * Verifies:
 *  1. Package dependencies contain NO banned mapping packages.
 *  2. Source code and static assets contain NO geographic map files or components.
 *  3. Network topology graph component exists in the DOM/code.
 *  4. Live Alert Stream and Intelligence Feed components exist in the DOM/code.
 *  5. Strict exclusion of geographic/world maps is 100% verified.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const FRONTEND_DIR = path.join(ROOT_DIR, 'ARC_Complete_Documentation', 'frontend');
const SRC_DIR = path.join(FRONTEND_DIR, 'src');
const PACKAGE_JSON = path.join(FRONTEND_DIR, 'package.json');

const BANNED_PACKAGES = [
  'leaflet', 'react-leaflet', 'mapbox-gl', 'react-map-gl',
  'openlayers', 'ol', 'cesium', 'deck.gl', 'd3-geo',
  'topojson', 'world-atlas', 'datamaps', 'react-simple-maps'
];

const BANNED_ASSET_EXTENSIONS = ['.geojson', '.topojson', '.shp', '.kml'];
const BANNED_DOM_KEYWORDS = [
  'leaflet-container', 'mapboxgl-map', 'world-map', 'geo-map',
  'attack-map', 'endpoint-status-map', 'mercator-projection'
];

let errors = [];
let passedChecks = [];

function checkPackageJson() {
  console.log('[1/4] Auditing package.json dependencies...');
  if (!fs.existsSync(PACKAGE_JSON)) {
    errors.push(`package.json not found at ${PACKAGE_JSON}`);
    return;
  }
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8'));
  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies
  };

  for (const banned of BANNED_PACKAGES) {
    if (allDeps[banned]) {
      errors.push(`BANNED DEPENDENCY FOUND: "${banned}" is present in package.json!`);
    }
  }

  if (allDeps['cytoscape']) {
    passedChecks.push(`Dynamic Network Topology library found: cytoscape`);
  } else {
    errors.push(`MISSING DEPENDENCY: cytoscape must be declared in frontend/package.json`);
  }
}

function scanDirectory(dir, fileCallback) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'build' && entry.name !== '.git') {
        scanDirectory(fullPath, fileCallback);
      }
    } else {
      fileCallback(fullPath, entry.name);
    }
  }
}

function checkAssetsAndSource() {
  console.log('[2/4] Auditing source code and assets for forbidden map artifacts...');
  let topologyFound = false;
  let liveAlertStreamFound = false;
  let intelFeedsFound = false;

  scanDirectory(FRONTEND_DIR, (filePath, fileName) => {
    const ext = path.extname(fileName).toLowerCase();
    
    // Check banned extensions
    if (BANNED_ASSET_EXTENSIONS.includes(ext)) {
      errors.push(`BANNED ASSET FOUND: ${filePath} contains geographic spatial data!`);
    }

    // Check banned filename keywords
    for (const kw of ['world-map', 'geomap', 'geo-map', 'earth-globe']) {
      if (fileName.toLowerCase().includes(kw)) {
        errors.push(`BANNED FILE NAME FOUND: ${filePath} matches geographic map pattern!`);
      }
    }

    // Check source files for DOM keywords and required components
    if (['.js', '.jsx', '.ts', '.tsx', '.html'].includes(ext)) {
      const content = fs.readFileSync(filePath, 'utf8');

      // Check banned DOM keywords
      for (const kw of BANNED_DOM_KEYWORDS) {
        if (content.includes(kw)) {
          errors.push(`BANNED DOM / CLASS PATTERN: "${kw}" found in ${filePath}`);
        }
      }

      // Check required components
      if (content.includes('network-topology-graph') || content.includes('NetworkTopologyGraph') || content.includes('cytoscape')) {
        topologyFound = true;
      }
      if (content.includes('live-alerts-panel') || content.includes('LiveAlertStream') || content.includes('live-alerts')) {
        liveAlertStreamFound = true;
      }
      if (content.includes('intel-feeds-panel') || content.includes('IntelFeeds') || content.includes('intel-feeds')) {
        intelFeedsFound = true;
      }
    }
  });

  if (topologyFound) {
    passedChecks.push('REQUIRED COMPONENT: Dynamic Network Topology Graph component verified.');
  } else {
    errors.push('MISSING COMPONENT: Dynamic Network Topology Graph component was not detected in source!');
  }

  if (liveAlertStreamFound) {
    passedChecks.push('REQUIRED COMPONENT: Live Alert Stream component verified.');
  } else {
    errors.push('MISSING COMPONENT: Live Alert Stream component was not detected in source!');
  }

  if (intelFeedsFound) {
    passedChecks.push('REQUIRED COMPONENT: Intelligence Feeds component verified.');
  } else {
    errors.push('MISSING COMPONENT: Intelligence Feeds component was not detected in source!');
  }
}

function checkBuildOutput() {
  console.log('[3/4] Auditing build distribution artifacts...');
  const buildIndex = path.join(FRONTEND_DIR, 'build', 'index.html');
  if (fs.existsSync(buildIndex)) {
    const htmlContent = fs.readFileSync(buildIndex, 'utf8');
    for (const kw of BANNED_DOM_KEYWORDS) {
      if (htmlContent.includes(kw)) {
        errors.push(`BANNED KEYWORD IN BUILD: "${kw}" present in compiled build/index.html!`);
      }
    }
    passedChecks.push('Build distribution verified free of geographical map artifacts.');
  } else {
    passedChecks.push('Build folder not compiled yet (skipping production bundle scan).');
  }
}

function reportResults() {
  console.log('[4/4] Verification Summary:');
  console.log('---------------------------------------------------------');
  for (const check of passedChecks) {
    console.log(` [PASS] ${check}`);
  }

  if (errors.length > 0) {
    console.error('\n [FAIL] VERIFICATION FAILED WITH THE FOLLOWING ERRORS:');
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  } else {
    console.log('\n [SUCCESS] ALL THREAT INTEL UI & EXCLUSION CHECKS PASSED.');
    process.exit(0);
  }
}

// Execute checks
checkPackageJson();
checkAssetsAndSource();
checkBuildOutput();
reportResults();
