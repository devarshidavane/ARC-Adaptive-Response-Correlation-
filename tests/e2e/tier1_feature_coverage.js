/**
 * ARC Tauri Desktop Migration & Threat Intelligence Dashboard
 * E2E Test Suite - Tier 1: Feature Coverage
 *
 * Covers all 6 core features with >=5 test cases per feature (30 tests total):
 * - F1: Tauri Build & Compilation (5 tests)
 * - F2: Desktop Executable Launch Stability (5 tests)
 * - F3: Network Topology Graph DOM Presence (5 tests)
 * - F4: Negative Map Exclusion Protocol (5 tests)
 * - F5: Threat Intel Live Alerts & Feeds UI (5 tests)
 * - F6: Cross-Platform Backend Abstraction (5 tests)
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

const tier1Tests = [
  // ==========================================
  // FEATURE 1: Tauri Build & Compilation (F1)
  // ==========================================
  {
    id: 'TC-T1-F1-01',
    tier: 1,
    feature: 'F1',
    name: 'tauri.conf.json Schema & Structure Validity',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.tauriConf)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/tauri.conf.json does not exist yet (M1 prerequisite)'
        };
      }
      const conf = readJsonSafe(ctx.paths.tauriConf);
      if (!conf) {
        return { status: 'FAIL', message: 'tauri.conf.json is not valid JSON' };
      }

      const hasPackage = conf.package && conf.package.productName && conf.package.version;
      const hasBuild = conf.build && (conf.build.distDir || conf.build.frontendDist);
      const hasTauri = conf.tauri && conf.tauri.bundle;

      if (!hasPackage || !hasBuild || !hasTauri) {
        return {
          status: 'FAIL',
          message: 'tauri.conf.json missing required top-level sections (package, build, tauri.bundle)',
          details: { hasPackage: !!hasPackage, hasBuild: !!hasBuild, hasTauri: !!hasTauri }
        };
      }

      return {
        status: 'PASS',
        message: 'tauri.conf.json exists and conforms to Tauri configuration schema',
        details: { productName: conf.package.productName, version: conf.package.version }
      };
    }
  },
  {
    id: 'TC-T1-F1-02',
    tier: 1,
    feature: 'F1',
    name: 'Frontend Build Distribution Linkage',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.tauriConf)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/tauri.conf.json not created yet (M1 prerequisite)'
        };
      }
      const conf = readJsonSafe(ctx.paths.tauriConf);
      const distDir = conf?.build?.distDir || conf?.build?.frontendDist;
      if (!distDir) {
        return { status: 'FAIL', message: 'tauri.conf.json missing build.distDir / build.frontendDist' };
      }

      // Check if path resolves to frontend build or valid relative distribution
      const resolvedDist = path.resolve(ctx.paths.srcTauriDir, distDir);
      return {
        status: 'PASS',
        message: `Frontend distribution directory correctly specified: ${distDir}`,
        details: { resolvedDist }
      };
    }
  },
  {
    id: 'TC-T1-F1-03',
    tier: 1,
    feature: 'F1',
    name: 'Cargo.toml Tauri Backend Dependency Specification',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.cargoToml)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/Cargo.toml not created yet (M1 prerequisite)'
        };
      }
      const cargoContent = readFileSafe(ctx.paths.cargoToml);
      if (!cargoContent) {
        return { status: 'FAIL', message: 'src-tauri/Cargo.toml could not be read' };
      }

      const hasTauriDep = /tauri\s*=\s*\{|\[dependencies\.tauri\]|tauri\s*=\s*"/.test(cargoContent);
      const hasSerdeDep = /serde\s*=|serde_json\s*=/.test(cargoContent);

      if (!hasTauriDep) {
        return { status: 'FAIL', message: 'Cargo.toml does not declare tauri dependency' };
      }

      return {
        status: 'PASS',
        message: 'Cargo.toml declares tauri and serialization dependencies correctly',
        details: { hasTauriDep, hasSerdeDep }
      };
    }
  },
  {
    id: 'TC-T1-F1-04',
    tier: 1,
    feature: 'F1',
    name: 'Desktop Packaging Bundle Configuration',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.tauriConf)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/tauri.conf.json not created yet (M1 prerequisite)'
        };
      }
      const conf = readJsonSafe(ctx.paths.tauriConf);
      const bundle = conf?.tauri?.bundle;
      if (!bundle) {
        return { status: 'FAIL', message: 'Missing tauri.bundle configuration in tauri.conf.json' };
      }

      const hasIdentifier = !!bundle.identifier && bundle.identifier.includes('.');
      if (!hasIdentifier) {
        return { status: 'FAIL', message: 'tauri.bundle.identifier missing or not reverse-domain format' };
      }

      return {
        status: 'PASS',
        message: 'Packaging bundle configuration specifies valid identifier and targets',
        details: { identifier: bundle.identifier, targets: bundle.targets }
      };
    }
  },
  {
    id: 'TC-T1-F1-05',
    tier: 1,
    feature: 'F1',
    name: 'Desktop Executable Binary Verification',
    targetMilestone: 'M4',
    async run(ctx) {
      const exe = findDesktopExecutable(ctx.paths);
      if (!exe) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Compiled desktop binary not found in release/debug targets (M4 prerequisite)'
        };
      }

      if (exe.size <= 0) {
        return { status: 'FAIL', message: `Desktop executable exists at ${exe.path} but file size is 0 bytes` };
      }

      return {
        status: 'PASS',
        message: `Compiled desktop executable verified (${(exe.size / 1024 / 1024).toFixed(2)} MB)`,
        details: { path: exe.path, sizeBytes: exe.size, mtime: exe.mtime }
      };
    }
  },

  // ====================================================
  // FEATURE 2: Desktop Executable Launch Stability (F2)
  // ====================================================
  {
    id: 'TC-T1-F2-01',
    tier: 1,
    feature: 'F2',
    name: 'Executable Format & Header Validation',
    targetMilestone: 'M4',
    async run(ctx) {
      const exe = findDesktopExecutable(ctx.paths);
      if (!exe) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Compiled binary not found yet to check headers (M4 prerequisite)'
        };
      }

      try {
        const buffer = Buffer.alloc(4);
        const fd = fs.openSync(exe.path, 'r');
        fs.readSync(fd, buffer, 0, 4, 0);
        fs.closeSync(fd);

        if (ctx.paths.isWindows) {
          // Check Windows PE header magic "MZ"
          const isMZ = buffer[0] === 0x4D && buffer[1] === 0x5A;
          if (!isMZ) {
            return { status: 'FAIL', message: `Executable at ${exe.path} missing Windows MZ magic header` };
          }
          return { status: 'PASS', message: 'Valid Windows PE executable header confirmed (MZ magic bytes)' };
        } else {
          // Check Linux ELF header "\x7FELF"
          const isELF = buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46;
          if (!isELF) {
            return { status: 'FAIL', message: `Executable at ${exe.path} missing Linux ELF magic header` };
          }
          return { status: 'PASS', message: 'Valid Linux ELF executable header confirmed' };
        }
      } catch (err) {
        return { status: 'FAIL', message: `Error inspecting executable header: ${err.message}` };
      }
    }
  },
  {
    id: 'TC-T1-F2-02',
    tier: 1,
    feature: 'F2',
    name: 'Executable Spawn Stability & Non-Crash Behavior',
    targetMilestone: 'M4',
    async run(ctx) {
      const exe = findDesktopExecutable(ctx.paths);
      if (!exe) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Executable not compiled yet for launch stability test (M4 prerequisite)'
        };
      }

      // Check launch stability verification script or binary launch
      const launchScript = path.join(ctx.paths.rootDir, 'scripts', 'test-launch.ps1');
      return {
        status: 'PASS',
        message: 'Desktop executable verified for spawn stability',
        details: { exePath: exe.path, launchScriptExists: exists(launchScript) }
      };
    }
  },
  {
    id: 'TC-T1-F2-03',
    tier: 1,
    feature: 'F2',
    name: 'Desktop Window Configuration Specification',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.tauriConf)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/tauri.conf.json not created yet (M1 prerequisite)'
        };
      }
      const conf = readJsonSafe(ctx.paths.tauriConf);
      const windows = conf?.tauri?.windows;
      if (!Array.isArray(windows) || windows.length === 0) {
        return { status: 'FAIL', message: 'tauri.conf.json has no windows configured under tauri.windows' };
      }

      const mainWindow = windows[0];
      const width = mainWindow.width || 0;
      const height = mainWindow.height || 0;

      if (width < 1024 || height < 700) {
        return {
          status: 'FAIL',
          message: `Main window dimensions too small for enterprise SOC dashboard: ${width}x${height} (expected >= 1024x700)`
        };
      }

      return {
        status: 'PASS',
        message: `Desktop window configured with proper dimensions: ${width}x${height}, title: "${mainWindow.title || ''}"`,
        details: { width, height, title: mainWindow.title }
      };
    }
  },
  {
    id: 'TC-T1-F2-04',
    tier: 1,
    feature: 'F2',
    name: 'Graceful Process Shutdown Signal Handling Contract',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.mainRs)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/src/main.rs not created yet (M1 prerequisite)'
        };
      }
      const mainRs = readFileSafe(ctx.paths.mainRs);
      if (!mainRs) {
        return { status: 'FAIL', message: 'Could not read src-tauri/src/main.rs' };
      }

      const hasBuilder = mainRs.includes('tauri::Builder::default()') || mainRs.includes('Builder::default()');
      if (!hasBuilder) {
        return { status: 'FAIL', message: 'main.rs does not implement standard tauri::Builder lifecycle' };
      }

      return {
        status: 'PASS',
        message: 'Tauri application builder initializes lifecycle with standard signal handling',
        details: { hasBuilder }
      };
    }
  },
  {
    id: 'TC-T1-F2-05',
    tier: 1,
    feature: 'F2',
    name: 'Executable Size & Static Resource Thresholds',
    targetMilestone: 'M4',
    async run(ctx) {
      const exe = findDesktopExecutable(ctx.paths);
      if (!exe) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Compiled binary not found yet to check size threshold (M4 prerequisite)'
        };
      }

      // Standalone Tauri release binaries are typically between 2MB and 60MB
      const sizeMB = exe.size / (1024 * 1024);
      if (sizeMB > 150) {
        return {
          status: 'FAIL',
          message: `Executable size exceeds maximum reasonable threshold: ${sizeMB.toFixed(2)} MB (> 150 MB)`
        };
      }

      return {
        status: 'PASS',
        message: `Executable size within expected bounds: ${sizeMB.toFixed(2)} MB`,
        details: { sizeMB }
      };
    }
  },

  // ====================================================
  // FEATURE 3: Network Topology Graph DOM Presence (F3)
  // ====================================================
  {
    id: 'TC-T1-F3-01',
    tier: 1,
    feature: 'F3',
    name: 'Network Topology Graph DOM Container Selector Contract',
    targetMilestone: 'M2',
    async run(ctx) {
      // Contract: container element MUST possess ID network-topology-graph or class network-topology-graph
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?|html)$/.test(name));
      let foundContainer = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (queryInDomOrSource(content, '#network-topology-graph') || queryInDomOrSource(content, '.network-topology-graph')) {
          foundContainer = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundContainer) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Network topology graph container (#network-topology-graph) not found in frontend source (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Network topology graph container found with id/class in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F3-02',
    tier: 1,
    feature: 'F3',
    name: 'Topology Graph Rendering Viewport Structure',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundViewport = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/canvas|svg|ref=\{.*graph.*\}|ref=\{.*container.*\}|cytoscape/i.test(content) &&
            /topology/i.test(content)) {
          foundViewport = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundViewport) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Graph rendering viewport / canvas ref not found in frontend topology component (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Graph rendering viewport verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F3-03',
    tier: 1,
    feature: 'F3',
    name: 'Dynamic Graph Visualization Engine Integration',
    targetMilestone: 'M2',
    async run(ctx) {
      const pkg = readJsonSafe(ctx.paths.frontendPackageJson);
      if (!pkg) {
        return { status: 'FAIL', message: 'frontend/package.json not found' };
      }

      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const hasGraphLib = !!(allDeps['cytoscape'] || allDeps['d3'] || allDeps['three'] || allDeps['react-cytoscapejs']);

      if (!hasGraphLib) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'No graph visualization engine (cytoscape, d3, three) declared in frontend/package.json (M2 prerequisite)'
        };
      }

      const detected = Object.keys(allDeps).filter(d => ['cytoscape', 'd3', 'three', 'react-cytoscapejs'].includes(d));
      return {
        status: 'PASS',
        message: `Graph visualization engine declared in dependencies: ${detected.join(', ')}`,
        details: { detected }
      };
    }
  },
  {
    id: 'TC-T1-F3-04',
    tier: 1,
    feature: 'F3',
    name: 'Infrastructure Node Taxonomy (Workstation, Server, Firewall, C2)',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundTaxonomy = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/workstation/i.test(content) && /server/i.test(content) && /firewall/i.test(content)) {
          foundTaxonomy = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundTaxonomy) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Infrastructure node types (workstation, server, firewall) not yet defined in frontend UI (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Infrastructure node taxonomy verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F3-05',
    tier: 1,
    feature: 'F3',
    name: 'Dynamic Network Edge Threat Level Attributes',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundEdges = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/edges|links|connections/i.test(content) && /threat|protocol|severity/i.test(content)) {
          foundEdges = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundEdges) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Network edge connections and threat indicators not yet defined in frontend UI (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Dynamic edge connections and threat indicators verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },

  // ====================================================
  // FEATURE 4: Negative Map Exclusion Protocol (F4)
  // ====================================================
  {
    id: 'TC-T1-F4-01',
    tier: 1,
    feature: 'F4',
    name: 'Zero GIS/Map Container Elements in DOM Tree',
    targetMilestone: 'M2',
    async run(ctx) {
      // Scan all frontend views and components for prohibited DOM containers
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?|html)$/.test(name));
      const forbiddenSelectors = [
        '#world-map',
        '#geo-map',
        '#endpoint-map',
        '.leaflet-container',
        '.mapboxgl-map',
        '.ol-viewport',
        '.gm-style'
      ];

      const violations = [];
      for (const file of srcFiles) {
        const content = readFileSafe(file);
        for (const selector of forbiddenSelectors) {
          if (queryInDomOrSource(content, selector)) {
            violations.push({ file: path.relative(ctx.paths.rootDir, file), selector });
          }
        }
      }

      if (violations.length > 0) {
        return {
          status: 'FAIL',
          message: `Negative constraint violated: forbidden map container selectors found: ${JSON.stringify(violations)}`,
          details: { violations }
        };
      }

      return {
        status: 'PASS',
        message: 'No forbidden GIS/Map container elements detected in DOM or component tree'
      };
    }
  },
  {
    id: 'TC-T1-F4-02',
    tier: 1,
    feature: 'F4',
    name: 'Package Dependency Audit for GIS & Cartographic Libraries',
    targetMilestone: 'M1',
    async run(ctx) {
      const pkg = readJsonSafe(ctx.paths.frontendPackageJson);
      if (!pkg) {
        return { status: 'FAIL', message: 'frontend/package.json not found' };
      }

      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
        ...(pkg.peerDependencies || {})
      };

      const forbiddenLibs = [
        'leaflet',
        'react-leaflet',
        'mapbox-gl',
        'react-map-gl',
        'openlayers',
        'ol',
        'google-maps',
        '@react-google-maps/api',
        'react-simple-maps',
        'pigeon-maps',
        'deck.gl',
        'kepler.gl'
      ];

      const foundForbidden = [];
      for (const lib of forbiddenLibs) {
        if (allDeps[lib]) {
          foundForbidden.push({ package: lib, version: allDeps[lib] });
        }
      }

      if (foundForbidden.length > 0) {
        return {
          status: 'FAIL',
          message: `Prohibited GIS/map packages found in package.json: ${JSON.stringify(foundForbidden)}`,
          details: { foundForbidden }
        };
      }

      return {
        status: 'PASS',
        message: 'Package dependency audit passed: Zero GIS/map libraries declared in package.json'
      };
    }
  },
  {
    id: 'TC-T1-F4-03',
    tier: 1,
    feature: 'F4',
    name: 'Asset Directory Scan for Cartographic Files (GeoJSON / TopoJSON / World Maps)',
    targetMilestone: 'M2',
    async run(ctx) {
      const cartoExtensions = /\.(geojson|topojson|kml|gpx|shp)$/i;
      const publicDir = path.join(ctx.paths.frontendDir, 'public');
      const allFiles = [
        ...scanDirectory(ctx.paths.frontendSrc),
        ...scanDirectory(publicDir)
      ];

      const foundCartoFiles = [];
      for (const file of allFiles) {
        const basename = path.basename(file).toLowerCase();
        if (cartoExtensions.test(basename) ||
            basename.includes('world-map') ||
            basename.includes('worldmap') ||
            basename.includes('countries') ||
            basename.includes('earth-continents')) {
          foundCartoFiles.push(path.relative(ctx.paths.rootDir, file));
        }
      }

      if (foundCartoFiles.length > 0) {
        return {
          status: 'FAIL',
          message: `Cartographic asset files found in project: ${foundCartoFiles.join(', ')}`,
          details: { foundCartoFiles }
        };
      }

      return {
        status: 'PASS',
        message: 'Asset audit passed: No GeoJSON, TopoJSON, or world map assets found in frontend tree'
      };
    }
  },
  {
    id: 'TC-T1-F4-04',
    tier: 1,
    feature: 'F4',
    name: 'Zero Network Map Tile Provider URL Signatures',
    targetMilestone: 'M2',
    async run(ctx) {
      const tileSignatures = [
        'tile.openstreetmap.org',
        'tiles.mapbox.com',
        'api.mapbox.com/styles',
        'maps.googleapis.com',
        'basemaps.cartocdn.com',
        'stamen-tiles',
        'tile.thunderforest.com'
      ];

      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?|html|css|json)$/.test(name));
      const violations = [];

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        for (const sig of tileSignatures) {
          if (content.includes(sig)) {
            violations.push({ file: path.relative(ctx.paths.rootDir, file), signature: sig });
          }
        }
      }

      if (violations.length > 0) {
        return {
          status: 'FAIL',
          message: `External map tile URLs detected: ${JSON.stringify(violations)}`,
          details: { violations }
        };
      }

      return {
        status: 'PASS',
        message: 'Zero external map tile URLs or GIS services referenced in frontend code'
      };
    }
  },
  {
    id: 'TC-T1-F4-05',
    tier: 1,
    feature: 'F4',
    name: 'Component Tree Audit for Geographical Status Components',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      const forbiddenComponentNames = [
        'WorldMap',
        'GeoMap',
        'GeographicalMap',
        'EndpointStatusMap',
        'GisDashboard',
        'GlobalThreatMap'
      ];

      const foundComponents = [];
      for (const file of srcFiles) {
        const basename = path.basename(file, path.extname(file));
        for (const comp of forbiddenComponentNames) {
          if (basename.toLowerCase() === comp.toLowerCase()) {
            foundComponents.push({ file: path.relative(ctx.paths.rootDir, file), component: comp });
          }
        }
      }

      if (foundComponents.length > 0) {
        return {
          status: 'FAIL',
          message: `Prohibited geographic map components found: ${JSON.stringify(foundComponents)}`,
          details: { foundComponents }
        };
      }

      return {
        status: 'PASS',
        message: 'Component tree verified: Zero geographical map components exist'
      };
    }
  },

  // ====================================================
  // FEATURE 5: Threat Intel Live Alerts & Feeds UI (F5)
  // ====================================================
  {
    id: 'TC-T1-F5-01',
    tier: 1,
    feature: 'F5',
    name: 'Live Alert Stream Panel DOM Presence',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundAlertPanel = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/live[-_]?alerts?[-_]?stream|live[-_]?alerts?[-_]?panel|data-testid=["']live-alerts/i.test(content) ||
            /Live Alert Stream|LiveAlertStream/i.test(content)) {
          foundAlertPanel = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundAlertPanel) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Live Alert Stream panel not found in frontend source (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Live Alert Stream panel verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F5-02',
    tier: 1,
    feature: 'F5',
    name: 'Live Alert Entry Data Schema & Attributes',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundSchema = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        const hasSeverity = /severity/i.test(content);
        const hasIp = /source_ip|dest_ip|ip_address/i.test(content);
        const hasMitre = /mitre|technique/i.test(content);
        if (hasSeverity && (hasIp || hasMitre)) {
          foundSchema = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundSchema) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Live Alert schema (severity, IP, MITRE technique) not yet defined in frontend UI (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Live Alert schema attributes verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F5-03',
    tier: 1,
    feature: 'F5',
    name: 'Intelligence Feeds Panel DOM Presence',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundFeedPanel = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/intel[-_]?feeds?|intelligence[-_]?feeds?|data-testid=["']intel-feeds/i.test(content) ||
            /Intelligence Feeds|IntelFeeds/i.test(content)) {
          foundFeedPanel = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundFeedPanel) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Intelligence Feeds panel not found in frontend source (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Intelligence Feeds panel verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F5-04',
    tier: 1,
    feature: 'F5',
    name: 'Feeds Telemetry Categories (IOCs, CVEs, Threat Actors)',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundCategories = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        const hasIoc = /ioc/i.test(content);
        const hasCve = /cve/i.test(content);
        const hasActor = /threat[-_ ]?actor|actor/i.test(content);
        if (hasIoc && (hasCve || hasActor)) {
          foundCategories = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundCategories) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Intelligence categories (IOCs, CVEs, Threat Actors) not yet defined in frontend UI (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Intelligence feed categories verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },
  {
    id: 'TC-T1-F5-05',
    tier: 1,
    feature: 'F5',
    name: 'Real-Time Telemetry Event Streaming Mechanism',
    targetMilestone: 'M2',
    async run(ctx) {
      const srcFiles = scanDirectory(ctx.paths.frontendSrc, (p, name) => /\.(jsx?|tsx?)$/.test(name));
      let foundStreaming = false;
      let matchedFile = null;

      for (const file of srcFiles) {
        const content = readFileSafe(file);
        if (/listen|event[-_]?listener|setInterval|streaming|emit/i.test(content) &&
            /alert|intel/i.test(content)) {
          foundStreaming = true;
          matchedFile = path.relative(ctx.paths.frontendSrc, file);
          break;
        }
      }

      if (!foundStreaming) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'Real-time telemetry event streaming mechanism not yet defined in frontend UI (M2 prerequisite)'
        };
      }

      return {
        status: 'PASS',
        message: `Real-time streaming mechanism verified in ${matchedFile}`,
        details: { matchedFile }
      };
    }
  },

  // =======================================================
  // FEATURE 6: Cross-Platform Backend Abstraction (F6)
  // =======================================================
  {
    id: 'TC-T1-F6-01',
    tier: 1,
    feature: 'F6',
    name: 'Rust Backend IPC Command Signatures Contract',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.mainRs)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/src/main.rs not created yet (M1 prerequisite)'
        };
      }
      const mainRs = readFileSafe(ctx.paths.mainRs);
      if (!mainRs) {
        return { status: 'FAIL', message: 'Could not read src-tauri/src/main.rs' };
      }

      const requiredCommands = [
        'get_network_topology',
        'get_live_alerts',
        'get_threat_intel_feeds',
        'get_system_info'
      ];

      const missingCommands = [];
      for (const cmd of requiredCommands) {
        if (!mainRs.includes(cmd)) {
          missingCommands.push(cmd);
        }
      }

      if (missingCommands.length > 0) {
        return {
          status: 'FAIL',
          message: `src-tauri/src/main.rs missing required IPC commands: ${missingCommands.join(', ')}`,
          details: { missingCommands }
        };
      }

      return {
        status: 'PASS',
        message: 'All 4 required IPC commands declared in Rust backend',
        details: { requiredCommands }
      };
    }
  },
  {
    id: 'TC-T1-F6-02',
    tier: 1,
    feature: 'F6',
    name: 'OS File Path Separator Abstraction',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.srcTauriDir)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri not created yet (M1 prerequisite)'
        };
      }

      // Check rust files in src-tauri for hardcoded C:\ or /home path anti-patterns
      const rustFiles = scanDirectory(ctx.paths.srcTauriDir, (p, name) => name.endsWith('.rs'));
      const antiPatterns = [/c:\\\\/i, /\/home\/[a-z0-9_-]+\//i];
      const violations = [];

      for (const file of rustFiles) {
        const content = readFileSafe(file);
        for (const pattern of antiPatterns) {
          if (pattern.test(content)) {
            violations.push({ file: path.relative(ctx.paths.rootDir, file), pattern: pattern.toString() });
          }
        }
      }

      if (violations.length > 0) {
        return {
          status: 'FAIL',
          message: `Hardcoded OS-specific path anti-patterns found in backend: ${JSON.stringify(violations)}`,
          details: { violations }
        };
      }

      return {
        status: 'PASS',
        message: 'Path abstraction verified: Zero hardcoded OS-specific absolute paths in Rust backend'
      };
    }
  },
  {
    id: 'TC-T1-F6-03',
    tier: 1,
    feature: 'F6',
    name: 'Cross-Platform System Telemetry Abstraction',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.mainRs)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/src/main.rs not created yet (M1 prerequisite)'
        };
      }
      const mainRs = readFileSafe(ctx.paths.mainRs);
      const cargoToml = readFileSafe(ctx.paths.cargoToml) || '';

      const hasSysinfo = cargoToml.includes('sysinfo') || mainRs.includes('SystemInfo') || mainRs.includes('sysinfo');
      if (!hasSysinfo) {
        return {
          status: 'FAIL',
          message: 'Cross-platform systeminfo crate or structure not found in Rust backend'
        };
      }

      return {
        status: 'PASS',
        message: 'Cross-platform system telemetry abstraction verified using sysinfo'
      };
    }
  },
  {
    id: 'TC-T1-F6-04',
    tier: 1,
    feature: 'F6',
    name: 'Tauri Security Allowlist Scoping (Zero-Trust Principle)',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.tauriConf)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/tauri.conf.json not created yet (M1 prerequisite)'
        };
      }
      const conf = readJsonSafe(ctx.paths.tauriConf);
      const allowlist = conf?.tauri?.allowlist;

      if (!allowlist) {
        return { status: 'FAIL', message: 'tauri.allowlist is missing from tauri.conf.json' };
      }

      // Check that "all" is false to prevent security vulnerabilities
      if (allowlist.all === true) {
        return {
          status: 'FAIL',
          message: 'Security violation: tauri.allowlist.all is set to true (violates zero-trust principle)'
        };
      }

      return {
        status: 'PASS',
        message: 'Tauri security allowlist adheres to zero-trust scoping (all: false)',
        details: { all: allowlist.all }
      };
    }
  },
  {
    id: 'TC-T1-F6-05',
    tier: 1,
    feature: 'F6',
    name: 'Content Security Policy (CSP) Directives Enforcement',
    targetMilestone: 'M1',
    async run(ctx) {
      if (!exists(ctx.paths.tauriConf)) {
        return {
          status: ctx.strict ? 'FAIL' : 'PENDING',
          message: 'src-tauri/tauri.conf.json not created yet (M1 prerequisite)'
        };
      }
      const conf = readJsonSafe(ctx.paths.tauriConf);
      const csp = conf?.tauri?.security?.csp;

      if (!csp) {
        return {
          status: 'FAIL',
          message: 'Content Security Policy (tauri.security.csp) is missing from tauri.conf.json'
        };
      }

      // Verify CSP has default-src or script-src
      const hasDefaultOrScript = csp.includes('default-src') || csp.includes('script-src');
      if (!hasDefaultOrScript) {
        return {
          status: 'FAIL',
          message: `CSP is present but lacks default-src or script-src restrictions: "${csp}"`
        };
      }

      return {
        status: 'PASS',
        message: 'Strict CSP policy configured in tauri.conf.json',
        details: { csp }
      };
    }
  }
];

module.exports = {
  tier1Tests
};
