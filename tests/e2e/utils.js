/**
 * ARC Tauri Desktop Migration & Threat Intelligence Dashboard
 * E2E Test Suite - Shared Utilities & Helpers
 *
 * Opaque-box requirement-driven testing helpers using standard Node.js libraries.
 * Zero external npm dependencies.
 */

const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

/**
 * Resolve project root and critical directory paths
 */
function resolveProjectPaths(customRoot = null) {
  const rootDir = customRoot || path.resolve(__dirname, '..', '..');
  const frontendDir = path.join(rootDir, 'ARC_Complete_Documentation', 'frontend');
  const frontendSrc = path.join(frontendDir, 'src');
  const frontendBuild = path.join(frontendDir, 'build');
  const frontendPackageJson = path.join(frontendDir, 'package.json');
  const srcTauriDir = path.join(rootDir, 'src-tauri');
  const tauriConf = path.join(srcTauriDir, 'tauri.conf.json');
  const cargoToml = path.join(srcTauriDir, 'Cargo.toml');
  const mainRs = path.join(srcTauriDir, 'src', 'main.rs');
  
  // Potential binary locations
  const isWindows = process.platform === 'win32';
  const exeExt = isWindows ? '.exe' : '';
  const possibleBinaries = [
    path.join(srcTauriDir, 'target', 'release', `arc${exeExt}`),
    path.join(srcTauriDir, 'target', 'release', `arc-desktop${exeExt}`),
    path.join(srcTauriDir, 'target', 'release', `app${exeExt}`),
    path.join(srcTauriDir, 'target', 'debug', `arc${exeExt}`),
    path.join(srcTauriDir, 'target', 'debug', `arc-desktop${exeExt}`),
    path.join(rootDir, 'target', 'release', `arc${exeExt}`),
    path.join(rootDir, 'target', 'debug', `arc${exeExt}`)
  ];

  return {
    rootDir,
    frontendDir,
    frontendSrc,
    frontendBuild,
    frontendPackageJson,
    srcTauriDir,
    tauriConf,
    cargoToml,
    mainRs,
    possibleBinaries,
    isWindows
  };
}

/**
 * Safe file reader
 */
function readFileSafe(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const stats = fs.statSync(filePath);
      if (stats.isFile()) {
        return fs.readFileSync(filePath, 'utf-8');
      }
    }
  } catch (err) {
    return null;
  }
  return null;
}

/**
 * Safe JSON reader
 */
function readJsonSafe(filePath) {
  try {
    const content = readFileSafe(filePath);
    if (content) {
      return JSON.parse(content);
    }
  } catch (err) {
    return null;
  }
  return null;
}

/**
 * Recursive directory scanner
 */
function scanDirectory(dirPath, filterFn = null, results = []) {
  if (!fs.existsSync(dirPath)) return results;
  try {
    const stats = fs.statSync(dirPath);
    if (!stats.isDirectory()) return results;

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'target') {
        continue; // Skip heavy directories unless specifically requested
      }
      if (entry.isDirectory()) {
        scanDirectory(fullPath, filterFn, results);
      } else if (entry.isFile()) {
        if (!filterFn || filterFn(fullPath, entry.name)) {
          results.push(fullPath);
        }
      }
    }
  } catch (err) {
    // Ignore access errors on forbidden paths
  }
  return results;
}

/**
 * Check for forbidden geographical map patterns (Negative Map Requirement)
 * Searches for leaflet, mapbox, openlayers, world-map, geo-map, gis, google-maps
 */
const FORBIDDEN_MAP_KEYWORDS = [
  'leaflet',
  'mapbox',
  'openlayers',
  'world-map',
  'world_map',
  'worldmap',
  'geo-map',
  'geomap',
  'geographical-map',
  'endpoint-status-map',
  'gis-view',
  'react-simple-maps',
  'google-maps',
  'googlemaps',
  'cartodb',
  'openstreetmap'
];

function scanForForbiddenMapTerms(target) {
  if (!target) return [];

  // If target is a path that exists on filesystem
  if (typeof target === 'string' && fs.existsSync(target)) {
    try {
      const stats = fs.statSync(target);
      if (stats.isDirectory()) {
        const files = scanDirectory(target);
        const aggregated = [];
        for (const file of files) {
          const fileViolations = scanForForbiddenMapTerms(file);
          if (fileViolations.length > 0) {
            aggregated.push({ file, violations: fileViolations });
          }
        }
        return aggregated;
      } else if (stats.isFile()) {
        const content = readFileSafe(target);
        return scanContentForForbiddenMapTerms(content, target);
      }
    } catch (e) {
      return [];
    }
  }

  // If target is raw string content
  return scanContentForForbiddenMapTerms(String(target), null);
}

function scanContentForForbiddenMapTerms(content, filePath = null) {
  if (!content) return [];
  const foundViolations = [];
  const lowerContent = content.toLowerCase();

  for (const keyword of FORBIDDEN_MAP_KEYWORDS) {
    if (lowerContent.includes(keyword)) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].toLowerCase().includes(keyword)) {
          foundViolations.push({
            keyword,
            filePath,
            lineNumber: i + 1,
            lineSnippet: lines[i].trim()
          });
        }
      }
    }
  }

  return foundViolations;
}

/**
 * Lightweight selector / DOM string scanner
 */
function queryInDomOrSource(content, selector) {
  if (!content) return false;
  
  if (selector.startsWith('#')) {
    const id = selector.slice(1);
    const idRegex = new RegExp(`id=["']${id}["']|id:\\s*["']${id}["']`, 'i');
    return idRegex.test(content);
  } else if (selector.startsWith('.')) {
    const className = selector.slice(1);
    const classRegex = new RegExp(`className=["'][^"']*\\b${className}\\b[^"']*["']|class=["'][^"']*\\b${className}\\b[^"']*["']`, 'i');
    return classRegex.test(content);
  } else if (selector.startsWith('[data-testid=')) {
    const match = selector.match(/\[data-testid=["']?([^"']+)["']?\]/);
    if (match) {
      const testId = match[1];
      const testIdRegex = new RegExp(`data-testid=["']${testId}["']`, 'i');
      return testIdRegex.test(content);
    }
  }
  return content.includes(selector);
}

/**
 * Locate desktop executable binary if already compiled
 */
function findDesktopExecutable(paths) {
  for (const binaryPath of paths.possibleBinaries) {
    if (fs.existsSync(binaryPath)) {
      try {
        const stats = fs.statSync(binaryPath);
        if (stats.isFile() && stats.size > 0) {
          return {
            path: binaryPath,
            size: stats.size,
            mtime: stats.mtime
          };
        }
      } catch (e) {
        // ignore
      }
    }
  }
  return null;
}

/**
 * Check if a file or directory exists
 */
function exists(p) {
  try {
    return fs.existsSync(p);
  } catch (e) {
    return false;
  }
}

module.exports = {
  resolveProjectPaths,
  readFileSafe,
  readJsonSafe,
  scanDirectory,
  FORBIDDEN_MAP_KEYWORDS,
  scanForForbiddenMapTerms,
  queryInDomOrSource,
  findDesktopExecutable,
  exists
};
