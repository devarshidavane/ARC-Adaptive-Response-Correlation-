const path = require('path');
const utils = require('../../../tests/e2e/utils');

console.log('=== Stress-Testing E2E Test Suite Integrity & Scanner Robustness ===');

// 1. Test forbidden map detector with subtle/obfuscated strings
const testStrings = [
  'const map = new Leaflet.Map();',
  'import mapboxgl from "mapbox-gl";',
  '<div className="mapboxgl-map"></div>',
  'fetch("https://tile.openstreetmap.org/1/2/3.png")',
  'const worldMap = {};',
  'endpoint-status-map container',
  'Clean React Component with Cytoscape and SOC alerts'
];

for (const s of testStrings) {
  const violations = utils.scanForForbiddenMapTerms(s);
  console.log(`Input: "${s.slice(0, 45)}..." -> Violations: ${violations.length} ${violations.length > 0 ? '(CAUGHT)' : '(CLEAN)'}`);
}

// 2. Test DOM query scanner
const sampleHtml = `
  <div id="network-topology-graph" class="network-topology-graph" data-testid="network-topology-graph">
    <canvas></canvas>
  </div>
`;
console.log('DOM Check ID: ', utils.queryInDomOrSource(sampleHtml, '#network-topology-graph'));
console.log('DOM Check Class: ', utils.queryInDomOrSource(sampleHtml, '.network-topology-graph'));
console.log('DOM Check TestId: ', utils.queryInDomOrSource(sampleHtml, '[data-testid="network-topology-graph"]'));
console.log('DOM Check Banned: ', utils.queryInDomOrSource(sampleHtml, '#world-map'));

// 3. Test PE Header inspection on invalid buffer
const badBuffer = Buffer.from('FAKE_BINARY_DATA');
const isMZ = badBuffer[0] === 0x4D && badBuffer[1] === 0x5A;
console.log('Fake binary MZ check passes? ', isMZ);
