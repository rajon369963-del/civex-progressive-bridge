import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import assert from 'node:assert';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.resolve(__dirname, '../index.html');
const html = fs.readFileSync(htmlPath, 'utf-8');

console.log('======================================================================');
console.log('🧪 BROWSER JAVASCRIPT OKAPI BM25 ROUTER EXECUTION TEST');
console.log('Target Source: ' + htmlPath);
console.log('======================================================================');

// 1. Extract exact <script> tag content from index.html
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert(scriptMatch, 'FAIL: Could not find <script> tag in index.html');
const jsCode = scriptMatch[1];

// 2. Set up sandbox and execute browser code in Node VM
const sandbox = {
  console,
  performance,
  document: {
    getElementById: () => ({ textContent: '', value: '' })
  },
  window: {}
};

vm.createContext(sandbox);
const exportsObj = vm.runInContext(jsCode + "\n;({ TOOL_CATALOG, routeQuery, avgdl });", sandbox);
const routeQuery = exportsObj.routeQuery;
const TOOL_CATALOG = exportsObj.TOOL_CATALOG;
const avgdl = exportsObj.avgdl;

// 3. Verify core runtime bindings
assert(typeof routeQuery === 'function', 'FAIL: routeQuery must be exported as a function');
assert(Array.isArray(TOOL_CATALOG), 'FAIL: TOOL_CATALOG must be an array');
assert.strictEqual(TOOL_CATALOG.length, 10, 'FAIL: TOOL_CATALOG must have 10 tools');
assert(typeof avgdl === 'number', 'FAIL: avgdl must be a number');

console.log('• Browser Script Loaded Successfully.');
console.log('• Dynamic avgdl (Average Document Length): ' + avgdl.toFixed(2));
assert(avgdl >= 40.0 && avgdl <= 55.0, 'FAIL: avgdl out of expected range');

// 4. Test Curated 10 Queries (Discriminative Routing)
const curatedQueries = [
  ["publish my code changes to remote repository", "tool_git_commit_and_push"],
  ["will it rain in my city weather forecast", "tool_weather_telemetry"],
  ["scan repository for passwords and credentials", "tool_secret_scanner"],
  ["spaced repetition flashcard review for retention", "tool_fsrs5_spaced_repetition"],
  ["vectorized sql query on columnar parquet table", "tool_sql_duckdb_lake"],
  ["simd parser for json using neon acceleration", "tool_simd_fast_json"],
  ["bloom filter duplicate suppression", "tool_bloom_dedup"],
  ["pretrade margin limit gate check", "tool_risk_gate_interceptor"],
  ["render darkmode svg badge with sha digest", "tool_svg_badge_generator"],
  ["calculate electric flux using gauss divergence law", "tool_gauss_law_derivation"]
];

const matchedTools = new Set();
for (const [q, expectedId] of curatedQueries) {
  const res = routeQuery(q);
  assert.strictEqual(res.status, "MATCH_FOUND", `Query "${q}" expected MATCH_FOUND, got ${res.status}`);
  assert.strictEqual(res.tool.id, expectedId, `Query "${q}" matched ${res.tool.id}, expected ${expectedId}`);
  assert(parseFloat(res.bm25_score) > 0, `BM25 score for "${q}" must be > 0`);
  matchedTools.add(res.tool.id);
  console.log(`  ✓ Curated: "${q}" -> ${res.tool.id} (Score: ${res.bm25_score}, ${res.latency_ms}ms)`);
}
assert.strictEqual(matchedTools.size, 10, 'All 10 curated queries must uniquely match 10 distinct tools');
console.log('• Curated Suite (10/10): 100% PASS [DISCRIMINATIVE]');

// 5. Test Hard Adversarial / OOD Queries
const adversarialQueries = [
  // Issue 1: "before" in stop words ensures no false route to risk gate
  ["remind me before I forget this chapter", "tool_fsrs5_spaced_repetition"],
  // Issue 2: synonyms for rainfall/prediction route to weather
  ["tomorrow rainfall prediction", "tool_weather_telemetry"],
  // Issue 3: field weighting prioritizes weather over generic Git summary words
  ["publish weather changes", "tool_weather_telemetry"],
  // True financial pretrade check
  ["pretrade margin limits prior to order dispatch", "tool_risk_gate_interceptor"]
];

for (const [q, expectedId] of adversarialQueries) {
  const res = routeQuery(q);
  assert.strictEqual(res.tool.id, expectedId, `Adversarial "${q}" matched ${res.tool.id}, expected ${expectedId}`);
  console.log(`  ✓ Adversarial: "${q}" -> ${res.tool.id} (Score: ${res.bm25_score}, ${res.latency_ms}ms)`);
}
console.log('• Adversarial Suite (4/4): 100% PASS [ROBUST]');

// 6. Test Negative Controls (Completely out-of-domain queries must fallback to clarifier)
const negativeQueries = [
  "make delicious pancakes with sweet syrup",
  "bake tasty chocolate cookies in the kitchen"
];

for (const q of negativeQueries) {
  const res = routeQuery(q);
  assert.strictEqual(res.status, "FALLBACK_CLARIFIER", `Query "${q}" should fallback to clarifier, got ${res.status}`);
  assert.strictEqual(res.tool.id, "tool_sovereign_clarifier");
  console.log(`  ✓ Negative Control: "${q}" -> FALLBACK_CLARIFIER (Score: 0.0)`);
}
console.log('• Negative Control Suite (2/2): 100% PASS [FALLBACK]');

console.log('----------------------------------------------------------------------');
console.log('✅ VERDICT: 16/16 BROWSER JAVASCRIPT TESTS PASSED IN NODE RUNTIME.');
console.log('======================================================================\n');
