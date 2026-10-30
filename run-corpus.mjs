#!/usr/bin/env node
// run-corpus.mjs - adversarial test runner for agent-sql-firewall.
// Usage (from the project folder):  npx tsx run-corpus.mjs
//
// Policy tested: plain reads are allowed; writes are allowed only when bounded by a key
// column (like id = 1); DDL, admin commands and multi-statement queries are blocked.
// POLICY_OVERRIDES below adjusts the corpus expectations to match that policy.
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';

/* ============ YOUR FIREWALL (already connected) ============ */
const firewallModule = await import('./src/astFirewall.ts');
const evaluateSql = firewallModule.evaluateSql ?? firewallModule.default?.evaluateSql;
if (typeof evaluateSql !== 'function') {
  console.error('Could not find evaluateSql in ./src/astFirewall.ts. Paste this error to Claude.');
  process.exit(2);
}

// true = allowed to reach the database, false = blocked.
// Anything else, or a thrown error, counts as BLOCKED (fail-closed).
async function isAllowed(sql) {
  return evaluateSql(sql).decision === 'allow';
}

// Your firewall allows writes that are bounded by a key column, so these corpus cases
// are EXPECTED to be allowed. Everything else keeps the expectation written in corpus.jsonl.
const POLICY_OVERRIDES = {
  d08: 'allow', // DELETE FROM users WHERE id = 1   (bounded delete)
  d10: 'allow', // INSERT INTO users (name) VALUES ('x')
  c03: 'allow', // the same INSERT, inside a WITH
};
/* =========================================================== */

async function evaluate(input) {
  const t0 = performance.now();
  let allowed = false;
  let crashed = false;
  try {
    allowed = (await isAllowed(input)) === true;
  } catch {
    crashed = true;
  }
  return { allowed, crashed, ms: performance.now() - t0 };
}

// ---- load corpus ----
const corpusPath = process.argv[2] ?? new URL('./corpus.jsonl', import.meta.url);
const cases = readFileSync(corpusPath, 'utf8')
  .split('\n')
  .filter((line) => line.trim().length > 0)
  .map((line, i) => {
    try {
      return JSON.parse(line);
    } catch {
      console.error(`Invalid JSON on corpus line ${i + 1}`);
      process.exit(2);
    }
  });

for (const c of cases) {
  if (POLICY_OVERRIDES[c.id]) c.expect = POLICY_OVERRIDES[c.id];
}

// ---- mutations: every blocked statement must STILL be blocked after these ----
function mulberry32(seed) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(1337);
const mutators = {
  upper: (s) => s.toUpperCase(),
  lower: (s) => s.toLowerCase(),
  randomCase: (s) => [...s].map((c) => (rand() < 0.5 ? c.toUpperCase() : c.toLowerCase())).join(''),
  wideSpaces: (s) => s.replace(/ /g, ' \n\t '),
  blockCommentPrefix: (s) => `/* x */ ${s}`,
  lineCommentPrefix: (s) => `-- x\n${s}`,
  trailingSemicolon: (s) => `${s} ;`,
  trailingComment: (s) => `${s}\n-- trailing`,
};

const stats = {};
const failures = [];
const timings = [];
let crashes = 0;

async function check(c, sql, label) {
  const r = await evaluate(sql);
  if (r.crashed) crashes++;
  else timings.push(r.ms);

  const s = (stats[c.category] ??= { total: 0, bypass: 0, falsePositive: 0 });
  s.total++;

  if (c.expect === 'block' && r.allowed) {
    s.bypass++;
    failures.push({ kind: 'BYPASS', id: c.id, label, sql, why: c.why });
  }
  if (c.expect === 'allow' && !r.allowed) {
    s.falsePositive++;
    failures.push({
      kind: r.crashed ? 'CRASH ON SAFE QUERY' : 'FALSE POSITIVE',
      id: c.id,
      label,
      sql,
      why: c.why,
    });
  }
}

// warm-up pass (not counted) so timings are not dominated by JIT start-up
for (const c of cases) await evaluate(c.sql);

for (const c of cases) {
  await check(c, c.sql, 'original');
  if (c.expect === 'block') {
    const seen = new Set([c.sql]);
    for (const [name, fn] of Object.entries(mutators)) {
      const variant = fn(c.sql);
      if (seen.has(variant)) continue;
      seen.add(variant);
      await check(c, variant, `mutation:${name}`);
    }
  }
}

// ---- robustness / stress ----
const stress = [
  ['empty string', ''],
  ['null byte', 'SELECT 1\u0000; DROP TABLE users'],
  ['huge IN list (50k items)', `SELECT 1 FROM t WHERE id IN (${Array.from({ length: 50000 }, (_, i) => i).join(',')})`],
  ['deep parentheses (5k)', `SELECT ${'('.repeat(5000)}1${')'.repeat(5000)}`],
  ['1 MB comment', `SELECT 1 /* ${'x'.repeat(1_000_000)} */`],
  ['100k semicolons', ';'.repeat(100000)],
  ['100k doubled quotes', `SELECT '${"''".repeat(100000)}'`],
  ['unicode', "SELECT '日本語 🚀'"],
  ['20k unterminated block comments', '/*'.repeat(20000)],
  ['20k single quotes', "'".repeat(20001)],
  ['20k dashes (line comments)', '--'.repeat(20000)],
];
const robustness = [];
for (const [name, input] of stress) {
  console.log(`Stress case: ${name} ...`);
  const r = await evaluate(input);
  robustness.push({
    case: name,
    ms: Math.round(r.ms),
    outcome: r.crashed ? 'crashed (fail-closed, investigate)' : r.allowed ? 'allowed' : 'blocked',
    slow: r.ms > 1000 ? 'SLOW - possible ReDoS / quadratic parsing' : '',
  });
}

// non-string inputs must never be allowed
for (const bad of [undefined, null, 123, {}, true]) {
  const r = await evaluate(bad);
  if (r.allowed) failures.push({ kind: 'BYPASS', id: `type:${typeof bad}`, label: 'non-string input', sql: String(bad), why: 'type confusion' });
}

// ---- report ----
const pct = (p) => {
  const a = [...timings].sort((x, y) => x - y);
  return a.length ? a[Math.min(a.length - 1, Math.floor(p * (a.length - 1)))] : NaN;
};

console.log('\n=== RESULTS BY CATEGORY ===');
console.table(stats);

console.log('\n=== STRESS / ROBUSTNESS ===');
console.table(robustness);

console.log(
  `\nLatency over ${timings.length} calls (ms): p50=${pct(0.5).toFixed(3)}  p95=${pct(0.95).toFixed(3)}  p99=${pct(0.99).toFixed(3)}`
);
console.log('(This times your isAllowed() call on short SQL strings, not a network round trip.)');

const bypasses = failures.filter((f) => f.kind === 'BYPASS');
const others = failures.filter((f) => f.kind !== 'BYPASS');

if (failures.length) {
  console.log('\n=== FAILURES ===');
  for (const f of failures) {
    console.log(`[${f.kind}] ${f.id} (${f.label}) ${JSON.stringify(f.sql).slice(0, 140)}\n    -> ${f.why}`);
  }
}

console.log('\n=== SUMMARY ===');
console.log(`Bypasses (dangerous SQL got through): ${bypasses.length}`);
console.log(`False positives / crashes on safe SQL: ${others.length}`);
console.log(`Crashes (thrown errors, treated as blocked): ${crashes}`);
console.log(
  bypasses.length === 0 && others.length === 0
    ? 'All checks passed. Now go write nastier cases.'
    : 'Every BYPASS is a bug to fix. Add each one you find to corpus.jsonl as a permanent regression test.'
);
process.exitCode = failures.length ? 1 : 0;
