// bench/bench.ts
// run: npm run bench
import os from 'node:os';
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { createFirewall } from '../src/astFirewall';
import { sqlFirewall } from '../src/index';
import { ATTACK_LIST, LEGIT, WORST_SHAPES } from '../test/corpus';
import { MUTATORS, rng } from '../test/mutators';

const RUNS = Number(process.env.FW_RUNS ?? 50_000);
const TRIALS = Number(process.env.FW_TRIALS ?? 5);
const BUDGET_P99 = Number(process.env.FW_P99_BUDGET_MS ?? 5); // normal queries (ms)
const BUDGET_WORST = Number(process.env.FW_WORST_BUDGET_MS ?? 100); // pathological inputs (ms)

// ---------------------------------------------------------------------------
// Corpus: your legit and attack queries plus 3 seeded mutations of each
// ---------------------------------------------------------------------------
function variants(list: string[], seed: number): string[] {
  const r = rng(seed);
  const ms = Object.values(MUTATORS);
  const out = [...list];
  for (const s of list) {
    for (let k = 0; k < 3; k++) out.push(ms[Math.floor(r() * ms.length)](s, r));
  }
  return out;
}
const legit = variants(LEGIT, 1);
const attacks = variants(ATTACK_LIST.map((a) => a.sql).filter((s) => s.length < 4000), 2);
const mixed = [...legit, ...attacks];

const fw = createFirewall(); // cache OFF, so every call does real work
const mw = sqlFirewall({ onAudit: () => {} });
const res: any = { locals: {}, headersSent: false, setHeader() {}, status() { return this; }, json() { return this; } };

// ---------------------------------------------------------------------------
// Measuring helpers
// ---------------------------------------------------------------------------
function measure(fn: (i: number) => void, runs: number, warm: number) {
  for (let i = 0; i < warm; i++) fn(i);
  const s = new Float64Array(runs);
  for (let i = 0; i < runs; i++) {
    const t = performance.now();
    fn(i);
    s[i] = performance.now() - t;
  }
  s.sort();
  const q = (p: number) => s[Math.min(runs - 1, Math.floor(runs * p))];
  return { p50: q(0.5), p95: q(0.95), p99: q(0.99), p999: q(0.999), max: s[runs - 1] };
}

const med = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const r3 = (x: number) => Number(x.toFixed(4));

const rows: any[] = [];

function scenario(
  name: string,
  fn: (i: number) => void,
  budget: number,
  runs: number = RUNS,
  warm: number = 5000,
  trials: number = TRIALS,
) {
  console.log('running', name);
  const t = Array.from({ length: trials }, () => measure(fn, runs, warm));
  const row = {
    scenario: name,
    p50: r3(med(t.map((x) => x.p50))),
    p95: r3(med(t.map((x) => x.p95))),
    p99: r3(med(t.map((x) => x.p99))),
    p999: r3(med(t.map((x) => x.p999))),
    max: r3(Math.max(...t.map((x) => x.max))),
    worstTrialP99: r3(Math.max(...t.map((x) => x.p99))),
    budgetMs: budget,
  };
  rows.push(row);
  return row;
}

// ---------------------------------------------------------------------------
// 1) Core engine on realistic traffic
// ---------------------------------------------------------------------------
scenario('core/legit', (i) => { fw.evaluate(legit[i % legit.length]); }, BUDGET_P99);
scenario('core/attacks', (i) => { fw.evaluate(attacks[i % attacks.length]); }, BUDGET_P99);
scenario('core/mixed', (i) => { fw.evaluate(mixed[i % mixed.length]); }, BUDGET_P99);

// ---------------------------------------------------------------------------
// 2) How latency grows with query size (informational, no budget)
// ---------------------------------------------------------------------------
for (const target of [100, 500, 2000, 8000]) {
  const n = Math.min(250, Math.floor(target / 4));
  const w = Math.max(1, Math.floor((target - 40) / n) - 2);
  const cols = Array.from({ length: n }, (_, i) => ('c' + i).padEnd(w, 'x')).join(', ');
  const sql = `SELECT ${cols} FROM users WHERE id = $1`;
  const v = fw.evaluate(sql);
  const label = `core/len~${sql.length}${v.decision === 'allow' ? '' : ' (BLOCKED:' + (v.violations[0]?.rule ?? '?') + ')'}`;
  scenario(label, () => { fw.evaluate(sql); }, 1000, 100, 10);
}

// ---------------------------------------------------------------------------
// 3) Full middleware (hashing + audit event + res.locals), no HTTP
// ---------------------------------------------------------------------------
const reqs = mixed.map((q) => ({ body: { query: q }, headers: {}, ip: '127.0.0.1' }));
scenario('middleware/mixed', (i) => { mw(reqs[i % reqs.length] as any, res, () => {}); }, BUDGET_P99 * 2);

// ---------------------------------------------------------------------------
// 4) Pathological inputs (synchronous CPU work on the event loop)
// ---------------------------------------------------------------------------
for (const [name, sql] of Object.entries(WORST_SHAPES)) {
  scenario(`worst/${name}`, () => { fw.evaluate(sql); }, BUDGET_WORST, 50, 5, 3);
}

// ---------------------------------------------------------------------------
// 5) Throughput and heap growth
// ---------------------------------------------------------------------------
console.log('running throughput');
const gc = (globalThis as any).gc as undefined | (() => void);
if (gc) gc();
const heap0 = process.memoryUsage().heapUsed;
const N = 100_000;
const t0 = performance.now();
for (let i = 0; i < N; i++) fw.evaluate(mixed[i % mixed.length]);
const secs = (performance.now() - t0) / 1000;
if (gc) gc();
const heapGrowthMB = (process.memoryUsage().heapUsed - heap0) / 1048576;

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const meta = {
  node: process.version,
  cpu: os.cpus()[0].model,
  cores: os.cpus().length,
  platform: `${os.platform()} ${os.release()}`,
  date: new Date().toISOString(),
  runsPerTrial: RUNS,
  trials: TRIALS,
  corpus: { legit: legit.length, attacks: attacks.length, worstShapes: Object.keys(WORST_SHAPES).length },
  throughputOpsPerSec: Math.round(N / secs),
  heapGrowthMB: gc ? Number(heapGrowthMB.toFixed(2)) : 'run with --expose-gc to measure',
};

console.log(meta);
console.table(rows);
fs.writeFileSync('bench/results.json', JSON.stringify({ meta, rows }, null, 2));

const failed = rows.filter((r) => r.p99 > r.budgetMs);
if (failed.length > 0) {
  console.error('BUDGET EXCEEDED:', failed.map((f) => f.scenario));
  process.exit(1);
}