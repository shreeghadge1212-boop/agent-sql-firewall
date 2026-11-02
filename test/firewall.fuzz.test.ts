import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fc from 'fast-check';
import { performance } from 'node:perf_hooks';
import { createFirewall } from '../src/astFirewall';
import { WORST_SHAPES } from './corpus';
import { QUOTED, statementArb } from './mutators';

const fw = createFirewall();

// ---------------------------------------------------------------------------
// Independent oracle: written WITHOUT using the firewall's logic.
// If the firewall ALLOWS something, this oracle must agree that it is safe.
// ---------------------------------------------------------------------------
const strip = (sql: string) =>
  sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n\r]*/g, ' ')
    .split(QUOTED)
    .filter((_, i) => i % 2 === 0)
    .join(' ')
    .toLowerCase();

const ALLOWED_FIRST = new Set(['select', 'with', 'insert', 'update', 'delete', 'values']);
const FORBIDDEN_ANYWHERE = /\b(set_config|dblink|pg_\w+|lo_\w+|information_schema)\b/;

function oracle(sql: string): string | null {
  // Empty statements (leading or trailing semicolons) are harmless, so ignore them.
  const t = strip(sql).replace(/^[;\s]+|[;\s]+$/g, '');
  const first = t.match(/^[a-z_]+/)?.[0];
  if (!first || !ALLOWED_FIRST.has(first)) return 'statement type not on allow-list was ALLOWED';
  if (FORBIDDEN_ANYWHERE.test(t)) return 'blocked identifier was ALLOWED';
  if (t.includes(';')) return 'multi-statement was ALLOWED';
  const conflict = /\bon\s+conflict\b/.test(t);
  const writes =
    /\bdelete\s+from\b/.test(t) || /\bupdate\s+(only\s+)?[\w."]+(\s+(as\s+)?\w+)?\s+set\b/.test(t);
  if (writes && !conflict && !/\bwhere\b/.test(t)) return 'unbounded write was ALLOWED';
  return null;
}

function check(sql: string) {
  const v = fw.evaluate(sql);
  expect(['allow', 'block']).toContain(v.decision);
  expect(Array.isArray(v.violations)).toBe(true);
  expect(typeof v.latencyMs).toBe('number');
  expect(v.decision === 'allow').toBe(v.violations.length === 0);
  if (v.decision === 'allow') {
    const problem = oracle(sql);
    if (problem) throw new Error(`${problem}: ${JSON.stringify(sql)}`);
  }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------
const VOCAB = [
  'SELECT', 'FROM', 'WHERE', 'DELETE', 'UPDATE', 'INSERT', 'INTO', 'VALUES', 'SET', 'AND', 'OR', 'NOT',
  '=', '<>', '>', '1', '0', "'x'", 'id', 'users', 'orders', 'tenant_id', '$1', ';', '(', ')', ',', '*',
  '--', '/*', '*/', 'WITH', 'AS', 'RETURNING', 'UNION', 'JOIN', 'ON', 'IN', 'ANY', 'DROP', 'TRUNCATE',
  'TABLE', 'DO', '$$', 'CASE', 'WHEN', 'THEN', 'END', 'LIKE', 'IS', 'NULL', 'TRUE', 'pg_sleep', 'now()',
  'count(*)', 'ON CONFLICT', 'DO UPDATE', 'USING', 'FOR', 'LIMIT',
];
const soup = fc.array(fc.constantFrom(...VOCAB), { minLength: 1, maxLength: 40 }).map((a) => a.join(' '));
const unicode = fc
  .array(fc.integer({ min: 0, max: 0x10ffff }), { maxLength: 200 })
  .map((cps) => String.fromCodePoint(...cps));

// ---------------------------------------------------------------------------
// Fuzz
// ---------------------------------------------------------------------------
describe('fuzz', () => {
  it('arbitrary strings: never throws, verdict well-formed, oracle holds', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 300 }), unicode, soup, statementArb), (s) => {
        check(s);
        return true;
      }),
      { numRuns: 30_000 },
    );
  });

  it('arbitrary non-strings: never throws, always block', () => {
    fc.assert(
      fc.property(fc.anything(), (x) => {
        const v = fw.evaluate(x);
        if (typeof x !== 'string') expect(v.decision).toBe('block');
        return true;
      }),
      { numRuns: 5_000 },
    );
  });
});

// ---------------------------------------------------------------------------
// DoS: pathological inputs. The firewall runs synchronously on the event loop,
// so a slow verdict blocks every other request in the process.
// ---------------------------------------------------------------------------
// Malformed or oversized shapes MUST be blocked. Valid-but-heavy shapes may be
// allowed, but must still be fast.
const MUST_BLOCK = new Set([
  'unterminatedString', 'commentBomb', 'dollarTags', 'quoteFlood', 'hugeInput',
  'manyUnions', 'operatorFlood', 'longIdentifier', 'longQuotedIdent', 'longNumber',
]);

describe('DoS: worst-case shapes must stay fast (sync work blocks the event loop)', () => {
  const rows: Array<{ shape: string; ms: number; decision: string; rule: string }> = [];

  beforeAll(() => {
    for (let i = 0; i < 2000; i++) fw.evaluate('SELECT id FROM users WHERE id = $1');
  });
  afterAll(() => console.table(rows));

  it.each(Object.entries(WORST_SHAPES))('%s', (name, sql) => {
    const t = performance.now();
    const v = fw.evaluate(sql);
    const ms = performance.now() - t;
    rows.push({ shape: name, ms: +ms.toFixed(2), decision: v.decision, rule: v.violations[0]?.rule ?? '-' });
    if (MUST_BLOCK.has(name)) expect(v.decision).toBe('block');
    expect(ms).toBeLessThan(150);
  });
});