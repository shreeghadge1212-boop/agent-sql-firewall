import { describe, it, expect, vi } from 'vitest';
import { createFirewall, evaluateSql } from '../src/astFirewall';
import {
  ATTACK_LIST, LEGIT, KNOWN_FALSE_POSITIVES, TENANT_OPTS, TENANT_BLOCK, TENANT_ALLOW, TENANT_KNOWN_GAPS,
} from './corpus';

const fw = createFirewall();

describe('attack corpus: every vector must be blocked', () => {
  it.each(ATTACK_LIST)('[$cat] $sql', ({ sql }) => {
    const v = fw.evaluate(sql);
    expect(v.decision).toBe('block');
    expect(v.violations.length).toBeGreaterThan(0);
  });
});

describe('legit corpus: every query must be allowed (false positives are findings)', () => {
  it.each(LEGIT)('%s', (sql) => {
    const v = fw.evaluate(sql);
    expect(v.violations.map((x) => `${x.rule}: ${x.detail}`)).toEqual([]);
    expect(v.decision).toBe('allow');
  });
});

describe('known limitations (it.fails = documented; turns RED when you fix them, then flip to it)', () => {
  it.fails.each(KNOWN_FALSE_POSITIVES)('false positive today: %s', (sql) => {
    expect(fw.evaluate(sql).decision).toBe('allow');
  });
  it.fails.each(TENANT_KNOWN_GAPS)('tenant gap today: %s', (sql) => {
    expect(createFirewall(TENANT_OPTS).evaluate(sql).decision).toBe('block');
  });
});

describe('non-string input always blocks', () => {
  it.each([null, undefined, 0, 1, NaN, true, {}, [], () => 1, Symbol('x'), 10n, new Date(), Buffer.from('SELECT 1')])(
    '%s', (x) => expect(fw.evaluate(x).decision).toBe('block'));
});

describe('tenant isolation', () => {
  const t = createFirewall(TENANT_OPTS);
  it.each(TENANT_BLOCK)('blocks %s', (sql) => expect(t.evaluate(sql).decision).toBe('block'));
  it.each(TENANT_ALLOW)('allows %s', (sql) => expect(t.evaluate(sql).decision).toBe('allow'));
});

describe('readOnly and allowedTables', () => {
  const ro = createFirewall({ readOnly: true });
  it.each([
    'INSERT INTO notes (title) VALUES ($1)',
    'UPDATE orders SET status = $1 WHERE id = $2',
    'DELETE FROM sessions WHERE id = $1',
    'WITH d AS (DELETE FROM users WHERE id = 1 RETURNING id) SELECT * FROM d',
  ])('readOnly blocks %s', (sql) => expect(ro.evaluate(sql).decision).toBe('block'));
  it('readOnly allows SELECT', () => expect(ro.evaluate('SELECT id FROM users WHERE id = $1').decision).toBe('allow'));

  const tbl = createFirewall({ allowedTables: ['orders'] });
  it('blocks other tables', () => expect(tbl.evaluate('SELECT * FROM users WHERE id = 1').decision).toBe('block'));
  it('blocks via join', () => expect(tbl.evaluate('SELECT * FROM orders o JOIN users u ON u.id = o.user_id').decision).toBe('block'));
  it('allows listed table and CTE names', () => {
    expect(tbl.evaluate('SELECT * FROM orders WHERE id = 1').decision).toBe('allow');
    expect(tbl.evaluate('WITH x AS (SELECT id FROM orders) SELECT * FROM x').decision).toBe('allow');
  });
});

describe('hostile configuration never weakens the firewall', () => {
  it.each([null, undefined, 'x', 5, [], { maxSqlLength: -1 }, { maxSqlLength: NaN }, { maxTokens: Infinity },
    { allowedTables: 'users' }, { tenantColumns: 'tenant_id' }, { extraAllowedFunctions: [1, null] }])(
    'options %j', (opts) => {
      const f = createFirewall(opts as any);
      expect(f.evaluate('DROP TABLE users').decision).toBe('block');
      expect(f.evaluate('DELETE FROM users').decision).toBe('block');
    });
});

describe('cache and callbacks', () => {
  it('cache is bounded, consistent, and not poisonable by callers', () => {
    const f = createFirewall({ cacheSize: 10 });
    for (let i = 0; i < 1000; i++) f.evaluate(`SELECT ${i}`);
    const a = f.evaluate('DELETE FROM users');
    a.violations.length = 0; // caller mutates the verdict
    expect(f.evaluate('DELETE FROM users').decision).toBe('block');
    expect(f.evaluate('DELETE FROM users').violations.length).toBeGreaterThan(0);
  });
  it('onDecision never receives SQL text, and a throwing callback is swallowed', () => {
    const events: any[] = [];
    const f = createFirewall({ onDecision: (e) => { events.push(e); throw new Error('boom'); } });
    expect(f.evaluate("SELECT 'TOP_SECRET_LITERAL'").decision).toBe('allow');
    expect(JSON.stringify(events)).not.toContain('TOP_SECRET_LITERAL');
    expect(events[0]).toMatchObject({ decision: 'allow', sqlLength: expect.any(Number) });
  });
  it('evaluateSql reuses one firewall per options object', () => {
    const o = { readOnly: true };
    expect(evaluateSql('DELETE FROM x WHERE id = 1', o).decision).toBe('block');
    expect(evaluateSql('DELETE FROM x WHERE id = 1').decision).toBe('allow');
  });
});