import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from 'pg';
import fc from 'fast-check';
import { createFirewall } from '../src/astFirewall';
import { ATTACK_LIST, LEGIT } from './corpus';
import { MUTATORS, HOSTILE, rng, statementArb } from './mutators';

const URL = process.env.FW_TEST_DB;
const MAX_ROWS = 100;
const TABLES = ['users', 'orders', 'sessions'];

describe.skipIf(!URL)('postgres effect oracle (THROWAWAY DATABASE ONLY)', () => {
  let db: Client;
  beforeAll(async () => {
    db = new Client({ connectionString: URL });
    await db.connect();
    await db.query(`
      DROP TABLE IF EXISTS users, orders, sessions, notes, users_snap, orders_snap, sessions_snap CASCADE;
      CREATE TABLE users (id int PRIMARY KEY, user_id int, name text, role text, tenant_id int);
      INSERT INTO users SELECT g, g % 5, 'u' || g, 'member', g % 3 FROM generate_series(1, 1000) g;
      CREATE TABLE orders (id int PRIMARY KEY, user_id int, status text, total int, tenant_id int);
      INSERT INTO orders SELECT g, g % 5, 'new', g, g % 3 FROM generate_series(1, 1000) g;
      CREATE TABLE sessions (id int PRIMARY KEY, user_id int);
      INSERT INTO sessions SELECT g, g % 5 FROM generate_series(1, 1000) g;
      CREATE TABLE notes (title text, body text);
      CREATE TABLE users_snap AS SELECT * FROM users;
      CREATE TABLE orders_snap AS SELECT * FROM orders;
      CREATE TABLE sessions_snap AS SELECT * FROM sessions;
    `);
    await db.query('SET statement_timeout = 2000');
  });
  afterAll(async () => { await db?.end(); });

  async function effect(sql: string): Promise<number | null> {
    const n = Math.max(0, ...[...sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1])));
    await db.query('BEGIN');
    try {
      try { await db.query(sql, n ? Array(n).fill('1') : undefined); } catch { return null; } // invalid for PG: no effect
      let rows = 0;
      try {
        for (const t of TABLES) {
          const r = await db.query(
            `SELECT greatest((SELECT count(*) FROM (SELECT * FROM ${t} EXCEPT SELECT * FROM ${t}_snap) a),
                             (SELECT count(*) FROM (SELECT * FROM ${t}_snap EXCEPT SELECT * FROM ${t}) b)) AS d`);
          rows += Number(r.rows[0].d);
        }
      } catch { return Infinity; } // structure changed (e.g. table dropped)
      return rows;
    } finally {
      await db.query('ROLLBACK');
    }
  }

  it.each(LEGIT)('legit corpus is valid Postgres syntax: %s', async (sql) => {
    try { await db.query('PREPARE s AS ' + sql.replace(/;\s*$/, '')); }
    catch (e: any) { expect(e.code).not.toBe('42601'); } // 42601 = syntax_error
    finally { await db.query('DEALLOCATE ALL').catch(() => {}); }
  });

  it(`no ALLOWED statement changes more than ${MAX_ROWS} rows`, async () => {
    const fw = createFirewall();
    const pool = [...ATTACK_LIST.map((a) => a.sql), ...LEGIT];
    const mutated = pool.flatMap((s, i) => Object.values({ ...MUTATORS, ...HOSTILE }).map((m, j) => m(s, rng(i * 31 + j))));
    const generated = fc.sample(statementArb, 4000);
    const offenders: { sql: string; rows: number }[] = [];
    let executed = 0;
    for (const sql of [...pool, ...mutated, ...generated]) {
      if (fw.evaluate(sql).decision !== 'allow') continue;
      const rows = await effect(sql);
      if (rows === null) continue;
      executed++;
      if (rows > MAX_ROWS) offenders.push({ sql, rows });
    }
    console.log(`executed ${executed} allowed statements against real Postgres`);
    expect(offenders.slice(0, 15), 'BYPASS / UNBOUNDED EFFECT').toEqual([]);
  }, 600_000);
});