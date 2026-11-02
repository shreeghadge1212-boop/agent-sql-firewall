  # agent-sql-firewall

  [![CI](https://github.com/shreeghadge1212-boop/agent-sql-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/shreeghadge1212-boop/agent-sql-firewall/actions)
  [![npm](https://img.shields.io/npm/v/agent-sql-firewall)](https://www.npmjs.com/package/agent-sql-firewall)
  [![license](https://img.shields.io/npm/l/agent-sql-firewall)](LICENSE)

  An open-source (MIT) SQL firewall middleware for Node.js and Express. It sits
  between an AI agent (LangChain, an MCP server, your own code) and Postgres,
  parses every query, and blocks destructive ones before they reach the database.

  It blocks things like: `DELETE` or `UPDATE` without a bounded `WHERE`, `DROP`,
  `TRUNCATE`, `DO` blocks, stacked statements (`SELECT 1; DROP TABLE ...`), writes
  hidden inside CTEs, side-effect functions (`pg_sleep`, `dblink`, `lo_import`),
  and access to system catalogs. It fails closed: anything it cannot understand
  is blocked.

  ## Install

  ```bash
  npm install agent-sql-firewall
  ```

  ## Quick start

  ```ts
  import express from 'express';
  import { sqlFirewall } from 'agent-sql-firewall';

  const app = express();
  app.use(express.json());

  // Start in monitor mode: it logs what it WOULD block, but blocks nothing.
  app.post('/agent/query', sqlFirewall({ mode: 'monitor' }), async (req, res) => {
    const result = await db.query(req.body.query);
    res.json(result.rows);
  });
  ```

  When you are happy with the logs, switch to enforcing (the default):

  ```ts
  sqlFirewall({ readOnly: true, allowedTables: ['orders', 'customers'] })
  ```

  A blocked request gets HTTP 403 with a request ID and rule codes. The audit log
  contains a SHA-256 hash of the query, never the SQL text or string literals.

  ### Options

  | Option | Meaning |
  |---|---|
  | `mode` | `'enforce'` (default) or `'monitor'` |
  | `readOnly` | Block every INSERT, UPDATE and DELETE |
  | `allowedTables` | Only these tables may be touched |
  | `requireTenantFilter`, `expectedTenantId`, `tenantColumns` | Require a tenant filter in WHERE |
  | `maxTokens` | Reject larger queries (default 600) |
  | `onAudit` | Your own audit sink (default: JSON line on stdout) |
  | `exposeViolations` | `'codes'` (default) or `'none'` in the 403 body |
  | `extractQuery` | Read the SQL from somewhere other than `req.body.query` |

  ## What it is not

  This is one safety layer. It is **not** a replacement for a least-privilege
  database role, row-level security, or network controls. It is not SOC2
  certified and has not had an independent security audit.

  ## Performance

  Measured on an Intel i5-13420H, Node v25.9.0, single thread, cache disabled
  (`npm run bench` reproduces this).

  | Case | p50 | p99 |
  |---|---|---|
  | Short legitimate queries (~10-25 tokens) | 0.31 ms | 1.3 ms |
  | Attacks rejected by the scanner | 0.004 ms | 3.6 ms |

  Cost grows roughly linearly with query size (about 0.03 ms per token), so a
  100-token query takes about 3 ms. Queries over 600 tokens are rejected by
  default. The worst valid-but-heavy input we measured took about 25 ms at p99.
  Checks run synchronously on the event loop, so keep `maxTokens` modest.

  ## Known limitations

  - **Key columns are hardcoded.** A write is treated as "bounded" if its WHERE
    clause compares `id`, `user_id`, `account_id`, `session_id`, `ticket_id`,
    `order_id`, `notification_id`, `item_id`, `webhook_id` or `uuid` to a value.
    Columns like `user_id` are usually not unique, so
    `DELETE FROM orders WHERE user_id = $1` can still remove many rows. Until
    this is configurable, use `readOnly: true` or monitor mode for agents that
    should not delete in bulk.
  - **Legitimate writes filtered by other columns are blocked** (for example
    `DELETE ... WHERE token = $1`).
  - **Tenant checks look only at the outer WHERE clause**, not joins or
    subqueries. Use Postgres row-level security for real tenant isolation.
  - **Dollar-quoted strings (`$$text$$`) are not supported by the parser** and
    are blocked.
  - **Identifiers starting with `pg_`, `lo_`, `txid_` or `dblink` are blocked**,
    even as column names.
  - **Postgres dialect only.** Unusual syntax the parser cannot read is blocked.
  - A test that runs allowed queries against a real Postgres and counts changed
    rows is included (`npm run test:pg`), but it is not yet part of CI and its
    results are not published.

  ## Testing

  `npm test` runs 231 tests: a corpus of 100+ attack vectors and legitimate
  queries, obfuscation mutations (case, whitespace, comments, Unicode tricks),
  30,000 random and grammar-generated inputs checked by an independent oracle,
  worst-case input timing, and middleware tests. Coverage is about 91%.

  ## Security

  Found a bypass? Please open an issue or a private security advisory on GitHub.

  ## License

  MIT