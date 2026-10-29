# agent-sql-firewall

**0.3ms AST Firewall for LLM Agents.** 

When your AI agent hallucinates a `DROP TABLE`, `TRUNCATE`, or executes an unbounded `DELETE` via prompt injection, this Express middleware blocks it deterministically before it hits your Postgres database. 

Runs **100% locally** on your infrastructure. Zero external API calls. Sub-millisecond latency. Built for MCP (Model Context Protocol) and autonomous agents in regulated sectors.

## The Problem
If your agent has database access, regex filters will fail. Attackers bypass them using CTE wrappers (`WITH x AS (DELETE FROM users)`), comment obfuscation (`DROP /* safe */ TABLE`), or OR-branch poisonings (`WHERE id=1 OR 1=1`). 

Proxying your database through a third-party API adds latency, creates a single point of failure, and violates SOC2/HIPAA compliance.

## The Solution
`agent-sql-firewall` uses `pgsql-ast-parser` to compile the actual Postgres Abstract Syntax Tree (AST) of the generated SQL in ~0.3ms. 

If it detects `DROP`, `TRUNCATE`, or any `UPDATE`/`DELETE` that lacks a safely bounded `WHERE` clause, it instantly drops the request with a 403.

## Installation
```bash
npm install agent-sql-firewall