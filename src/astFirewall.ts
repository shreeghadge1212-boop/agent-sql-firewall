/**
 * agent-sql-firewall core.
 *
 * Defence in depth, cheapest layer first:
 *   0. Input checks      type, size, null bytes                       (O(1))
 *   1. Scanner           our own linear-time, Postgres-aware tokenizer (O(n))
 *                        - understands comments (nested), '..' / E'..' / $tag$..$tag$ strings, ".." identifiers
 *                        - counts statements, enforces size/complexity limits, blocks odd syntax
 *   2. Token rules       first keyword allow-list, SELECT INTO, row locking, blocked identifiers
 *   3. Parser            pgsql-ast-parser, only reached when layers 0-2 pass
 *   4. AST rules         statement types, bounded WHERE on writes, function allow-list,
 *                        system-catalog and table checks, tenant isolation
 *
 * Every layer fails CLOSED: if anything is unexpected, the verdict is "block". evaluate() never throws.
 * This is a safety layer, not a replacement for a least-privilege database role.
 */
import { parse } from "pgsql-ast-parser";
import type { Statement, Expr } from "pgsql-ast-parser";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RuleViolationCode =
  | "EMPTY_OR_INVALID_SQL"
  | "SQL_TOO_LARGE"
  | "TOO_COMPLEX"
  | "INVALID_SYNTAX"
  | "MULTI_STATEMENT"
  | "PARSE_FAILURE"
  | "PARSER_MISMATCH"
  | "DISALLOWED_STATEMENT_TYPE"
  | "DESTRUCTIVE_DDL"
  | "READ_ONLY_VIOLATION"
  | "UNBOUNDED_MUTATION"
  | "UNSAFE_WHERE_BOUNDARY"
  | "JOINED_MUTATION_BLOCKED"
  | "UNBOUNDED_UPSERT"
  | "SELECT_INTO"
  | "ROW_LOCKING"
  | "BLOCKED_IDENTIFIER"
  | "SIDE_EFFECT_FUNCTION"
  | "FUNCTION_NOT_ALLOWED"
  | "SYSTEM_CATALOG_ACCESS"
  | "TABLE_NOT_ALLOWED"
  | "MISSING_TENANT_ISOLATION"
  | "CROSS_TENANT_SPOOFING"
  | "INTERNAL_ERROR";

export interface RuleViolation {
  rule: RuleViolationCode;
  detail: string;
}

export interface FirewallVerdict {
  decision: "allow" | "block";
  violations: RuleViolation[];
  latencyMs: number;
}

/** Passed to onDecision. Deliberately contains NO SQL text, so logs cannot leak customer data. */
export interface DecisionEvent {
  decision: "allow" | "block";
  rules: RuleViolationCode[];
  latencyMs: number;
  sqlLength: number;
}

export interface FirewallOptions {
  /** Allowed columns for bounded WHERE clauses on mutations. Default: ['id'] */
  uniqueKeyColumns?: string[];
  /** Enforce that every SELECT/UPDATE/DELETE filters by a tenant identifier column */
  requireTenantFilter?: boolean;
  /** Allowed column names for tenant scoping (default: tenant_id, org_id, organization_id, workspace_id) */
  tenantColumns?: string[];
  /** Optional strict session tenant ID to prevent cross-tenant spoofing (e.g. WHERE tenant_id = 'other_org') */
  expectedTenantId?: string | number;
  /** Block every INSERT/UPDATE/DELETE. Use for read-only agents. Default false. */
  readOnly?: boolean;
  /** If set, the SQL may only touch these tables (names, or "schema.name"). CTE names are always fine. */
  allowedTables?: string[];
  /** Extra functions to allow on top of the built-in safe list. */
  extraAllowedFunctions?: string[];
  /** Extra identifiers/functions to block (matched anywhere, case-insensitive). */
  extraBlockedWords?: string[];
  /** Reject SQL longer than this many characters before doing anything else. Default 8192. */
  maxSqlLength?: number;
  /** Reject SQL with more tokens than this. Default 600. */
  maxTokens?: number;
  /** Reject SQL nested deeper than this (parentheses + brackets). Default 24. */
  maxNesting?: number;
  /** Allow backslashes inside normal '...' strings. Default false (see README: they are ambiguous). */
  allowBackslashInStrings?: boolean;
  /** Cache verdicts for identical short SQL strings (0 = off, the default). */
  cacheSize?: number;
  /** Include the parser's error text in verdicts. Off by default because it can echo SQL content. */
  includeParserErrors?: boolean;
  /** Called after every decision. Errors thrown by this callback are swallowed. */
  onDecision?: (event: DecisionEvent) => void;
}

export interface Firewall {
  /** Never throws. Anything unexpected becomes a "block" verdict. */
  evaluate(sql: unknown): FirewallVerdict;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MAX_SQL_LENGTH = 8192;
const DEFAULT_MAX_TOKENS = 600;
const DEFAULT_MAX_NESTING = 24;
// NEW: per-token length limits, enforced by the scanner BEFORE the parser sees anything.
// A single giant token (for example 8000 "+" characters) can make the parser spend hundreds of ms.
const MAX_WORD_LEN = 128; // Postgres identifiers are at most 63 bytes
const MAX_OPERATOR_LEN = 16; // real operators are 1-4 characters
const MAX_NUMBER_LEN = 64;
const MAX_AST_DEPTH = 64;
const MAX_AST_NODES = 20000;
const MAX_DETAIL_LENGTH = 80;
const CACHE_MAX_SQL_LENGTH = 4096;

const DEFAULT_TENANT_COLUMNS = ["tenant_id", "org_id", "organization_id", "workspace_id"];

// Statements the firewall will even consider. Everything else is rejected before parsing.
const ALLOWED_START = new Set(["select", "with", "insert", "update", "delete", "values"]);
const DDL_START = new Set(["drop", "truncate", "alter", "create", "grant", "revoke", "do"]);
const SET_OPERATIONS = new Set(["union", "union all", "intersect", "intersect all", "except", "except all"]);

// Words that are blocked anywhere in the SQL (outside string literals), in any casing, quoted or not.
const BLOCKED_WORDS = new Set([
  "set_config",
  "current_setting",
  "nextval",
  "currval",
  "lastval",
  "setval",
  "information_schema",
  "generate_series",
  "generate_subscripts",
  "repeat",
  "wipe_everything",
]);
const BLOCKED_PREFIXES = ["pg_", "dblink", "txid_"];

// Kept for clearer error codes in the AST layer.
const BLOCKED_FUNCTIONS = new Set([
  "pg_sleep",
  "pg_read_file",
  "pg_read_binary_file",
  "pg_ls_dir",
  "pg_stat_file",
  "pg_terminate_backend",
  "pg_cancel_backend",
  "pg_reload_conf",
  "pg_rotate_logfile",
  "dblink",
  "dblink_exec",
  "lo_import",
  "lo_export",
  "wipe_everything",
]);

// Default-deny: only these functions may be called. Add more with extraAllowedFunctions.
const DEFAULT_ALLOWED_FUNCTIONS = [
  // aggregates
  "count", "sum", "avg", "min", "max", "array_agg", "string_agg", "json_agg", "jsonb_agg",
  "json_object_agg", "jsonb_object_agg", "bool_and", "bool_or", "every", "stddev", "variance",
  // strings
  "lower", "upper", "initcap", "length", "char_length", "character_length", "octet_length",
  "substring", "substr", "trim", "btrim", "ltrim", "rtrim", "replace", "concat", "concat_ws",
  "left", "right", "position", "strpos", "split_part", "starts_with", "reverse", "translate",
  "ascii", "chr", "md5", "format", "to_char", "to_number",
  // math
  "abs", "ceil", "ceiling", "floor", "round", "trunc", "mod", "div", "power", "sqrt", "exp", "ln",
  "log", "sign", "greatest", "least", "random", "gen_random_uuid",
  // conditionals
  "coalesce", "nullif",
  // date and time
  "now", "current_date", "current_time", "current_timestamp", "localtime", "localtimestamp",
  "date_trunc", "date_part", "extract", "age", "to_timestamp", "to_date", "make_date",
  "make_timestamp", "make_interval", "timezone",
  // json
  "json_build_object", "jsonb_build_object", "json_build_array", "jsonb_build_array",
  "json_extract_path", "jsonb_extract_path", "json_extract_path_text", "jsonb_extract_path_text",
  "json_array_length", "jsonb_array_length", "json_typeof", "jsonb_typeof", "to_json", "to_jsonb",
  "row_to_json", "jsonb_pretty", "jsonb_strip_nulls", "jsonb_set",
  // window functions
  "row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile", "lag", "lead",
  "first_value", "last_value", "nth_value",
  // arrays and sub-expressions
  "array_length", "array_upper", "array_lower", "cardinality", "array_to_string", "string_to_array",
  "array_append", "array_prepend", "array_cat", "array_position", "array_remove", "unnest",
  "any", "all", "some", "array", "row", "exists",
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

type AddFn = (rule: RuleViolationCode, detail: string) => void;

function clip(text: string): string {
  return text.length > MAX_DETAIL_LENGTH ? text.slice(0, MAX_DETAIL_LENGTH) + "..." : text;
}

function positiveInt(value: unknown, fallback: number): number {
  return typeof value === "number" && isFinite(value) && value >= 1 ? Math.floor(value) : fallback;
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] === "string" && value[i].length > 0) out.push(value[i].toLowerCase());
  }
  return out;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

interface ResolvedConfig {
  uniqueKeyCols: Set<string>;
  maxSqlLength: number;
  maxTokens: number;
  maxNesting: number;
  allowBackslashInStrings: boolean;
  readOnly: boolean;
  requireTenantFilter: boolean;
  tenantCols: Set<string>;
  expectedTenantId: string | number | undefined;
  allowedTables: Set<string> | null;
  allowedFunctions: Set<string>;
  extraBlockedWords: Set<string>;
  cacheSize: number;
  includeParserErrors: boolean;
  onDecision: ((event: DecisionEvent) => void) | undefined;
}

function resolveConfig(options: FirewallOptions): ResolvedConfig {
  const opts: FirewallOptions = options && typeof options === "object" ? options : {};
  const uniqueKeyCols = new Set<string>(
    Array.isArray(opts.uniqueKeyColumns) ? stringList(opts.uniqueKeyColumns) : ["id"]
  );
  const tenantCols = new Set<string>(
    Array.isArray(opts.tenantColumns) ? stringList(opts.tenantColumns) : DEFAULT_TENANT_COLUMNS
  );
  const allowedFunctions = new Set<string>(DEFAULT_ALLOWED_FUNCTIONS);
  stringList(opts.extraAllowedFunctions).forEach((f) => allowedFunctions.add(f));
  const tables = stringList(opts.allowedTables);
  return {
    uniqueKeyCols,
    maxSqlLength: positiveInt(opts.maxSqlLength, DEFAULT_MAX_SQL_LENGTH),
    maxTokens: positiveInt(opts.maxTokens, DEFAULT_MAX_TOKENS),
    maxNesting: positiveInt(opts.maxNesting, DEFAULT_MAX_NESTING),
    allowBackslashInStrings: opts.allowBackslashInStrings === true,
    readOnly: opts.readOnly === true,
    requireTenantFilter: opts.requireTenantFilter === true,
    tenantCols,
    expectedTenantId: opts.expectedTenantId,
    allowedTables: Array.isArray(opts.allowedTables) ? new Set<string>(tables) : null,
    allowedFunctions,
    extraBlockedWords: new Set<string>(stringList(opts.extraBlockedWords)),
    cacheSize: typeof opts.cacheSize === "number" && opts.cacheSize > 0 ? Math.floor(opts.cacheSize) : 0,
    includeParserErrors: opts.includeParserErrors === true,
    onDecision: typeof opts.onDecision === "function" ? opts.onDecision : undefined,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function createFirewall(options: FirewallOptions = {}): Firewall {
  const cfg = resolveConfig(options);
  const cache = cfg.cacheSize > 0 ? new Map<string, RuleViolation[]>() : null;

  function evaluate(sql: unknown): FirewallVerdict {
    const start = performance.now();
    let violations: RuleViolation[] | undefined;
    const cacheable = cache !== null && typeof sql === "string" && sql.length <= CACHE_MAX_SQL_LENGTH;

    if (cache && cacheable) {
      const hit = cache.get(sql as string);
      if (hit) violations = hit.slice();
    }

    if (!violations) {
      let failed = false;
      try {
        violations = analyze(sql, cfg);
      } catch {
        failed = true;
        violations = [{ rule: "INTERNAL_ERROR", detail: "Unexpected firewall error (fail-closed)." }];
      }
      if (cache && cacheable && !failed) {
        if (cache.size >= cfg.cacheSize) {
          const oldest = cache.keys().next().value;
          if (oldest !== undefined) cache.delete(oldest);
        }
        cache.set(sql as string, violations.slice());
      }
    }

    const verdict: FirewallVerdict = {
      decision: violations.length > 0 ? "block" : "allow",
      violations,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };

    if (cfg.onDecision) {
      try {
        cfg.onDecision({
          decision: verdict.decision,
          rules: violations.map((v) => v.rule),
          latencyMs: verdict.latencyMs,
          sqlLength: typeof sql === "string" ? sql.length : 0,
        });
      } catch {
        // A broken logger must never break the firewall.
      }
    }
    return verdict;
  }

  return { evaluate };
}

const defaultFirewall = createFirewall();
const firewallsByOptions = new WeakMap<object, Firewall>();

/**
 * Convenience wrapper. The firewall is built once per options object, so reuse the same object.
 * (Changing the options object after the first call has no effect.)
 */
export function evaluateSql(sql: string, options?: FirewallOptions): FirewallVerdict {
  if (!options || typeof options !== "object") return defaultFirewall.evaluate(sql);
  let firewall = firewallsByOptions.get(options);
  if (!firewall) {
    firewall = createFirewall(options);
    firewallsByOptions.set(options, firewall);
  }
  return firewall.evaluate(sql);
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

function analyze(sql: unknown, cfg: ResolvedConfig): RuleViolation[] {
  const violations: RuleViolation[] = [];
  const add: AddFn = (rule, detail) => {
    if (!violations.some((v) => v.rule === rule)) violations.push({ rule, detail: clip(detail) });
  };

  // Layer 0: cheap input checks
  if (typeof sql !== "string" || sql.trim().length === 0) {
    add("EMPTY_OR_INVALID_SQL", "SQL payload is empty or not a string.");
    return violations;
  }
  if (sql.length > cfg.maxSqlLength) {
    add("SQL_TOO_LARGE", `SQL is ${sql.length} characters; the limit is ${cfg.maxSqlLength}.`);
    return violations;
  }
  if (sql.indexOf("\u0000") !== -1) {
    add("INVALID_SYNTAX", "SQL contains a null byte.");
    return violations;
  }

  // Layer 1: our own linear-time scanner
  const scan = scanSql(sql, cfg);
  if (scan.error) {
    add(scan.error.rule, scan.error.detail);
    return violations;
  }
  const statements = scan.statements;
  if (statements.length === 0) {
    add("EMPTY_OR_INVALID_SQL", "SQL contains no statements.");
    return violations;
  }
  if (statements.length > 1) {
    add("MULTI_STATEMENT", `Multiple SQL statements detected (${statements.length}).`);
  }

  // Layer 2: token rules (still before the parser, so hostile input never reaches it)
  checkTokens(statements, cfg, add);
  if (violations.length > 0) return violations;

  // Layer 3: parser, fail-closed
  let ast: Statement[];
  try {
    ast = parse(sql);
  } catch (err: any) {
    const extra = cfg.includeParserErrors && err && err.message ? `: ${String(err.message)}` : "";
    add("PARSE_FAILURE", `Fail-closed: SQL could not be parsed${extra}`);
    return violations;
  }
  if (!Array.isArray(ast) || ast.length === 0) {
    add("PARSE_FAILURE", "Parser returned no statements.");
    return violations;
  }
  if (ast.length !== statements.length) {
    add("PARSER_MISMATCH", `Scanner saw ${statements.length} statement(s) but the parser saw ${ast.length}.`);
    return violations;
  }

  // Layer 4: AST rules
  inspectAst(ast, cfg, add);
  return violations;
}

// ---------------------------------------------------------------------------
// Layer 1: scanner (linear time, no regular expressions)
// ---------------------------------------------------------------------------

const K_WORD = 1; // unquoted identifier or keyword, lower-cased
const K_QIDENT = 2; // "quoted identifier", lower-cased content
const K_STRING = 3; // any string literal (content is dropped)
const K_NUMBER = 4;
const K_PUNCT = 5; // ( ) [ ] , .
const K_OP = 6;
const K_PARAM = 7; // $1

interface Tok {
  k: number;
  v: string;
}

interface ScanResult {
  statements: Tok[][];
  error?: { rule: RuleViolationCode; detail: string };
}

const OP_CHAR = new Uint8Array(128);
"+-*/<>=~!@#%^&|?:".split("").forEach((ch) => {
  OP_CHAR[ch.charCodeAt(0)] = 1;
});

function isWordStart(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c >= 128;
}
function isWordChar(c: number): boolean {
  return isWordStart(c) || (c >= 48 && c <= 57) || c === 36;
}
function isDigit(c: number): boolean {
  return c >= 48 && c <= 57;
}
function isOpChar(c: number): boolean {
  return c < 128 && OP_CHAR[c] === 1;
}

function scanSql(sql: string, cfg: ResolvedConfig): ScanResult {
  const n = sql.length;
  const statements: Tok[][] = [];
  let current: Tok[] = [];
  let tokenCount = 0;
  let depth = 0;
  let sawPlainBackslash = false;
  let i = 0;

  const fail = (rule: RuleViolationCode, detail: string): ScanResult => ({ statements, error: { rule, detail } });
  const push = (k: number, v: string): void => {
    current.push({ k, v });
    tokenCount++;
  };

  // Reads a '...' string starting at the opening quote. Returns the index after the closing quote, or -1.
  const readString = (start: number, backslashEscapes: boolean): number => {
    let j = start + 1;
    while (j < n) {
      const d = sql.charCodeAt(j);
      if (d === 39) {
        if (sql.charCodeAt(j + 1) === 39) {
          j += 2;
          continue;
        }
        return j + 1;
      }
      if (d === 92) {
        if (backslashEscapes) {
          j += 2;
          continue;
        }
        sawPlainBackslash = true;
      }
      j++;
    }
    return -1;
  };

  while (i < n) {
    if (tokenCount > cfg.maxTokens) {
      return fail("TOO_COMPLEX", `SQL has more than ${cfg.maxTokens} tokens.`);
    }
    const c = sql.charCodeAt(i);

    // whitespace
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 12 || c === 11) {
      i++;
      continue;
    }
    // control characters and DEL
    if (c < 32 || c === 127) {
      return fail("INVALID_SYNTAX", "Control character in SQL.");
    }

    // -- line comment
    if (c === 45 && sql.charCodeAt(i + 1) === 45) {
      i += 2;
      while (i < n) {
        const d = sql.charCodeAt(i);
        if (d === 10 || d === 13) break;
        i++;
      }
      continue;
    }

    // /* block comment */ (Postgres allows nesting)
    if (c === 47 && sql.charCodeAt(i + 1) === 42) {
      let level = 1;
      i += 2;
      while (i < n && level > 0) {
        const d = sql.charCodeAt(i);
        if (d === 47 && sql.charCodeAt(i + 1) === 42) {
          level++;
          i += 2;
        } else if (d === 42 && sql.charCodeAt(i + 1) === 47) {
          level--;
          i += 2;
        } else {
          i++;
        }
      }
      if (level > 0) return fail("INVALID_SYNTAX", "Unterminated block comment.");
      continue;
    }

    // 'string'
    if (c === 39) {
      const end = readString(i, false);
      if (end < 0) return fail("INVALID_SYNTAX", "Unterminated string literal.");
      push(K_STRING, "");
      i = end;
      continue;
    }

    // "quoted identifier"
    if (c === 34) {
      let j = i + 1;
      while (j < n) {
        const d = sql.charCodeAt(j);
        if (d === 34) {
          if (sql.charCodeAt(j + 1) === 34) {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      if (j >= n) return fail("INVALID_SYNTAX", "Unterminated quoted identifier.");
      // NEW: bounded identifier length
      if (j - i > MAX_WORD_LEN + 2) return fail("INVALID_SYNTAX", "Quoted identifier is too long.");
      push(K_QIDENT, sql.slice(i + 1, j).split('""').join('"').toLowerCase());
      i = j + 1;
      continue;
    }

    // $1 parameters and $tag$ dollar-quoted strings
    if (c === 36) {
      if (isDigit(sql.charCodeAt(i + 1))) {
        let j = i + 1;
        while (j < n && isDigit(sql.charCodeAt(j))) j++;
        push(K_PARAM, sql.slice(i, j));
        i = j;
        continue;
      }
      let j = i + 1;
      while (j < n) {
        const d = sql.charCodeAt(j);
        const ok = j === i + 1 ? isWordStart(d) : isWordChar(d) && d !== 36;
        if (!ok) break;
        j++;
      }
      if (j < n && sql.charCodeAt(j) === 36) {
        const tag = sql.slice(i, j + 1);
        const end = sql.indexOf(tag, j + 1);
        if (end < 0) return fail("INVALID_SYNTAX", "Unterminated dollar-quoted string.");
        push(K_STRING, "");
        i = end + tag.length;
        continue;
      }
      return fail("INVALID_SYNTAX", "Unexpected '$'.");
    }

    // numbers
    if (isDigit(c) || (c === 46 && isDigit(sql.charCodeAt(i + 1)))) {
      let j = i + 1;
      while (j < n) {
        const d = sql.charCodeAt(j);
        if (isDigit(d) || (d >= 65 && d <= 90) || (d >= 97 && d <= 122) || d === 95 || d === 46) j++;
        else break;
      }
      // NEW: bounded numeric literal length
      if (j - i > MAX_NUMBER_LEN) return fail("INVALID_SYNTAX", "Numeric literal is too long.");
      push(K_NUMBER, sql.slice(i, j));
      i = j;
      continue;
    }

    // words, plus E'..' / B'..' / X'..' / N'..' / U&'..' string prefixes
    if (isWordStart(c)) {
      let j = i + 1;
      while (j < n && isWordChar(sql.charCodeAt(j))) j++;
      // NEW: bounded identifier/keyword length
      if (j - i > MAX_WORD_LEN) return fail("INVALID_SYNTAX", "Identifier or keyword is too long.");
      const word = sql.slice(i, j).toLowerCase();
      const next = sql.charCodeAt(j);
      if (next === 39 && (word === "e" || word === "b" || word === "x" || word === "n")) {
        const end = readString(j, word === "e");
        if (end < 0) return fail("INVALID_SYNTAX", "Unterminated string literal.");
        push(K_STRING, "");
        i = end;
        continue;
      }
      if (word === "u" && next === 38) {
        const after = sql.charCodeAt(j + 1);
        if (after === 34) return fail("INVALID_SYNTAX", 'Unicode-escaped identifiers (U&"...") are not allowed.');
        if (after === 39) {
          const end = readString(j + 1, false);
          if (end < 0) return fail("INVALID_SYNTAX", "Unterminated string literal.");
          push(K_STRING, "");
          i = end;
          continue;
        }
      }
      push(K_WORD, word);
      i = j;
      continue;
    }

    // punctuation
    if (c === 40 || c === 91) {
      depth++;
      if (depth > cfg.maxNesting) return fail("TOO_COMPLEX", `SQL is nested deeper than ${cfg.maxNesting} levels.`);
      push(K_PUNCT, c === 40 ? "(" : "[");
      i++;
      continue;
    }
    if (c === 41 || c === 93) {
      depth--;
      if (depth < 0) return fail("INVALID_SYNTAX", "Unbalanced closing bracket.");
      push(K_PUNCT, c === 41 ? ")" : "]");
      i++;
      continue;
    }
    if (c === 44 || c === 46) {
      push(K_PUNCT, c === 44 ? "," : ".");
      i++;
      continue;
    }
    if (c === 59) {
      if (depth > 0) return fail("INVALID_SYNTAX", "Semicolon inside brackets.");
      if (current.length > 0) {
        statements.push(current);
        current = [];
      }
      i++;
      continue;
    }

    // operators (stop before a comment starts)
    if (isOpChar(c)) {
      let j = i + 1;
      while (j < n) {
        const d = sql.charCodeAt(j);
        if (!isOpChar(d)) break;
        if (d === 45 && sql.charCodeAt(j + 1) === 45) break;
        if (d === 47 && sql.charCodeAt(j + 1) === 42) break;
        j++;
      }
      // NEW: bounded operator length (blocks "++++++..." floods before the parser)
      if (j - i > MAX_OPERATOR_LEN) return fail("INVALID_SYNTAX", "Operator is too long.");
      push(K_OP, sql.slice(i, j));
      i = j;
      continue;
    }

    // anything else ( { } \ ` and so on ) is not valid SQL outside strings
    return fail("INVALID_SYNTAX", "Unexpected character in SQL.");
  }

  if (depth !== 0) return fail("INVALID_SYNTAX", "Unbalanced brackets.");
  if (sawPlainBackslash && !cfg.allowBackslashInStrings) {
    return fail(
      "INVALID_SYNTAX",
      "Backslash inside a normal string is ambiguous (depends on a server setting). Use E'...' or set allowBackslashInStrings."
    );
  }
  if (current.length > 0) statements.push(current);
  return { statements };
}

// ---------------------------------------------------------------------------
// Layer 2: token rules
// ---------------------------------------------------------------------------

function isBlockedWord(word: string, cfg: ResolvedConfig): boolean {
  for (let i = 0; i < BLOCKED_PREFIXES.length; i++) {
    if (word.startsWith(BLOCKED_PREFIXES[i])) return true;
  }
  if (word.indexOf("_to_xml") !== -1) return true; // query_to_xml() and friends run SQL from a string
  return BLOCKED_WORDS.has(word) || cfg.extraBlockedWords.has(word);
}

function checkTokens(statements: Tok[][], cfg: ResolvedConfig, add: AddFn): void {
  for (let s = 0; s < statements.length; s++) {
    const stmt = statements[s];
    const first = stmt[0];

    if (first.k !== K_WORD || !ALLOWED_START.has(first.v)) {
      const label = first.k === K_WORD ? first.v : "(non-keyword)";
      add("DISALLOWED_STATEMENT_TYPE", `Statement starting with '${label}' is not permitted.`);
      if (first.k === K_WORD && DDL_START.has(first.v)) {
        add("DESTRUCTIVE_DDL", "Destructive DDL, procedural block or privilege change detected.");
      }
    }

    for (let t = 0; t < stmt.length; t++) {
      const tok = stmt[t];

      if (tok.k === K_WORD) {
        const w = tok.v;
        if (w === "into") {
          const prev = t > 0 ? stmt[t - 1] : undefined;
          if (!(prev && prev.k === K_WORD && prev.v === "insert")) {
            add("SELECT_INTO", "SELECT ... INTO (creates a table) is not permitted.");
          }
        } else if (w === "for") {
          const nx = stmt[t + 1];
          if (nx && nx.k === K_WORD && (nx.v === "update" || nx.v === "share" || nx.v === "no" || nx.v === "key")) {
            add("ROW_LOCKING", "Row locking (FOR UPDATE / FOR SHARE) is not permitted.");
          }
        } else if (w === "merge") {
          add("DISALLOWED_STATEMENT_TYPE", "MERGE is not permitted.");
        } else if (cfg.readOnly && (w === "insert" || w === "update" || w === "delete")) {
          add("READ_ONLY_VIOLATION", "Write keywords are not permitted in read-only mode.");
        }
      }

      if ((tok.k === K_WORD || tok.k === K_QIDENT) && isBlockedWord(tok.v, cfg)) {
        add("BLOCKED_IDENTIFIER", `Blocked identifier '${tok.v}'.`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Layer 4: AST rules
// ---------------------------------------------------------------------------

interface TableRef {
  name: string;
  schema: string | null;
  write: boolean;
}

interface InspectCtx {
  cfg: ResolvedConfig;
  add: AddFn;
  cteNames: Set<string>;
  tableRefs: TableRef[];
  writes: boolean;
  inspected: WeakSet<object>;
}

function inspectAst(ast: Statement[], cfg: ResolvedConfig, add: AddFn): void {
  const ctx: InspectCtx = { cfg, add, cteNames: new Set<string>(), tableRefs: [], writes: false, inspected: new WeakSet<object>() };
  for (let i = 0; i < ast.length; i++) inspectStatement(ast[i], ctx, 0);
  auditAst(ast, ctx);
  evaluateTables(ctx);
}

function inspectStatement(stmt: any, ctx: InspectCtx, depth: number): void {
  const { add, cfg } = ctx;

  if (depth > MAX_AST_DEPTH) {
    add("TOO_COMPLEX", "SQL nesting is too deep.");
    return;
  }
  if (!stmt || typeof stmt !== "object") {
    add("PARSE_FAILURE", "Invalid AST statement node.");
    return;
  }

  const type = stmt.type;

  // WITH ... AS (...) : inspect every CTE and the main statement so wrapped writes are caught
  if (type === "with") {
    if (!Array.isArray(stmt.bind) || !stmt.in) {
      add("DISALLOWED_STATEMENT_TYPE", "Unsupported WITH structure.");
      return;
    }
    for (let i = 0; i < stmt.bind.length; i++) {
      const cte = stmt.bind[i];
      if (cte && cte.statement) inspectStatement(cte.statement, ctx, depth + 1);
      else add("PARSE_FAILURE", "Unsupported CTE structure.");
    }
    inspectStatement(stmt.in, ctx, depth + 1);
    return;
  }
  if (type === "with recursive") {
    inspectStatement(stmt.bind, ctx, depth + 1);
    inspectStatement(stmt.in, ctx, depth + 1);
    return;
  }

  // UNION / INTERSECT / EXCEPT
  if (typeof type === "string" && SET_OPERATIONS.has(type)) {
    inspectStatement(stmt.left, ctx, depth + 1);
    inspectStatement(stmt.right, ctx, depth + 1);
    return;
  }

  if (type === "values") return;

  if (type === "select") {
    if (cfg.requireTenantFilter) enforceTenantScope(stmt.where, ctx);
    return;
  }

  if (type !== "insert" && type !== "update" && type !== "delete") {
    add("DISALLOWED_STATEMENT_TYPE", `Statement type '${String(type)}' is not permitted.`);
    add("DESTRUCTIVE_DDL", `Blocked non-DML statement '${String(type)}'.`);
    return;
  }

  // From here on: INSERT, UPDATE or DELETE
  ctx.writes = true;
  ctx.inspected.add(stmt);
  if (cfg.readOnly) add("READ_ONLY_VIOLATION", "Write statements are not permitted in read-only mode.");

  if (type === "insert") {
    if (stmt.insert) inspectStatement(stmt.insert, ctx, depth + 1);
    if (stmt.insert && stmt.insert.type === "select") {
      if (stmt.onConflict && stmt.onConflict.do && stmt.onConflict.do !== "do nothing") {
        if (!stmt.insert.where || !isBoundedWhere(stmt.insert.where, ctx)) {
          add("UNBOUNDED_UPSERT", "INSERT ... SELECT with ON CONFLICT DO UPDATE lacks a bounded WHERE clause.");
        }
      }
    }
    return;
  }

  // UPDATE or DELETE
  if ((type === "update" && stmt.from) || (type === "delete" && stmt.using)) {
    add("JOINED_MUTATION_BLOCKED", `${type.toUpperCase()} with a joined FROM/USING clause is blocked.`);
  }
  if (!stmt.where) {
    add("UNBOUNDED_MUTATION", `${type.toUpperCase()} statement is missing a WHERE clause.`);
    return;
  }
  if (!isBoundedWhere(stmt.where, ctx)) {
    add("UNSAFE_WHERE_BOUNDARY", `${type.toUpperCase()} WHERE clause does not deterministically bound a key.`);
  }
  if (cfg.requireTenantFilter) enforceTenantScope(stmt.where, ctx);
}

// One iterative walk over the whole syntax tree (no recursion, bounded size).
function auditAst(roots: any[], ctx: InspectCtx): void {
  const stack: any[] = [];
  for (let i = 0; i < roots.length; i++) stack.push(roots[i]);
  let visited = 0;

  while (stack.length > 0) {
    const node = stack.pop();
    if (node === null || typeof node !== "object") continue;
    if (++visited > MAX_AST_NODES) {
      ctx.add("TOO_COMPLEX", "SQL syntax tree is too large.");
      return;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) stack.push(node[i]);
      continue;
    }

    const type = node.type;
    if ((type === "insert" || type === "update" || type === "delete") && !ctx.inspected.has(node)) {
      ctx.add(
        "DISALLOWED_STATEMENT_TYPE",
        "Write statement in an unsupported position (for example nested inside a subquery)."
      );
    }
    if (type === "call") {
      checkCall(node, ctx);
    } else if (type === "table") {
      recordTable(node.name, false, ctx);
    } else if (type === "insert") {
      recordTable(node.into, true, ctx);
    } else if (type === "update") {
      recordTable(node.table, true, ctx);
    } else if (type === "delete") {
      recordTable(node.from, true, ctx);
    } else if (type === "with" && Array.isArray(node.bind)) {
      for (let i = 0; i < node.bind.length; i++) {
        const alias = node.bind[i] && node.bind[i].alias;
        if (alias && typeof alias.name === "string") ctx.cteNames.add(alias.name.toLowerCase());
      }
    } else if (type === "with recursive" && node.alias && typeof node.alias.name === "string") {
      ctx.cteNames.add(node.alias.name.toLowerCase());
    }

    const keys = Object.keys(node);
    for (let k = 0; k < keys.length; k++) {
      const child = node[keys[k]];
      if (child !== null && typeof child === "object") stack.push(child);
    }
  }
}

function checkCall(node: any, ctx: InspectCtx): void {
  const fn = node.function;
  if (!fn || typeof fn.name !== "string") {
    ctx.add("FUNCTION_NOT_ALLOWED", "Unrecognised function call shape (fail-closed).");
    return;
  }
  const name = fn.name.toLowerCase();
  const schema = typeof fn.schema === "string" && fn.schema.length > 0 ? fn.schema.toLowerCase() : null;

  if (schema !== null && schema !== "pg_catalog") {
    ctx.add("FUNCTION_NOT_ALLOWED", `Schema-qualified function '${schema}.${name}()' is not allowed.`);
  } else if (BLOCKED_FUNCTIONS.has(name)) {
    ctx.add("SIDE_EFFECT_FUNCTION", `Execution of administrative/side-effect function '${name}()' is blocked.`);
  } else if (!ctx.cfg.allowedFunctions.has(name)) {
    ctx.add("FUNCTION_NOT_ALLOWED", `Function '${name}()' is not on the allow-list.`);
  }
}

function recordTable(ref: any, write: boolean, ctx: InspectCtx): void {
  if (!ref || typeof ref !== "object" || typeof ref.name !== "string") return;
  ctx.tableRefs.push({
    name: ref.name.toLowerCase(),
    schema: typeof ref.schema === "string" && ref.schema.length > 0 ? ref.schema.toLowerCase() : null,
    write,
  });
}

function evaluateTables(ctx: InspectCtx): void {
  const allowed = ctx.cfg.allowedTables;
  for (let i = 0; i < ctx.tableRefs.length; i++) {
    const ref = ctx.tableRefs[i];
    if (
      ref.schema === "pg_catalog" ||
      ref.schema === "information_schema" ||
      ref.schema === "pg_toast" ||
      ref.name.startsWith("pg_")
    ) {
      ctx.add("SYSTEM_CATALOG_ACCESS", `Access to system catalog '${ref.name}' is not permitted.`);
      continue;
    }
    if (allowed) {
      if (ref.schema === null && ctx.cteNames.has(ref.name)) continue;
      const qualified = ref.schema ? `${ref.schema}.${ref.name}` : ref.name;
      if (!allowed.has(ref.name) && !allowed.has(qualified)) {
        ctx.add("TABLE_NOT_ALLOWED", `Table '${qualified}' is not on the allow-list.`);
      }
    }
  }
  if (allowed && ctx.writes && !ctx.tableRefs.some((r) => r.write)) {
    ctx.add("TABLE_NOT_ALLOWED", "Could not determine which table is being written (fail-closed).");
  }
}

// ---------------------------------------------------------------------------
// Tenant isolation and WHERE-boundary logic
// ---------------------------------------------------------------------------

function enforceTenantScope(whereExpr: Expr | undefined, ctx: InspectCtx): void {
  const { add, cfg } = ctx;
  if (!whereExpr) {
    add("MISSING_TENANT_ISOLATION", "Query is missing a WHERE clause containing a mandatory tenant filter.");
    return;
  }
  const result = checkTenantExpr(whereExpr, cfg.tenantCols, cfg.expectedTenantId, 0);
  if (result.spoofed) {
    add("CROSS_TENANT_SPOOFING", `Tenant filter value does not match authorized tenant '${cfg.expectedTenantId}'.`);
  } else if (!result.hasValidTenantFilter) {
    add(
      "MISSING_TENANT_ISOLATION",
      `Query WHERE clause must enforce equality on one of: ${Array.from(cfg.tenantCols).join(", ")}.`
    );
  }
}

function checkTenantExpr(
  expr: any,
  tenantCols: Set<string>,
  expectedTenantId: string | number | undefined,
  depth: number
): { hasValidTenantFilter: boolean; spoofed: boolean } {
  if (!expr || typeof expr !== "object" || depth > MAX_AST_DEPTH) {
    return { hasValidTenantFilter: false, spoofed: false };
  }

  if (expr.type === "binary") {
    const op = String(expr.op).toUpperCase();

    if (op === "AND") {
      const left = checkTenantExpr(expr.left, tenantCols, expectedTenantId, depth + 1);
      const right = checkTenantExpr(expr.right, tenantCols, expectedTenantId, depth + 1);
      return {
        hasValidTenantFilter:
          (left.hasValidTenantFilter || right.hasValidTenantFilter) && !left.spoofed && !right.spoofed,
        spoofed: left.spoofed || right.spoofed,
      };
    }

    // In an OR, BOTH sides must be tenant-scoped to prevent `(tenant_id = 'a' OR 1=1)`
    if (op === "OR") {
      const left = checkTenantExpr(expr.left, tenantCols, expectedTenantId, depth + 1);
      const right = checkTenantExpr(expr.right, tenantCols, expectedTenantId, depth + 1);
      return {
        hasValidTenantFilter: left.hasValidTenantFilter && right.hasValidTenantFilter,
        spoofed: left.spoofed || right.spoofed,
      };
    }

    if (op === "=") {
      const colName = extractColumnName(expr.left);
      const literalVal = extractScalarValue(expr.right);
      if (colName && tenantCols.has(colName) && isSafeScalarOrParam(expr.right, 0)) {
        if (expectedTenantId !== undefined && literalVal !== null && String(literalVal) !== String(expectedTenantId)) {
          return { hasValidTenantFilter: false, spoofed: true };
        }
        return { hasValidTenantFilter: true, spoofed: false };
      }
    }
  }

  return { hasValidTenantFilter: false, spoofed: false };
}

function isBoundedWhere(expr: any, ctx: InspectCtx, depth: number = 0): boolean {
  if (!expr || typeof expr !== "object" || depth > MAX_AST_DEPTH) return false;

  if (expr.type === "binary") {
    const op = String(expr.op).toUpperCase();

    if (op === "AND") {
      // If either side has a tautology, reject; otherwise require at least one bounded key
      if (isTautologyOrSweep(expr.left, 0) || isTautologyOrSweep(expr.right, 0)) return false;
      return isBoundedWhere(expr.left, ctx, depth + 1) || isBoundedWhere(expr.right, ctx, depth + 1);
    }

    if (op === "OR") {
      // Every branch of an OR must independently be safely bounded
      return isBoundedWhere(expr.left, ctx, depth + 1) && isBoundedWhere(expr.right, ctx, depth + 1);
    }

    if (op === "=") {
      const leftCol = extractColumnName(expr.left);
      const rightCol = extractColumnName(expr.right);
      if (leftCol && rightCol) return false; // WHERE id = id
      if (leftCol && ctx.cfg.uniqueKeyCols.has(leftCol)) return isSafeScalarOrParam(expr.right, 0);
      return false;
    }

    if (op === "IN") {
      const leftCol = extractColumnName(expr.left);
      if (!leftCol || !ctx.cfg.uniqueKeyCols.has(leftCol)) return false;
      if (expr.right && expr.right.type === "list" && Array.isArray(expr.right.expressions)) {
        const items: any[] = expr.right.expressions;
        return items.length > 0 && items.length <= 100 && items.every((item: any) => isSafeScalarOrParam(item, 0));
      }
      return false;
    }
  }

  return false;
}

function isTautologyOrSweep(expr: any, depth: number): boolean {
  if (!expr || typeof expr !== "object" || depth > MAX_AST_DEPTH) return true;

  if (expr.type === "binary") {
    const op = String(expr.op).toUpperCase();
    if (op === "OR" || op === "AND") {
      return isTautologyOrSweep(expr.left, depth + 1) || isTautologyOrSweep(expr.right, depth + 1);
    }
    if (op === "=") {
      const leftCol = extractColumnName(expr.left);
      const rightCol = extractColumnName(expr.right);
      if (leftCol && rightCol && leftCol === rightCol) return true;
      if (!leftCol && !rightCol) return true; // constant comparison like 1 = 1
      return false;
    }
    if (["!=", "<>", ">", "<", ">=", "<=", "LIKE", "ILIKE"].includes(op)) return true;
  }

  if (expr.type === "unary") {
    const op = String(expr.op).toUpperCase();
    if (op.includes("NULL") || op === "NOT") return true;
  }

  return false;
}

function extractColumnName(node: any): string | null {
  if (!node || typeof node !== "object") return null;
  if (node.type === "ref" && typeof node.name === "string") return node.name.toLowerCase();
  return null;
}

function extractScalarValue(node: any): string | number | boolean | null {
  if (!node || typeof node !== "object") return null;
  if (node.type === "string" || node.type === "integer" || node.type === "numeric" || node.type === "boolean") {
    return node.value;
  }
  return null;
}

function isSafeScalarOrParam(node: any, depth: number): boolean {
  if (!node || typeof node !== "object" || depth > 8) return false;

  if (node.type === "string") {
    const val = String(node.value).trim().toLowerCase();
    return !(val === "true" || val === "false" || val === "%" || val === "");
  }
  if (node.type === "integer" || node.type === "numeric") return true;
  if (node.type === "parameter") return true;

  // typed parameters like $1::uuid
  if (node.type === "cast") return isSafeScalarOrParam(node.operand, depth + 1);

  // negative numbers like -5
  if (node.type === "unary" && (node.op === "-" || node.op === "+")) {
    return !!node.operand && (node.operand.type === "integer" || node.operand.type === "numeric");
  }

  // ANY($1) array parameter binding
  if (
    node.type === "call" &&
    node.function &&
    String(node.function.name).toLowerCase() === "any" &&
    Array.isArray(node.args) &&
    node.args.length === 1
  ) {
    return isSafeScalarOrParam(node.args[0], depth + 1);
  }

  if (node.type === "array select" && node.expr) return isSafeScalarOrParam(node.expr, depth + 1);

  return false;
} 