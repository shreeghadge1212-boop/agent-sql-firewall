// src/index.ts
import { createHash, randomUUID } from 'node:crypto';
import { createFirewall } from './astFirewall';
import type { FirewallOptions, RuleViolation, RuleViolationCode } from './astFirewall';

export { evaluateSql, createFirewall } from './astFirewall';
export type {
  FirewallOptions,
  FirewallVerdict,
  RuleViolation,
  RuleViolationCode,
  DecisionEvent,
} from './astFirewall';

// ---------------------------------------------------------------------------
// Minimal structural types: works with Express 4/5 without requiring @types/express
// ---------------------------------------------------------------------------

export interface ReqLike {
  body?: unknown;
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
}

export interface ResLike {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
  locals: Record<string, any>;
  headersSent?: boolean;
}

export type NextLike = (err?: unknown) => void;
export type SqlFirewallMiddleware = (req: ReqLike, res: ResLike, next: NextLike) => void;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type AuditReason = 'allowed' | 'policy_violation' | 'invalid_input' | 'internal_error';

export interface AuditEvent {
  timestamp: string;
  requestId: string;
  mode: 'enforce' | 'monitor';
  decision: 'allow' | 'block';
  /** true only when the request was actually rejected (false for would-be blocks in monitor mode) */
  enforced: boolean;
  reason: AuditReason;
  rules: RuleViolationCode[];
  violations: RuleViolation[];
  /** SHA-256 of the query for correlation. The SQL text itself is never logged. */
  queryHash: string | null;
  queryLength: number;
  latencyMs: number;
  sourceIp: string | undefined;
}

export interface SqlFirewallOptions extends FirewallOptions {
  /**
   * 'enforce' (default) rejects with 403. 'monitor' logs would-be blocks and lets traffic through.
   * Any value other than 'monitor' enforces, so a typo fails closed.
   */
  mode?: 'enforce' | 'monitor';
  /** Where to read the SQL from. Default: req.body.query */
  extractQuery?: (req: ReqLike) => unknown;
  /** Audit sink. Never awaited, never allowed to affect the decision. Default: JSON line on stdout. */
  onAudit?: (event: AuditEvent) => void | Promise<void>;
  /**
   * 'codes' (default): 403 body lists generic rule codes, so an AI agent can self-correct and retry.
   * 'none': 403 body is fully opaque. Rule `detail` strings are never sent to clients.
   */
  exposeViolations?: 'codes' | 'none';
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{8,128}$/;

const defaultExtract = (req: ReqLike): unknown =>
  req.body !== null && typeof req.body === 'object' ? (req.body as { query?: unknown }).query : undefined;

const defaultAudit = (event: AuditEvent): void => {
  process.stdout.write(`${JSON.stringify({ source: 'agent-sql-firewall', ...event })}\n`);
};

function getRequestId(req: ReqLike): string {
  try {
    const header = req.headers['x-request-id'];
    const candidate = Array.isArray(header) ? header[0] : header;
    // Only accept well-formed IDs so callers cannot inject log-forging content.
    if (typeof candidate === 'string' && REQUEST_ID_PATTERN.test(candidate)) return candidate;
  } catch {
    /* fall through */
  }
  return randomUUID();
}

function emitAudit(sink: (event: AuditEvent) => void | Promise<void>, event: AuditEvent): void {
  try {
    const result = sink(event);
    if (result && typeof (result as Promise<void>).catch === 'function') {
      (result as Promise<void>).catch(() => undefined);
    }
  } catch {
    // A broken logger must never change a security decision.
  }
}

function isVerdictShape(v: unknown): v is { decision: 'allow' | 'block'; violations: RuleViolation[] } {
  if (typeof v !== 'object' || v === null) return false;
  const r = v as Record<string, unknown>;
  return (r.decision === 'allow' || r.decision === 'block') && Array.isArray(r.violations);
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

export function sqlFirewall(options: SqlFirewallOptions = {}): SqlFirewallMiddleware {
  const {
    mode = 'enforce',
    extractQuery = defaultExtract,
    onAudit = defaultAudit,
    exposeViolations = 'codes',
    ...firewallOptions
  } = options;

  // Built ONCE. Never per request.
  const firewall = createFirewall(firewallOptions);
  const auditedMode: 'enforce' | 'monitor' = mode === 'monitor' ? 'monitor' : 'enforce';
  const enforce = auditedMode === 'enforce';

  return function sqlFirewallMiddleware(req, res, next): void {
    const started = performance.now();
    const requestId = getRequestId(req);

    // Default posture is BLOCK. Only a clean "allow" verdict flips it.
    let decision: 'allow' | 'block' = 'block';
    let reason: AuditReason = 'internal_error';
    let violations: RuleViolation[] = [];
    let query: string | null = null;

    try {
      const raw = extractQuery(req);

      if (typeof raw !== 'string' || raw.trim().length === 0) {
        reason = 'invalid_input';
        violations = [{ rule: 'EMPTY_OR_INVALID_SQL', detail: 'SQL payload is missing or not a string.' }];
      } else {
        query = raw;
        const verdict: unknown = firewall.evaluate(raw);
        if (isVerdictShape(verdict)) {
          decision = verdict.decision;
          violations = verdict.violations;
          reason = decision === 'allow' ? 'allowed' : 'policy_violation';
        } else {
          violations = [{ rule: 'INTERNAL_ERROR', detail: 'Malformed verdict (fail-closed).' }];
        }
      }
    } catch {
      decision = 'block';
      reason = 'internal_error';
      violations = [{ rule: 'INTERNAL_ERROR', detail: 'Middleware error (fail-closed).' }];
    }

    const enforced = decision === 'block' && enforce;
    const rules = violations.map((v) => v.rule);

    emitAudit(onAudit, {
      timestamp: new Date().toISOString(),
      requestId,
      mode: auditedMode,
      decision,
      enforced,
      reason,
      rules,
      violations,
      queryHash: query === null ? null : createHash('sha256').update(query, 'utf8').digest('hex'),
      queryLength: query === null ? 0 : query.length,
      latencyMs: Number((performance.now() - started).toFixed(3)),
      sourceIp: req.ip,
    });

    try {
      res.locals.sqlFirewall = { requestId, decision, reason, rules, enforced };
    } catch {
      /* non-fatal */
    }

    if (enforced) {
      try {
        if (!res.headersSent) {
          res.setHeader('Cache-Control', 'no-store');
          res.setHeader('X-Request-Id', requestId);
          res.status(403);
          res.json({
            error: 'forbidden',
            message: 'Query blocked by SQL firewall policy.',
            requestId,
            ...(exposeViolations === 'codes' ? { rules } : {}),
          });
        }
      } catch {
        // If the response itself fails, the request is still NOT forwarded.
      }
      return;
    }

    next();
  };
}

export default sqlFirewall;