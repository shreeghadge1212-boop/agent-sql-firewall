import { Request, Response, NextFunction } from 'express';
import { evaluateSql, FirewallOptions, FirewallVerdict } from './astFirewall';

// Re-export types so users can use the engine programmatically if they aren't using Express
export { evaluateSql, FirewallOptions, FirewallVerdict };

export interface MiddlewareOptions extends FirewallOptions {
  /** Function to extract the raw SQL string from the request */
  extractSql?: (req: Request) => string | undefined;
  /** Custom handler when a violation occurs. Defaults to a 403 JSON response. */
  onViolation?: (req: Request, res: Response, verdict: FirewallVerdict) => void;
}

export const agentSqlFirewall = (options: MiddlewareOptions = {}) => {
  const extract = options.extractSql || ((req: Request) => req.body?.sql);

  return (req: Request, res: Response, next: NextFunction): void => {
    const sql = extract(req);

    // If no SQL is found, pass to the next middleware
    if (!sql || typeof sql !== 'string') {
      next();
      return;
    }

    const verdict = evaluateSql(sql, options);

    if (verdict.decision === 'block') {
      if (options.onViolation) {
        options.onViolation(req, res, verdict);
        return;
      }

      res.status(403).json({
        error: 'PolicyViolation',
        message: 'Agent execution blocked: Destructive or unauthorized SQL detected.',
        violations: verdict.violations,
        latencyMs: verdict.latencyMs
      });
      return;
    }

    // Attach latency metric to headers for observability
    res.setHeader('x-firewall-latency-ms', verdict.latencyMs.toString());
    next();
  };
};