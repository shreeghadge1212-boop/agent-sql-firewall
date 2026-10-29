import { Request, Response, NextFunction } from 'express';
import { evaluateSql, FirewallOptions, FirewallVerdict } from './astFirewall';
export { evaluateSql, FirewallOptions, FirewallVerdict };
export interface MiddlewareOptions extends FirewallOptions {
    /** Function to extract the raw SQL string from the request */
    extractSql?: (req: Request) => string | undefined;
    /** Custom handler when a violation occurs. Defaults to a 403 JSON response. */
    onViolation?: (req: Request, res: Response, verdict: FirewallVerdict) => void;
}
export declare const agentSqlFirewall: (options?: MiddlewareOptions) => (req: Request, res: Response, next: NextFunction) => void;
