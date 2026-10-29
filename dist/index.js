"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.agentSqlFirewall = exports.evaluateSql = void 0;
const astFirewall_1 = require("./astFirewall");
Object.defineProperty(exports, "evaluateSql", { enumerable: true, get: function () { return astFirewall_1.evaluateSql; } });
const agentSqlFirewall = (options = {}) => {
    const extract = options.extractSql || ((req) => req.body?.sql);
    return (req, res, next) => {
        const sql = extract(req);
        // If no SQL is found, pass to the next middleware
        if (!sql || typeof sql !== 'string') {
            next();
            return;
        }
        const verdict = (0, astFirewall_1.evaluateSql)(sql, options);
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
exports.agentSqlFirewall = agentSqlFirewall;
