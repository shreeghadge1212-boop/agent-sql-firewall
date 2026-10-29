export type RuleViolationCode = "EMPTY_OR_INVALID_SQL" | "MULTI_STATEMENT" | "PARSE_FAILURE" | "DISALLOWED_STATEMENT_TYPE" | "DESTRUCTIVE_DDL" | "UNBOUNDED_MUTATION" | "UNSAFE_WHERE_BOUNDARY" | "JOINED_MUTATION_BLOCKED" | "UNBOUNDED_UPSERT" | "SIDE_EFFECT_FUNCTION" | "MISSING_TENANT_ISOLATION" | "CROSS_TENANT_SPOOFING";
export interface RuleViolation {
    rule: RuleViolationCode;
    detail: string;
}
export interface FirewallVerdict {
    decision: "allow" | "block";
    violations: RuleViolation[];
    latencyMs: number;
}
export interface FirewallOptions {
    /** Enforce that every SELECT/UPDATE/DELETE filters by a tenant identifier column */
    requireTenantFilter?: boolean;
    /** Allowed column names for tenant scoping (default: tenant_id, org_id, organization_id, workspace_id) */
    tenantColumns?: string[];
    /** Optional strict session tenant ID to prevent cross-tenant spoofing (e.g. WHERE tenant_id = 'other_org') */
    expectedTenantId?: string | number;
}
export declare function evaluateSql(sql: string, options?: FirewallOptions): FirewallVerdict;
