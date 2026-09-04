/**
 * Aletheia MCP Server: Core Type Definitions
 * 
 * Signature S3: Scope Creep Beyond Mandate
 * Signature S2b: Adversarial Input Exploitation
 * Signature S5: No Safe State Fallback
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type Verdict = "ALLOW" | "BLOCK" | "CONFIRM_REQUIRED";

export type RiskTolerance = "low" | "medium" | "high";

export interface Violation {
  signature: "S3" | "S2b" | "S5";
  type:
    | "DESTRUCTIVE_FS_COMMAND"
    | "DESTRUCTIVE_SQL_DDL"
    | "UNBOUNDED_SQL_MUTATION"
    | "CREDENTIAL_EXFILTRATION"
    | "OUT_OF_SCOPE_MUTATION"
    | "SENSITIVE_FILE_ACCESS"
    | "OBFUSCATION_BYPASS"
    | "INTERPRETER_ESCAPE_EXECUTION"
    | "PRIVILEGE_ESCALATION"
    | "PROMPT_INJECTION_PAYLOAD"
    | "UNAUTHORIZED_NETWORK_EGRESS"
    | "SYSTEM_STABILITY_THREAT"
    | "UNAUTHORIZED_MANDATE_ESCALATION"
    | "DISALLOWED_TOOL";
  severity: Severity;
  description: string;
  evidence: string;
  remediation: string;
}

export interface Mandate {
  sessionId: string;
  taskDescription: string;
  allowedTools: string[];
  disallowedTools?: string[];
  allowedPaths: string[];
  disallowedPaths?: string[];
  allowWrite: boolean;
  allowDestructive: boolean;
  allowNetwork: boolean;
  allowSubshells: boolean;
  riskTolerance: RiskTolerance;
  operatorSecret?: string; // Optional operator secret required to loosen boundaries
  isLocked?: boolean;       // If true, mandate cannot be loosened at runtime by the agent
  createdAt: number;
  updatedAt: number;
}

export interface AssessmentResult {
  verdict: Verdict;
  riskScore: number; // 0.0 (benign) to 1.0 (maximum threat)
  passed: boolean;
  violations: Violation[];
  latencyMs: number;
  timestamp: number;
  toolName: string;
  evaluatedScope: {
    mandateTask: string;
    isWriteAttempt: boolean;
    isNetworkAttempt: boolean;
    targetPaths: string[];
  };
  explanation: string;
}

export interface AuditRecord {
  id: string;
  timestamp: number;
  toolName: string;
  rawInput: Record<string, unknown>;
  verdict: Verdict;
  riskScore: number;
  violationsCount: number;
  latencyMs: number;
  violationTypes: string[];
}

export interface TelemetrySummary {
  uptimeSeconds: number;
  totalEvaluations: number;
  verdicts: {
    allow: number;
    block: number;
    confirmRequired: number;
  };
  blockRatePercent: number;
  latency: {
    minMs: number;
    avgMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    maxMs: number;
  };
  violationsBySignature: Record<string, number>;
  violationsByType: Record<string, number>;
}
