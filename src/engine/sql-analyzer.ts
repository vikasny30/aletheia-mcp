/**
 * Aletheia MCP Server: High-Performance SQL Query & DDL/DML Guard
 * 
 * Target latency: <0.1ms
 * Detects: Destructive DDL (DROP, TRUNCATE), unbounded DML (DELETE/UPDATE without WHERE),
 * privilege tampering (GRANT, ALTER USER), and multi-statement injection tricks.
 */

import { Violation, Mandate } from "./types.js";

const DESTRUCTIVE_DDL_PATTERNS = [
  {
    pattern: /\bDROP\s+(DATABASE|SCHEMA|TABLE|VIEW|INDEX|TRIGGER|FUNCTION|PROCEDURE)\b/i,
    description: "Destructive DDL DROP operation",
  },
  {
    pattern: /\bTRUNCATE(\s+TABLE)?\b/i,
    description: "Destructive DDL TRUNCATE operation (fast table wipe)",
  },
  {
    pattern: /\bALTER\s+TABLE\s+\S+\s+DROP\s+(COLUMN|CONSTRAINT)\b/i,
    description: "Destructive DDL ALTER TABLE DROP operation",
  },
];

const PRIVILEGE_PATTERNS = [
  /\bGRANT\s+.*\s+TO\b/i,
  /\bREVOKE\s+.*\s+FROM\b/i,
  /\bALTER\s+USER\b/i,
  /\bCREATE\s+USER\b/i,
  /\bDROP\s+USER\b/i,
];

const WRITE_STATEMENTS = /\b(INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|MERGE\s+INTO)\b/i;

export interface SqlAnalysis {
  isDestructive: boolean;
  isWriteAttempt: boolean;
  statementType: "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "DDL" | "UNKNOWN";
  hasWhereClause: boolean;
  violations: Violation[];
  targetTables: string[];
}

export function analyzeSqlQuery(rawSql: string, mandate: Mandate): SqlAnalysis {
  const normalized = rawSql.trim().replace(/\s+/g, " ");
  const violations: Violation[] = [];

  // Determine statement type
  let statementType: SqlAnalysis["statementType"] = "UNKNOWN";
  if (/^SELECT\b/i.test(normalized)) statementType = "SELECT";
  else if (/^INSERT\b/i.test(normalized)) statementType = "INSERT";
  else if (/^UPDATE\b/i.test(normalized)) statementType = "UPDATE";
  else if (/^DELETE\b/i.test(normalized)) statementType = "DELETE";
  else if (/^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(normalized)) statementType = "DDL";

  const isWriteAttempt = WRITE_STATEMENTS.test(normalized) || statementType === "DDL";
  const hasWhereClause = /\bWHERE\b/i.test(normalized);

  // 1. Check for Destructive DDL (DROP, TRUNCATE)
  for (const { pattern, description } of DESTRUCTIVE_DDL_PATTERNS) {
    if (pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type: "DESTRUCTIVE_SQL_DDL",
        severity: "CRITICAL",
        description,
        evidence: normalized.slice(0, 100),
        remediation: "Destructive schema and data drops are blocked in agent execution mode.",
      });
    }
  }

  // 2. Check for Unbounded Mutations (DELETE or UPDATE without WHERE clause)
  if (statementType === "DELETE" && !hasWhereClause) {
    violations.push({
      signature: "S3",
      type: "UNBOUNDED_SQL_MUTATION",
      severity: "CRITICAL",
      description: "DELETE statement without WHERE clause (unbounded table deletion)",
      evidence: normalized.slice(0, 100),
      remediation: "Provide explicit WHERE predicates targeting specific keys.",
    });
  }

  if (statementType === "UPDATE" && !hasWhereClause) {
    violations.push({
      signature: "S3",
      type: "UNBOUNDED_SQL_MUTATION",
      severity: "HIGH",
      description: "UPDATE statement without WHERE clause (unbounded column overwrite across all rows)",
      evidence: normalized.slice(0, 100),
      remediation: "Add an explicit WHERE clause to constrain the update scope.",
    });
  }

  // 3. Check for Privilege Escalation / User tampering
  for (const pattern of PRIVILEGE_PATTERNS) {
    if (pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type: "PRIVILEGE_ESCALATION",
        severity: "CRITICAL",
        description: "SQL user privilege manipulation attempt",
        evidence: normalized.slice(0, 100),
        remediation: "Agents are not permitted to grant roles, create users, or alter security attributes.",
      });
      break;
    }
  }

  // 4. Check Multi-statement injection attempt (; followed by DDL/DML)
  if (/;\s*(DROP|DELETE|TRUNCATE|UPDATE|INSERT|GRANT|ALTER)\b/i.test(normalized)) {
    violations.push({
      signature: "S3",
      type: "DESTRUCTIVE_SQL_DDL",
      severity: "CRITICAL",
      description: "Multiple chained statements detected containing mutation/DDL",
      evidence: normalized.slice(0, 100),
      remediation: "Only single parameterized statements are allowed per query execution.",
    });
  }

  // 5. Evaluate against Mandate
  if (isWriteAttempt && !mandate.allowWrite) {
    violations.push({
      signature: "S3",
      type: "OUT_OF_SCOPE_MUTATION",
      severity: "HIGH",
      description: "SQL data/schema write attempt rejected under read-only mandate",
      evidence: normalized.slice(0, 100),
      remediation: "The active session mandate allows SELECT only. Enable allowWrite to execute mutations.",
    });
  }

  // Extract table names heuristically
  const targetTables: string[] = [];
  const tableMatches = normalized.matchAll(/\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+([`"']?)([a-zA-Z0-9_]+)\1/gi);
  for (const match of tableMatches) {
    if (match[2] && !targetTables.includes(match[2])) {
      targetTables.push(match[2]);
    }
  }

  return {
    isDestructive: violations.some((v) => v.severity === "CRITICAL"),
    isWriteAttempt,
    statementType,
    hasWhereClause,
    violations,
    targetTables,
  };
}
