/**
 * Aletheia MCP Server: High-Performance SQL Query & DDL/DML Guard
 * 
 * Target latency: <0.1ms
 * Detects: Destructive DDL (DROP, TRUNCATE), unbounded DML (DELETE/UPDATE without WHERE or with WHERE 1=1),
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

// Tautological predicate patterns that fake a bounded WHERE clause
const TAUTOLOGICAL_WHERE_PATTERN = /\bWHERE\s+(1\s*=\s*1|0\s*=\s*0|true|'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+)\s*(;|$)/i;

export interface SqlAnalysis {
  isDestructive: boolean;
  isWriteAttempt: boolean;
  statementType: "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "DDL" | "UNKNOWN";
  hasWhereClause: boolean;
  isTautological: boolean;
  violations: Violation[];
  targetTables: string[];
}

export function analyzeSqlQuery(rawSql: string, mandate: Mandate): SqlAnalysis {
  // Strip inline SQL comments:
  // 1. Remove single-line comments (-- ...)
  const noSingleLine = rawSql.replace(/--.*$/gm, " ");

  // 2. Representation A (spaced - ANSI SQL standard delimiter): comments become spaces
  const repSpace = noSingleLine.replace(/\/\*[\s\S]*?\*\//g, " ").trim().replace(/\s+/g, " ");

  // 3. Representation B (collapsed): comments collapsed to catch keyword splitting like DR/**/OP
  const repCollapsed = noSingleLine.replace(/\/\*[\s\S]*?\*\//g, "").trim().replace(/\s+/g, " ");

  const normalized = repSpace;
  const violations: Violation[] = [];

  // Determine statement type (check both representations)
  let statementType: SqlAnalysis["statementType"] = "UNKNOWN";
  if (/^SELECT\b/i.test(repSpace) || /^SELECT\b/i.test(repCollapsed)) statementType = "SELECT";
  else if (/^INSERT\b/i.test(repSpace) || /^INSERT\b/i.test(repCollapsed)) statementType = "INSERT";
  else if (/^UPDATE\b/i.test(repSpace) || /^UPDATE\b/i.test(repCollapsed)) statementType = "UPDATE";
  else if (/^DELETE\b/i.test(repSpace) || /^DELETE\b/i.test(repCollapsed)) statementType = "DELETE";
  else if (/^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(repSpace) || /^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(repCollapsed)) statementType = "DDL";

  const isWriteAttempt = WRITE_STATEMENTS.test(repSpace) || WRITE_STATEMENTS.test(repCollapsed) || statementType === "DDL";
  const hasWhereClause = /\bWHERE\b/i.test(repSpace) || /\bWHERE\b/i.test(repCollapsed);
  const isTautological = hasWhereClause && (TAUTOLOGICAL_WHERE_PATTERN.test(repSpace) || TAUTOLOGICAL_WHERE_PATTERN.test(repCollapsed));

  // 1. Check for Destructive DDL (DROP, TRUNCATE) across both representations
  for (const { pattern, description } of DESTRUCTIVE_DDL_PATTERNS) {
    if (pattern.test(repSpace) || pattern.test(repCollapsed)) {
      violations.push({
        signature: "S3",
        type: "DESTRUCTIVE_SQL_DDL",
        severity: "CRITICAL",
        description,
        evidence: (pattern.test(repSpace) ? repSpace : repCollapsed).slice(0, 100),
        remediation: "Destructive schema and data drops are blocked in agent execution mode.",
      });
    }
  }

  // 2. Check for Unbounded Mutations (DELETE or UPDATE without WHERE clause or with tautological WHERE)
  if (statementType === "DELETE" && (!hasWhereClause || isTautological)) {
    violations.push({
      signature: "S3",
      type: "UNBOUNDED_SQL_MUTATION",
      severity: "CRITICAL",
      description: isTautological
        ? "DELETE statement with tautological WHERE predicate (WHERE 1=1) effectively wipes entire table"
        : "DELETE statement without WHERE clause (unbounded table deletion)",
      evidence: normalized.slice(0, 100),
      remediation: "Provide explicit non-tautological WHERE predicates targeting specific keys.",
    });
  }

  if (statementType === "UPDATE" && (!hasWhereClause || isTautological)) {
    violations.push({
      signature: "S3",
      type: "UNBOUNDED_SQL_MUTATION",
      severity: "HIGH",
      description: isTautological
        ? "UPDATE statement with tautological WHERE predicate (WHERE 1=1) overwrites column across all rows"
        : "UPDATE statement without WHERE clause (unbounded column overwrite across all rows)",
      evidence: normalized.slice(0, 100),
      remediation: "Add an explicit non-tautological WHERE clause to constrain the update scope.",
    });
  }

  // 3. Check for Privilege Escalation / User tampering across both representations
  for (const pattern of PRIVILEGE_PATTERNS) {
    if (pattern.test(repSpace) || pattern.test(repCollapsed)) {
      violations.push({
        signature: "S3",
        type: "PRIVILEGE_ESCALATION",
        severity: "CRITICAL",
        description: "SQL user privilege manipulation attempt",
        evidence: (pattern.test(repSpace) ? repSpace : repCollapsed).slice(0, 100),
        remediation: "Agents are not permitted to grant roles, create users, or alter security attributes.",
      });
      break;
    }
  }

  // 4. Check Multi-statement injection attempt (; followed by DDL/DML) across both representations
  const chainedPattern = /;\s*(DROP|DELETE|TRUNCATE|UPDATE|INSERT|GRANT|ALTER)\b/i;
  if (chainedPattern.test(repSpace) || chainedPattern.test(repCollapsed)) {
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
    isTautological,
    violations,
    targetTables,
  };
}
