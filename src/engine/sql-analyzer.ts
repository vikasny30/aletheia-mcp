/**
 * Aletheia MCP Server: High-Performance SQL Query & DDL/DML Guard
 * 
 * Target latency: <0.1ms
 * Detects: Destructive DDL (DROP, TRUNCATE), unbounded DML (DELETE/UPDATE without WHERE or with WHERE 1=1),
 * privilege tampering (GRANT, ALTER USER), and multi-statement injection tricks.
 */

import { Violation, Mandate } from "./types.js";
import { analyzeUrl } from "./network-analyzer.js";

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

const SQL_SYSTEM_ESCAPE_PATTERNS: Array<{
  pattern: RegExp;
  description: string;
}> = [
  {
    pattern: /\bCOPY\b[\s\S]*?\b(FROM|TO)\s+PROGRAM\b/i,
    description: "Database command execution via COPY PROGRAM (PostgreSQL)",
  },
  {
    pattern: /\b(pg_read_file|pg_read_binary_file|pg_write_file|lo_import|lo_export)\s*\(/i,
    description: "Database filesystem access function pg_read_file / lo_import (PostgreSQL)",
  },
  {
    pattern: /\bLOAD\s+DATA\s+(?:LOCAL\s+)?INFILE\b/i,
    description: "Database arbitrary file read via LOAD DATA INFILE (MySQL)",
  },
  {
    pattern: /\bINTO\s+(OUTFILE|DUMPFILE)\b/i,
    description: "Database arbitrary file write via INTO OUTFILE / DUMPFILE (MySQL)",
  },
  {
    pattern: /\bATTACH\s+(?:DATABASE\s+)?['`"]?[^;'`"]+['`"]?\s+AS\b/i,
    description: "Arbitrary database file attachment via ATTACH DATABASE (SQLite)",
  },
  {
    pattern: /\bxp_cmdshell\b/i,
    description: "Operating system command execution via xp_cmdshell",
  },
  {
    pattern: /\bload_extension\s*\(/i,
    description: "SQLite dynamic library / extension loading (load_extension)",
  },
  {
    pattern: /\b(DBMS_LOB\.(?:LOADFROMFILE|LOADBLOBFROMFILE)|DBMS_SCHEDULER\b|DBMS_JAVA\b|UTL_FILE\b|UTL_HTTP\b|UTL_TCP\b|UTL_SMTP\b)/i,
    description: "Database procedural package escape (Oracle DBMS_LOB / DBMS_SCHEDULER / UTL_HTTP / UTL_FILE)",
  },
  {
    pattern: /\b(OPENROWSET|OPENDATASOURCE|dblink)\s*\(/i,
    description: "Database external query / distributed command primitive (OPENROWSET / dblink)",
  },
];

// Cloud instance metadata patterns directly detectable in SQL queries (dotted, decimal, hex, octal, and IPv6)
const SQL_METADATA_PATTERNS = [
  /\b169\.254\.169\.254\b/,
  /\bmetadata\.google\.internal\b/i,
  /\b169\.254\.170\.2\b/,
  /\[::ffff:(?:169\.254\.169\.254|[0-9a-f]{1,4}:[0-9a-f]{1,4})\]/i,
  /\b2852039166\b/,
  /\b2852039170\b/,
  /\b0xa9fea9fe\b/i,
  /\b0xa9\.0xfe\.0xa9\.0xfe\b/i,
  /\b0251\.0376\.0251\.0376\b/,
];

// Tautological predicate patterns that fake a bounded WHERE clause
const TAUTOLOGICAL_WHERE_PATTERN = /\bWHERE\s+(?:1\s*=\s*1|0\s*=\s*0|true\b|'[^']*'\s*=\s*'[^']*'|(\d+)\s*=\s*\1)(?=\s*(?:;|$|\)|RETURNING\b|ORDER\b|LIMIT\b|GROUP\b|HAVING\b|WINDOW\b|INTO\b|--|\/\*))/i;

export interface SqlAnalysis {
  isDestructive: boolean;
  isWriteAttempt: boolean;
  statementType: "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "DDL" | "UNKNOWN";
  hasWhereClause: boolean;
  isTautological: boolean;
  violations: Violation[];
  targetTables: string[];
}

function toSqlString(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (Array.isArray(raw)) return raw.map((x) => String(x ?? "")).join(";\n");
  if (raw !== null && typeof raw === "object") {
    try {
      return JSON.stringify(raw);
    } catch {
      return String(raw);
    }
  }
  if (raw !== undefined && raw !== null) return String(raw);
  return "";
}

/**
 * Masks string literals (single-quoted and Postgres dollar-quoted) to eliminate false positives
 * on benign queries containing keywords in strings (e.g. SELECT $$DROP TABLE users;$$;).
 * Preserves DO $$ blocks because the contents of procedural DO blocks are executable code.
 */
function maskSqlStringLiterals(sql: string): string {
  const doBlocks: string[] = [];
  let s = sql.replace(/\bDO\s+(\$[a-zA-Z0-9_]*\$)[\s\S]*?\1/gi, (match) => {
    doBlocks.push(match);
    return `__DO_BLOCK_${doBlocks.length - 1}__`;
  });

  // Mask standard single-quoted literals: '...'
  s = s.replace(/'(?:[^'\\]|\\.)*'/g, "'__STR__'");

  // Mask PostgreSQL dollar-quoted string constants: $$...$$ or $tag$...$tag$
  s = s.replace(/\$([a-zA-Z0-9_]*)\$[\s\S]*?\$\1\$/g, "'__STR__'");

  // Restore preserved DO procedural blocks
  s = s.replace(/__DO_BLOCK_(\d+)__/g, (_, idx) => doBlocks[Number(idx)]);
  return s;
}

export function analyzeSqlQuery(rawSqlInput: unknown, mandate: Mandate): SqlAnalysis {
  const rawSql = toSqlString(rawSqlInput);
  // Strip inline SQL comments (both ANSI -- and MySQL # single-line comments)
  const noSingleLine = rawSql.replace(/--.*$/gm, " ").replace(/#.*$/gm, " ");

  // Mask string literals to eliminate false positives in benign SELECT string literals
  const maskedSql = maskSqlStringLiterals(noSingleLine);

  // 1. Representation A (spaced - ANSI SQL standard delimiter): comments become spaces
  const repSpace = maskedSql.replace(/\/\*[\s\S]*?\*\//g, " ").trim().replace(/\s+/g, " ");

  // 2. Representation B (collapsed): comments collapsed to catch keyword splitting like DR/**/OP
  const repCollapsed = maskedSql.replace(/\/\*[\s\S]*?\*\//g, "").trim().replace(/\s+/g, " ");

  const normalized = repSpace;
  const violations: Violation[] = [];

  // Determine statement type (check both representations)
  let statementType: SqlAnalysis["statementType"] = "UNKNOWN";
  if (/^SELECT\b/i.test(repSpace) || /^SELECT\b/i.test(repCollapsed)) statementType = "SELECT";
  else if (/^INSERT\b/i.test(repSpace) || /^INSERT\b/i.test(repCollapsed)) statementType = "INSERT";
  else if (/^UPDATE\b/i.test(repSpace) || /^UPDATE\b/i.test(repCollapsed)) statementType = "UPDATE";
  else if (/^DELETE\b/i.test(repSpace) || /^DELETE\b/i.test(repCollapsed)) statementType = "DELETE";
  else if (/^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(repSpace) || /^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(repCollapsed)) statementType = "DDL";

  // Check for DELETE and UPDATE operations anywhere in the query (including CTEs and DO blocks)
  const hasDelete = /\bDELETE\s+FROM\b/i.test(repSpace) || /\bDELETE\s+FROM\b/i.test(repCollapsed);
  const hasUpdate = /\bUPDATE\s+\S+\s+SET\b/i.test(repSpace) || /\bUPDATE\s+\S+\s+SET\b/i.test(repCollapsed);

  const isWriteAttempt = hasDelete || hasUpdate || WRITE_STATEMENTS.test(repSpace) || WRITE_STATEMENTS.test(repCollapsed) || statementType === "DDL";
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
  // Evaluated anywhere mutation keywords appear (including CTEs, DO blocks, etc.)
  if ((hasDelete || statementType === "DELETE") && (!hasWhereClause || isTautological)) {
    violations.push({
      signature: "S3",
      type: "UNBOUNDED_SQL_MUTATION",
      severity: "CRITICAL",
      description: isTautological
        ? "DELETE statement with tautological WHERE predicate (WHERE 1=1 or WHERE true) effectively wipes entire table"
        : "DELETE statement without WHERE clause (unbounded table deletion)",
      evidence: normalized.slice(0, 100),
      remediation: "Provide explicit non-tautological WHERE predicates targeting specific keys.",
    });
  }

  if ((hasUpdate || statementType === "UPDATE") && (!hasWhereClause || isTautological)) {
    violations.push({
      signature: "S3",
      type: "UNBOUNDED_SQL_MUTATION",
      severity: "HIGH",
      description: isTautological
        ? "UPDATE statement with tautological WHERE predicate (WHERE 1=1 or WHERE true) overwrites column across all rows"
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

  // 3.5. Check for Database System/OS Escapes & Filesystem primitives
  for (const { pattern, description } of SQL_SYSTEM_ESCAPE_PATTERNS) {
    if (pattern.test(repSpace) || pattern.test(repCollapsed) || pattern.test(rawSql)) {
      violations.push({
        signature: "S3",
        type: "PRIVILEGE_ESCALATION",
        severity: "CRITICAL",
        description,
        evidence: (pattern.test(repSpace) ? repSpace : pattern.test(repCollapsed) ? repCollapsed : rawSql).slice(0, 100),
        remediation: "Database OS execution and filesystem access primitives are strictly prohibited in agent execution mode.",
      });
      break;
    }
  }

  // 3.6. Check Direct Cloud Instance Metadata in SQL query
  for (const metaPattern of SQL_METADATA_PATTERNS) {
    if (metaPattern.test(rawSql) || metaPattern.test(repSpace) || metaPattern.test(repCollapsed)) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "CRITICAL",
        description: "Cloud instance metadata access detected in SQL query",
        evidence: rawSql.slice(0, 120),
        remediation: "Requests to cloud metadata endpoints (AWS/GCP/Azure) are strictly prohibited to prevent credential exfiltration.",
      });
      break;
    }
  }

  // 3.7. Check Embedded URLs in SQL query for SSRF
  if (rawSql.includes("http://") || rawSql.includes("https://")) {
    const urlRegex = /https?:\/\/[^\s"'`<>\\;)]+/gi;
    for (const match of rawSql.matchAll(urlRegex)) {
      const urlRes = analyzeUrl(match[0], mandate);
      for (const v of urlRes.violations) {
        if (v.severity === "CRITICAL" || urlRes.isSSRF) {
          violations.push({
            ...v,
            description: `SQL embedded URL SSRF violation: ${v.description}`,
          });
        }
      }
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
      remediation: "The active session mandate allows SELECT only. Enabling allowWrite requires operator authorization (operatorSecret); agents cannot self-authorize database mutations.",
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
