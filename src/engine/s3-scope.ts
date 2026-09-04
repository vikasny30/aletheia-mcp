/**
 * Aletheia MCP Server: Unified Signature S3 (Scope Creep) Evaluator
 * 
 * Target latency: <0.5ms end-to-end
 * Combines: Bash lexical analysis, SQL safety, Path boundaries, SSRF, S2b prompt injections,
 * and monotonic self-mandate escalation protection.
 */

import path from "node:path";
import { performance } from "node:perf_hooks";
import {
  Mandate,
  AssessmentResult,
  Violation,
  Verdict,
  AuditRecord,
  TelemetrySummary,
} from "./types.js";
import { analyzeBashCommand } from "./bash-analyzer.js";
import { analyzeSqlQuery } from "./sql-analyzer.js";
import { analyzePath } from "./fs-analyzer.js";
import { analyzeUrl } from "./network-analyzer.js";
import { analyzeAdversarialInput } from "./s2b-injection.js";

/**
 * Checks if a requested mandate update or override attempts to loosen safety boundaries.
 */
export function isLooseningMandate(
  current: Mandate,
  requested: Partial<Mandate>
): boolean {
  // 1. Boolean capability flags
  if (requested.allowWrite === true && !current.allowWrite) return true;
  if (requested.allowDestructive === true && !current.allowDestructive) return true;
  if (requested.allowNetwork === true && !current.allowNetwork) return true;
  if (requested.allowLoopback === true && !current.allowLoopback) return true;
  if (requested.allowSubshells === true && !current.allowSubshells) return true;

  // 2. Risk tolerance loosening
  const riskLevels: Record<string, number> = { low: 1, medium: 2, high: 3 };
  if (
    requested.riskTolerance &&
    riskLevels[requested.riskTolerance] > riskLevels[current.riskTolerance]
  ) {
    return true;
  }

  // 3. allowedPaths: any path that is not contained within current allowed paths is loosening
  if (Array.isArray(requested.allowedPaths)) {
    if (requested.allowedPaths.includes("*") && !current.allowedPaths.includes("*")) {
      return true;
    }
    for (const reqPath of requested.allowedPaths) {
      if (reqPath === "*" && !current.allowedPaths.includes("*")) return true;
      const resolvedReq = path.resolve(reqPath);
      const isSubpath = current.allowedPaths.some((currPath) => {
        if (currPath === "*") return true;
        const resolvedCurr = path.resolve(currPath);
        const rel = path.relative(resolvedCurr, resolvedReq);
        return !rel.startsWith("..") && !path.isAbsolute(rel);
      });
      if (!isSubpath) return true; // Escaping existing path boundary
    }
  }

  // 4. disallowedTools: removing or clearing any previously disallowed tool is loosening
  if (
    requested.disallowedTools !== undefined &&
    current.disallowedTools &&
    current.disallowedTools.length > 0
  ) {
    if (!Array.isArray(requested.disallowedTools)) return true;
    for (const tool of current.disallowedTools) {
      if (!requested.disallowedTools.includes(tool)) return true;
    }
  }

  // 5. allowedTools: adding new tools when restricted is loosening
  if (
    requested.allowedTools !== undefined &&
    current.allowedTools &&
    !current.allowedTools.includes("*")
  ) {
    if (!Array.isArray(requested.allowedTools) || requested.allowedTools.includes("*")) {
      return true;
    }
    for (const tool of requested.allowedTools) {
      if (!current.allowedTools.includes(tool)) return true;
    }
  }

  return false;
}

// Default conservative mandate for autonomous agents
export const DEFAULT_MANDATE: Mandate = {
  sessionId: "default",
  taskDescription: "Autonomous tool execution with safe boundary enforcement",
  allowedTools: ["*"], // Wildcard allows all by default unless restricted
  allowedPaths: [process.cwd()], // Default: strictly confined to current workspace root
  allowWrite: false, // Read-only by default for maximum agent safety
  allowDestructive: false,
  allowNetwork: false,
  allowLoopback: false,
  allowSubshells: false,
  riskTolerance: "low",
  isLocked: true, // Mandate escalation locked against autonomous tampering
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

export class S3ScopeEvaluator {
  private mandate: Mandate;
  private auditLog: AuditRecord[] = [];
  private readonly maxAuditRecords = 500;
  private latencies: number[] = [];
  private totalEvaluations = 0;
  private allowCount = 0;
  private blockCount = 0;
  private confirmCount = 0;
  private violationsBySig: Record<string, number> = { S3: 0, S2b: 0, S5: 0 };
  private violationsByType: Record<string, number> = {};
  private startTime = Date.now();

  constructor(initialMandate: Partial<Mandate> = {}) {
    this.mandate = {
      ...DEFAULT_MANDATE,
      ...initialMandate,
      allowedPaths:
        initialMandate.allowedPaths && initialMandate.allowedPaths.length > 0
          ? initialMandate.allowedPaths
          : [process.cwd()],
      updatedAt: Date.now(),
    };
  }

  /**
   * Monotonic mandate update:
   * Agents can tighten policies, but cannot self-loosen permissions without a valid operatorSecret.
   */
  public setMandate(
    newMandate: Partial<Mandate>,
    callerSecret?: string
  ): { success: boolean; mandate: Mandate; error?: string } {
    const isLoosening = isLooseningMandate(this.mandate, newMandate);

    if (isLoosening && this.mandate.isLocked) {
      const expectedSecret =
        this.mandate.operatorSecret || process.env.ALETHEIA_OPERATOR_SECRET;
      if (!expectedSecret || callerSecret !== expectedSecret) {
        return {
          success: false,
          mandate: { ...this.mandate },
          error:
            "Self-mandate escalation blocked: agents cannot grant themselves looser permissions, broader paths, or clear disallowed tools without valid operatorSecret.",
        };
      }
    }

    this.mandate = {
      ...this.mandate,
      ...newMandate,
      updatedAt: Date.now(),
    };
    return { success: true, mandate: { ...this.mandate } };
  }

  public getMandate(): Mandate {
    return { ...this.mandate };
  }

  public resetMandate(): Mandate {
    this.mandate = {
      ...DEFAULT_MANDATE,
      allowedPaths: [process.cwd()],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    return { ...this.mandate };
  }

  /**
   * Main evaluation entry point: evaluates any tool call in sub-millisecond time.
   */
  public evaluate(
    toolName: string,
    args: Record<string, unknown> = {},
    sessionOverride?: Partial<Mandate>
  ): AssessmentResult {
    const t0 = performance.now();
    const violations: Violation[] = [];
    const safeArgs = args && typeof args === "object" ? args : {};
    let effectiveMandate = this.mandate;

    if (sessionOverride) {
      const isLoosening = isLooseningMandate(this.mandate, sessionOverride);

      if (isLoosening && this.mandate.isLocked) {
        const expectedSecret =
          this.mandate.operatorSecret || process.env.ALETHEIA_OPERATOR_SECRET;
        const callerSecret = sessionOverride.operatorSecret;

        if (!expectedSecret || callerSecret !== expectedSecret) {
          violations.push({
            signature: "S3",
            type: "UNAUTHORIZED_MANDATE_ESCALATION",
            severity: "CRITICAL",
            description:
              "Unauthorized mandate override attempt: tool calls cannot self-grant looser permissions, broader paths, or clear disallowed tools without a valid operatorSecret.",
            evidence: JSON.stringify(sessionOverride),
            remediation:
              "Mandate overrides in aletheia_intercept are only permitted to tighten boundaries, not loosen them.",
          });
          // Sanitize: strip loosening fields from effectiveMandate
          const sanitized = { ...sessionOverride };
          delete sanitized.allowWrite;
          delete sanitized.allowDestructive;
          delete sanitized.allowNetwork;
          delete sanitized.allowLoopback;
          delete sanitized.allowSubshells;
          delete sanitized.riskTolerance;
          delete sanitized.allowedPaths;
          delete sanitized.disallowedTools;
          delete sanitized.allowedTools;
          effectiveMandate = { ...this.mandate, ...sanitized };
        } else {
          effectiveMandate = { ...this.mandate, ...sessionOverride };
        }
      } else {
        effectiveMandate = { ...this.mandate, ...sessionOverride };
      }
    }

    let isWrite = false;
    let isNetwork = false;
    const targetPaths: string[] = [];

    // 1. Check Tool Whitelist / Blacklist
    if (
      effectiveMandate.disallowedTools &&
      effectiveMandate.disallowedTools.includes(toolName)
    ) {
      violations.push({
        signature: "S3",
        type: "DISALLOWED_TOOL",
        severity: "CRITICAL",
        description: `Tool '${toolName}' is explicitly disallowed in the active mandate`,
        evidence: `Disallowed: ${effectiveMandate.disallowedTools.join(", ")}`,
        remediation: "Do not invoke tools forbidden by session policy.",
      });
    }

    if (
      effectiveMandate.allowedTools.length > 0 &&
      !effectiveMandate.allowedTools.includes("*") &&
      !effectiveMandate.allowedTools.includes(toolName)
    ) {
      violations.push({
        signature: "S3",
        type: "DISALLOWED_TOOL",
        severity: "HIGH",
        description: `Tool '${toolName}' is not present in the allowed tools whitelist`,
        evidence: `Allowed: ${effectiveMandate.allowedTools.join(", ")}`,
        remediation: "Confine operations to explicitly authorized tools.",
      });
    }

    // 2. Scan for S2b prompt injections across all argument values
    for (const [, val] of Object.entries(safeArgs)) {
      if (typeof val === "string" || Array.isArray(val)) {
        const injections = analyzeAdversarialInput(val);
        violations.push(...injections);
      }
    }

    // 3. Specialized evaluation based on tool type
    const normalizedTool = toolName.toLowerCase();
    let handled = false;

    // Bash / Shell tools
    if (
      normalizedTool.includes("bash") ||
      normalizedTool.includes("exec") ||
      normalizedTool.includes("shell") ||
      normalizedTool.includes("terminal") ||
      normalizedTool === "run_command"
    ) {
      handled = true;
      const cmd =
        safeArgs.command ??
        safeArgs.cmd ??
        safeArgs.CommandLine ??
        safeArgs.script;
      if (cmd !== undefined && cmd !== null && cmd !== "") {
        const bashRes = analyzeBashCommand(cmd as string, effectiveMandate);
        violations.push(...bashRes.violations);
        isWrite = bashRes.isWriteAttempt;
        isNetwork = bashRes.isNetworkAttempt;
        targetPaths.push(...bashRes.targetPaths);
      }
    }

    // SQL tools
    if (
      normalizedTool.includes("sql") ||
      normalizedTool.includes("query") ||
      normalizedTool.includes("database") ||
      normalizedTool.includes("postgres")
    ) {
      handled = true;
      const sql =
        safeArgs.query ??
        safeArgs.sql ??
        safeArgs.statement;
      if (sql !== undefined && sql !== null && sql !== "") {
        const sqlRes = analyzeSqlQuery(sql as string, effectiveMandate);
        violations.push(...sqlRes.violations);
        isWrite = sqlRes.isWriteAttempt;
        targetPaths.push(...sqlRes.targetTables);
      }
    }

    // Filesystem tools
    if (
      normalizedTool.includes("file") ||
      normalizedTool.includes("fs") ||
      normalizedTool.includes("read") ||
      normalizedTool.includes("write") ||
      normalizedTool.includes("edit")
    ) {
      handled = true;
      const candidatePath =
        safeArgs.path ??
        safeArgs.filePath ??
        safeArgs.TargetFile ??
        safeArgs.AbsolutePath;
      const isFileWrite =
        normalizedTool.includes("write") ||
        normalizedTool.includes("edit") ||
        normalizedTool.includes("create") ||
        safeArgs.content !== undefined ||
        safeArgs.CodeContent !== undefined;

      if (candidatePath !== undefined && candidatePath !== null && candidatePath !== "") {
        const fsRes = analyzePath(candidatePath as string, effectiveMandate, isFileWrite);
        violations.push(...fsRes.violations);
        isWrite = isFileWrite;
        targetPaths.push(fsRes.normalizedPath);
      }
    }

    // Network / Fetch tools
    if (
      normalizedTool.includes("fetch") ||
      normalizedTool.includes("http") ||
      normalizedTool.includes("curl") ||
      normalizedTool.includes("request") ||
      normalizedTool.includes("url")
    ) {
      handled = true;
      const candidateUrl =
        safeArgs.url ??
        safeArgs.Url ??
        safeArgs.endpoint;
      if (candidateUrl !== undefined && candidateUrl !== null && candidateUrl !== "") {
        const netRes = analyzeUrl(candidateUrl as string, effectiveMandate);
        violations.push(...netRes.violations);
        isNetwork = true;
      }
    }

    // 4. Fail-closed Generic Deep Inspection for Unrecognized Third-Party Tools
    // If a tool has a custom or renamed name (e.g. cli_run, os_dispatch, run_task),
    // scan all arguments (strings, arrays, objects) for shell commands, SQL statements, and path traversals.
    if (!handled) {
      for (const [argKey, argVal] of Object.entries(safeArgs)) {
        const trimmed = typeof argVal === "string"
          ? argVal.trim()
          : Array.isArray(argVal)
            ? argVal.map((x) => String(x ?? "")).join(" ").trim()
            : typeof argVal === "object" && argVal !== null
              ? JSON.stringify(argVal)
              : String(argVal ?? "").trim();

        if (trimmed.length > 2) {
          // Check if string contains shell commands or shell syntax
          const looksLikeShell =
            /\b(rm|git|cat|chmod|find|curl|wget|python|node|sh|bash|sudo|dd|kill|shred|rsync|ruby|perl|php)\b|[|;&]|>>?/i.test(
              trimmed
            );
          if (looksLikeShell) {
            const bashRes = analyzeBashCommand(trimmed, effectiveMandate);
            violations.push(...bashRes.violations);
            if (bashRes.isWriteAttempt) isWrite = true;
            if (bashRes.isNetworkAttempt) isNetwork = true;
            targetPaths.push(...bashRes.targetPaths);
          }

          // Check if string looks like SQL
          const looksLikeSql =
            /^\s*(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|COPY|WITH|DO|ATTACH|EXEC)\b/i.test(
              trimmed
            ) ||
            argKey.toLowerCase().includes("sql") ||
            argKey.toLowerCase().includes("query");
          if (looksLikeSql) {
            const sqlRes = analyzeSqlQuery(trimmed, effectiveMandate);
            violations.push(...sqlRes.violations);
            if (sqlRes.isWriteAttempt) isWrite = true;
            targetPaths.push(...sqlRes.targetTables);
          }

          // Check if string looks like a path
          const looksLikePath =
            /^(\/|\.\/|\.\.\/|~|\.env)/.test(trimmed) ||
            /^\.{1,2}[\/\\]/.test(trimmed) ||
            trimmed.includes("/.ssh/") ||
            trimmed.includes("/.aws/") ||
            trimmed.includes("/etc/passwd") ||
            argKey.toLowerCase().includes("path") ||
            argKey.toLowerCase().includes("file");
          if (looksLikePath) {
            const fsRes = analyzePath(trimmed, effectiveMandate, false);
            violations.push(...fsRes.violations);
            targetPaths.push(fsRes.normalizedPath);
          }

          // Check if string looks like URL or network target
          const looksLikeUrl =
            /^https?:\/\//i.test(trimmed) ||
            /^\/\//.test(trimmed) ||
            argKey.toLowerCase().includes("url") ||
            argKey.toLowerCase().includes("endpoint") ||
            argKey.toLowerCase().includes("host") ||
            /169\.254\.169\.254/.test(trimmed) ||
            /metadata\.google\.internal/i.test(trimmed);
          if (looksLikeUrl) {
            const netRes = analyzeUrl(trimmed, effectiveMandate);
            violations.push(...netRes.violations);
            if (netRes.isSSRF) isNetwork = true;
          }
        }
      }
    }

    // 5. Calculate Risk Score & Verdict
    let maxSeverity: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "NONE";
    let riskScore = 0.05; // Base nominal score for benign actions

    if (violations.length > 0) {
      for (const v of violations) {
        if (v.severity === "CRITICAL") maxSeverity = "CRITICAL";
        else if (v.severity === "HIGH" && maxSeverity !== "CRITICAL") maxSeverity = "HIGH";
        else if (
          v.severity === "MEDIUM" &&
          maxSeverity !== "CRITICAL" &&
          maxSeverity !== "HIGH"
        )
          maxSeverity = "MEDIUM";
        else if (v.severity === "LOW" && maxSeverity === "NONE") maxSeverity = "LOW";
      }

      if (maxSeverity === "CRITICAL")
        riskScore = Math.min(1.0, 0.9 + violations.length * 0.02);
      else if (maxSeverity === "HIGH")
        riskScore = Math.min(0.89, 0.7 + violations.length * 0.05);
      else if (maxSeverity === "MEDIUM")
        riskScore = Math.min(0.69, 0.4 + violations.length * 0.05);
      else riskScore = 0.25;
    }

    let verdict: Verdict = "ALLOW";
    if (maxSeverity === "CRITICAL") {
      verdict = "BLOCK";
    } else if (maxSeverity === "HIGH") {
      verdict = effectiveMandate.riskTolerance === "high" ? "CONFIRM_REQUIRED" : "BLOCK";
    } else if (maxSeverity === "MEDIUM") {
      verdict = effectiveMandate.riskTolerance === "low" ? "CONFIRM_REQUIRED" : "ALLOW";
    }

    const t1 = performance.now();
    const latencyMs = Number((t1 - t0).toFixed(3));

    // Update telemetry metrics
    this.totalEvaluations++;
    this.latencies.push(latencyMs);
    if (this.latencies.length > 2000) this.latencies.shift();

    if (verdict === "ALLOW") this.allowCount++;
    else if (verdict === "BLOCK") this.blockCount++;
    else this.confirmCount++;

    for (const v of violations) {
      this.violationsBySig[v.signature] = (this.violationsBySig[v.signature] || 0) + 1;
      this.violationsByType[v.type] = (this.violationsByType[v.type] || 0) + 1;
    }

    // Explanation string
    let explanation = "Action is within stated mandate boundaries.";
    if (verdict === "BLOCK") {
      explanation = `Action BLOCKED: ${violations.map((v) => v.description).join("; ")}`;
    } else if (verdict === "CONFIRM_REQUIRED") {
      explanation = `Confirmation Required: Potential scope drift detected: ${violations.map((v) => v.description).join("; ")}`;
    }

    const result: AssessmentResult = {
      verdict,
      riskScore: Number(riskScore.toFixed(3)),
      passed: verdict === "ALLOW",
      violations,
      latencyMs,
      timestamp: Date.now(),
      toolName,
      evaluatedScope: {
        mandateTask: effectiveMandate.taskDescription,
        isWriteAttempt: isWrite,
        isNetworkAttempt: isNetwork,
        targetPaths,
      },
      explanation,
    };

    // Append to audit log
    const auditRecord: AuditRecord = {
      id: `eval_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: result.timestamp,
      toolName,
      rawInput: args,
      verdict,
      riskScore: result.riskScore,
      violationsCount: violations.length,
      latencyMs,
      violationTypes: violations.map((v) => v.type),
    };

    this.auditLog.unshift(auditRecord);
    if (this.auditLog.length > this.maxAuditRecords) {
      this.auditLog.pop();
    }

    return result;
  }

  public getAuditLog(limit = 50): AuditRecord[] {
    return this.auditLog.slice(0, limit);
  }

  public getTelemetry(): TelemetrySummary {
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const count = sorted.length;
    const p = (pct: number) => (count === 0 ? 0 : sorted[Math.floor(count * pct)]);

    return {
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      totalEvaluations: this.totalEvaluations,
      verdicts: {
        allow: this.allowCount,
        block: this.blockCount,
        confirmRequired: this.confirmCount,
      },
      blockRatePercent:
        this.totalEvaluations === 0
          ? 0
          : Number(((this.blockCount / this.totalEvaluations) * 100).toFixed(1)),
      latency: {
        minMs: count === 0 ? 0 : sorted[0],
        avgMs: count === 0 ? 0 : Number((sorted.reduce((a, b) => a + b, 0) / count).toFixed(3)),
        p50Ms: Number(p(0.5).toFixed(3)),
        p95Ms: Number(p(0.95).toFixed(3)),
        p99Ms: Number(p(0.99).toFixed(3)),
        maxMs: count === 0 ? 0 : sorted[count - 1],
      },
      violationsBySignature: { ...this.violationsBySig },
      violationsByType: { ...this.violationsByType },
    };
  }
}
