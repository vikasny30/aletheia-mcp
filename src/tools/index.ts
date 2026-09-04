/**
 * Aletheia MCP Server: Tool Definitions and Handlers
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import { S3ScopeEvaluator } from "../engine/s3-scope.js";
import { Mandate } from "../engine/types.js";

const execAsync = promisify(exec);

export function registerTools(evaluator: S3ScopeEvaluator) {
  const toolDefinitions = [
    {
      name: "aletheia_set_mandate",
      description:
        "Establish or update the active operational safety mandate for this agent session. Declares permissible boundaries, allowed tools, filesystem directories, write permissions, and risk tolerance.",
      inputSchema: {
        type: "object",
        properties: {
          taskDescription: {
            type: "string",
            description: "Concise summary of the current user-authorized task/objective.",
          },
          allowedTools: {
            type: "array",
            items: { type: "string" },
            description: "Whitelisted tool names. Use ['*'] to allow all non-disallowed tools.",
          },
          disallowedTools: {
            type: "array",
            items: { type: "string" },
            description: "Explicitly prohibited tool names.",
          },
          allowedPaths: {
            type: "array",
            items: { type: "string" },
            description: "Permitted filesystem root directories. Operations outside these paths will be flagged.",
          },
          allowWrite: {
            type: "boolean",
            description: "Authorize filesystem modifications or database write operations (default: false).",
          },
          allowDestructive: {
            type: "boolean",
            description: "Authorize destructive commands like file deletions or schema changes (default: false).",
          },
          allowNetwork: {
            type: "boolean",
            description: "Authorize outbound network connectivity and external API calls (default: false).",
          },
          allowSubshells: {
            type: "boolean",
            description: "Authorize nested subshell execution ($() or backticks) (default: false).",
          },
          riskTolerance: {
            type: "string",
            enum: ["low", "medium", "high"],
            description: "Threshold policy: 'low' blocks any potential drift; 'high' permits warnings for non-critical risks.",
          },
        },
        required: ["taskDescription"],
      },
    },
    {
      name: "aletheia_get_mandate",
      description: "Retrieve the current operational safety mandate, permissions, and active boundary constraints.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
    {
      name: "aletheia_intercept",
      description:
        "Universal sub-millisecond safety gatekeeper. Evaluates any proposed tool invocation against Signature S3 (Scope Creep) and S2b (Prompt Injection) to block destructive, out-of-boundary, or compromised actions before execution.",
      inputSchema: {
        type: "object",
        properties: {
          tool_name: {
            type: "string",
            description: "The name of the tool intended to be called (e.g. 'bash', 'execute_sql', 'write_file').",
          },
          tool_args: {
            type: "object",
            description: "The argument dictionary intended for the tool call.",
          },
          mandate_override: {
            type: "object",
            description: "Optional one-off overrides to apply to the evaluation.",
          },
        },
        required: ["tool_name", "tool_args"],
      },
    },
    {
      name: "aletheia_safe_bash",
      description:
        "Execute a shell/bash command with inline sub-millisecond Signature S3 scope creep protection. Blocks destructive deletes (rm -rf), disk formatting, fork bombs, credential harvesting, privilege escalation, and unauthorized network egress.",
      inputSchema: {
        type: "object",
        properties: {
          command: {
            type: "string",
            description: "The shell command line to evaluate and safely execute.",
          },
          cwd: {
            type: "string",
            description: "Working directory for execution. Defaults to current directory.",
          },
          timeoutMs: {
            type: "number",
            description: "Maximum execution time in milliseconds (default: 15000).",
          },
        },
        required: ["command"],
      },
    },
    {
      name: "aletheia_safe_sql",
      description:
        "Audit or execute a database query with Signature S3 safety filters. Detects destructive DDL (DROP, TRUNCATE), unbounded DML (DELETE/UPDATE without WHERE), and privilege tampering.",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "The SQL statement to evaluate.",
          },
          database_type: {
            type: "string",
            description: "Database dialect ('postgres', 'mysql', 'sqlite', 'snowflake').",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "aletheia_get_telemetry",
      description:
        "Retrieve runtime safety telemetry: total tool calls evaluated, block rate %, latency percentiles (p50, p95, p99 < 1ms), and violation counts broken down by signature.",
      inputSchema: {
        type: "object",
        properties: {
          auditLogLimit: {
            type: "number",
            description: "Number of recent audit records to include (default: 20).",
          },
        },
      },
    },
  ];

  async function handleCall(name: string, args: Record<string, unknown> = {}) {
    switch (name) {
      case "aletheia_set_mandate": {
        const updated = evaluator.setMandate(args as unknown as Partial<Mandate>);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "mandate_updated",
                  mandate: updated,
                  message: "Safety envelope active. Subsequent tool calls will be graded against this mandate.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "aletheia_get_mandate": {
        const current = evaluator.getMandate();
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(current, null, 2),
            },
          ],
        };
      }

      case "aletheia_intercept": {
        const toolName = String(args.tool_name || "");
        const toolArgs = (args.tool_args as Record<string, unknown>) || {};
        const override = (args.mandate_override as Partial<Mandate>) || undefined;

        const assessment = evaluator.evaluate(toolName, toolArgs, override);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(assessment, null, 2),
            },
          ],
        };
      }

      case "aletheia_safe_bash": {
        const command = String(args.command || "");
        const cwd = args.cwd ? String(args.cwd) : process.cwd();
        const timeoutMs = typeof args.timeoutMs === "number" ? args.timeoutMs : 15000;

        // 1. Intercept first
        const assessment = evaluator.evaluate("bash", { command, cwd });

        if (assessment.verdict === "BLOCK") {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "BLOCKED",
                    reason: "Aletheia S3 Scope Creep Policy Violation",
                    assessment,
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        if (assessment.verdict === "CONFIRM_REQUIRED") {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "CONFIRMATION_REQUIRED",
                    warning: "Command requires explicit confirmation due to elevated risk profile.",
                    assessment,
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        // 2. Safe to execute
        try {
          const { stdout, stderr } = await execAsync(command, {
            cwd,
            timeout: timeoutMs,
            maxBuffer: 10 * 1024 * 1024,
          });

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "EXECUTED",
                    verdict: "ALLOW",
                    latencyMs: assessment.latencyMs,
                    stdout: stdout.trim(),
                    stderr: stderr.trim(),
                  },
                  null,
                  2
                ),
              },
            ],
          };
        } catch (err: unknown) {
          const e = err as { message: string; stdout?: string; stderr?: string };
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "EXECUTION_ERROR",
                    error: e.message,
                    stdout: e.stdout?.trim(),
                    stderr: e.stderr?.trim(),
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }
      }

      case "aletheia_safe_sql": {
        const query = String(args.query || "");
        const assessment = evaluator.evaluate("sql", { query });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: assessment.verdict,
                  evaluation: assessment,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "aletheia_get_telemetry": {
        const limit = typeof args.auditLogLimit === "number" ? args.auditLogLimit : 20;
        const telemetry = evaluator.getTelemetry();
        const recentAudit = evaluator.getAuditLog(limit);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  telemetry,
                  recentAudit,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  return { toolDefinitions, handleCall };
}
