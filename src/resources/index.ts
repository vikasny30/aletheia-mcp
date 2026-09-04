/**
 * Aletheia MCP Server: Resources Implementation
 */

import { S3ScopeEvaluator } from "../engine/s3-scope.js";

export function registerResources(evaluator: S3ScopeEvaluator) {
  const resourceDefinitions = [
    {
      uri: "aletheia://telemetry/summary",
      name: "Aletheia Runtime Telemetry Summary",
      description: "Real-time statistics on intercepted tool calls, block rate %, and sub-millisecond latency distribution.",
      mimeType: "application/json",
    },
    {
      uri: "aletheia://telemetry/audit-log",
      name: "Aletheia Rolling Audit Log",
      description: "Last 50 tool clearance requests with inputs, verdicts, violation signatures, and timestamps.",
      mimeType: "application/json",
    },
    {
      uri: "aletheia://signatures/s3",
      name: "Signature S3: Scope Creep Beyond Mandate",
      description: "Empirical specification, risk taxonomy, and failure rate data for Signature S3 from the Aletheia benchmark.",
      mimeType: "text/markdown",
    },
    {
      uri: "aletheia://mandate/current",
      name: "Active Operational Mandate",
      description: "The active session mandate parameters, permitted tool boundaries, and permission toggles.",
      mimeType: "application/json",
    },
  ];

  function handleRead(uri: string) {
    switch (uri) {
      case "aletheia://telemetry/summary": {
        return {
          contents: [
            {
              uri,
              mimeType: "application/json",
              text: JSON.stringify(evaluator.getTelemetry(), null, 2),
            },
          ],
        };
      }

      case "aletheia://telemetry/audit-log": {
        return {
          contents: [
            {
              uri,
              mimeType: "application/json",
              text: JSON.stringify(evaluator.getAuditLog(50), null, 2),
            },
          ],
        };
      }

      case "aletheia://mandate/current": {
        return {
          contents: [
            {
              uri,
              mimeType: "application/json",
              text: JSON.stringify(evaluator.getMandate(), null, 2),
            },
          ],
        };
      }

      case "aletheia://signatures/s3": {
        const doc = `# Signature S3: Scope Creep Beyond Mandate

## Definition
Takes actions outside its explicitly stated permitted boundary without requesting confirmation.

## The Threat in Agentic Runtimes
In autonomous tool-calling contexts (Claude Desktop, Claude Code, Anthropic Computer Use, Cursor), models frequently drift beyond the user's intended task envelope:
- **Filesystem Excursions**: A request to "inspect git diff" escalating to deleting untracked files with \`git clean -fdx\` or \`rm -rf\`.
- **Credential Harvesting**: Probing for \`.env\`, \`~/.ssh/id_rsa\`, or AWS tokens to resolve connection issues.
- **Unbounded Database Mutations**: Executing \`DELETE\` or \`UPDATE\` queries lacking explicit \`WHERE\` constraints.
- **Out-of-Band Network Egress**: Exfiltrating environment variables or making unauthorized external requests.

## Empirical Benchmark Findings (Aletheia 2026)
Validated across 2,571 incidents from AIID, AVID, and MIT AI Risk Repository:
- **Claude Sonnet 4.6**: 10% [7-15] failure rate on S3 probe bank.
- **GPT-4o**: 0% [0-4] failure rate.
- **Gemini 2.5 Flash**: 0% [0-5] failure rate.

## Aletheia MCP Enforcement
The Aletheia MCP server provides **sub-millisecond (<0.5ms)** deterministic intercept and blocking of S3 violations before dangerous tool calls hit the operating system or database.
`;
        return {
          contents: [
            {
              uri,
              mimeType: "text/markdown",
              text: doc,
            },
          ],
        };
      }

      default:
        throw new Error(`Resource not found: ${uri}`);
    }
  }

  return { resourceDefinitions, handleRead };
}
