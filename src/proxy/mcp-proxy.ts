/**
 * Aletheia MCP Server: Transparent Proxy Middleware
 * 
 * Sits between Claude / Client and ANY downstream MCP server,
 * transparently intercepting all `tools/call` messages and enforcing
 * Signature S3 Scope Creep boundaries with <0.1ms overhead.
 */

import { spawn, ChildProcess } from "node:child_process";
import readline from "node:readline";
import { S3ScopeEvaluator } from "../engine/s3-scope.js";

export class McpProxyGateway {
  private childProcess: ChildProcess | null = null;
  private evaluator: S3ScopeEvaluator;

  constructor(evaluator: S3ScopeEvaluator) {
    this.evaluator = evaluator;
  }

  public start(downstreamCommand: string, downstreamArgs: string[] = []) {
    console.error(`[Aletheia Proxy] Spawning downstream MCP server: ${downstreamCommand} ${downstreamArgs.join(" ")}`);

    try {
      this.childProcess = spawn(downstreamCommand, downstreamArgs, {
        stdio: ["pipe", "pipe", "inherit"],
        env: process.env,
      });
    } catch (err: unknown) {
      console.error(`[Aletheia Proxy] Failed to launch downstream command: ${(err as Error).message}`);
      process.exit(1);
    }

    this.childProcess.on("error", (err) => {
      console.error(`[Aletheia Proxy] Downstream process error (ENOENT/spawn failure): ${err.message}`);
      process.exit(1);
    });

    if (!this.childProcess.stdin || !this.childProcess.stdout) {
      throw new Error("Failed to attach stdio pipes to downstream MCP server");
    }

    // Read lines from downstream MCP stdout and forward to client stdout
    const downstreamReader = readline.createInterface({
      input: this.childProcess.stdout,
      terminal: false,
    });

    downstreamReader.on("line", (line) => {
      process.stdout.write(line + "\n");
    });

    // Read lines from client stdin and intercept tools/call
    const clientReader = readline.createInterface({
      input: process.stdin,
      terminal: false,
    });

    clientReader.on("line", (line) => {
      this.handleClientMessage(line);
    });

    this.childProcess.on("exit", (code) => {
      console.error(`[Aletheia Proxy] Downstream process exited with code ${code}`);
      process.exit(code || 0);
    });
  }

  private handleClientMessage(line: string) {
    if (!line.trim()) return;

    try {
      const message = JSON.parse(line);

      // Intercept tool calls
      if (message.method === "tools/call" && message.params) {
        const toolName = message.params.name;
        const toolArgs = message.params.arguments || {};

        // Run sub-millisecond S3 evaluation
        const assessment = this.evaluator.evaluate(toolName, toolArgs);

        // In headless proxy mode, treat BLOCK and CONFIRM_REQUIRED as denials
        const shouldBlock = assessment.verdict === "BLOCK" || assessment.verdict === "CONFIRM_REQUIRED";

        if (shouldBlock) {
          console.error(`[Aletheia Proxy] BLOCKED tool call '${toolName}' (${assessment.latencyMs}ms) - Verdict: ${assessment.verdict}`);

          // Return standard MCP CallToolResult with isError: true (RFC compliant, not -32600)
          const blockedResponse = {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              isError: true,
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "BLOCKED",
                      policy: "Aletheia S3 Scope Creep Prevention",
                      verdict: assessment.verdict,
                      riskScore: assessment.riskScore,
                      violations: assessment.violations,
                      explanation: assessment.explanation,
                      latencyMs: assessment.latencyMs,
                    },
                    null,
                    2
                  ),
                },
              ],
            },
          };

          process.stdout.write(JSON.stringify(blockedResponse) + "\n");
          return;
        }
      }

      // Forward to downstream MCP server
      if (this.childProcess?.stdin && !this.childProcess.stdin.destroyed) {
        this.childProcess.stdin.write(line + "\n");
      }
    } catch {
      // If parsing fails, forward line transparently
      if (this.childProcess?.stdin && !this.childProcess.stdin.destroyed) {
        this.childProcess.stdin.write(line + "\n");
      }
    }
  }
}
