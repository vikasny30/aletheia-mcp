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

    // Signal forwarding: propagate SIGINT/SIGTERM to downstream server with supervised wait and SIGKILL escalation
    let isShuttingDown = false;
    const forwardSignal = (signal: NodeJS.Signals) => {
      if (isShuttingDown) return;
      isShuttingDown = true;

      if (!this.childProcess || this.childProcess.killed) {
        process.exit(0);
        return;
      }

      // Send initial graceful termination signal
      try {
        this.childProcess.kill(signal);
      } catch {}

      // Supervised wait: escalate to SIGKILL if child has not exited within 5 seconds
      const killTimer = setTimeout(() => {
        if (this.childProcess && !this.childProcess.killed) {
          console.error(`[Aletheia Proxy] Downstream process did not exit within timeout; escalating to SIGKILL`);
          try {
            this.childProcess.kill("SIGKILL");
          } catch {}
        }
        process.exit(1);
      }, 5000);

      if (killTimer.unref) killTimer.unref();

      // Clean exit when child process confirms termination
      this.childProcess.once("exit", (code) => {
        clearTimeout(killTimer);
        process.exit(code || 0);
      });
    };
    process.on("SIGINT", () => forwardSignal("SIGINT"));
    process.on("SIGTERM", () => forwardSignal("SIGTERM"));

    // Read lines from downstream MCP stdout and forward to client stdout with single-listener backpressure handling
    const downstreamReader = readline.createInterface({
      input: this.childProcess.stdout,
      terminal: false,
    });

    let isStdoutDraining = false;
    downstreamReader.on("line", (line) => {
      const ok = process.stdout.write(line + "\n");
      if (!ok && this.childProcess?.stdout && !isStdoutDraining) {
        isStdoutDraining = true;
        this.childProcess.stdout.pause();
        process.stdout.once("drain", () => {
          isStdoutDraining = false;
          this.childProcess?.stdout?.resume();
        });
      }
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

    let message: any;
    try {
      message = JSON.parse(line);
    } catch {
      // Non-JSON line or framing data - forward transparently to downstream
      if (this.childProcess?.stdin && !this.childProcess.stdin.destroyed) {
        this.childProcess.stdin.write(line + "\n");
      }
      return;
    }

    // Intercept tool calls
    if (message && message.method === "tools/call" && message.params) {
      const toolName = String(message.params.name || "");
      const toolArgs =
        message.params.arguments && typeof message.params.arguments === "object"
          ? message.params.arguments
          : {};

      let assessment;
      try {
        // Run sub-millisecond S3 evaluation
        assessment = this.evaluator.evaluate(toolName, toolArgs);
      } catch (err: unknown) {
        console.error(
          `[Aletheia Proxy] Internal evaluation error on tool '${toolName}': ${(err as Error).message}`
        );
        // Fail closed: NEVER forward unvalidated tool calls to downstream server if evaluator throws
        const errorResponse = {
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
                    verdict: "BLOCK",
                    riskScore: 1.0,
                    violations: [
                      {
                        signature: "S3",
                        type: "EVALUATOR_INTERNAL_ERROR",
                        severity: "CRITICAL",
                        description: `Security evaluation failed closed due to an internal error: ${(err as Error).message}`,
                        evidence: String(toolArgs).slice(0, 100),
                        remediation: "Verify tool call argument formats. Tool call rejected under fail-closed security policy.",
                      },
                    ],
                    explanation: "Tool call rejected due to internal evaluation exception (fail-closed security policy).",
                  },
                  null,
                  2
                ),
              },
            ],
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + "\n");
        return;
      }

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

    // Forward non-tool-call message or ALLOWed tool call to downstream MCP server
    if (this.childProcess?.stdin && !this.childProcess.stdin.destroyed) {
      this.childProcess.stdin.write(line + "\n");
    }
  }
}
