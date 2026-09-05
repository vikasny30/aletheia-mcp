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

  private evaluateSingleToolCall(call: any): { isBlocked: boolean; response: any } | null {
    if (!call || call.method !== "tools/call" || !call.params) {
      return null;
    }

    const toolName = String(call.params.name || "");
    const toolArgs = call.params.arguments !== undefined ? call.params.arguments : {};

    let assessment;
    try {
      assessment = this.evaluator.evaluate(toolName, toolArgs);
    } catch (err: unknown) {
      console.error(
        `[Aletheia Proxy] Internal evaluation error on tool '${toolName}': ${(err as Error).message}`
      );
      return {
        isBlocked: true,
        response: {
          jsonrpc: "2.0",
          id: call.id !== undefined ? call.id : null,
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
        },
      };
    }

    const shouldBlock = assessment.verdict === "BLOCK" || assessment.verdict === "CONFIRM_REQUIRED";
    if (shouldBlock) {
      console.error(
        `[Aletheia Proxy] BLOCKED tool call '${toolName}' (${assessment.latencyMs}ms) - Verdict: ${assessment.verdict}`
      );
      return {
        isBlocked: true,
        response: {
          jsonrpc: "2.0",
          id: call.id !== undefined ? call.id : null,
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
        },
      };
    }

    return { isBlocked: false, response: null };
  }

  public processClientMessage(
    line: string,
    writeDownstream?: (data: string) => void,
    writeClient?: (data: string) => void
  ) {
    const sendDownstream =
      writeDownstream ||
      ((data: string) => {
        if (this.childProcess?.stdin && !this.childProcess.stdin.destroyed) {
          this.childProcess.stdin.write(data);
        }
      });

    const sendClient =
      writeClient ||
      ((data: string) => {
        process.stdout.write(data);
      });

    if (!line.trim()) return;

    let message: any;
    try {
      message = JSON.parse(line);
    } catch {
      // Non-JSON line or framing data - forward transparently to downstream
      sendDownstream(line + "\n");
      return;
    }

    // Handle JSON-RPC 2.0 Batch Requests (array of message objects)
    if (Array.isArray(message)) {
      let anyBlocked = false;
      const responses: any[] = [];

      for (const item of message) {
        const evalRes = this.evaluateSingleToolCall(item);
        if (evalRes && evalRes.isBlocked) {
          anyBlocked = true;
          responses.push(evalRes.response);
        }
      }

      if (anyBlocked) {
        // Fail closed: if ANY tool call in a batch is blocked, NEVER forward to downstream
        for (const item of message) {
          if (item && item.id !== undefined && !responses.some((r) => r.id === item.id)) {
            responses.push({
              jsonrpc: "2.0",
              id: item.id !== undefined ? item.id : null,
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
                        explanation: "Batch request rejected because batch contained security policy violations.",
                      },
                      null,
                      2
                    ),
                  },
                ],
              },
            });
          }
        }
        sendClient(JSON.stringify(responses) + "\n");
        return;
      }

      // If no blocked tool calls, forward batch downstream
      sendDownstream(line + "\n");
      return;
    }

    // Handle single JSON-RPC tool call
    const evalRes = this.evaluateSingleToolCall(message);
    if (evalRes && evalRes.isBlocked) {
      sendClient(JSON.stringify(evalRes.response) + "\n");
      return;
    }

    // Forward non-tool-call message or ALLOWed tool call to downstream MCP server
    sendDownstream(line + "\n");
  }

  private handleClientMessage(line: string) {
    this.processClientMessage(line);
  }
}
