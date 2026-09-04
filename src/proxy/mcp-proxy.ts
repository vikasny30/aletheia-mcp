/**
 * Aletheia MCP Server: Transparent Proxy Middleware
 * 
 * Sits between Claude / Client and ANY downstream MCP server,
 * transparently intercepting all `tools/call` messages and enforcing
 * Signature S3 Scope Creep boundaries with <0.5ms overhead.
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

    this.childProcess = spawn(downstreamCommand, downstreamArgs, {
      stdio: ["pipe", "pipe", "inherit"],
      env: process.env,
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

      // Check if this is a tool execution request
      if (message.method === "tools/call" && message.params) {
        const toolName = message.params.name;
        const toolArgs = message.params.arguments || {};

        // Run sub-millisecond S3 evaluation
        const assessment = this.evaluator.evaluate(toolName, toolArgs);

        if (assessment.verdict === "BLOCK") {
          console.error(`[Aletheia Proxy] BLOCKED out-of-scope tool call '${toolName}' (${assessment.latencyMs}ms)`);

          // Return JSON-RPC error response directly to client without forwarding downstream
          const blockedResponse = {
            jsonrpc: "2.0",
            id: message.id,
            error: {
              code: -32600,
              message: `Aletheia Policy Block: Action violates Signature S3 (Scope Creep Beyond Mandate)`,
              data: assessment,
            },
          };

          process.stdout.write(JSON.stringify(blockedResponse) + "\n");
          return;
        }
      }

      // If allowed or not a tools/call message, forward to downstream MCP server
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
