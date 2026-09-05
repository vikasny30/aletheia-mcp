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
import { registerTools } from "../tools/index.js";
import { registerResources } from "../resources/index.js";
import { registerPrompts } from "../prompts/index.js";

type PendingRequestType = "initialize" | "tools" | "resources" | "prompts";

export class McpProxyGateway {
  private childProcess: ChildProcess | null = null;
  private evaluator: S3ScopeEvaluator;

  // Aletheia's own tools/resources/prompts, so they remain reachable when Aletheia
  // is wrapping a downstream server rather than running standalone.
  private toolDefinitions: any[];
  private handleToolCall: (name: string, args: Record<string, unknown>) => Promise<any>;
  private aletheiaToolNames: Set<string>;

  private resourceDefinitions: any[];
  private handleResourceRead: (uri: string) => any;
  private aletheiaResourceUris: Set<string>;

  private promptDefinitions: any[];
  private handlePromptGet: (name: string, args: Record<string, string>) => any;
  private aletheiaPromptNames: Set<string>;

  // Tracks client-issued initialize/list requests awaiting a downstream response,
  // so that response can be merged with Aletheia's own definitions before relaying it.
  private pendingRequests = new Map<string | number, PendingRequestType>();

  constructor(evaluator: S3ScopeEvaluator) {
    this.evaluator = evaluator;

    const tools = registerTools(evaluator);
    this.toolDefinitions = tools.toolDefinitions;
    this.handleToolCall = tools.handleCall;
    this.aletheiaToolNames = new Set(this.toolDefinitions.map((t: any) => t.name));

    const resources = registerResources(evaluator);
    this.resourceDefinitions = resources.resourceDefinitions;
    this.handleResourceRead = resources.handleRead;
    this.aletheiaResourceUris = new Set(this.resourceDefinitions.map((r: any) => r.uri));

    const prompts = registerPrompts();
    this.promptDefinitions = prompts.promptDefinitions;
    this.handlePromptGet = prompts.handleGet;
    this.aletheiaPromptNames = new Set(this.promptDefinitions.map((p: any) => p.name));
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
      const outLine = this.mergeAletheiaIntoDownstreamResponse(line);
      const ok = process.stdout.write(outLine + "\n");
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

  /**
   * Merges Aletheia's own tools/resources/prompts (and capability flags) into a
   * downstream response the client is waiting on, if that response corresponds to
   * an initialize/list request this proxy is tracking. Otherwise passes the line
   * through unchanged. Ensures Aletheia's meta-tools, resources, and prompts stay
   * reachable even when Aletheia is only wrapping a downstream server, not running
   * standalone.
   */
  private mergeAletheiaIntoDownstreamResponse(line: string): string {
    let parsed: any;
    try {
      parsed = JSON.parse(line);
    } catch {
      return line;
    }

    if (!parsed || parsed.id === undefined || !this.pendingRequests.has(parsed.id)) {
      return line;
    }

    const type = this.pendingRequests.get(parsed.id)!;
    this.pendingRequests.delete(parsed.id);

    if (type === "initialize") {
      if (parsed.result) {
        parsed.result.capabilities = parsed.result.capabilities || {};
        parsed.result.capabilities.tools = parsed.result.capabilities.tools || {};
        parsed.result.capabilities.resources = parsed.result.capabilities.resources || {};
        parsed.result.capabilities.prompts = parsed.result.capabilities.prompts || {};
        return JSON.stringify(parsed);
      }
      return line;
    }

    // For list methods: if the downstream understood the request, append Aletheia's
    // own definitions to the result. If the downstream doesn't implement the method
    // at all (e.g. a minimal server with no resources/prompts support), it will have
    // returned a "Method not found" error -- since Aletheia itself DOES support the
    // method, synthesize a successful response containing just Aletheia's entries
    // rather than propagating the downstream's error to the client.
    if (type === "tools") {
      if (parsed.result) {
        parsed.result.tools = [...(parsed.result.tools || []), ...this.toolDefinitions];
        return JSON.stringify(parsed);
      }
      if (parsed.error) {
        return JSON.stringify({ jsonrpc: "2.0", id: parsed.id, result: { tools: this.toolDefinitions } });
      }
    } else if (type === "resources") {
      if (parsed.result) {
        parsed.result.resources = [...(parsed.result.resources || []), ...this.resourceDefinitions];
        return JSON.stringify(parsed);
      }
      if (parsed.error) {
        return JSON.stringify({ jsonrpc: "2.0", id: parsed.id, result: { resources: this.resourceDefinitions } });
      }
    } else if (type === "prompts") {
      if (parsed.result) {
        parsed.result.prompts = [...(parsed.result.prompts || []), ...this.promptDefinitions];
        return JSON.stringify(parsed);
      }
      if (parsed.error) {
        return JSON.stringify({ jsonrpc: "2.0", id: parsed.id, result: { prompts: this.promptDefinitions } });
      }
    }

    return line;
  }

  /** Handles a tools/call targeting one of Aletheia's own tools, entirely locally. */
  private handleAletheiaToolCall(message: any, sendClient: (data: string) => void) {
    const toolName = String(message.params.name);
    const toolArgs = (message.params.arguments as Record<string, unknown>) || {};
    this.handleToolCall(toolName, toolArgs)
      .then((result) => {
        sendClient(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\n");
      })
      .catch((err: unknown) => {
        sendClient(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            error: { code: -32603, message: `Aletheia tool execution error: ${(err as Error).message}` },
          }) + "\n"
        );
      });
  }

  /** Handles a resources/read targeting one of Aletheia's own resources, entirely locally. */
  private handleAletheiaResourceRead(message: any, sendClient: (data: string) => void) {
    try {
      const result = this.handleResourceRead(String(message.params.uri));
      sendClient(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\n");
    } catch (err: unknown) {
      sendClient(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32602, message: `Aletheia resource error: ${(err as Error).message}` },
        }) + "\n"
      );
    }
  }

  /** Handles a prompts/get targeting one of Aletheia's own prompts, entirely locally. */
  private handleAletheiaPromptGet(message: any, sendClient: (data: string) => void) {
    try {
      const args = (message.params.arguments as Record<string, string>) || {};
      const result = this.handlePromptGet(String(message.params.name), args);
      sendClient(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\n");
    } catch (err: unknown) {
      sendClient(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32602, message: `Aletheia prompt error: ${(err as Error).message}` },
        }) + "\n"
      );
    }
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

    // Track initialize/list requests so the matching downstream response can be
    // merged with Aletheia's own tools/resources/prompts before reaching the client.
    if (!Array.isArray(message) && message.id !== undefined && typeof message.method === "string") {
      if (message.method === "initialize") this.pendingRequests.set(message.id, "initialize");
      else if (message.method === "tools/list") this.pendingRequests.set(message.id, "tools");
      else if (message.method === "resources/list") this.pendingRequests.set(message.id, "resources");
      else if (message.method === "prompts/list") this.pendingRequests.set(message.id, "prompts");
    }

    // Requests targeting one of Aletheia's own tools/resources/prompts are handled
    // entirely locally -- they never reach the downstream server, so they remain
    // reachable whether Aletheia is running standalone or wrapping another server.
    if (!Array.isArray(message) && message.params) {
      if (message.method === "tools/call" && this.aletheiaToolNames.has(String(message.params.name))) {
        this.handleAletheiaToolCall(message, sendClient);
        return;
      }
      if (message.method === "resources/read" && this.aletheiaResourceUris.has(String(message.params.uri))) {
        this.handleAletheiaResourceRead(message, sendClient);
        return;
      }
      if (message.method === "prompts/get" && this.aletheiaPromptNames.has(String(message.params.name))) {
        this.handleAletheiaPromptGet(message, sendClient);
        return;
      }
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
