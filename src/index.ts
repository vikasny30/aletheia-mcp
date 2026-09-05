#!/usr/bin/env node
/**
 * Aletheia MCP Server: Entrypoint
 * 
 * Model Context Protocol (MCP) server providing sub-millisecond runtime safety,
 * behavioral filtering, and Signature S3 (Scope Creep) protection for Claude & autonomous agents.
 */

import fs from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { S3ScopeEvaluator } from "./engine/s3-scope.js";
import { Mandate } from "./engine/types.js";
import { registerTools } from "./tools/index.js";
import { registerResources } from "./resources/index.js";
import { registerPrompts } from "./prompts/index.js";
import { McpProxyGateway } from "./proxy/mcp-proxy.js";

const VERSION = "0.2.0";

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--version") || args.includes("-v")) {
    console.log(`aletheia-mcp v${VERSION}`);
    process.exit(0);
  }

  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
Aletheia MCP Server v${VERSION}
Runtime Safety & Scope Creep (Signature S3) Guard for Autonomous Agents

Usage:
  npx aletheia-mcp [options]                       Start standard MCP server on stdio
  npx aletheia-mcp [options] --proxy <cmd> [args]  Start transparent proxy wrapping downstream server

Options:
  --allow-write            Authorize filesystem writes and mutations (default: read-only)
  --allow-network          Authorize outbound network requests (default: local-only)
  --allow-loopback         Authorize requests to localhost/127.0.0.1 dev servers (default: blocked)
  --allowed-paths <paths>  Comma-separated allowed directories (default: current working directory)
  --secret <token>         Operator authentication token for runtime mandate changes
  --mandate <file.json>    Load initial mandate parameters from JSON file
  --version, -v            Show version
  --help, -h               Show help

Note: --allow-write / --allow-network / --allow-loopback / --allowed-paths set the
INITIAL mandate at startup and are not subject to the operator-secret requirement --
that requirement only applies to changing an already-running session's mandate
(e.g. via the aletheia_set_mandate tool). Most users who want their agent to be able
to write files should just add --allow-write (and --allowed-paths) here, not chase
operatorSecret.
    `);
    process.exit(0);
  }

  // Parse initial mandate configuration
  const initialMandate: Partial<Mandate> = {
    allowWrite: args.includes("--allow-write") || process.env.ALETHEIA_ALLOW_WRITE === "true",
    allowNetwork: args.includes("--allow-network") || process.env.ALETHEIA_ALLOW_NETWORK === "true",
    allowLoopback: args.includes("--allow-loopback") || process.env.ALETHEIA_ALLOW_LOOPBACK === "true",
  };

  const secretIdx = args.indexOf("--secret");
  if (secretIdx !== -1 && args[secretIdx + 1]) {
    initialMandate.operatorSecret = args[secretIdx + 1];
  } else if (process.env.ALETHEIA_OPERATOR_SECRET) {
    initialMandate.operatorSecret = process.env.ALETHEIA_OPERATOR_SECRET;
  }

  const pathsIdx = args.indexOf("--allowed-paths");
  if (pathsIdx !== -1 && args[pathsIdx + 1]) {
    initialMandate.allowedPaths = args[pathsIdx + 1].split(",").map((p) => p.trim());
  }

  const mandateFileIdx = args.indexOf("--mandate");
  if (mandateFileIdx !== -1 && args[mandateFileIdx + 1]) {
    try {
      const fileData = fs.readFileSync(args[mandateFileIdx + 1], "utf-8");
      const parsed = JSON.parse(fileData);
      Object.assign(initialMandate, parsed);
    } catch (e: unknown) {
      console.error(`[Aletheia MCP] Warning: Failed to read mandate file: ${(e as Error).message}`);
    }
  }

  const evaluator = new S3ScopeEvaluator(initialMandate);

  // Mode 2: Transparent Proxy Mode
  const proxyIndex = args.indexOf("--proxy");
  if (proxyIndex !== -1 && args.length > proxyIndex + 1) {
    const downstreamCmd = args[proxyIndex + 1];
    const downstreamArgs = args.slice(proxyIndex + 2);
    const proxy = new McpProxyGateway(evaluator);
    proxy.start(downstreamCmd, downstreamArgs);
    return;
  }

  // Mode 1: Standalone Standard MCP Server
  const server = new Server(
    {
      name: "aletheia-mcp",
      version: VERSION,
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
    }
  );

  const { toolDefinitions, handleCall } = registerTools(evaluator);
  const { resourceDefinitions, handleRead } = registerResources(evaluator);
  const { promptDefinitions, handleGet } = registerPrompts();

  // 1. Tool handlers
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDefinitions,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    return await handleCall(request.params.name, request.params.arguments || {});
  });

  // 2. Resource handlers
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: resourceDefinitions,
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    return handleRead(request.params.uri);
  });

  // 3. Prompt handlers
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: promptDefinitions,
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    return handleGet(
      request.params.name,
      (request.params.arguments as Record<string, string>) || {}
    );
  });

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error(`[Aletheia MCP] Server running on stdio (v${VERSION}) — S3 Scope Creep filter active`);
}

main().catch((error) => {
  console.error("[Aletheia MCP] Fatal server error:", error);
  process.exit(1);
});
