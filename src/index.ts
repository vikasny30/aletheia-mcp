#!/usr/bin/env node
/**
 * Aletheia MCP Server: Entrypoint
 * 
 * Model Context Protocol (MCP) server providing sub-millisecond runtime safety,
 * behavioral filtering, and Signature S3 (Scope Creep) protection for Claude & autonomous agents.
 */

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
import { registerTools } from "./tools/index.js";
import { registerResources } from "./resources/index.js";
import { registerPrompts } from "./prompts/index.js";
import { McpProxyGateway } from "./proxy/mcp-proxy.js";

const VERSION = "1.0.0";

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
  npx aletheia-mcp                     Start standard MCP server on stdio
  npx aletheia-mcp --proxy <cmd>...    Start transparent proxy wrapping downstream MCP server
  npx aletheia-mcp --version           Show version
  npx aletheia-mcp --help              Show help
    `);
    process.exit(0);
  }

  const evaluator = new S3ScopeEvaluator();

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
