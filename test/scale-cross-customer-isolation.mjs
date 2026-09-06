#!/usr/bin/env node
/**
 * Verifies that Aletheia's own --allowed-paths boundary -- not the downstream server's
 * own permissions -- is what prevents one customer's instance from reading another
 * customer's data. The downstream filesystem server is deliberately given access to
 * BOTH sandboxes, so any blocking observed here is provably Aletheia's own enforcement,
 * not a coincidence of the wrapped server's own scoping. Uses an ordinary, non-"sensitive"
 * filename with a unique marker string, so this tests the allowedPaths boundary itself,
 * not the separate unconditional sensitive-filename protections.
 *
 * Run: node test/scale-cross-customer-isolation.mjs
 */
import { spawn } from "node:child_process";
import readline from "node:readline";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, "..");
const BASE = fs.mkdtempSync(path.join(os.tmpdir(), "aletheia-isolation-"));

async function main() {
  const sandboxA = path.join(BASE, "customer-A");
  const sandboxB = path.join(BASE, "customer-B");
  fs.mkdirSync(sandboxA, { recursive: true });
  fs.mkdirSync(sandboxB, { recursive: true });

  const MARKER = "CUSTOMER_B_PRIVATE_CONTENT_" + Math.random().toString(36).slice(2);
  const secretPath = path.join(sandboxB, "notes.txt");
  fs.writeFileSync(secretPath, MARKER);

  // Customer A's Aletheia instance, scoped ONLY to sandboxA -- but the downstream
  // filesystem server is given BOTH directories, so it would permit cross-access on its own.
  const proxyA = spawn("node", [
    path.join(REPO, "dist/index.js"), "--allow-write", "--allowed-paths", sandboxA,
    "--proxy", "node", path.join(REPO, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), sandboxA, sandboxB,
  ], { cwd: REPO });

  const responses = new Map();
  const rl = readline.createInterface({ input: proxyA.stdout, terminal: false });
  rl.on("line", (line) => { try { const m = JSON.parse(line); if (m.id !== undefined) responses.set(m.id, m); } catch {} });
  proxyA.stderr.on("data", () => {});

  function send(id, method, params) { proxyA.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n"); }
  async function waitFor(id, t = 5000) {
    const start = Date.now();
    while (!responses.has(id)) { if (Date.now() - start > t) return { TIMEOUT: true }; await new Promise((r) => setTimeout(r, 20)); }
    return responses.get(id);
  }

  send(1, "initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "isolation-test", version: "1" } });
  await waitFor(1);
  send(2, "notifications/initialized", undefined);

  // Sanity control: A reading its OWN sandbox must still work
  fs.writeFileSync(path.join(sandboxA, "own.txt"), "customer A own content");
  send(3, "tools/call", { name: "read_text_file", arguments: { path: path.join(sandboxA, "own.txt") } });
  const ownResp = await waitFor(3);
  const ownWorked = !!ownResp.result?.content;
  console.log(`Sanity control -- Customer A reading its OWN file: ${ownWorked ? "ALLOWED (correct)" : "BLOCKED (unexpected failure)"}`);

  // The real test: A attempting to read B's ordinary, non-sensitive file
  send(4, "tools/call", { name: "read_text_file", arguments: { path: secretPath } });
  const crossResp = await waitFor(4);
  const wasBlocked = crossResp.result?.isError === true;
  const leaked = JSON.stringify(crossResp).includes(MARKER);

  console.log(`\nCustomer A accessing Customer B's ordinary file: ${wasBlocked ? "BLOCKED (correct)" : "ALLOWED"}`);
  console.log(`Content actually leaked into the response: ${leaked ? "YES -- SECURITY FAILURE" : "no"}`);
  console.log(`\nFull cross-access response:\n${JSON.stringify(crossResp, null, 2)}`);

  proxyA.kill("SIGKILL");
  fs.rmSync(BASE, { recursive: true, force: true });

  process.exit(ownWorked && wasBlocked && !leaked ? 0 : 1);
}
main().catch((e) => { console.error("HARNESS ERROR:", e); process.exit(1); });
