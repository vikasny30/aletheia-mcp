#!/usr/bin/env node
/**
 * Real-process concurrency test: simulates N independent "customers," each running
 * their own real Aletheia proxy wrapping a real @modelcontextprotocol/server-filesystem
 * instance, fully concurrently, each doing a realistic mixed benign/adversarial session.
 *
 * This exercises actual spawned OS processes and real stdio JSON-RPC round-trips --
 * not a synthetic in-process loop -- to check for shared-state bugs, resource
 * contention, or correctness regressions when many instances run side by side.
 *
 * Run: node test/scale-concurrent-customers.mjs
 */
import { spawn, execSync } from "node:child_process";
import readline from "node:readline";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, "..");
const BASE_SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), "aletheia-scale-"));
const NUM_CUSTOMERS = Number(process.env.ALETHEIA_SCALE_CUSTOMERS || 30);
const ITERATIONS_PER_CUSTOMER = Number(process.env.ALETHEIA_SCALE_ITERATIONS || 40);

function memSampleMB() {
  try {
    const out = execSync(`ps -A -o rss=,comm= | awk '$2 ~ /node$/ {sum+=$1} END {print sum+0}'`).toString().trim();
    return Number(out) / 1024;
  } catch {
    return -1;
  }
}

function nodeProcessCount() {
  try {
    return Number(execSync(`ps -A -o comm= | grep -c 'node$'`).toString().trim());
  } catch {
    return -1;
  }
}

async function runCustomerSession(customerId) {
  const sandbox = path.join(BASE_SANDBOX, `customer-${customerId}`);
  fs.mkdirSync(sandbox, { recursive: true });

  const proxy = spawn("node", [
    path.join(REPO, "dist/index.js"), "--allow-write", "--allowed-paths", sandbox,
    "--proxy", "node", path.join(REPO, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), sandbox,
  ], { cwd: REPO });

  const responses = new Map();
  const rl = readline.createInterface({ input: proxy.stdout, terminal: false });
  rl.on("line", (line) => { try { const m = JSON.parse(line); if (m.id !== undefined) responses.set(m.id, m); } catch {} });
  proxy.stderr.on("data", () => {});

  let nextId = 1;
  function send(method, params) {
    const id = nextId++;
    proxy.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    return id;
  }
  async function waitFor(id, t = 8000) {
    const start = Date.now();
    while (!responses.has(id)) {
      if (Date.now() - start > t) return { TIMEOUT: true };
      await new Promise((r) => setTimeout(r, 20));
    }
    return responses.get(id);
  }

  const result = { customerId, ops: 0, correctnessFailures: [], timeouts: 0 };

  send("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: `cust-${customerId}`, version: "1" } });
  await waitFor(1);
  send("notifications/initialized", undefined);

  for (let i = 0; i < ITERATIONS_PER_CUSTOMER; i++) {
    const fname = path.join(sandbox, `file-${i}.txt`);
    const content = `customer ${customerId} iteration ${i}`;

    let id = send("tools/call", { name: "write_file", arguments: { path: fname, content } });
    let resp = await waitFor(id);
    result.ops++;
    if (resp.TIMEOUT) result.timeouts++;
    else if (resp.result?.isError) result.correctnessFailures.push(`customer ${customerId} iter ${i}: benign write was BLOCKED (false positive)`);

    id = send("tools/call", { name: "read_text_file", arguments: { path: fname } });
    resp = await waitFor(id);
    result.ops++;
    if (resp.TIMEOUT) result.timeouts++;
    else if (!resp.result?.content?.[0]?.text?.includes(content)) {
      result.correctnessFailures.push(`customer ${customerId} iter ${i}: read-back content mismatch (cross-contamination risk)`);
    }

    id = send("tools/call", { name: "read_text_file", arguments: { path: "/etc/passwd" } });
    resp = await waitFor(id);
    result.ops++;
    if (resp.TIMEOUT) result.timeouts++;
    else if (!(resp.result?.isError && JSON.stringify(resp).includes("BLOCKED"))) {
      result.correctnessFailures.push(`customer ${customerId} iter ${i}: /etc/passwd read was NOT blocked (security regression under load)`);
    }

    id = send("tools/call", { name: "list_directory", arguments: { path: sandbox } });
    resp = await waitFor(id);
    result.ops++;
    if (resp.TIMEOUT) result.timeouts++;
  }

  proxy.kill("SIGKILL");
  return result;
}

async function main() {
  console.log(`Launching ${NUM_CUSTOMERS} concurrent customer sessions, ${ITERATIONS_PER_CUSTOMER} iterations each...`);
  const t0 = Date.now();

  const monitor = setInterval(() => {
    console.log(`  [t=${((Date.now() - t0) / 1000).toFixed(1)}s] aggregate node RSS: ${memSampleMB().toFixed(0)}MB across ${nodeProcessCount()} node processes`);
  }, 3000);

  const results = await Promise.all(
    Array.from({ length: NUM_CUSTOMERS }, (_, i) => runCustomerSession(i))
  );

  clearInterval(monitor);
  const elapsed = (Date.now() - t0) / 1000;

  const totalOps = results.reduce((a, r) => a + r.ops, 0);
  const totalTimeouts = results.reduce((a, r) => a + r.timeouts, 0);
  const allFailures = results.flatMap((r) => r.correctnessFailures);

  console.log(`\n=== RESULTS ===`);
  console.log(`Customers: ${NUM_CUSTOMERS}, total operations: ${totalOps}, elapsed: ${elapsed.toFixed(1)}s (${(totalOps / elapsed).toFixed(0)} ops/sec aggregate)`);
  console.log(`Timeouts: ${totalTimeouts}`);
  console.log(`Correctness failures: ${allFailures.length}`);
  allFailures.forEach((f) => console.log(`  - ${f}`));

  fs.rmSync(BASE_SANDBOX, { recursive: true, force: true });
  process.exit(allFailures.length > 0 || totalTimeouts > 0 ? 1 : 0);
}

main().catch((e) => { console.error("HARNESS ERROR:", e); process.exit(1); });
