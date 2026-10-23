import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const fixtures = fileURLToPath(new URL("./fixtures", import.meta.url));

// A minimal MCP client: one server process, requests matched to replies by id.
function connect(cwd) {
  const server = spawn(process.execPath, [cli, "mcp"], { cwd, stdio: ["pipe", "pipe", "inherit"] });
  const waiting = new Map();
  readline.createInterface({ input: server.stdout }).on("line", (line) => {
    const message = JSON.parse(line);
    waiting.get(message.id)?.(message);
  });
  let next = 1;
  return {
    request(method, params) {
      const id = next++;
      server.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      return new Promise((resolve) => waiting.set(id, resolve));
    },
    notify(method) {
      server.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method })}\n`);
    },
    close: () => server.stdin.end(),
  };
}

test("the MCP server starts, lists its tools and checks an app", async () => {
  const mcp = connect(fixtures);
  const init = await mcp.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  assert.equal(init.result.protocolVersion, "2025-06-18");
  assert.equal(init.result.serverInfo.name, "rls-probe");
  mcp.notify("notifications/initialized");
  const tools = await mcp.request("tools/list", {});
  assert.deepEqual(tools.result.tools.map((t) => t.name), ["check_supabase_security", "write_supabase_grants_migration"]);
  const check = await mcp.request("tools/call", { name: "check_supabase_security", arguments: { path: "leaky" } });
  assert.equal(check.result.isError, false);
  assert.match(check.result.content[0].text, /^rls-probe: grade F\. 6 problems to fix/);
  assert.equal(check.result.structuredContent.grade, "F");
  assert.match(check.result.content[0].text, /## What to change/);
  assert.equal(check.result.structuredContent.exitCode, 1);
  const missing = await mcp.request("tools/call", { name: "check_supabase_security", arguments: { path: "nowhere" } });
  assert.equal(missing.result.isError, true);
  const unknown = await mcp.request("no/such/method", {});
  assert.equal(unknown.error.code, -32601);
  mcp.close();
});

test("the MCP grants tool writes the safe grants as a migration", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-mcp-"));
  fs.cpSync(path.join(fixtures, "fixed"), dir, { recursive: true });
  const mcp = connect(dir);
  await mcp.request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  const wrote = await mcp.request("tools/call", { name: "write_supabase_grants_migration", arguments: {} });
  assert.match(wrote.result.content[0].text, /^Wrote .*_rls_probe_grants\.sql/);
  assert.match(wrote.result.content[0].text, /grant select, insert, update, delete on public\.notes to authenticated;/);
  mcp.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
