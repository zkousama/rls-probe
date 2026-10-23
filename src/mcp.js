// rls-probe as a local MCP server over stdio, for Claude Code, Cursor, Windsurf and
// Claude Desktop: `rls-probe mcp`. It speaks the slice of the protocol it needs
// (start-up, listing tools, calling them) with no dependencies, and runs each check
// as its own process, so the memory a probe takes is freed when it ends.
import { execFile } from "node:child_process";
import fs from "node:fs";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { explain } from "./explain.js";
import { renderGrants } from "./grants.js";
import { renderText } from "./report.js";
import { reviewBrief } from "./review.js";

const VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"];
const CLI = fileURLToPath(new URL("./cli.js", import.meta.url));
const VERSION = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
// Many MCP clients give up on a tool call after about a minute, so fixes get 25 seconds
// of testing; on a very large app the rest are listed as untested.
const FIX_TIME = "--fix-time=25";

const PATH = {
  type: "string",
  description: "The app's folder (the one holding supabase/migrations), a migrations folder, or one .sql file such as the output of `supabase db dump`. Relative to the project root; defaults to it.",
};

const TOOLS = [
  {
    name: "check_supabase_security",
    title: "Check a Supabase app's security",
    description: "Runs the app's Supabase migrations in an in-memory Postgres (nothing touches a live database), signs in two users and tries every table as a visitor and as the other user. Also checks the code for leaked keys and open edge functions, and what Supabase's October 30, 2026 grants change breaks. Returns the problems in plain words, what to change with SQL that was tested on a copy of the database, and the details. Run it after any change to supabase/migrations, and again after fixing, until no problems are left.",
    inputSchema: { type: "object", properties: { path: PATH }, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "write_supabase_security_fixes",
    title: "Write the tested security fixes as a migration",
    description: "Writes a new migration next to the others with a fix for each database problem check_supabase_security finds, but only fixes that passed a test: each was applied to a copy of the database and probed again, closing its problem without the owner of any row losing access or anything new opening. Fixes for things that may be on purpose are written commented out. Problems in the code (leaked keys, open edge functions) are listed, not fixed. Read the file before applying it.",
    inputSchema: { type: "object", properties: { path: PATH }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "write_supabase_grants_migration",
    title: "Write the safe grants as a migration",
    description: "For Supabase's October 30, 2026 grants change: writes a new migration next to the others with only the grants that are safe, for tables whose row-level security already limits who reaches which rows, and for the service role. Tables a grant would expose are listed as comments, not granted. Read the file before applying it.",
    inputSchema: { type: "object", properties: { path: PATH }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
];

const INSTRUCTIONS = "Use check_supabase_security after creating or changing anything in supabase/migrations, before deploying, and whenever the user asks whether their Supabase app is secure. rls-probe only sees the database the migrations build, so check each finding against the code before changing anything: it may already be handled, or be on purpose. Fix the real ones in new migration files, never by weakening a policy, preferring the tested SQL the check returns (or write_supabase_security_fixes). Record the ones you rule out in rls-probe.json at the app's root, each with its reason, so they stop counting. Each tested fix says what changes afterwards: tell the user when that limits a feature, such as a feed showing only the user's own posts. Ask the user before making private anything that may be public on purpose. Check again until no problems are left.";

export function serve() {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    if (!line.trim()) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    }
    if (message.id === undefined || message.id === null) return; // a notification
    // A client that passes a progress token hears from a long check every few seconds,
    // which some use to keep waiting.
    const token = message.params?._meta?.progressToken;
    const started = Date.now();
    const beat = token === undefined ? null : setInterval(() => {
      const seconds = Math.round((Date.now() - started) / 1000);
      send({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: token, progress: seconds, message: `Still checking (${seconds} s)` } });
    }, 5000);
    try {
      send({ jsonrpc: "2.0", id: message.id, result: await handle(message) });
    } catch (error) {
      send({ jsonrpc: "2.0", id: message.id, error: { code: error.code ?? -32603, message: error.message } });
    } finally {
      clearInterval(beat);
    }
  });
  // Replies still on their way out go first.
  rl.on("close", () => process.stdout.write("", () => process.exit(0)));
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handle({ method, params }) {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: VERSIONS.includes(params?.protocolVersion) ? params.protocolVersion : VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: { name: "rls-probe", title: "rls-probe", version: VERSION },
        instructions: INSTRUCTIONS,
      };
    case "ping":
      return {};
    case "tools/list":
      return { tools: TOOLS };
    case "tools/call":
      return call(params?.name, params?.arguments ?? {});
    default:
      throw Object.assign(new Error(`Method not found: ${method}`), { code: -32601 });
  }
}

async function call(name, { path: target = "." }) {
  if (name === "check_supabase_security") {
    const run = await probe(target, ["--oct30", "--test-fixes", FIX_TIME, "--json"]);
    if (!run.report) return failed(run);
    const r = run.report;
    const e = explain(r);
    const text = [
      `rls-probe: ${e.grade ? `grade ${e.grade}. ` : ""}${e.verdict.charAt(0).toUpperCase()}${e.verdict.slice(1)}`,
      "",
      ...[...e.problems, ...e.notes].map((p) => `- ${p.severity.toUpperCase()}: ${p.headline}`),
      e.grants ? `\n${e.grants.headline}` : "",
      e.team ? `\n${e.team.headline}` : "",
      e.missing.length ? `\nNot checked (never created by the migrations): ${e.missing.join(", ")}` : "",
      "",
      "## Review and fix",
      "",
      reviewBrief(r).trimEnd(),
      "",
      "## Details",
      "",
      renderText(r) + (r.grantsChange ? renderGrants(r.grantsChange) : ""),
    ].join("\n");
    return { content: [{ type: "text", text }], structuredContent: { grade: e.grade, verdict: e.verdict, exitCode: run.code, problems: e.problems, notes: e.notes }, isError: false };
  }
  if (name === "write_supabase_security_fixes") {
    const run = await probe(target, ["--fix-policies", FIX_TIME, "--json"]);
    if (!run.report) return failed(run);
    const file = run.report.policyFixWritten;
    const problems = run.report.findings.filter((f) => f.severity !== "review").length;
    const text = file
      ? [`Wrote ${file}. Read it before applying it, then run check_supabase_security again.`, "", fs.readFileSync(file, "utf8")].join("\n")
      : problems ? "No fix passed its test, so no migration was written. Run check_supabase_security for what to change." : "Nothing to fix, so no migration was written.";
    return { content: [{ type: "text", text }], isError: false };
  }
  if (name === "write_supabase_grants_migration") {
    const run = await probe(target, ["--fix", "--json"]);
    if (!run.report) return failed(run);
    const g = run.report.grantsChange;
    const text = run.report.fixWritten
      ? [`Wrote ${run.report.fixWritten}. Read it before applying it.`, "", fs.readFileSync(run.report.fixWritten, "utf8")].join("\n")
      : "Nothing is safe to grant, so no migration was written.";
    const held = [...g.unsafe.map((u) => u.table), ...g.closedNoRls.map((c) => c.table)];
    return { content: [{ type: "text", text: held.length ? `${text}\nHeld back until fixed: ${held.join(", ")}. Run check_supabase_security for what to change.` : text }], isError: false };
  }
  throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
}

// One rls-probe run as its own process. Exit 1 means it found something, which is
// a normal result here.
function probe(target, flags) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, target, ...flags], { cwd: process.cwd(), maxBuffer: 256 * 1024 * 1024 }, (error, stdout, stderr) => {
      const code = error?.code ?? 0;
      try {
        resolve({ code, report: JSON.parse(stdout) });
      } catch {
        resolve({ code, stderr: stderr.trim() || error?.message || "rls-probe gave no report" });
      }
    });
  });
}

function failed(run) {
  return { content: [{ type: "text", text: run.stderr }], isError: true };
}
