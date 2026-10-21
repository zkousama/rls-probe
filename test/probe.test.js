import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { splitStatements } from "../src/split.js";

const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const leaky = fileURLToPath(new URL("./fixtures/leaky", import.meta.url));
const fixed = fileURLToPath(new URL("./fixtures/fixed", import.meta.url));

function run(target) {
  try {
    return { code: 0, report: JSON.parse(execFileSync("node", [cli, target, "--json"], { encoding: "utf8" })) };
  } catch (error) {
    return { code: error.status, report: JSON.parse(error.stdout) };
  }
}

test("splits on semicolons outside quotes, comments and dollar-quoted bodies", () => {
  const sql = `create table a (x text default ';'); -- a; comment
    create function f() returns int language plpgsql as $body$ begin return 1; end; $body$;
    /* block; */ select 'it''s; fine';`;
  assert.equal(splitStatements(sql).length, 3);
});

const leakyRun = run(leaky);
const byTable = Object.fromEntries(leakyRun.report.results.map((r) => [r.table, r]));

test("a table without row-level security is open to visitors", () => {
  assert.deepEqual(byTable.orders.anon, { read: 1, readTotal: 2, exposed: [], update: true, delete: true, insert: true });
});

test("a `using (true)` policy for signed-in users lets them read and edit each other's rows", () => {
  assert.equal(byTable.messages.anon.read, 0);
  assert.equal(byTable.messages.B.read, 1);
  assert.equal(byTable.messages.B.update, true);
  assert.equal(byTable.messages.B.insert, false, "the insert policy checks sender_id = auth.uid()");
});

test("owner policies keep other users out", () => {
  assert.deepEqual(byTable.notes.B, { read: 0, readTotal: 1, exposed: [], update: false, delete: false, insert: false });
  assert.deepEqual(byTable.notes.anon, { read: 0, readTotal: 0, exposed: [], update: false, delete: false, insert: false });
});

test("rows created by a sign-up trigger count as that user's", () => {
  assert.equal(byTable.profiles.owned, true);
  assert.equal(byTable.profiles.anon.read, 1);
  assert.deepEqual(byTable.profiles.anon.exposed, ["email"]);
});

test("the code scan finds a service role key, an open edge function and a public bucket", () => {
  const titles = leakyRun.report.findings.map((f) => `${f.severity} ${f.title}`);
  assert.ok(titles.includes("critical Supabase service role key in the code"));
  assert.ok(titles.includes("high Edge function open to anyone"));
  assert.ok(titles.includes("review Public storage bucket"));
  assert.ok(titles.includes("high Function runs with full rights and anyone can call it"));
  assert.equal(leakyRun.code, 1);
});

test("the fixed app passes", () => {
  const { code, report } = run(fixed);
  assert.deepEqual(report.findings.filter((f) => f.severity !== "review"), []);
  assert.equal(code, 0);
});

const newGrants = fileURLToPath(new URL("./fixtures/new-grants", import.meta.url));

function runWith(target, ...flags) {
  try {
    return JSON.parse(execFileSync("node", [cli, target, "--json", ...flags], { encoding: "utf8" }));
  } catch (error) {
    return JSON.parse(error.stdout);
  }
}

test("--oct30 sorts tables into safe to grant, fix first, and closed only by missing grants", () => {
  const g = runWith(leaky, "--oct30").grantsChange;
  assert.deepEqual(g.breaks.map((b) => b.table).sort(), ["categories", "notes"]);
  assert.deepEqual(g.unsafe.map((u) => u.table).sort(), ["messages", "profiles"]);
  assert.deepEqual(g.closedNoRls.map((c) => c.table), ["orders"]);
});

// These are the grants a real local Supabase, opted into the change, was checked
// against with scripts/compare-grants-with-supabase.mjs: 30 of 30 checks passed.
test("--oct30 suggests exactly the grants the policies need, sequences included", () => {
  const lines = runWith(newGrants, "--oct30").grantsChange.breaks.flatMap((b) => b.grant);
  assert.deepEqual(lines, [
    "grant select on public.categories to anon, authenticated;",
    "grant select, insert, update on public.messages to authenticated;",
    "grant select, insert, update, delete on public.notes to authenticated;",
    "grant select, insert, update, delete on public.orders to authenticated;",
    "grant select, update on public.profiles to authenticated;",
    "grant select, insert, update, delete on public.tags to authenticated;",
    "grant usage on sequence public.tags_id_seq to authenticated;",
  ]);
});

test("--grants=explicit probes a project without the old default grants", () => {
  const report = runWith(leaky, "--grants=explicit");
  const orders = report.results.find((r) => r.table === "orders");
  assert.equal(orders.anon.read, 0, "no grant, so even a table without row-level security is closed");
  assert.equal(orders.anon.insert, false);
});

test("--fix writes the safe grants as a migration, and a second run finds nothing left to grant", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-fix-"));
  fs.cpSync(fixed, dir, { recursive: true });
  const first = runWith(dir, "--fix");
  assert.ok(first.fixWritten?.endsWith("_rls_probe_grants.sql"));
  const sql = fs.readFileSync(first.fixWritten, "utf8");
  assert.match(sql, /grant select, insert, update, delete on public\.notes to authenticated;/);
  const second = runWith(dir, "--oct30").grantsChange;
  assert.deepEqual([second.breaks, second.unsafe, second.closedNoRls], [[], [], []]);
  fs.rmSync(dir, { recursive: true, force: true });
});
