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

// Supabase's changelog revokes the old defaults from service_role too, and grants it every
// new table in its example, so edge functions and server code need their own grants.
test("--oct30 grants the service role every table, and the sequences behind its inserts", () => {
  const g = runWith(newGrants, "--oct30").grantsChange;
  assert.deepEqual(g.server.flatMap((s) => s.grant), [
    "grant select, insert, update, delete on public.categories to service_role;",
    "grant usage on sequence public.categories_id_seq to service_role;",
    "grant select, insert, update, delete on public.messages to service_role;",
    "grant select, insert, update, delete on public.notes to service_role;",
    "grant select, insert, update, delete on public.orders to service_role;",
    "grant select, insert, update, delete on public.profiles to service_role;",
    "grant select, insert, update, delete on public.tags to service_role;",
    "grant usage on sequence public.tags_id_seq to service_role;",
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
  assert.match(sql, /grant select, insert, update, delete on public\.notes to service_role;/);
  const second = runWith(dir, "--oct30").grantsChange;
  assert.deepEqual([second.breaks, second.server, second.unsafe, second.closedNoRls], [[], [], [], []]);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("splits long comment headers in linear time, and keeps $a2$ bodies whole", () => {
  const rule = `-- ${"-".repeat(75)}`;
  const header = [rule, ...Array.from({ length: 200 }, (_, i) => `-- note ${i}`), rule].join("\n");
  const started = Date.now();
  const parts = splitStatements(`${header}\ncreate table t (id int);\n${header}\ndo $a2$ begin perform 1; end $a2$;`);
  assert.equal(parts.length, 2);
  assert.ok(parts[1].endsWith("end $a2$"));
  assert.ok(Date.now() - started < 1000, "a backtracking regex takes minutes on this");
});

// Real apps' migrations, condensed: a pg_dump header, Supabase's pre-installed extensions,
// BEGIN/COMMIT, realtime, pgvector, staff roles, a shared organization, a broken sign-up trigger.
const messy = run(fileURLToPath(new URL("./fixtures/messy", import.meta.url)));
const messyTable = Object.fromEntries(messy.report.results.map((r) => [r.table, r]));
const messyFindings = messy.report.findings.map((f) => `${f.severity} ${f.where}: ${f.title}`);

test("a messy history loads: settings end with their file, BEGIN/COMMIT is ignored, Supabase's extensions exist", () => {
  const { failed, missing, skipped } = messy.report.load;
  assert.deepEqual(failed.map((f) => f.error).sort(), ['relation "legacy_table" does not exist', 'relation "old_drafts" does not exist']);
  assert.deepEqual(missing, ["legacy_table", "old_drafts"]);
  assert.ok(skipped.some((s) => s.reason === "vector index"));
  assert.equal(skipped.filter((s) => s.reason === "transaction control").length, 2);
  for (const t of ["organizations", "photos", "posts", "drafts", "invoices"]) assert.ok(messyTable[t]?.anon, `${t} probed`);
});

test("a sign-up trigger that fails doesn't stop the probe", () => {
  assert.ok(messy.report.seedProblems.some((p) => p.table === "auth.users" && /without the sign-up trigger/.test(p.error)));
});

test("the other user is a plain stranger: no staff role, not in A's organization", () => {
  assert.equal(messyTable.invoices.B.read, 0, "B has no row in user_roles, so isn't staff");
  assert.equal(messyTable.invoices.B.update, false);
  assert.equal(messyTable.organizations.B.update, false, "B owns a different organization than A");
  assert.ok(!messyFindings.some((f) => /invoices|organization/.test(f) && !f.startsWith("review")));
});

test("real holes in a messy app are still found", () => {
  assert.ok(messyFindings.includes("critical photos: Visitors who aren't signed in can change data"), "seeded through a LIKE check");
  assert.ok(messyFindings.includes("high posts: Visitors can read users' data"), "row_security = off didn't leak");
  assert.ok(messyFindings.includes("high server_notes: Row-level security is off"), "reported though visitors are revoked");
  assert.ok(messyFindings.includes("high app_settings: Any signed-in user can change shared data"), "updated_by doesn't make it owned");
  assert.equal(messy.code, 1);
});
