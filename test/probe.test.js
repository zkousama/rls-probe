import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { explain } from "../src/explain.js";
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

function runText(target, ...flags) {
  try {
    return execFileSync("node", [cli, target, ...flags], { encoding: "utf8" });
  } catch (error) {
    return error.stdout;
  }
}

test("the plain summary leads with what someone who doesn't read SQL needs", () => {
  const out = runText(leaky, "--oct30");
  assert.match(out, /^rls-probe: grade F\. 6 problems to fix \(5 tables checked\)\./);
  assert.match(out, /CRITICAL {2}Anyone on the internet can see, change, delete and add every row in the orders table\./);
  assert.match(out, /HIGH {6}Anyone on the internet can see your users' profiles, including email\./);
  assert.match(out, /run rls-probe with --prompt/);
  assert.match(out, /\nDetails\n/);
});

test("the fix prompt names the app's own policies, owner columns and grants", () => {
  const out = runText(leaky, "--oct30", "--prompt");
  assert.match(out, /Change the policy "auth write" \(using true\) on "messages" so a user can only change rows where sender_id points to a profiles row whose id = auth\.uid\(\)/);
  assert.match(out, /add policies so each user can only see and change their own rows \(user_id = auth\.uid\(\)\)/);
  assert.match(out, /^grant select, insert, update, delete on public\.notes to authenticated;$/m);
  assert.match(out, /Don't grant anon or authenticated anything on messages, profiles or orders/);
  assert.equal(runText(fixed, "--prompt"), "rls-probe found nothing to fix.\n");
});

test("SARIF points each finding at the line that creates its table, or at the code", () => {
  const sarif = JSON.parse(runText(leaky, "--sarif"));
  const results = sarif.runs[0].results;
  const at = (rule) => results.find((r) => r.ruleId === rule).locations[0].physicalLocation;
  // Paths are relative to where rls-probe runs (the repository root, in CI).
  const app = path.relative(process.cwd(), leaky).split(path.sep).join("/");
  assert.deepEqual(at("rls-off/critical"), { artifactLocation: { uri: `${app}/supabase/migrations/20250101000000_init.sql` }, region: { startLine: 24 } });
  assert.deepEqual(at("service-key/critical"), { artifactLocation: { uri: `${app}/src/supabase.ts` }, region: { startLine: 3 } });
  assert.ok(sarif.runs[0].tool.driver.rules.every((r) => r.properties["security-severity"]));
});

test("a single .sql file, such as the output of supabase db dump, is probed on its own", () => {
  const dump = fileURLToPath(new URL("./fixtures/leaky/supabase/migrations/20250101000000_init.sql", import.meta.url));
  const { report } = run(dump);
  assert.equal(report.migrations, 1);
  assert.equal(Object.fromEntries(report.results.map((r) => [r.table, r])).orders.anon.read, 1);
  const sarif = JSON.parse(runText(dump, "--sarif"));
  assert.ok(sarif.runs[0].results.every((r) => !r.locations[0].physicalLocation.artifactLocation.uri.includes("..")));
});

test("Supabase's newer sb_secret_ keys are caught in the code, like service role keys", () => {
  assert.ok(messyFindings.includes("critical src/admin.ts:1: Supabase secret key in the code"));
});

// Advice that only looks right is how "revoke from anon" shipped while public could still
// run the function. Each do-it-yourself fix is applied as a migration and probed again.
test("the do-it-yourself fixes close what they say they close, and owners keep their rows", () => {
  const before = run(leaky).report;
  const sql = explain(before).problems.concat(explain(before).notes).filter((p) => p.selfFix?.where === "SQL Editor").map((p) => p.selfFix.code);
  assert.ok(sql.length >= 3);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-selffix-"));
  fs.cpSync(leaky, dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "supabase", "migrations", "99999999999999_fixes.sql"), sql.join("\n"));
  const after = run(dir).report;
  const left = after.findings.map((f) => `${f.kind} ${f.where}`);
  for (const gone of ["rls-off orders", "definer-function", "view-bypass", "public-bucket"]) {
    assert.ok(!left.some((k) => k.startsWith(gone)), `${gone} is fixed`);
  }
  const orders = after.results.find((r) => r.table === "orders");
  assert.equal(orders.B.read, 0, "another user no longer reads the orders");
  assert.ok(orders.A.read > 0 && orders.A.update && orders.A.insert, "the owner still reads, edits and adds their own");
  fs.rmSync(dir, { recursive: true, force: true });
});
