import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { explain } from "../src/explain.js";
import { renderGrants } from "../src/grants.js";
import { splitStatements } from "../src/split.js";

const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const leaky = fileURLToPath(new URL("./fixtures/leaky", import.meta.url));
const fixed = fileURLToPath(new URL("./fixtures/fixed", import.meta.url));

function run(target, ...flags) {
  try {
    return { code: 0, report: JSON.parse(execFileSync("node", [cli, target, "--json", ...flags], { encoding: "utf8" })) };
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
  // Called as a visitor with the id of user A's order, delete_order() deleted it.
  assert.ok(titles.includes("critical Function runs with full rights and anyone can call it"));
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
// against with scripts/compare-grants-with-supabase.mjs: 30 of 30 checks passed. The view
// (order_totals, security_invoker over orders) came later and wasn't part of that check.
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
    "grant select on public.order_totals to authenticated;",
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
    "grant select, insert, update, delete on public.order_totals to service_role;",
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
  // Probed, though seeded through a LIKE check. Visitors can only add photos, and the insert
  // policy is named "anyone uploads", so the app's own migration says that's on purpose.
  const photos = messy.report.findings.find((f) => f.kind === "visitor-write" && f.where === "photos");
  assert.ok(photos, "seeded through a LIKE check");
  assert.deepEqual([photos.severity, photos.intent.verdict], ["review", "on purpose"]);
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

test("storage: who can read, change and upload into another user's folder, bucket by bucket", () => {
  const files = Object.fromEntries(messy.report.storage.buckets.map((b) => [b.bucket, b]));
  assert.deepEqual(files.documents.B, { read: true, update: false, delete: false, insert: true }, "any signed-in user reads and uploads");
  assert.equal(files.documents.anon.read, false);
  assert.equal(files.avatars.B.insert, false, "avatars are kept to each user's own folder");
  assert.equal(files.receipts.assumed, true, "made in the dashboard, found through its policies");
  assert.deepEqual(files.receipts.B, { read: false, update: false, delete: false, insert: false });
  assert.ok(files.receipts.A.read && files.receipts.A.insert, "the owner keeps their own files");
  assert.ok(messyFindings.includes("medium storage bucket documents: Users can upload into someone else's folder"));
  assert.ok(messyFindings.includes("review storage bucket documents: Users can read each other's files"));
  assert.ok(!messyFindings.some((f) => f.includes("receipts")));
});

test("--badge prints a README badge in the grade's colour", () => {
  assert.match(runText(fixed, "--badge"), /^\[!\[rls-probe: grade B\]\(https:\/\/img\.shields\.io\/badge\/rls--probe-grade%20B-1f7a4d\)\]\(https:\/\/zkousama\.github\.io\/rls-probe\/\)/);
});

// The check has to be able to say no: a fix that closes the hole by locking the owner
// out, and one whose SQL fails, are both rejected.
test("fixes are offered only when they close the problem and the owner keeps their rows", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { checkFixes, verifyFixes } = await import("../src/fixes.js");
  const { findMigrations, readMigrations } = await import("../src/node.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const migrations = readMigrations(findMigrations(leaky));
  const report = await runProbe({ migrations, snapshot });
  const proposed = await verifyFixes({ migrations, report, snapshot });
  assert.ok(proposed.length >= 6 && proposed.every((f) => f.verified), "the generated fixes pass");
  const checked = await checkFixes({ migrations, report, snapshot, fixes: [
    { kind: "user-read", where: "messages", sql: 'create policy "nobody reads" on public.messages as restrictive for select to authenticated using (false);' },
    { kind: "view-bypass", where: "order_totals", sql: "alter view public.no_such_view set (security_invoker = true);" },
  ] });
  assert.deepEqual(checked.map((f) => f.verified), [false, false]);
});

test("--fix-policies writes the tested fixes as a migration, and a second run finds no database problem left", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-fix-policies-"));
  fs.cpSync(leaky, dir, { recursive: true });
  const first = run(dir, "--fix-policies").report;
  assert.ok(first.policyFixWritten?.endsWith("_rls_probe_security_fixes.sql"));
  const sql = fs.readFileSync(first.policyFixWritten, "utf8");
  assert.match(sql, /^revoke select on public\."profiles" from anon;$/m);
  assert.match(sql, /^-- alter view public\."order_totals" set \(security_invoker = true\);$/m, "fixes for things that may be on purpose stay commented out");
  assert.match(sql, /-- Fix these in the code, not the database:\n-- {3}Supabase service role key in the code/);
  const after = run(dir).report;
  assert.deepEqual(after.findings.filter((f) => f.severity !== "review").map((f) => f.kind).sort(), ["open-function", "service-key"]);
  const orders = after.results.find((r) => r.table === "orders");
  assert.ok(orders.A.read > 0 && orders.A.update && orders.A.delete && orders.A.insert, "the owner keeps every right to their own orders");
  fs.rmSync(dir, { recursive: true, force: true });
});

// is_staff() is called by the invoices policy, so revoking it would lock owners out of
// their invoices; making the avatars bucket private would expose its files to visitors
// through its select policy. Neither shows up on the table the fix is about.
test("a fix that breaks something elsewhere in the database is held back", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { checkFixes, verifyFixes } = await import("../src/fixes.js");
  const { findMigrations, readMigrations } = await import("../src/node.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const migrations = readMigrations(findMigrations(fileURLToPath(new URL("./fixtures/messy", import.meta.url))));
  const report = await runProbe({ migrations, snapshot, keep: true });
  const verdict = Object.fromEntries((await verifyFixes({ migrations, report, snapshot })).map((f) => [`${f.kind} ${f.where}`, f.verified]));
  // Both are known to fail from the report alone, so neither is offered.
  assert.equal(verdict["definer-function is_staff(uid uuid)"], undefined);
  assert.equal(verdict["public-bucket storage bucket avatars"], undefined);
  assert.equal(verdict["visitor-write photos"], true);
  assert.equal(verdict["rls-off-users server_notes"], true);
  assert.equal(verdict["storage-user-upload storage bucket documents"], true);
  // Tried anyway, the revoke is caught by what it does to the invoices table.
  const [revoke] = await checkFixes({ migrations, report, snapshot, fixes: [
    { kind: "definer-function", where: "is_staff(uid uuid)", sql: "revoke execute on function public.is_staff(uid uuid) from public, anon, authenticated;" },
  ] });
  assert.equal(revoke.verified, false);
});

test("the fix prompt carries the SQL that passed the test, and what changes afterwards", () => {
  const out = runText(leaky, "--prompt");
  assert.match(out, /rls-probe tested this SQL on a copy of the database\. It closes the problem, and afterwards visitors who aren't signed in can't read profiles, and each signed-in user sees only their own rows\.\n\n {3}revoke select on public\."profiles" from anon;/);
});

// Each security definer function is called as a visitor and as user B, aimed at user
// A's rows: what it does decides how serious it is, not only what its body looks like.
test("risky functions are called, and judged by what they did to another user's rows", () => {
  const { report } = run(fileURLToPath(new URL("./fixtures/functions", import.meta.url)));
  const by = Object.fromEntries(report.findings.filter((f) => f.kind === "definer-function").map((f) => [f.function, f]));
  assert.equal(by.get_profile.severity, "high");
  assert.ok(by.get_profile.leak, "a visitor got user A's profile, email included");
  assert.equal(by.rename_project.severity, "high");
  assert.equal(by.rename_project.callers, "users", "only signed-in users can call it, and user B renamed A's project");
  assert.deepEqual(by.rename_project.proof.changed, [{ table: "projects", how: "changed", columns: ["name"] }]);
  assert.equal(by.bump_views.severity, "review", "a view counter going up is what it's for");
  assert.deepEqual(by.bump_views.counter, { table: "projects", columns: ["view_count"] });
  assert.equal(by.delete_my_project.severity, "review");
  assert.ok(by.delete_my_project.tried, "called, and A's project survived");
  const plain = explain(report).problems.map((p) => p.headline);
  assert.ok(plain.includes("Any signed-in user can call the database function rename_project() to change other users' projects: rls-probe tried it, and the test user's row in projects was changed."));
});

// A teammate (D) joins user A's organization through org_members. What D can do with
// A's rows is shown, not counted, and a fix may not take it away: the select fix for
// tasks keeps "rows of a group you belong to".
test("a teammate is seeded into A's group, and fixes keep what teammates share", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-teams-"));
  fs.cpSync(fileURLToPath(new URL("./fixtures/teams", import.meta.url)), dir, { recursive: true });
  const { report } = run(dir, "--fix-policies");
  assert.deepEqual(report.teams, ["org_members"]);
  const tasks = report.results.find((r) => r.table === "tasks");
  assert.ok(tasks.D.read > 0 && tasks.D.update, "a member reads and edits the organization's tasks");
  assert.ok(!report.findings.some((f) => f.kind.startsWith("team")), "teammates' access is not a finding");
  assert.equal(explain(report).grade, "D");
  assert.match(explain(report).team.headline, /can see and change tasks of other members/);
  const sql = fs.readFileSync(report.policyFixWritten, "utf8");
  assert.match(sql, /exists \(select 1 from public\."org_members" m where m\."org_id" = "tasks"\."org_id" and m\."user_id" = \(select auth\.uid\(\)\)\)/);
  const after = run(dir).report;
  const fixed = after.results.find((r) => r.table === "tasks");
  assert.equal(fixed.B.read, 0, "a stranger no longer reads the tasks");
  assert.ok(fixed.D.read > 0 && fixed.D.update, "the teammate still reads and edits them");
  fs.rmSync(dir, { recursive: true, force: true });
});

// A report bigger than a pipe's buffer (64 KB) used to be cut off when rls-probe exited,
// breaking `--json | jq` and the MCP server on large apps.
test("a large JSON report arrives whole through a pipe", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-large-"));
  fs.mkdirSync(path.join(dir, "supabase", "migrations"), { recursive: true });
  const tables = Array.from({ length: 80 }, (_, i) => `create table public.notes_${i} (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes_${i} enable row level security;
create policy "read all ${i}" on public.notes_${i} for select to authenticated using (true);`);
  fs.writeFileSync(path.join(dir, "supabase", "migrations", "20250101000000_many.sql"), tables.join("\n"));
  // Through a shell pipe, as with jq: Node's own child processes use socket pairs,
  // whose bigger buffers hid the problem.
  const out = execFileSync("sh", ["-c", `"${process.execPath}" "${cli}" "${dir}" --json | cat`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  assert.ok(out.length > 65536);
  assert.equal(JSON.parse(out).results.length, 80);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("fixes not tried before the deadline are marked untested, not failed", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { verifyFixes } = await import("../src/fixes.js");
  const { findMigrations, readMigrations } = await import("../src/node.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const migrations = readMigrations(findMigrations(leaky));
  const report = await runProbe({ migrations, snapshot, keep: true });
  const fixes = await verifyFixes({ migrations, report, snapshot, deadline: performance.now() });
  assert.ok(fixes.length && fixes.every((f) => !f.verified && f.untested === "ran out of time"));
  report.fixes = fixes;
  assert.ok(explain(report).problems.every((p) => !p.selfFix?.tested), "nothing untested is offered as tested");
});

// rls-probe.json records findings someone checked and ruled out, with the reason. They're
// listed as accepted, not counted; an entry without a reason, or matching nothing, is
// pointed out.
test("rls-probe.json accepts findings with a reason, and says what it can't use", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-accept-"));
  fs.cpSync(leaky, dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "rls-probe.json"), JSON.stringify({ accept: [
    { finding: "user-read:messages", reason: "messages are a public chat room" },
    { finding: "view-bypass:order_totals" },
    { finding: "visitor-read:no_such_table", reason: "fixed last week" },
  ] }));
  const { report } = run(dir);
  const ids = report.findings.map((f) => `${f.kind}:${f.where}`);
  assert.ok(!ids.includes("user-read:messages"), "the accepted finding doesn't count");
  assert.ok(ids.includes("view-bypass:order_totals"), "one without a reason still counts");
  assert.deepEqual(report.accepted.map((f) => [f.kind, f.reason]), [["user-read", "messages are a public chat room"]]);
  assert.equal(report.acceptNotes.length, 2);
  const out = runText(dir);
  assert.match(out, /Accepted in rls-probe\.json, so not counted:\n {2}- user-read:messages: messages are a public chat room/);
  assert.match(out, /view-bypass:order_totals has no reason, so it still counts/);
  assert.match(out, /accepts visitor-read:no_such_table, which no longer comes up/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// The review is for an agent that reads the code: each finding with what was seen, the
// migration lines behind it, a check to run, why it might not apply, and the tested fix.
test("the review for coding agents gives evidence, sources, checks that run, and the tested fix", async () => {
  const out = runText(leaky, "--review");
  assert.match(out, /^# rls-probe review: grade F/);
  assert.match(out, /## \d\. HIGH `user-write:messages`/);
  assert.match(out, /What rls-probe saw: signed in as user B, who owns nothing of user A's, has no role and is in another organization, it could change user A's row in messages\./);
  assert.match(out, /Where: messages is created at 20250101000000_init\.sql:33; policy "auth write" \(update, to authenticated\) at 20250101000000_init\.sql:40\./);
  assert.match(out, /Tested fix \(afterwards, each signed-in user can change only their own rows in messages\):/);
  assert.match(out, /"accept": \[\{ "finding": "rls-off:orders"/);
  // Every check runs on the app's database, and leaves it as it was.
  const { loadDatabase } = await import("../src/load.js");
  const { findMigrations, readMigrations } = await import("../src/node.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const { db } = await loadDatabase(readMigrations(findMigrations(leaky)), { snapshot: await baseSnapshot() });
  const checks = [...out.matchAll(/```sql\n(begin;[\s\S]*?rollback;)\n```/g)].map((m) => m[1]).filter((sql) => !sql.includes("/*"));
  assert.ok(checks.length >= 4);
  for (const sql of checks) await db.exec(sql);
  await db.close();
});

// A key in a test file is usually made up for the test (a secret scanner's own tests are
// full of them). It's worth a look, not a critical problem.
test("keys in test files are worth a look, not critical", async () => {
  const { scanCode } = await import("../src/static.js");
  const key = ["sk", "proj", "A".repeat(40)].join("-");
  const found = scanCode([
    { path: "src/lib/__tests__/scan.test.ts", text: `const fake = "${key}";` },
    { path: "src/lib/openai.ts", text: `const real = "${key}";` },
  ]);
  assert.deepEqual(found.map((f) => [f.where, f.severity]), [["src/lib/__tests__/scan.test.ts:1", "review"], ["src/lib/openai.ts:1", "critical"]]);
});

// Every local Supabase prints the same keys (issuer supabase-demo, and one sb_secret_ key);
// example and test env files are full of them, and they open nothing real.
test("Supabase's public local development keys aren't reported as leaks", async () => {
  const { scanCode } = await import("../src/static.js");
  const jwt = (claims) => ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", Buffer.from(JSON.stringify(claims)).toString("base64url"), "c2lnbmF0dXJlLXNpZ25hdHVyZQ"].join(".");
  const found = scanCode([
    { path: ".env.example", text: `SUPABASE_SERVICE_ROLE_KEY=${jwt({ iss: "supabase-demo", role: "service_role", exp: 1983812996 })}\nSUPABASE_SECRET_KEY=${["sb", "secret", "N7UND0UgjKTVK-Uodkm0Hg", "xSvEMPvz"].join("_")}` },
    { path: "src/admin.ts", text: `const key = "${jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role" })}";` },
    { path: "e2e/lib/constants.ts", text: `const k = "${["sk", "proj", "B".repeat(40)].join("-")}";` },
  ]);
  assert.deepEqual(found.map((f) => [f.kind, f.where, f.severity]), [["service-key", "src/admin.ts:1", "critical"], ["secret", "e2e/lib/constants.ts:1", "review"]]);
});

// A function that checks its caller through a helper (private.require_user(),
// util.assert_company_access()) checks its caller; a bucket supabase/config.toml makes
// public is public; an edge function whose code isn't there can't be judged.
test("helpers that check the caller, buckets from config.toml, and missing function code", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-helpers-"));
  fs.mkdirSync(path.join(dir, "supabase", "migrations"), { recursive: true });
  fs.writeFileSync(path.join(dir, "supabase", "migrations", "20250101000000_app.sql"), `
create schema private;
create function private.require_user() returns uuid language plpgsql as $$
begin
  if auth.uid() is null then raise exception 'sign in first'; end if;
  return auth.uid();
end $$;
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create function public.archive_note(p_id uuid) returns void language plpgsql security definer as $$
declare v_user uuid := private.require_user();
begin
  update public.notes set body = null where id = p_id and user_id = v_user;
end $$;
revoke execute on function public.archive_note(uuid) from public, anon;
grant execute on function public.archive_note(uuid) to authenticated;
create policy "anyone reads avatars" on storage.objects for select using (bucket_id = 'avatars');
`);
  fs.writeFileSync(path.join(dir, "supabase", "config.toml"), `[storage.buckets.avatars]\npublic = true\n\n[functions.stripe-webhook]\nverify_jwt = false\n`);
  const { report } = run(dir);
  const ids = report.findings.map((f) => `${f.kind}:${f.where}`);
  assert.ok(!ids.some((id) => id.startsWith("definer-function:archive_note")), "checks its caller through private.require_user()");
  assert.ok(!ids.includes("storage-visitor-read:storage bucket avatars"), "avatars is public in config.toml, so reading it is what public means");
  assert.ok(ids.includes("public-bucket:storage bucket avatars"));
  const hook = report.findings.find((f) => f.kind === "open-function");
  assert.equal(hook.severity, "review");
  assert.ok(hook.missing);
  fs.rmSync(dir, { recursive: true, force: true });
});

// When each harmful fix is the only one touching the table where the harm shows, it's found
// from that one try, not by halving the set again and again (which ran out of time on an app
// with 400 tables).
test("fixes that each harm only their own table are found without trying them one by one", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { checkFixes } = await import("../src/fixes.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const owned = (t) => `create table public.${t} (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.${t} enable row level security;
create policy "own ${t}" on public.${t} for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());`;
  const open = (t) => `${owned(t)}\ncreate policy "anyone reads ${t}" on public.${t} for select to anon using (true);`;
  const bad = ["b1", "b2", "b3", "b4", "b5"];
  const good = ["g1", "g2", "g3"];
  const migrations = [{ name: "20250101000000_app.sql", sql: [...bad.map(owned), ...good.map(open)].join("\n") }];
  const report = await runProbe({ migrations, snapshot, keep: true });
  let trials = 0;
  const checked = await checkFixes({ migrations, report, snapshot, onTrial: () => trials++, fixes: [
    ...bad.map((t) => ({ kind: "user-read", where: t, sql: `create policy "nobody reads ${t}" on public.${t} as restrictive for select to authenticated using (false);` })),
    ...good.map((t) => ({ kind: "visitor-read", where: t, sql: `revoke select on public.${t} from anon;` })),
  ] });
  assert.deepEqual(Object.fromEntries(checked.map((f) => [f.where, f.verified])), { b1: false, b2: false, b3: false, b4: false, b5: false, g1: true, g2: true, g3: true });
  assert.ok(trials <= 2, `${trials} tries`);
});

// Revoking a function a trigger calls takes away the owner's own updates; the trigger points
// at it, so it's tried apart at once, not after halving the rest.
test("harm through a trigger is pinned on the fix that caused it", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { checkFixes } = await import("../src/fixes.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const open = (t) => `create table public.${t} (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.${t} enable row level security;
create policy "own ${t}" on public.${t} for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "anyone reads ${t}" on public.${t} for select to anon using (true);`;
  const migrations = [{ name: "20250101000000_app.sql", sql: `${["orders", "g1", "g2"].map(open).join("\n")}
create function public.approved(p uuid) returns boolean language sql security definer as $$ select true $$;
create function public.guard_orders() returns trigger language plpgsql as $$
begin
  if not approved(new.id) then raise exception 'needs approval'; end if;
  return new;
end $$;
create trigger guard before update on public.orders for each row execute function public.guard_orders();
` }];
  const report = await runProbe({ migrations, snapshot, keep: true });
  let trials = 0;
  const checked = await checkFixes({ migrations, report, snapshot, onTrial: () => trials++, fixes: [
    { kind: "definer-function", where: "approved(p uuid)", sql: "revoke execute on function public.approved(p uuid) from public, anon, authenticated;" },
    ...["g1", "g2"].map((t) => ({ kind: "visitor-read", where: t, sql: `revoke select on public.${t} from anon;` })),
  ] });
  assert.deepEqual(checked.map((f) => f.verified), [false, true, true]);
  assert.ok(trials <= 3, `${trials} tries`);
});

// Trying fixes doesn't call functions again, so a function that refused every call in the
// inspection (and so isn't a finding) mustn't count as a new problem in each try. An error
// about a column called last_login isn't a refusal, though: that function is just broken.
test("a function that refused its calls doesn't fail every fix, and a broken one isn't a refusal", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { verifyFixes } = await import("../src/fixes.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const migrations = [{ name: "20250101000000_app.sql", sql: `
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "anyone reads notes" on public.notes for select to anon using (true);
create function public.clear_notes(p_user uuid) returns void language plpgsql security definer as $$
begin
  if current_setting('app.maintenance', true) is distinct from 'on' then raise exception 'not allowed'; end if;
  update public.notes set body = null where user_id = p_user;
end $$;
-- Broken: notes has no last_login, so every call fails.
create function public.record_login(p_user uuid) returns void language plpgsql security definer as $$
begin
  update public.notes set last_login = now() where user_id = p_user;
end $$;
` }];
  const report = await runProbe({ migrations, snapshot, keep: true });
  const functions = report.findings.filter((f) => f.kind === "definer-function").map((f) => f.function);
  assert.deepEqual(functions, ["record_login"], "clear_notes refused every call; record_login only failed");
  const fixes = await verifyFixes({ migrations, report, snapshot });
  assert.ok(fixes.some((f) => f.where === "notes"));
  assert.deepEqual(fixes.filter((f) => !f.verified).map((f) => `${f.kind}:${f.where}`), []);
  assert.ok(fixes.some((f) => f.kind === "definer-function" && f.verified), "record_login's revoke passes too");
});

// A function that hands out a secret from Supabase Vault is caught by calling it: rls-probe
// puts a stand-in secret under each name the function reads, and looks for it in what comes
// back. One that turns callers away, and one that returns only the project's URL, aren't.
test("functions that hand out Vault secrets are caught by calling them", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-vault-"));
  fs.mkdirSync(path.join(dir, "supabase", "migrations"), { recursive: true });
  fs.writeFileSync(path.join(dir, "supabase", "migrations", "20250101000000_app.sql"), `
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create function public.webhook_secret() returns text language plpgsql security definer as $$
declare v text;
begin
  select decrypted_secret into v from vault.decrypted_secrets where name = 'webhook_secret';
  return v;
end $$;
create function public.read_secret(p_id uuid) returns text language plpgsql security definer as $$
begin
  if auth.role() is distinct from 'service_role' then raise exception 'authentication required'; end if;
  return (select decrypted_secret from vault.decrypted_secrets where id = p_id);
end $$;
create function public.project_url() returns text language plpgsql security definer as $$
declare v text;
begin
  select decrypted_secret into v from vault.decrypted_secrets where name = 'supabase_url';
  return v;
end $$;
`);
  const { report } = run(dir);
  const fn = (name) => report.findings.find((f) => f.kind === "definer-function" && f.function === name);
  const leak = fn("webhook_secret");
  assert.equal(leak.severity, "critical");
  assert.deepEqual(leak.secrets, ["webhook_secret"]);
  assert.match(explain(report).problems.find((i) => i.id === "definer-function:webhook_secret()").headline,
    /anyone on the internet can call the database function webhook_secret\(\) and get the secret "webhook_secret" from Supabase Vault/i);
  assert.equal(fn("read_secret"), undefined, "it turns every caller away");
  assert.equal(fn("project_url")?.severity ?? "review", "review", "the project's URL isn't a secret");
  fs.rmSync(dir, { recursive: true, force: true });
});

// pg_dump writes auth.uid() as "auth"."uid"(); a function that checks its caller that way
// still checks its caller.
test("a caller check written with quotes, as pg_dump writes it, counts", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const sql = `create table public.orders (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), total int);
alter table public.orders enable row level security;
create policy "own orders" on public.orders to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
CREATE FUNCTION "public"."close_account"() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET "search_path" TO '' AS $$
DECLARE v uuid;
BEGIN
  SELECT "auth"."uid"() INTO v;
  IF v IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  DELETE FROM "public"."orders" WHERE "user_id" = v;
END $$;
REVOKE ALL ON FUNCTION "public"."close_account"() FROM PUBLIC, anon;
GRANT ALL ON FUNCTION "public"."close_account"() TO "authenticated";
`;
  const report = await runProbe({ migrations: [{ name: "20250101000000_app.sql", sql }], snapshot });
  const f = report.findings.find((x) => x.kind === "definer-function");
  assert.equal(f?.severity ?? "review", "review");
});

// A pg_dump of a project ends with that project's default privileges, the whole list: one
// that took anon and authenticated out of the defaults for functions locks a function with
// "revoke ... from public" alone. The same lines in an ordinary migration only add a grant.
test("a pg_dump's default privileges replace the platform's", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const app = `CREATE TABLE "public"."orders" ("id" uuid DEFAULT gen_random_uuid() PRIMARY KEY, "user_id" uuid NOT NULL REFERENCES auth.users (id), "total" int);
ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own orders" ON "public"."orders" TO "authenticated" USING ("user_id" = auth.uid()) WITH CHECK ("user_id" = auth.uid());
CREATE FUNCTION "public"."wipe_orders"("p_user" uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN DELETE FROM public.orders WHERE user_id = p_user; END $$;
REVOKE ALL ON FUNCTION "public"."wipe_orders"("p_user" uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."wipe_orders"("p_user" uuid) TO "service_role";
GRANT ALL ON TABLE "public"."orders" TO "anon";
GRANT ALL ON TABLE "public"."orders" TO "authenticated";
GRANT ALL ON TABLE "public"."orders" TO "service_role";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";
`;
  const header = "SET statement_timeout = 0;\nSELECT pg_catalog.set_config('search_path', '', false);\nSET check_function_bodies = false;\n";
  const callable = async (sql) => (await runProbe({ migrations: [{ name: "20250101000000_app.sql", sql }], snapshot })).findings.some((f) => f.kind === "definer-function");
  assert.equal(await callable(header + app), false, "the dump's defaults leave anon out, so revoking from public locks it");
  assert.equal(await callable(app), true, "on Supabase's defaults, anon keeps its own grant");
});

// An edge function's check is often in shared code it imports (a key middleware in
// supabase/functions/_shared). A header named in a CORS list isn't a check.
test("edge functions that check keys in code they import aren't open", async () => {
  const { scanCode } = await import("../src/static.js");
  const found = scanCode([
    { path: "supabase/config.toml", text: "[functions.keys]\nverify_jwt = false\n\n[functions.open]\nverify_jwt = false\n" },
    { path: "supabase/functions/keys/index.ts", text: "import { app } from '../_shared/routes/keys.ts'\nDeno.serve(app.fetch)\n" },
    { path: "supabase/functions/_shared/routes/keys.ts", text: "import { requireKey } from '../middleware.ts'\nimport { cors } from '../cors.ts'\nexport const app = new Hono().use(cors).get('/', requireKey, (c) => c.json([]))\n" },
    { path: "supabase/functions/_shared/middleware.ts", text: "export const requireKey = async (c, next) => {\n  const key = c.req.header('capgkey') ?? c.req.header('authorization')\n  if (!(await valid(key))) return c.json({ error: 'invalid key' }, 401)\n  await next()\n}\n" },
    { path: "supabase/functions/_shared/cors.ts", text: "export const cors = { allowHeaders: ['authorization', 'apikey', 'content-type'] }\n" },
    { path: "supabase/functions/open/index.ts", text: "import { cors } from '../_shared/cors.ts'\nimport { createApp } from '../_shared/app.ts'\nDeno.serve(createApp(() => new Response('ok', { headers: cors })))\n" },
    // Every function's plumbing: it reads a key for something, but using it isn't a check.
    { path: "supabase/functions/_shared/app.ts", text: "export const createApp = (handler) => (req) => { log(req.headers.get('authorization') ? 'with key' : 'no key'); return handler(req) }\n" },
  ]);
  const sev = Object.fromEntries(found.filter((f) => f.kind === "open-function").map((f) => [f.function, f.severity]));
  assert.deepEqual(sev, { keys: "review", open: "high" });
});

// How sure a finding is decides how loud it is. A function anyone can call that rls-probe
// called, aimed at another user's rows, and saw do nothing is worth a look; one it couldn't
// call is medium, since nobody has checked it; one that did harm stays critical. Each
// finding says whether rls-probe tried it or read it in the code.
test("functions are as loud as what rls-probe saw them do, and every finding says how it knows", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const sql = `create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create table public.tags (id bigint generated always as identity primary key, name text);
create type public.span as (lo int, hi int);
create function public.touch_note(p_id uuid) returns void language plpgsql security definer as $$
begin
  update public.notes set body = body where id = p_id and false;
end $$;
create function public.wipe_notes(p_user uuid) returns void language plpgsql security definer as $$
begin
  delete from public.notes where user_id = p_user;
end $$;
create function public.resize(p_span public.span) returns void language plpgsql security definer as $$
begin
  update public.notes set body = null where length(body) between (p_span).lo and (p_span).hi;
end $$;
`;
  const report = await runProbe({ migrations: [{ name: "20250101000000_app.sql", sql }], snapshot, code: [{ path: "src/admin.ts", text: 'const key = "' + ["sb", "secret", "Q".repeat(40)].join("_") + '";' }] });
  const fn = (name) => report.findings.find((f) => f.kind === "definer-function" && f.function === name);
  assert.equal(fn("touch_note").severity, "review", "called on another user's row, it changed nothing");
  assert.equal(fn("wipe_notes").severity, "critical", "called as a visitor, it deleted another user's notes");
  assert.equal(fn("resize").severity, "medium", "it takes an argument rls-probe can't fill, so nobody has checked it");
  const how = Object.fromEntries(explain(report).problems.concat(explain(report).notes).map((i) => [i.id, i.evidence]));
  assert.equal(how["rls-off:tags"], "tried");
  assert.equal(how["definer-function:wipe_notes(p_user uuid)"], "tried");
  assert.equal(how["definer-function:resize(p_span span)"], "read");
  assert.equal(Object.entries(how).find(([id]) => id.startsWith("service-key"))?.[1], "read");
});

// Views lose the old default grants too. One that follows the tables' rules is as safe to
// grant as the tables under it; one that runs as its owner shows every row it selects, so
// it's safe only where those tables hide nothing from that role. The service key gets them all.
test("views get the grants the October 30 change takes away, and the unsafe ones are held back", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-views-"));
  fs.mkdirSync(path.join(dir, "supabase", "migrations"), { recursive: true });
  fs.writeFileSync(path.join(dir, "supabase", "migrations", "20250101000000_app.sql"), `
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create table public.categories (id bigint generated always as identity primary key, name text);
alter table public.categories enable row level security;
create policy "anyone reads categories" on public.categories for select using (true);
create view public.my_notes with (security_invoker = true) as select id, body from public.notes;
create view public.note_stats as select user_id, count(*) as n from public.notes group by user_id;
create view public.category_list as select name from public.categories;
`);
  const g = runWith(dir, "--oct30").grantsChange;
  const safe = g.breaks.flatMap((b) => b.grant);
  assert.ok(safe.includes("grant select on public.my_notes to authenticated;"), "it follows the notes policies");
  assert.ok(safe.includes("grant select on public.category_list to anon, authenticated;"), "categories hide nothing from anyone");
  const held = g.unsafe.find((u) => u.table === "note_stats");
  assert.match(held.problems.join(" "), /runs as its owner.*security_invoker/);
  const server = g.server.flatMap((s) => s.grant);
  for (const v of ["my_notes", "note_stats", "category_list"]) assert.ok(server.includes(`grant select, insert, update, delete on public.${v} to service_role;`), v);
  assert.match(renderGrants(g), /^2 tables and 3 views get their API access only from Supabase's old default grants/m);
  fs.rmSync(dir, { recursive: true, force: true });
});

// What a key looks like isn't a key: another service's sk- key, a placeholder, code that
// strips a PEM header, an example env file. A real OpenAI key and a real private key are.
test("look-alike keys aren't reported; real ones are", async () => {
  const { scanCode } = await import("../src/static.js");
  const real = ["sk", "proj", "C".repeat(40)].join("-");
  const pem = ["-----BEGIN", "PRIVATE", "KEY-----"].join(" ");
  const found = scanCode([
    { path: "src/keys.ts", text: [
      `const helicone = "${["sk", "helicone", "D".repeat(40)].join("-")}";`,
      `<input placeholder="${["sk", "or", "v1", "E".repeat(40)].join("-")}" />`,
      `const clean = key.replace(/${pem}/g, "");`,
      `const openai = "${real}";`,
      `const pem = "${pem}\\n${"F".repeat(64)}";`,
    ].join("\n") },
    { path: ".env.example", text: `OPENAI_API_KEY=${real}` },
  ]);
  assert.deepEqual(found.map((f) => [f.title, f.where, f.severity]), [
    ["OpenAI API key", "src/keys.ts:4", "critical"],
    ["private key", "src/keys.ts:5", "critical"],
    ["OpenAI API key", ".env.example:1", "review"],
  ]);
});

// A waitlist has no owners and holds emails: the fix closes it to everyone but server code,
// not "everyone reads", and its test doesn't count that as anyone losing access.
test("a table without owners that holds private columns is fixed to server-only", async () => {
  const { runProbe } = await import("../src/engine.js");
  const { verifyFixes } = await import("../src/fixes.js");
  const { baseSnapshot } = await import("../src/snapshot.js");
  const snapshot = await baseSnapshot();
  const migrations = [{ name: "20250101000000_waitlist.sql", sql: "create table public.waitlist (id bigint generated always as identity primary key, email text not null, created_at timestamptz default now());" }];
  const report = await runProbe({ migrations, snapshot, keep: true });
  const [fix] = await verifyFixes({ migrations, report, snapshot });
  assert.equal(fix.sql, 'alter table public."waitlist" enable row level security;');
  assert.ok(fix.verified);
  report.fixes = [fix];
  assert.match(explain(report).problems[0].ask, /only server code using the service role can reach it.*never one that lets them read email/);
});

// What a finding was meant to be, read from the app's own code and migrations: only the
// service role or plain SQL reaches it (so nobody else needed access), the app keeps to
// users' own rows, a policy and comment say anyone may send a message, a public feed reads
// every post (can't tell).
test("the app's code and migrations say what each finding was meant to be", () => {
  const { report } = run(fileURLToPath(new URL("./fixtures/intent", import.meta.url)));
  const said = Object.fromEntries(report.findings.map((f) => [`${f.kind}:${f.where}`, [f.severity, f.intent?.verdict, f.intent?.reasons[0]]]));
  assert.deepEqual(said["rls-off:waitlist"].slice(0, 2), ["critical", "mistake"]);
  assert.match(said["rls-off:waitlist"][2], /only with the service role \(supabase\/functions\/join\/index\.ts:5\)/);
  assert.deepEqual(said["rls-off:legacy_stats"].slice(0, 2), ["critical", "mistake"]);
  assert.match(said["rls-off:legacy_stats"][2], /plain SQL from server code \(server\/stats\.ts:3\)/);
  assert.deepEqual(said["user-read:notes"].slice(0, 2), ["high", "mistake"], "the app treats notes as each user's own, so reading others' is a leak");
  assert.deepEqual(said["visitor-write:contact_messages"].slice(0, 2), ["review", "on purpose"]);
  assert.match(said["visitor-write:contact_messages"][2], /"Anyone can submit"/);
  assert.equal(said["impersonation:contact_messages"][1], "unclear", "anyone may send a message, but not in someone else's name");
  assert.deepEqual(said["user-read:posts"].slice(0, 2), ["review", "unclear"]);
  // Without the app's code (a pasted schema), only what the migrations say counts.
  const schema = run(path.join(fileURLToPath(new URL("./fixtures/intent", import.meta.url)), "supabase", "migrations", "20250101000000_app.sql")).report;
  assert.ok(schema.findings.filter((f) => f.where !== "contact_messages").every((f) => !f.intent));
});

// Step 2: rls-probe.json declares who may see, add and change rows in each table. rls-probe
// drafts it from the app's code, asks only what the code can't tell, and then checks the
// database against it.
// A function the app calls runs as the caller unless it's security definer, so the tables
// it reads are read by the app's visitors and users: reading them isn't "not needed".
test("tables read through a function the app calls count as used by the app", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-via-"));
  fs.cpSync(fileURLToPath(new URL("./fixtures/intent", import.meta.url)), dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "supabase/migrations/20250103000000_scores.sql"), `create table public.scores (id bigint generated always as identity primary key, player text not null, points int not null);
create function public.top_scores() returns setof public.scores language sql stable as $$ select * from public.scores order by points desc limit 10 $$;
create table public.ledger (id bigint generated always as identity primary key, amount int not null);
create function public.ledger_total() returns bigint language sql stable security definer as $$ select sum(amount) from public.ledger $$;
`);
  fs.writeFileSync(path.join(dir, "src/pages/Scores.tsx"), `import { supabase } from "../lib/supabase";
export async function load() {
  const top = await supabase.rpc("top_scores");
  const total = await supabase.rpc("ledger_total");
  return { top, total };
}
`);
  const { report } = run(dir);
  const scores = report.findings.find((f) => f.kind === "rls-off" && f.where === "scores");
  assert.equal(scores.intent.verdict, "unclear");
  assert.match(scores.intent.reasons[0], /through top_scores\(\) \(src\/pages\/Scores\.tsx:3\), which runs as the caller/);
  const ledger = report.findings.find((f) => f.kind === "rls-off" && f.where === "ledger");
  assert.equal(ledger.intent.verdict, "mistake", "ledger_total() runs as its owner, so callers never needed the table");
  fs.rmSync(dir, { recursive: true, force: true });
});

// A setting with a name that doesn't say which key it holds (SUPABASE_KEY) is the service role
// when the example env file says so, and so is code that gets its client from such a module.
test("a key setting the example env file calls the service role key counts as one", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-envkey-"));
  fs.cpSync(fileURLToPath(new URL("./fixtures/intent", import.meta.url)), dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "supabase/migrations/20250104000000_audit.sql"), "create table public.audit_entries (id bigint generated always as identity primary key, action text not null);\n");
  fs.mkdirSync(path.join(dir, "backend/src/infra"), { recursive: true });
  fs.writeFileSync(path.join(dir, "backend/.env.example"), 'SUPABASE_URL="http://localhost:54321"\nSUPABASE_KEY="<supabase-service-role-key>"\n');
  fs.writeFileSync(path.join(dir, "backend/src/infra/client.py"), 'import os\nfrom supabase import create_client\n\nclient = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])\n');
  fs.writeFileSync(path.join(dir, "backend/src/audit.py"), 'from src.infra.client import client\n\n\ndef recent():\n    return client.table("audit_entries").select("action").execute()\n');
  const { report } = run(dir);
  const audit = report.findings.find((f) => f.kind === "rls-off" && f.where === "audit_entries");
  assert.equal(audit.intent.verdict, "mistake");
  assert.match(audit.intent.reasons[0], /only with the service role \(backend\/src\/audit\.py:5\)/);
  const posts = report.findings.find((f) => f.where === "posts" && f.intent);
  assert.equal(posts.intent.verdict, "unclear", "the front end's public key is still the public key");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("--draft-access answers what the code shows and asks the rest, keeping existing answers", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-draft-"));
  fs.cpSync(fileURLToPath(new URL("./fixtures/intent", import.meta.url)), dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "rls-probe.json"), JSON.stringify({ accept: [{ finding: "x:y", reason: "kept" }], access: { posts: { read: "everyone" } } }));
  // A shared table no code uses, which any signed-in user may read and change: only the
  // change is a finding, so only the change is drafted as server-only.
  fs.writeFileSync(path.join(dir, "supabase/migrations/20250102000000_labels.sql"), `create table public.labels (id bigint generated always as identity primary key, name text not null);
alter table public.labels enable row level security;
create policy "read labels" on public.labels for select to authenticated using (true);
create policy "edit labels" on public.labels for update to authenticated using (true);
insert into public.labels (name) values ('a'), ('b');
`);
  // Written in place: `> rls-probe.json` would empty the file before it was read.
  const out = execFileSync("node", [cli, dir, "--draft-access"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  assert.match(out, /Wrote \S*rls-probe\.json: 6 tables, 0 questions for you\./);
  const draft = JSON.parse(fs.readFileSync(path.join(dir, "rls-probe.json"), "utf8"));
  assert.deepEqual(draft.accept, [{ finding: "x:y", reason: "kept" }], "the rest of the file stays");
  assert.deepEqual(draft.access.waitlist, { read: "server", add: "server", change: "server" }, "only the service role reaches it");
  assert.deepEqual(draft.access.legacy_stats, { read: "server", add: "server", change: "server" }, "only plain SQL from the server reaches it");
  assert.equal(draft.access.notes.read, "owner", "the app only reads users' own notes");
  assert.equal(draft.access.contact_messages.add, "everyone", "the policy says anyone can submit");
  assert.equal(draft.access.posts.read, "everyone", "an answer already given stays as it is");
  assert.ok(draft.access.posts.add && draft.access.posts.change, "and the rest of that table is drafted around it");
  assert.deepEqual(draft.access.labels, { read: "signed-in", add: "server", change: "server" }, "a draft never says less than the database allows where nothing was found");
  // Checked against the file, only the answer given adds a finding (posts are read by signed-in
  // users only, not everyone); nothing drafted does.
  assert.deepEqual(run(dir).report.findings.filter((f) => f.kind.startsWith("access-")).map((f) => `${f.kind} ${f.where} ${f.verb}`), ["access-too-closed posts read"]);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("declared access: what matches is accepted, what allows more stays a problem, what allows less is flagged", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-access-"));
  fs.cpSync(fileURLToPath(new URL("./fixtures/intent", import.meta.url)), dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "rls-probe.json"), JSON.stringify({ access: {
    posts: { read: "signed-in", add: "signed-in" },
    notes: { read: "owner", add: "owner" },
    contact_messages: { add: "everyone" },
    legacy_stats: { read: "server", add: "server", change: "server" },
    waitlist: { read: "nobody", change: "? who" },
  } }));
  const { report } = run(dir);
  const ids = (list) => list.map((f) => `${f.kind}:${f.where}`);
  assert.ok(ids(report.accepted).includes("user-read:posts"), "signed-in users reading posts is what was declared");
  assert.ok(ids(report.accepted).includes("visitor-write:contact_messages"));
  assert.match(report.accepted.find((f) => f.where === "posts").reason, /any signed-in user may see rows in posts/);
  const notes = report.findings.find((f) => f.kind === "user-read" && f.where === "notes");
  assert.match(notes.intent.reasons[0], /rls-probe\.json says only the row's owner may see rows in notes/);
  const stats = report.findings.find((f) => f.where === "legacy_stats");
  assert.match(stats.intent.reasons[0], /only your server code may see, add, change or delete rows in legacy_stats/);
  // Adding means adding one's own rows, so "owner" there is the same as any signed-in user.
  assert.ok(!report.findings.some((f) => f.kind === "access-too-open" && f.where === "notes"), "owners adding their own notes is what was declared");
  const closed = report.findings.find((f) => f.kind === "access-too-closed");
  assert.deepEqual([closed.where, closed.verb, closed.declared, closed.observed, closed.severity], ["posts", "add", "signed-in", "server", "review"]);
  assert.ok(report.access.problems.some((p) => /waitlist" read is "nobody"/.test(p)), "a level that doesn't exist is pointed out");
  assert.ok(report.access.problems.some((p) => /1 question to answer \(waitlist \(change\)\)/.test(p)));
  assert.match(runText(dir), /rls-probe\.json declares \d+ rules for 4 tables: \d+ match, \d+ allows? more than declared, 1 allows less/);
  fs.rmSync(dir, { recursive: true, force: true });
});
