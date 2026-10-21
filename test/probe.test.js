import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
