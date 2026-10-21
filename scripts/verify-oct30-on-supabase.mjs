// Checks rls-probe's --oct30 suggestions for any app on a real local Supabase opted into
// the 2026 grants change. Put the opt-in migration from test/fixtures/new-grants first in the
// app's supabase/migrations, run `supabase start` there, then:
//   rls-probe <app> --oct30 --json > report.json   (on the migrations without the opt-in)
//   node scripts/verify-oct30-on-supabase.mjs <supabase folder> report.json <grants.sql>
// grants.sql holds the "Safe to grant" lines. It checks the API refuses before and answers
// after, and runs the probe against the real database to show the grants open nothing new.
import { execSync } from "node:child_process";
import fs from "node:fs";
import pg from "pg";
import { findingsFrom } from "../src/report.js";
import { probeTables } from "../src/probe.js";
import { readSchema } from "../src/schema.js";
import { USERS, seed } from "../src/seed.js";

const [sbDir, reportFile, grantsFile] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportFile, "utf8"));
const safe = report.grantsChange.breaks.map((b) => b.table);
const fixFirst = report.grantsChange.unsafe.map((u) => u.table);
const status = JSON.parse(execSync("npx -y supabase@latest status -o json", { cwd: sbDir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
const checks = [];
const check = (name, ok, detail = "") => checks.push({ name, ok, detail });

// A real signed-in user, through the real API.
const email = `verify-${Date.now()}@example.com`;
const admin = { apikey: status.SERVICE_ROLE_KEY, Authorization: `Bearer ${status.SERVICE_ROLE_KEY}`, "Content-Type": "application/json" };
await fetch(`${status.API_URL}/auth/v1/admin/users`, { method: "POST", headers: admin, body: JSON.stringify({ email, password: "password123!", email_confirm: true }) });
const login = await (await fetch(`${status.API_URL}/auth/v1/token?grant_type=password`, { method: "POST", headers: { apikey: status.ANON_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ email, password: "password123!" }) })).json();
const get = async (table) => {
  const res = await fetch(`${status.API_URL}/rest/v1/${table}?select=*&limit=1`, { headers: { apikey: status.ANON_KEY, Authorization: `Bearer ${login.access_token}` } });
  return { status: res.status, body: await res.text() };
};

// 1. Before: every table refuses with 42501.
for (const t of [...safe, ...fixFirst]) {
  const r = await get(t);
  check(`before: ${t} refuses (42501)`, r.body.includes("42501"), `${r.status}`);
}

// 2. Apply only the suggested grants.
const client = new pg.Client({ connectionString: status.DB_URL });
await client.connect();
await client.query(fs.readFileSync(grantsFile, "utf8"));

// 3. After: safe tables answer, fix-first tables still refuse.
for (const t of safe) {
  const r = await get(t);
  check(`after: ${t} answers`, r.status === 200, `${r.status} ${r.status === 200 ? "" : r.body.slice(0, 120)}`);
}
for (const t of fixFirst) {
  const r = await get(t);
  check(`after: ${t} still refuses (not granted)`, r.body.includes("42501"), `${r.status}`);
}

// 4. rls-probe's probe, against the real database. The adapter gives pg the
// two calls the probe uses.
const db = {
  query: async (sql, params) => { const r = await client.query(sql, params); return { rows: r.rows, affectedRows: r.rowCount }; },
  exec: async (sql) => { await client.query(sql); },
};
const tables = await readSchema(db);
const { known, problems } = await seed(db, tables);
for (const p of problems) check(`seed ${p.table}`, false, p.error);
const real = await probeTables(db, tables, known);
const legacy = Object.fromEntries(report.results.map((r) => [r.table, r]));
const fields = ["update", "delete", "insert"];
for (const t of safe) {
  const r = real.find((x) => x.table === t);
  if (!r?.anon) { check(`probe ${t}`, false, r?.skipped ?? "missing"); continue; }
  const extra = [];
  for (const who of ["anon", "B"]) {
    if (r[who].read > 0 && !(legacy[t]?.[who]?.read > 0)) extra.push(`${who} read`);
    for (const f of fields) if (r[who][f] && !legacy[t]?.[who]?.[f]) extra.push(`${who} ${f}`);
  }
  check(`real probe: ${t} allows nothing the rules didn't already allow`, extra.length === 0, extra.join(", "));
}
// The app keeps working: everything user A could do to their own rows with the old
// default grants, they can still do with only the suggested ones.
for (const t of safe) {
  const r = real.find((x) => x.table === t);
  const before = legacy[t]?.A;
  if (!r?.A || !before) continue;
  const lost = ["read", ...fields].filter((f) => (f === "read" ? before.read > 0 && !(r.A.read > 0) : before[f] && !r.A[f]));
  check(`real: user A can still do everything the rules allow on their own ${t} rows`, lost.length === 0, `refused: ${lost.join(", ")}`);
}
const serious = findingsFrom(real.filter((r) => safe.includes(r.table)), [], [], []).filter((f) => f.severity !== "review");
check("real probe: no critical, high or medium finding on the granted tables", serious.length === 0, serious.map((f) => `${f.where}: ${f.title}`).join("; "));

// 5. Each user still reaches their own rows where the rules let them read.
for (const t of safe) {
  const owned = known.get(t)?.some((x) => x.owner === "A");
  if (!owned) continue;
  await client.query("begin");
  await client.query("select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true)", [JSON.stringify({ sub: USERS.A.id, role: "authenticated" }), USERS.A.id]);
  await client.query("set local role authenticated");
  let n = 0, error = "";
  try { n = (await client.query(`select count(*)::int as n from public."${t}"`)).rows[0].n; } catch (e) { error = e.message; }
  await client.query("rollback");
  check(`real: user A can query ${t} without permission errors`, !error, error);
  if (!error && n === 0) checks.push({ name: `note: A sees 0 rows of ${t} (the rules hide even their own, or the seed has none they may see)`, ok: true });
}
await client.end();

for (const c of checks) console.log(`${c.ok ? "pass" : "FAIL"}  ${c.name}${c.ok || !c.detail ? "" : `  (${c.detail})`}`);
const real_ = checks.filter((c) => !c.name.startsWith("note:"));
console.log(`\n${real_.filter((c) => c.ok).length} of ${real_.length} passed`);
