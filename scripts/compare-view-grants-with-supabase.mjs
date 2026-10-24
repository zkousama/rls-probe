// Checks rls-probe's view grants against a real local Supabase opted into the 2026 grants
// change. In a folder holding test/fixtures/new-grants/supabase, add test/fixtures/view-grants.sql
// as one more migration, run `supabase start`, then:
//   node scripts/compare-view-grants-with-supabase.mjs <folder> <grants.sql> [project_id]
// where grants.sql holds the "Safe to grant" and "Your server too" lines rls-probe --oct30
// prints for that folder. order_totals and my_order_totals (a view on it) follow the tables'
// rules; all_order_totals runs as its owner, so rls-probe holds it back.
import { execFileSync, execSync } from "node:child_process";
import fs from "node:fs";

const [dir, grantsFile] = process.argv.slice(2);
const status = JSON.parse(execSync("npx -y supabase@2.121.0 status -o json", { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
const URL_ = status.API_URL;
const ANON = status.ANON_KEY;
const SERVICE = status.SERVICE_ROLE_KEY;
const db = (sql) => execFileSync("docker", ["exec", "-i", `supabase_db_${process.argv[4] ?? "rlsgrants"}`, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q", "-t", "-A"], { input: sql, encoding: "utf8" }).trim();

async function call(method, path, token, body, prefer) {
  const res = await fetch(`${URL_}${path}`, {
    method,
    headers: { apikey: token === SERVICE ? SERVICE : ANON, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

const users = {};
for (const key of ["A", "B"]) {
  const email = `${key.toLowerCase()}-views-${Date.now()}@example.com`;
  const res = await fetch(`${URL_}/auth/v1/admin/users`, { method: "POST", headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, "Content-Type": "application/json" }, body: JSON.stringify({ email, password: "password123!", email_confirm: true }) });
  const created = await res.json();
  const login = await call("POST", "/auth/v1/token?grant_type=password", ANON, { email, password: "password123!" });
  users[key] = { id: created.id, token: login.data.access_token };
}
const A = users.A.token, B = users.B.token;
const checks = [];
const check = (name, ok, detail = "") => checks.push({ name, ok, detail });
const denied = (r) => r.status >= 400 && JSON.stringify(r.data).includes("42501");
const rows = (r) => (Array.isArray(r.data) ? r.data : null);

// 1. Before any grant, the views refuse users and the service key alike.
for (const v of ["order_totals", "my_order_totals", "all_order_totals"]) {
  const r = await call("GET", `/rest/v1/${v}?select=*`, A);
  check(`before grants: signed-in user gets 42501 on ${v}`, denied(r), `${r.status}`);
  const s = await call("GET", `/rest/v1/${v}?select=*`, SERVICE);
  check(`before grants: the service key gets 42501 on ${v}`, denied(s), `${s.status}`);
}

// 2. Apply exactly what rls-probe suggested; each user adds an order.
db(fs.readFileSync(grantsFile, "utf8"));
for (const [key, token] of [["A", A], ["B", B]]) {
  const r = await call("POST", "/rest/v1/orders", token, { user_id: users[key].id, total: key === "A" ? 10 : 20 }, "return=representation");
  check(`after grants: ${key} adds their own order`, r.status === 201, `${r.status} ${r.status === 201 ? "" : JSON.stringify(r.data)}`);
}

// 3. Views that follow the tables' rules show each user only their own rows.
for (const v of ["order_totals", "my_order_totals"]) {
  const a = rows(await call("GET", `/rest/v1/${v}?select=*`, A));
  check(`after grants: A reads ${v} and sees only their own total`, a?.length === 1 && a[0].user_id === users.A.id, JSON.stringify(a));
  const b = rows(await call("GET", `/rest/v1/${v}?select=*`, B));
  check(`after grants: B reads ${v} and sees none of A's`, b !== null && !b.some((x) => x.user_id === users.A.id), JSON.stringify(b));
  const visitor = await call("GET", `/rest/v1/${v}?select=*`, ANON);
  check(`after grants: a visitor reads nothing from ${v}`, denied(visitor) || rows(visitor)?.length === 0, `${visitor.status}`);
}

// 4. The view rls-probe held back stays closed to users; the service key reads every view.
const held = await call("GET", "/rest/v1/all_order_totals?select=*", A);
check("after grants: all_order_totals (held back) still refuses users", denied(held), `${held.status}`);
for (const v of ["order_totals", "my_order_totals", "all_order_totals"]) {
  const s = rows(await call("GET", `/rest/v1/${v}?select=*`, SERVICE));
  check(`after grants: the service key reads both users' rows in ${v}`, s?.length === 2, JSON.stringify(s));
}

for (const c of checks) console.log(`${c.ok ? "pass" : "FAIL"}  ${c.name}${c.ok ? "" : `  (${c.detail})`}`);
console.log(`\n${checks.filter((c) => c.ok).length} of ${checks.length} passed`);
process.exit(checks.every((c) => c.ok) ? 0 : 1);
