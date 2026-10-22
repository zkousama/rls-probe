// Checks rls-probe's grant suggestions against a real local Supabase opted into the
// 2026 grants change. Run `supabase start` in a folder holding test/fixtures/new-grants/supabase
// (its first migration opts in), then: node scripts/compare-grants-with-supabase.mjs <folder> <grants.sql> [project_id]
// where grants.sql holds the "Safe to grant" lines from `rls-probe test/fixtures/new-grants --oct30`.
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
    headers: { apikey: ANON, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

const users = {};
for (const key of ["A", "B"]) {
  const email = `${key.toLowerCase()}-${Date.now()}@example.com`;
  const res = await fetch(`${URL_}/auth/v1/admin/users`, { method: "POST", headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, "Content-Type": "application/json" }, body: JSON.stringify({ email, password: "password123!", email_confirm: true, user_metadata: { full_name: `User ${key}` } }) });
  const created = await res.json();
  const login = await call("POST", "/auth/v1/token?grant_type=password", ANON, { email, password: "password123!" });
  users[key] = { id: created.id, token: login.data.access_token };
}
const A = users.A.token, B = users.B.token;
const checks = [];
const check = (name, ok, detail = "") => checks.push({ name, ok, detail });
const denied = (r) => r.status >= 400 && JSON.stringify(r.data).includes("42501");

// 1. Before any grant: the new defaults make every table refuse.
for (const t of ["categories", "messages", "notes", "orders", "profiles", "tags"]) {
  const r = await call("GET", `/rest/v1/${t}?select=*`, A);
  check(`before grants: signed-in user gets 42501 on ${t}`, denied(r), `${r.status}`);
}
const anonCat = await call("GET", "/rest/v1/categories?select=*", ANON);
check("before grants: visitor gets 42501 on categories", denied(anonCat), `${anonCat.status}`);

// 2. Apply exactly what rls-probe suggested, and seed a category (nobody may insert those).
db(fs.readFileSync(grantsFile, "utf8"));
db("insert into public.categories (name) values ('football'), ('basketball');");

// 3. The app works for its own users.
const own = {
  notes: { owner_id: users.A.id, body: "A's note" },
  orders: { user_id: users.A.id, total: 10 },
  messages: { sender_id: users.A.id, body: "A's message" },
  tags: { owner_id: users.A.id, name: "A's tag" },
};
const ids = {};
for (const [t, row] of Object.entries(own)) {
  const r = await call("POST", `/rest/v1/${t}`, A, row, "return=representation");
  check(`after grants: A creates their own ${t} row`, r.status === 201, `${r.status} ${r.status === 201 ? "" : JSON.stringify(r.data)}`);
  ids[t] = r.data?.[0]?.id;
}
for (const t of ["notes", "orders", "messages", "tags"]) {
  const r = await call("GET", `/rest/v1/${t}?select=*`, A);
  check(`after grants: A reads their own ${t}`, Array.isArray(r.data) && r.data.length === 1, `${r.data?.length ?? r.status}`);
}
const profA = await call("GET", `/rest/v1/profiles?select=*&id=eq.${users.A.id}`, A);
check("after grants: A reads their own profile", Array.isArray(profA.data) && profA.data.length === 1, `${profA.data?.length ?? profA.status}`);
const updA = await call("PATCH", `/rest/v1/notes?id=eq.${ids.notes}`, A, { body: "edited" }, "return=representation");
check("after grants: A edits their own note", Array.isArray(updA.data) && updA.data.length === 1);
const cats = await call("GET", "/rest/v1/categories?select=*", ANON);
check("after grants: a visitor reads categories", Array.isArray(cats.data) && cats.data.length === 2, `${cats.data?.length ?? cats.status}`);

// 4. Nothing leaks.
for (const t of ["notes", "orders", "messages", "tags"]) {
  const r = await call("GET", `/rest/v1/${t}?select=*`, B);
  check(`after grants: B sees none of A's ${t}`, Array.isArray(r.data) && r.data.length === 0, `${r.data?.length ?? r.status}`);
  const v = await call("GET", `/rest/v1/${t}?select=*`, ANON);
  check(`after grants: a visitor can't read ${t}`, denied(v) || (Array.isArray(v.data) && v.data.length === 0), `${v.status}`);
}
const profB = await call("GET", `/rest/v1/profiles?select=*&id=eq.${users.A.id}`, B);
check("after grants: B can't read A's profile", Array.isArray(profB.data) && profB.data.length === 0, `${profB.data?.length ?? profB.status}`);
const updB = await call("PATCH", `/rest/v1/notes?id=eq.${ids.notes}`, B, { body: "hijacked" }, "return=representation");
check("after grants: B can't edit A's note", Array.isArray(updB.data) && updB.data.length === 0);
const delB = await call("DELETE", `/rest/v1/orders?id=eq.${ids.orders}`, B, null, "return=representation");
check("after grants: B can't delete A's order", Array.isArray(delB.data) && delB.data.length === 0);
const catW = await call("POST", "/rest/v1/categories", A, { name: "hacked" });
check("after grants: a user can't add categories", catW.status >= 400, `${catW.status}`);

for (const c of checks) console.log(`${c.ok ? "pass" : "FAIL"}  ${c.name}${c.ok ? "" : `  (${c.detail})`}`);
console.log(`\n${checks.filter((c) => c.ok).length} of ${checks.length} passed`);
