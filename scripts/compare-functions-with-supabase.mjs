// Checks rls-probe's function calls against a real local Supabase. Run `supabase start` in a
// folder holding the migrations of test/fixtures/leaky, or of test/fixtures/functions, then:
//   node scripts/compare-functions-with-supabase.mjs <that folder>
// It signs up two real users, gives the first one rows, calls each security definer function
// the probe called, over the REST API (/rest/v1/rpc) as a visitor and as the second user, aimed
// at the first user's rows, and compares what happened to them with what the probe reported.
import { execFileSync, execSync } from "node:child_process";

const V = process.argv[2];
const status = JSON.parse(execSync("npx -y supabase@2.121.0 status -o json", { cwd: V, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
const URL_ = status.API_URL;
const ANON = status.ANON_KEY ?? status.PUBLISHABLE_KEY;
const SERVICE = status.SERVICE_ROLE_KEY ?? status.SECRET_KEY;

async function call(method, path, { token = ANON, apikey = ANON, body, prefer } = {}) {
  const res = await fetch(`${URL_}${path}`, {
    method,
    headers: { apikey, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}
const svc = (method, path, opts = {}) => call(method, path, { ...opts, token: SERVICE, apikey: SERVICE });
const tables = new Set(Object.keys((await svc("GET", "/rest/v1/")).data?.definitions ?? {}));

const users = {};
for (const key of ["A", "B"]) {
  const email = `${key.toLowerCase()}-${Date.now()}@example.com`;
  const created = await svc("POST", "/auth/v1/admin/users", { body: { email, password: "password123!", email_confirm: true, user_metadata: { full_name: `User ${key}` } } });
  if (created.status >= 300) throw new Error(`create user ${key}: ${JSON.stringify(created.data)}`);
  const login = await call("POST", "/auth/v1/token?grant_type=password", { body: { email, password: "password123!" } });
  users[key] = { id: created.data.id, email, token: login.data.access_token };
}

// The first user's rows, which each call is aimed at, and how to read them back.
const rows = {};
const one = async (table, body) => {
  const res = await svc("POST", `/rest/v1/${table}`, { body, prefer: "return=representation,resolution=merge-duplicates" });
  if (res.status >= 300) throw new Error(`seed ${table}: ${JSON.stringify(res.data)}`);
  return res.data[0];
};
if (tables.has("orders")) rows.orders = await one("orders", { user_id: users.A.id, total: 10 });
if (tables.has("projects")) {
  await one("profiles", { id: users.A.id, email: users.A.email, display_name: "User A" });
  await one("profiles", { id: users.B.id, email: users.B.email, display_name: "User B" });
  rows.projects = await one("projects", { owner_id: users.A.id, name: "A's project" });
}

// The arguments the probe used, in the real database's ids.
const CASES = {
  delete_order: { table: "orders", args: () => ({ order_id: rows.orders.id }) },
  rename_project: { table: "projects", args: () => ({ project_id: rows.projects.id, new_name: "rls-probe" }) },
  bump_views: { table: "projects", args: () => ({ project_id: rows.projects.id }) },
  delete_my_project: { table: "projects", args: () => ({ project_id: rows.projects.id }) },
  get_profile: { table: "profiles", args: () => ({ uid: users.A.id }) },
};

const probe = JSON.parse((() => {
  try { return execFileSync("node", [new URL("../src/cli.js", import.meta.url).pathname, V, "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }); }
  catch (e) { return e.stdout; }
})());

let checks = 0;
let mismatches = 0;
console.log("function           who   rest-api                     rls-probe");
for (const f of probe.functions.filter((x) => CASES[x.name])) {
  const c = CASES[f.name];
  for (const who of ["anon", "B"]) {
    const row = rows[c.table];
    const before = row ? (await svc("GET", `/rest/v1/${c.table}?id=eq.${row.id}&select=*`)).data[0] : null;
    const res = await call("POST", `/rest/v1/rpc/${f.name}`, { token: who === "anon" ? ANON : users.B.token, body: c.args() });
    const ok = res.status < 300;
    const after = row ? (await svc("GET", `/rest/v1/${c.table}?id=eq.${row.id}&select=*`)).data[0] : null;
    const how = !before ? null : !after ? "deleted" : JSON.stringify(after) !== JSON.stringify(before) ? "changed" : null;
    const columns = how === "changed" ? Object.keys(before).filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k])) : [];
    const returned = ok && JSON.stringify(res.data ?? "").includes(users.A.email);
    // Put the row back for the next call.
    if (how === "deleted") Object.assign(row, await one(c.table, before));
    if (how === "changed") await svc("PATCH", `/rest/v1/${c.table}?id=eq.${row.id}`, { body: before });
    const real = { ok, how, columns, returned };
    // The probe doesn't call a function a role can't run: that's a refusal.
    const p = f.calls?.[who];
    const offline = p ? { ok: p.ok, how: p.changed.find((x) => x.table === c.table)?.how ?? null, columns: p.changed.find((x) => x.table === c.table)?.columns ?? [], returned: p.returned } : { ok: false, how: null, columns: [], returned: false };
    const same = real.ok === offline.ok && real.how === offline.how && real.returned === offline.returned
      && JSON.stringify(real.columns.filter((k) => k !== "updated_at").sort()) === JSON.stringify(offline.columns.filter((k) => k !== "updated_at").sort());
    checks++;
    if (!same) mismatches++;
    const show = (x) => `${x.ok ? "ran" : "refused"}${x.how ? `, ${x.how}${x.columns.length ? ` (${x.columns.join(", ")})` : ""}` : ""}${x.returned ? ", returned A's email" : ""}`;
    console.log(`${f.name.padEnd(18)} ${who.padEnd(5)} ${show(real).padEnd(28)} ${show(offline)}${same ? "" : "   <-- differs"}`);
  }
}
console.log(`\n${checks} checks, ${mismatches} differences`);
