// Checks rls-probe against a real local Supabase. Run `supabase start` in a folder
// holding test/fixtures/leaky/supabase, then: node scripts/compare-with-supabase.mjs <that folder>
// It signs up two real users, repeats every probe over the REST API, and prints where the two disagree.
import { execSync, execFileSync } from "node:child_process";

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

const users = {};
for (const key of ["A", "B"]) {
  const email = `${key.toLowerCase()}-${Date.now()}@example.com`;
  const created = await svc("POST", "/auth/v1/admin/users", { body: { email, password: "password123!", email_confirm: true, user_metadata: { full_name: `User ${key}` } } });
  if (created.status >= 300) throw new Error(`create user ${key}: ${JSON.stringify(created.data)}`);
  const login = await call("POST", "/auth/v1/token?grant_type=password", { body: { email, password: "password123!" } });
  users[key] = { id: created.data.id, token: login.data.access_token };
}

const seedRows = {
  orders: (o) => ({ user_id: users[o].id, total: o === "A" ? 10 : 20 }),
  messages: (o) => ({ sender_id: users[o].id, body: `from ${o}` }),
  notes: (o) => ({ owner_id: users[o].id, body: `note ${o}` }),
  categories: (o) => ({ name: `cat ${o} ${Date.now()}` }),
};
const owner = { orders: "user_id", messages: "sender_id", notes: "owner_id", profiles: "id", categories: null };
const pk = { orders: "id", messages: "id", notes: "id", profiles: "id", categories: "id" };
const setCol = { orders: "user_id", messages: "sender_id", notes: "owner_id", profiles: "full_name", categories: "name" };
const rowsOf = {};
for (const [table, make] of Object.entries(seedRows)) {
  const res = await svc("POST", `/rest/v1/${table}`, { body: [make("A"), make("B")], prefer: "return=representation" });
  if (res.status >= 300) throw new Error(`seed ${table}: ${JSON.stringify(res.data)}`);
  rowsOf[table] = res.data;
}
rowsOf.profiles = (await svc("GET", `/rest/v1/profiles?select=*&id=in.(${users.A.id},${users.B.id})`)).data;

const results = {};
for (const table of Object.keys(owner)) {
  const ownerCol = owner[table];
  const aRow = ownerCol ? rowsOf[table].find((r) => r[ownerCol] === users.A.id) : rowsOf[table][0];
  results[table] = {};
  for (const who of ["anon", "B"]) {
    const token = who === "anon" ? ANON : users.B.token;
    const read = await call("GET", `/rest/v1/${table}?select=*`, { token });
    const visible = Array.isArray(read.data) ? read.data : [];
    const readA = ownerCol ? visible.filter((r) => r[ownerCol] === users.A.id).length : visible.filter((r) => rowsOf[table].some((s) => s[pk[table]] === r[pk[table]])).length;
    const upd = await call("PATCH", `/rest/v1/${table}?${pk[table]}=eq.${aRow[pk[table]]}`, { token, body: { [setCol[table]]: aRow[setCol[table]] }, prefer: "return=representation" });
    const insertBody = table === "profiles" ? null : (table === "categories" ? { name: `probe ${who} ${Date.now()}` } : seedRows[table]("A"));
    let insert = false;
    if (insertBody) {
      const ins = await call("POST", `/rest/v1/${table}`, { token, body: insertBody, prefer: "return=representation" });
      insert = ins.status === 201;
      if (insert) await svc("DELETE", `/rest/v1/${table}?${pk[table]}=eq.${ins.data[0][pk[table]]}`);
    }
    const del = await call("DELETE", `/rest/v1/${table}?${pk[table]}=eq.${aRow[pk[table]]}`, { token, prefer: "return=representation" });
    const deleted = Array.isArray(del.data) && del.data.length > 0;
    if (deleted) {
      const { id, ...rest } = aRow;
      const restore = await svc("POST", `/rest/v1/${table}`, { body: table === "messages" ? rest : aRow, prefer: "return=representation" });
      if (table === "messages") Object.assign(aRow, restore.data[0]);
    }
    results[table][who] = { read: readA, update: Array.isArray(upd.data) && upd.data.length > 0, delete: deleted, insert };
  }
}

const probe = JSON.parse((() => {
  try { return execFileSync("node", [new URL("../src/cli.js", import.meta.url).pathname, new URL("../test/fixtures/leaky", import.meta.url).pathname, "--json"], { encoding: "utf8" }); }
  catch (e) { return e.stdout; }
})());
let mismatches = 0;
console.log("table       who   field   rest-api  rls-probe");
for (const r of probe.results) {
  for (const who of ["anon", "B"]) {
    for (const field of ["read", "update", "delete", "insert"]) {
      if (r.table === "profiles" && field === "insert") continue;
      const real = results[r.table][who][field];
      const offline = field === "read" ? r[who].read : r[who][field];
      const same = field === "read" ? (real > 0) === (offline > 0) : real === offline;
      if (!same) mismatches++;
      console.log(`${r.table.padEnd(11)} ${who.padEnd(5)} ${field.padEnd(7)} ${String(real).padEnd(9)} ${offline}${same ? "" : "   <-- differs"}`);
    }
  }
}
console.log(`\n${mismatches} differences`);
