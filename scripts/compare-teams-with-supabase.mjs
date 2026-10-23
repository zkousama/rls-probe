// Checks rls-probe's teammate against a real local Supabase. Run `supabase start` in a folder
// holding the migration of test/fixtures/teams, then:
//   node scripts/compare-teams-with-supabase.mjs <that folder>
// It signs up three real users: A and their teammate D in one organization, B in another. It
// checks over the REST API what B and D can do to A's task, applies the fix rls-probe tested for
// the tasks table to the real database, and checks again, comparing each time with the probe.
import { execFileSync, execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const V = process.argv[2];
const status = JSON.parse(execSync("npx -y supabase@2.121.0 status -o json", { cwd: V, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
const URL_ = status.API_URL;
const ANON = status.ANON_KEY ?? status.PUBLISHABLE_KEY;
const SERVICE = status.SERVICE_ROLE_KEY ?? status.SECRET_KEY;
const project = /^project_id\s*=\s*"([^"]+)"/m.exec(fs.readFileSync(path.join(V, "supabase", "config.toml"), "utf8"))[1];

async function call(method, url, { token = ANON, apikey = ANON, body, prefer } = {}) {
  const res = await fetch(`${URL_}${url}`, {
    method,
    headers: { apikey, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, data: text ? JSON.parse(text) : null };
}
const svc = (method, url, opts = {}) => call(method, url, { ...opts, token: SERVICE, apikey: SERVICE });
const insert = async (table, body) => {
  const res = await svc("POST", `/rest/v1/${table}`, { body, prefer: "return=representation" });
  if (res.status >= 300) throw new Error(`seed ${table}: ${JSON.stringify(res.data)}`);
  return res.data;
};

const users = {};
for (const key of ["A", "B", "D"]) {
  const email = `${key.toLowerCase()}-${Date.now()}@example.com`;
  const created = await svc("POST", "/auth/v1/admin/users", { body: { email, password: "password123!", email_confirm: true } });
  const login = await call("POST", "/auth/v1/token?grant_type=password", { body: { email, password: "password123!" } });
  users[key] = { id: created.data.id, token: login.data.access_token };
}
const [orgA, orgB] = await insert("organizations", [{ name: "A's organization" }, { name: "B's organization" }]);
await insert("org_members", [
  { org_id: orgA.id, user_id: users.A.id, role: "owner" },
  { org_id: orgB.id, user_id: users.B.id, role: "owner" },
  { org_id: orgA.id, user_id: users.D.id, role: "member" },
]);
const [task] = await insert("tasks", [{ org_id: orgA.id, user_id: users.A.id, title: "A's task", client_email: "client@example.com" }]);

async function real() {
  const out = {};
  for (const who of ["B", "D", "A"]) {
    const read = await call("GET", `/rest/v1/tasks?id=eq.${task.id}&select=id`, { token: users[who].token });
    const update = await call("PATCH", `/rest/v1/tasks?id=eq.${task.id}`, { token: users[who].token, body: { title: task.title }, prefer: "return=representation" });
    out[who] = { read: Array.isArray(read.data) && read.data.length > 0, update: Array.isArray(update.data) && update.data.length > 0 };
  }
  return out;
}
const probe = (dir, ...flags) => JSON.parse((() => {
  try { return execFileSync("node", [new URL("../src/cli.js", import.meta.url).pathname, dir, "--json", ...flags], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }); }
  catch (e) { return e.stdout; }
})());
const offline = (report) => {
  const r = report.results.find((x) => x.table === "tasks");
  return Object.fromEntries(["B", "D", "A"].map((who) => [who, { read: r[who].read > 0, update: r[who].update }]));
};

let checks = 0;
let mismatches = 0;
const compare = (label, a, b) => {
  console.log(`\n${label}\nwho  field   rest-api  rls-probe`);
  for (const who of ["B", "D", "A"]) {
    for (const field of ["read", "update"]) {
      const same = a[who][field] === b[who][field];
      checks++;
      if (!same) mismatches++;
      console.log(`${who.padEnd(4)} ${field.padEnd(7)} ${String(a[who][field]).padEnd(9)} ${b[who][field]}${same ? "" : "   <-- differs"}`);
    }
  }
};

const before = probe(V, "--test-fixes");
compare("Before the fix (B: another organization; D: A's teammate)", await real(), offline(before));
const fix = before.fixes.find((f) => f.kind === "user-read" && f.where === "tasks" && f.verified);
if (!fix) throw new Error("rls-probe tested no fix for the tasks table");
console.log(`\nApplying the fix rls-probe tested:\n${fix.sql}`);
execFileSync("docker", ["exec", "-i", `supabase_db_${project}`, "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], { input: fix.sql, stdio: ["pipe", "ignore", "inherit"] });

// The probe's view of the same database with the fix, as one more migration.
const copy = fs.mkdtempSync(path.join(os.tmpdir(), "rls-probe-teams-"));
fs.cpSync(path.join(V, "supabase"), path.join(copy, "supabase"), { recursive: true });
fs.writeFileSync(path.join(copy, "supabase", "migrations", "99999999999999_fix.sql"), fix.sql);
compare("After the fix", await real(), offline(probe(copy)));
fs.rmSync(copy, { recursive: true, force: true });
console.log(`\n${checks} checks, ${mismatches} differences`);
