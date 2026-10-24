// What the app's own code and migrations say each finding was meant to be. The database
// alone can't tell a public catalog from a leak; the code that uses it often can:
//   - which key reaches a table: only the service role (server code) means visitors and
//     users never needed access; the public key means the app relies on the rules;
//   - whether queries keep to the user's own rows (.eq("user_id", user.id));
//   - whether the code that adds rows runs before or after sign-in;
//   - what comments and policy names say ("anyone can submit", "Allow all operations").
// Each finding gets a verdict, "mistake", "on purpose" or "unclear", with the reasons,
// quoted from the code. Only an explicit "on purpose" lowers its severity.
import { findingId } from "./accept.js";
import { TEST_FILE } from "./static.js";

// Generated type files name every table; they say nothing about use.
const TYPES_FILE = /(^|\/)(database|supabase)[.-]?types?\.[jt]s$|\.d\.ts$|(^|\/)types\/(supabase|database)\.[jt]s$/i;
const MIGRATION = /(^|\/)migrations?\//;
// A client made with the service role or secret key, or one named as the admin client.
const ADMIN = /service_?role|SERVICE_ROLE|SUPABASE_SECRET_KEY|sb_secret_|createAdminClient|createServiceClient|createServiceRoleClient|supabaseAdmin|adminClient|admin-client|getServiceSupabase/;
// The signed-in user's own id, as code usually spells it.
const SELF = /\b(user|session\??\.user|currentUser|me|viewer|profile|auth\??\.user|data\??\.user)!?\??\.(id|sub)\b|auth\.uid\(\)|getUser\(\)|currentUserId|myId/;
// Code that runs after sign-in.
const SIGNED_IN = /auth\.getUser|auth\.getSession|getClaims|useUser\b|useSession\b|useAuth\b|requireAuth|withAuth|currentUser|session\?\.user|redirect\(\s*['"`]\/(login|sign-?in|auth)/i;
// Tables that take rows from anyone on purpose: forms, sign-up lists, counters.
const FORM = /(waitlist|contact|feedback|submission|signup|sign_up|subscribe|subscriber|newsletter|lead|inquir|enquir|page_?views?|analytics|visits?|play_events|events?_log|telemetry)/i;
// Words that say "meant for everyone" or "server only".
// ("public." is the schema, not an intent; "not anyone" says the opposite.)
const OPEN_WORDS = /\b(publicly|public (read|reads|access|data|bucket|files?|page|profiles?|listing|catalog|feed|form)|anyone|everyone|any (users?|visitors?|one)|all users|unauthenticated|allow all|world[- ]readable)\b/i;
const NEGATED = /\b(not|no|never|prevent|block|den(y|ies)|only|unless|except|without|shouldn't|must not)\b/i;
const CLOSED_WORDS = /\b(server[- ]only|service[ _]role only|no application code|internal only|admin only|never (exposed|reaches)|private)\b/i;

const READS = new Set(["rls-off", "rls-off-users", "visitor-read", "user-read", "view-bypass", "storage-visitor-read", "storage-user-read", "public-bucket"]);

// code: [{ path, text }]. migrations: [{ name, sql }]. Returns { [finding id]: { verdict, reasons } }.
export function readIntent(report, code, migrations, functions = []) {
  const use = usage(code);
  throughFunctions(use, functions, report);
  const out = {};
  // Whether any code hands the public key to a client that runs as a visitor or user.
  const publicKey = code.some((f) => !TYPES_FILE.test(f.path) && /SUPABASE_(ANON|PUBLISHABLE)_KEY|supabase(Anon|Publishable)Key|createBrowserClient|anonKey/i.test(f.text));
  for (const f of report.findings) {
    if (["service-key", "secret", "browser-secret", "open-function"].includes(f.kind)) continue;
    const verdict = judge(f, report, use, migrations, publicKey);
    if (verdict) out[findingId(f)] = verdict;
  }
  return out;
}

function judge(f, report, use, migrations, publicKey) {
  const reasons = [];
  const name = f.kind === "definer-function" ? f.function : f.bucket ?? f.where;
  const u = (f.kind === "definer-function" ? use.rpc : f.bucket ? use.storage : use.tables).get(name) ?? { user: [], admin: [] };
  const at = (x) => `${x.path}:${x.line}`;
  // How the app reaches it: with the public key, or through a function that runs as the caller.
  const how = (x) => (x.via ? ` through ${x.via}() (${at(x)}), which runs as the caller` : ` with the public key (${at(x)})`);

  // What the migrations say about it, next to where it's made and its policies.
  const said = hints(f, report, migrations);
  // Rows added in someone else's name are never what "anyone can add" means.
  if (said.open && f.kind !== "impersonation") {
    // Meant to be open, but with private columns in it: the columns are the question.
    if (f.columns?.length) return { verdict: "unclear", reasons: [`${said.open} says ${name} is meant to be open, but it includes ${f.columns.join(", ")}; is that meant to be seen too?`] };
    // What rls-probe saw happen outweighs what a comment says was meant.
    const seen = f.leak ? "it handed over another user's private data" : f.proof?.changed.some((c) => c.how !== "added") ? "it changed or deleted another user's rows" : null;
    if (seen) return { verdict: "unclear", reasons: [`${said.open} says it's meant to be open, but when rls-probe called it, ${seen}`] };
    return { verdict: "on purpose", reasons: [`the migrations say so: ${said.open}`], lower: true };
  }
  if (said.closed) reasons.push(`the migrations say it's not for the app's users: ${said.closed}`);
  // Without the app's code, only what the migrations say counts.
  if (!use.hasCode) return said.closed ? { verdict: "mistake", reasons } : null;

  if (!publicKey) reasons.push("the app's code doesn't seem to give visitors the public key, so outsiders may not have it; it isn't secret, though");

  if (f.kind === "definer-function") {
    if (!u.user.length) {
      reasons.unshift(u.admin.length ? `the app calls it only with the service role (${at(u.admin[0])}), so visitors and users don't need to` : "no app code calls it, so visitors and users don't need to");
      return { verdict: "mistake", reasons, revokeSafe: true };
    }
    reasons.unshift(`the app calls it as the user (${at(u.user[0])}), so taking it away would break that; it needs a check inside instead`);
    return { verdict: "mistake", reasons, revokeSafe: false };
  }

  // Named in user-facing code but not in a call rls-probe can read (a data provider's
  // resource): the app may use it through the API, so "server only" can't be concluded.
  // (Reads through a function the app calls don't tell what the code does with it directly.)
  const named = !u.user.some((x) => !x.via) && use.named(name);
  if (named) return { verdict: "unclear", reasons: [`the app names "${name}" (${at(named)}) in a way rls-probe can't follow, so it may read or change it through the API`, ...reasons] };
  // Only the service role or plain SQL from server code reaches it: nobody else needed access.
  const sql = !f.bucket && use.sql(name);
  if (!u.user.length && (u.admin.length || sql || said.closed)) {
    if (!said.closed || u.admin.length || sql) reasons.unshift(u.admin.length ? `the app reaches ${name} only with the service role (${at(u.admin[0])}), so visitors and users never needed access`
      : `the app reaches ${name} with plain SQL from server code (${at(sql)}), not through Supabase's API, so visitors and users never needed access`);
    return { verdict: "mistake", reasons };
  }
  if (!u.user.length) {
    reasons.unshift(`no code in this repository uses ${name} through Supabase's API, so the app doesn't need it open (unless something outside the repository does)`);
    return { verdict: "mistake", reasons };
  }

  const owner = report.results.find((r) => r.table === f.where)?.ownedThrough?.[0]?.column;
  const reads = u.user.filter((x) => x.ops.has("select"));
  const writes = u.user.filter((x) => ["insert", "upsert", "update", "delete", "upload"].some((o) => x.ops.has(o)));

  if (READS.has(f.kind)) {
    const own = owner && reads.length && reads.every((x) => x.filters.includes(owner));
    // The app treats the rows as each user's own: others reading them is a leak, whatever the columns are called.
    if (own) return { verdict: "mistake", reasons: [`the app only reads users' own rows (${at(reads[0])} filters on ${owner}), so seeing others' isn't needed`, ...reasons], raise: true };
    if (/^visitor-|^storage-visitor-|^rls-off$/.test(f.kind) && reads.length && reads.every((x) => x.signedIn)) {
      return { verdict: "mistake", reasons: [`the app reads ${name} only after sign-in (${at(reads[0])}), so visitors don't need it`, ...reasons] };
    }
    return { verdict: "unclear", reasons: [`the app reads ${name}${how(reads[0] ?? u.user[0])}; whether others' rows are meant to show depends on what it's for`, ...reasons] };
  }

  // Adding rows without signing in: a form, if the app does it before sign-in.
  if (f.kind === "visitor-write" && f.actions.every((a) => a === "insert")) {
    const open = writes.filter((x) => !x.signedIn);
    if (open.length && FORM.test(name)) return { verdict: "on purpose", reasons: [`the app adds rows to ${name} without a sign-in (${at(open[0])}), as a form does`, ...reasons], lower: true };
    if (writes.length && !open.length) return { verdict: "mistake", reasons: [`the app adds rows to ${name} only after sign-in (${at(writes[0])}), so visitors don't need to`, ...reasons] };
    if (FORM.test(name)) return { verdict: "unclear", reasons: [`${name} sounds like something anyone fills in (a form or a counter)`, ...reasons] };
  }
  const ownWrites = owner && writes.length && writes.every((x) => x.filters.includes(owner));
  if (ownWrites) return { verdict: "mistake", reasons: [`the app only changes users' own rows (${at(writes[0])} filters on ${owner}), so changing others' isn't needed`, ...reasons] };
  return { verdict: "unclear", reasons: [`the app ${writes.length ? `writes to ${name}${how(writes[0])}` : `uses ${name}${how(u.user[0])}`}; whether others may do the same depends on what it's for`, ...reasons] };
}

// What the migrations say about a finding: the names of the policies that grant the
// action at fault, and the comment written right above the table, bucket, function or
// those policies (or on their own first line). A hint counts only for the action it's
// about: a "public read" policy says nothing about uploads.
const CMD = { read: "SELECT", update: "UPDATE", delete: "DELETE", insert: "INSERT" };
const READ_WORDS = /\b(read|reads|view|viewable|see|select|list|download|browse|show)/i;
const WRITE_WORDS = /\b(insert|inserts|add|submit|create|creates|upload|uploads|write|update|edit|delete|sign up|subscribe|change)/i;
function hints(f, report, migrations) {
  const out = {};
  const name = f.kind === "definer-function" ? f.function : f.bucket ?? f.where;
  const table = f.kind.startsWith("storage") || f.kind === "public-bucket" ? "storage.objects" : f.where;
  // A function may read and write; what rls-probe saw it do is judged in judge().
  const actions = f.actions ?? (f.kind === "definer-function" ? ["read", "update"] : ["read"]);
  const reads = actions.includes("read");
  const writes = actions.some((a) => a !== "read");
  const rule = (p) => `${p.using ?? ""} ${p.check ?? ""}`;
  // The policies granting this finding's actions; for files, this bucket's.
  const granting = (report.policies?.[table] ?? []).filter((p) => (p.cmd === "ALL" || actions.some((a) => CMD[a] === p.cmd))
    && (!f.bucket || rule(p).includes(`'${f.bucket}'`)));
  for (const p of granting) {
    const open = f.bucket ? !/auth\./.test(rule(p)) : p.using === "true" || p.check === "true";
    if (!open || !/allow all|all operations|everyone|anyone|public/i.test(p.name)) continue;
    // "Public" says readable; only a name about writing ("insert", "allow all") excuses writes.
    const about = { read: READ_WORDS.test(p.name) || !WRITE_WORDS.test(p.name), write: WRITE_WORDS.test(p.name) || /allow all|all operations/i.test(p.name) };
    if ((reads && about.read) || (writes && about.write)) out.open ??= `the policy "${p.name}"`;
  }
  const spots = [report.createdAt?.[name], ...granting.map((p) => report.policyAt?.[table]?.[p.name])].filter(Boolean);
  for (const spot of spots) {
    const m = migrations.find((x) => x.name === spot.file);
    if (!m) continue;
    for (const c of commentsAt(m.sql.split("\n"), spot.line)) {
      if (CLOSED_WORDS.test(c)) out.closed ??= `"${c.trim().slice(0, 120)}"`;
      else if (OPEN_WORDS.test(c) && !NEGATED.test(c)) {
        // Which actions the comment is about; one about none of them is about reading.
        const about = { read: READ_WORDS.test(c) || !WRITE_WORDS.test(c), write: WRITE_WORDS.test(c) };
        if ((reads && about.read) || (writes && about.write)) out.open ??= `"${c.trim().slice(0, 120)}"`;
      }
    }
  }
  return out;
}

// The comment block right above a statement, as one paragraph, and a comment on its own
// first line. Blank lines and the "drop ... if exists" that usually comes first are
// skipped on the way up.
function commentsAt(lines, line) {
  const above = [];
  let i = line - 2;
  while (i >= 0 && (!lines[i].trim() || /^\s*drop\s+(policy|table|function|view|trigger)\s+if\s+exists\b/i.test(lines[i]))) i--;
  while (i >= 0 && /^\s*--/.test(lines[i])) above.unshift(lines[i--].replace(/^\s*--\s?/, ""));
  const inline = /--\s*(.*)$/.exec(lines[line - 1] ?? "")?.[1];
  return [above.join(" "), inline].filter(Boolean);
}

// Every supabase-js call in the code, by table, bucket and function: where, with which
// key, what it does, what it filters on, and whether it runs after sign-in.
// A function the app calls runs as the visitor or user calling it, unless it's security
// definer: the tables it reads and writes are then used by the app through the API, as
// that caller. Recorded like the app's own calls, at the line that calls the function.
function throughFunctions(use, functions, report) {
  for (const fn of functions) {
    const calls = use.rpc.get(fn.name)?.user ?? [];
    if (fn.definer || !calls.length || !fn.body) continue;
    for (const { table } of report.results) {
      const after = (verb) => new RegExp(`\\b${verb}\\s+(?:"?public"?\\.)?"?${table.replace(/\W/g, "\\$&")}"?(?![\\w"])`, "i").test(fn.body);
      const ops = new Set([
        ...(after("(?:from|join)") ? ["select"] : []),
        ...(after("insert\\s+into") ? ["insert"] : []),
        ...(after("update") ? ["update"] : []),
        ...(after("delete\\s+from") ? ["delete"] : []),
      ]);
      if (!ops.size) continue;
      const e = use.tables.get(table) ?? { user: [], admin: [] };
      for (const c of calls) e.user.push({ ...c, ops, filters: [], via: fn.name });
      use.tables.set(table, e);
    }
  }
}

// Whether a file runs with the service role: it names it (ADMIN), reads a setting the example
// env files say holds the service role key under a name that doesn't say so (SUPABASE_KEY),
// or gets its client from a module of the app that only uses such a key.
const PUBLIC_KEY = /SUPABASE_(ANON|PUBLISHABLE)_KEY|supabase(Anon|Publishable)Key|anonKey|createBrowserClient/i;
function serverCode(code, app) {
  const settings = new Set();
  for (const { path, text } of code) {
    if (!/(^|\/)\.env[\w.-]*$/.test(path)) continue;
    for (const m of text.matchAll(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=(.*)$/gm)) {
      if (/KEY|TOKEN|SECRET/.test(m[1]) && /service[_ -]?role|sb_secret_/i.test(m[2])) settings.add(m[1]);
    }
  }
  const names = [...settings].map((n) => new RegExp(`\\b${n}\\b`));
  const direct = (text) => ADMIN.test(text) || names.some((n) => n.test(text));
  const modules = app.filter((f) => direct(f.text) && !PUBLIC_KEY.test(f.text)).map((f) => f.path.replace(/\.\w+$/, "").replace(/\/(index|__init__)$/, ""));
  // Where an import points, as a path without its extension: "./client", "@/lib/db", "src.infra.client".
  const imported = (path, text) => [
    ...[...text.matchAll(/\bfrom\s+['"]([^'"]+)['"]|\brequire\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1] ?? m[2]),
    ...[...text.matchAll(/^\s*from\s+(\.*[\w.]+)\s+import\b/gm)].map((m) => m[1].replace(/^(\.+)/, (dots) => (dots.length === 1 ? "./" : "../".repeat(dots.length - 1))).replace(/(?<=\w)\./g, "/")),
  ].map((spec) => {
    if (spec.startsWith(".")) {
      const parts = path.split("/").slice(0, -1);
      for (const p of spec.split("/")) p === ".." ? parts.pop() : p !== "." && parts.push(p);
      return parts.join("/");
    }
    return spec.replace(/^[@~]\//, "");
  });
  // A one-word name ("supabase") is a package unless it's a file at the root.
  return (path, text) => direct(text) || imported(path, text).some((spec) => modules.some((m) => m === spec || (spec.includes("/") && m.endsWith(`/${spec}`))));
}

function usage(code) {
  const tables = new Map();
  const storage = new Map();
  const rpc = new Map();
  const add = (map, name, entry) => {
    const e = map.get(name) ?? { user: [], admin: [] };
    (entry.admin ? e.admin : e.user).push(entry);
    map.set(name, e);
  };
  // The app's own code: not types, migrations, tests, settings, or tool folders (.claude, .github).
  const app = code.filter(({ path }) => !TYPES_FILE.test(path) && !MIGRATION.test(path) && !TEST_FILE.test(path) && !path.endsWith(".json") && !/(^|\/)\.[\w-]+\//.test(path));
  const lineIn = (text, i) => text.slice(0, i).split("\n").length;
  const find = (pattern) => {
    for (const { path, text } of app) {
      const m = pattern.exec(text);
      if (m) return { path, line: lineIn(text, m.index) };
    }
    return null;
  };
  const word = (name) => name.replace(/\W/g, "\\$&");
  const isAdmin = serverCode(code, app);
  for (const { path, text } of app) {
    if (!/\.(from|rpc|table)\(/.test(text)) continue;
    const admin = isAdmin(path, text);
    const signedIn = SIGNED_IN.test(text);
    const lineOf = (i) => text.slice(0, i).split("\n").length;
    // supabase-js .from("t") and supabase-py .table("t"), and the calls chained after.
    for (const m of text.matchAll(/(\.storage\s*)?\.(?:from|table)\(\s*['"`]([\w.-]+)['"`]\s*\)([\s\S]{0,400})/g)) {
      // The chain ends at a statement's end, a blank line or the next statement.
      const chain = m[3].split(/;|\n\s*\n|\n\s*(?:const|let|var|return|if|await|for|export|function)\b/)[0];
      const ops = new Set([...chain.matchAll(/\.(select|insert|upsert|update|delete|upload|download|list|remove|getPublicUrl|createSignedUrl)\(/g)].map((x) => x[1]));
      // Columns the query pins to the signed-in user's own id (user.id, session.user.id,
      // auth.uid()); a uid passed in from elsewhere may be anyone's.
      const filters = [...chain.matchAll(/\.(?:eq|match)\(\s*\{?\s*['"`]?([\w.]+)['"`]?\s*[,:]\s*([^),}]+)/g)]
        .filter((x) => SELF.test(x[2])).map((x) => x[1]);
      const entry = { path, line: lineOf(m.index), admin, signedIn, ops, filters };
      if (m[1] || [...ops].some((o) => ["upload", "download", "list", "remove", "getPublicUrl", "createSignedUrl"].includes(o))) {
        if (ops.has("list") || ops.has("download") || ops.has("getPublicUrl") || ops.has("createSignedUrl")) ops.add("select");
        add(storage, m[2], entry);
      } else add(tables, m[2], entry);
    }
    for (const m of text.matchAll(/\.rpc\(\s*['"`](\w+)['"`]/g)) add(rpc, m[1], { path, line: lineOf(m.index), admin, signedIn, ops: new Set(["call"]), filters: [] });
  }
  return {
    tables, storage, rpc,
    // Whether there's any app code to judge by (a pasted schema has none).
    hasCode: app.length > 0,
    // Plain SQL naming the table in code (a direct database connection, server side).
    sql: (name) => find(new RegExp(`\\b(from|into|update|join)\\s+(?:"?public"?\\.)?"?${word(name)}"?\\b`, "i")),
    // The table's name as a string in user-facing code: not server code, not the
    // service role's, and not a supabase-js call rls-probe already read.
    named: (name) => {
      const quoted = new RegExp(`['"\`]${word(name)}['"\`]`);
      for (const { path, text } of app) {
        if (isAdmin(path, text) || /(^|\/)supabase\/functions\//.test(path) || path.endsWith(".py")) continue;
        const m = quoted.exec(text.replace(/\.(from|table|rpc)\(\s*['"`][\w.-]+['"`]/g, ""));
        if (m) return { path, line: lineIn(text, m.index) };
      }
      return null;
    },
  };
}
