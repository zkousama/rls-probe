// Fixes for what the probe found, as SQL that is applied to a copy of the database
// and probed again before it's offered. A fix counts only if its problem is gone,
// nothing new opened, and the owner of each row can still do everything they could. Existing policies are left
// as they are: a fix revokes a grant or adds a restrictive policy, which narrows what
// the app's own policies allow without rewriting them.
import { runProbe } from "./engine.js";
import { memberCan } from "./report.js";
import { q } from "./seed.js";

const CMD = { read: "select", update: "update", delete: "delete", insert: "insert" };
const SEE = { read: "see", update: "change", delete: "delete", insert: "add" };
const UID = "(select auth.uid())";
const FIX_FILE = "99999999999999_rls_probe_fixes.sql";
// Found in the app's code, so no migration fixes them.
const CODE_KINDS = ["service-key", "secret", "browser-secret", "open-function"];

// "This row is the signed-in user's", along one route from the table to auth.users.
function mine(table, route) {
  if (route?.length === 1) return `${q(route[0].column)} = ${UID}`;
  if (route?.length === 2) {
    const [hop, end] = route;
    // A profile keyed by the user's own id: the reference is the owner.
    if (hop.refColumn === end.column) return `${q(hop.column)} = ${UID}`;
    return `exists (select 1 from public.${q(hop.table)} p where p.${q(hop.refColumn)} = ${q(table)}.${q(hop.column)} and p.${q(end.column)} = ${UID})`;
  }
  return null;
}

// A restrictive policy: rows pass only if they also meet this condition, whatever
// the app's other policies allow. Insert takes a check, select and delete a using
// clause, update both.
function restrict(name, on, cmd, role, condition) {
  const clause = cmd === "insert" ? `with check (${condition})` : cmd === "update" ? `using (${condition})\n  with check (${condition})` : `using (${condition})`;
  return `create policy ${q(name.slice(0, 63))} on ${on} as restrictive\n  for ${cmd} to ${role}\n  ${clause};`;
}

export function proposeFixes(report) {
  const out = [];
  for (const f of report.findings) {
    const fix = fixFor(f, report);
    if (fix) out.push({ kind: f.kind, where: f.where, ...fix });
  }
  return out;
}

// The SQL for one finding, and what the app does differently afterwards, said plainly.
function fixFor(f, report) {
  const t = f.where;
  const table = `public.${q(t)}`;
  const r = report.results.find((x) => x.table === t);
  // Rows a user is party to, and rows of a group they're in, so teammates keep theirs.
  const parties = [
    ...(r?.parties ?? []).map((route) => mine(t, route)).filter(Boolean),
    ...(r?.groups ?? []).map((g) => `exists (select 1 from public.${q(g.members)} m where m.${q(g.groupColumn)} = ${q(t)}.${q(g.column)} and m.${q(g.userColumn)} = ${UID})`),
  ];
  const ours = r?.groups?.length ? " and those of groups they belong to" : "";
  const anyParty = parties.length ? parties.join(" or ") : null;
  const author = mine(t, r?.ownedThrough);
  const acts = list((f.actions ?? []).map((a) => SEE[a]));
  const ownOnly = (cmd) => restrict(`rls-probe: own${ours ? " or group's" : ""} ${t} only (${cmd})`, table, cmd, "authenticated", anyParty);
  switch (f.kind) {
    case "rls-off":
    case "rls-off-users":
      if (r?.owned && anyParty && author) {
        return {
          sql: `alter table ${table} enable row level security;\ncreate policy ${q(`rls-probe: owners manage their ${t}`.slice(0, 63))} on ${table}\n  for all to authenticated\n  using (${anyParty})\n  with check (${author});`,
          effect: `each signed-in user sees and changes only their own rows in ${t}${ours}, and visitors see none.`,
        };
      }
      // A table without owners that holds private columns (a waitlist's emails): only
      // server code, with the service role, reaches it.
      if (r && !r.owned && f.columns?.length) {
        return {
          sql: `alter table ${table} enable row level security;`,
          effect: `only your server code (the service role) can read or change ${t}; the app's visitors and users can't.`,
          // Taking everyone's access away is the point; nobody owns these rows.
          lockdown: true,
        };
      }
      // A shared table, like a list of categories: everyone keeps reading it, nobody writes.
      return r && !r.owned ? {
        sql: `alter table ${table} enable row level security;\ncreate policy ${q(`rls-probe: everyone reads ${t}`.slice(0, 63))} on ${table}\n  for select to anon, authenticated\n  using (true);`,
        effect: `everyone can still read ${t}, and only your server code (the service role) can change it.`,
      } : null;
    case "visitor-write":
      return { sql: `revoke ${f.actions.map((a) => CMD[a]).join(", ")} on ${table} from anon;`, effect: `visitors who aren't signed in can't ${acts} rows in ${t}.` };
    case "visitor-read": {
      // Signed-in users who'd still read other users' private columns are limited too:
      // otherwise closing the door to visitors only uncovers the next problem.
      const users = r.B?.read && r.B.exposed?.length && anyParty;
      return {
        sql: [`revoke select on ${table} from anon;`, ...(users ? [ownOnly("select")] : [])].join("\n"),
        effect: `visitors who aren't signed in can't read ${t}${users ? `, and each signed-in user sees only their own rows${ours}` : ""}.`,
      };
    }
    case "user-read":
      return anyParty ? { sql: ownOnly("select"), effect: `each signed-in user sees only their own rows in ${t}${ours}.` } : null;
    case "user-write":
      return anyParty ? { sql: f.actions.map((a) => ownOnly(CMD[a])).join("\n"), effect: `each signed-in user can ${acts} only their own rows in ${t}${ours}.` } : null;
    case "impersonation":
      return author ? { sql: restrict(`rls-probe: add ${t} as yourself only`, table, "insert", "authenticated", author), effect: `users can add rows to ${t} only in their own name.` } : null;
    case "definer-function":
      // A function the app's own policies call can't be taken from users: every row
      // those policies guard would close to them too.
      if (namedInPolicies(report, f.function)) return null;
      return {
        sql: `revoke execute on function public.${t} from public, anon, authenticated;`,
        effect: `the app can't call ${f.function}() any more. If it does (supabase.rpc("${f.function}")), check the caller with auth.uid() inside the function instead.`,
      };
    case "view-bypass":
      return { sql: `alter view public.${q(t)} set (security_invoker = true);`, effect: `the ${t} view shows each person only the rows the tables underneath let them see.` };
    case "public-bucket":
      // Visitors can list its files through the policies: a private bucket would hand
      // them over the same way, so making it private is no fix on its own.
      if (report.storage?.buckets.find((b) => b.bucket === f.bucket)?.anon?.read) return null;
      return {
        sql: `update storage.buckets set public = false where id = ${literal(f.bucket)};`,
        effect: `public links to files in ${f.bucket} stop working; the app needs signed links (createSignedUrl) instead.`,
      };
    case "storage-visitor-write":
    case "storage-visitor-read":
    case "storage-user-write":
    case "storage-user-upload":
    case "storage-user-read": {
      const elsewhere = `bucket_id <> ${literal(f.bucket)}`;
      const ownFolder = `${elsewhere} or (storage.foldername(name))[1] = ${UID}::text`;
      const visitor = f.kind.startsWith("storage-visitor");
      return {
        sql: f.actions.map((a) => restrict(`rls-probe: ${visitor ? "no visitor" : "own folder"} ${CMD[a]} in ${f.bucket}`, "storage.objects", CMD[a],
          visitor ? "anon" : "authenticated", visitor ? elsewhere : ownFolder)).join("\n"),
        effect: visitor ? `visitors who aren't signed in can't ${acts} files in ${f.bucket}.` : `each signed-in user can ${acts} files in ${f.bucket} only in their own folder.`,
      };
    }
    default:
      return null;
  }
}

// Applies the proposed fixes as one more migration and probes again. A fix is
// verified when its problem is gone and its SQL ran, as long as, across the whole
// database, the owner of each row (user A) and their teammate lost nothing and no
// new problem appeared. migrated: the report's saved copy of the database (runProbe's
// keep), so the migrations don't run again for each try. deadline: a time
// (performance.now()) after which fixes not yet tested are left out, marked untested.
export async function verifyFixes({ migrations, report, snapshot, migrated = report.migrated, deadline = Infinity, trialTime = report.trialTime }) {
  return checkFixes({ migrations, report, snapshot, migrated, deadline, trialTime, fixes: proposeFixes(report) });
}

// fixes: [{ kind, where, sql }], each meant to close the finding of that kind and place.
export async function checkFixes({ migrations, report, snapshot, migrated = report.migrated, deadline = Infinity, trialTime = report.trialTime, fixes, onTrial }) {
  // A try that can't finish before the deadline isn't started: its time is guessed from
  // the probe that made the report (trialTime, in ms), then from the last try.
  let cost = trialTime ?? 0;
  const run = async (some) => {
    if (performance.now() + cost > deadline) return null;
    const started = performance.now();
    onTrial?.(some.length);
    const result = await tryFixes({ migrations, report, snapshot, migrated, fixes: some });
    cost = performance.now() - started;
    return result;
  };
  const settled = new Set();
  const reached = new Map();
  const reach = (where) => reached.get(where) ?? reached.set(where, policyReach(where, report)).get(where);
  const kept = await keep(fixes, run, { isEntangled: (fix) => entangled(fix, report), affects: (fix, where) => affects(fix, where, reach) }, settled);
  return fixes.map((fix) => ({ ...fix, verified: kept.includes(fix), ...(settled.has(fix) ? {} : { untested: "ran out of time" }) }));
}

// Whether a policy, other than those of the table `except`, names this table or function.
function namedInPolicies(report, word, except) {
  const pattern = new RegExp(`\\b${word.replace(/\W/g, "\\$&")}\\b`);
  return Object.entries(report.policies ?? {}).some(([table, list]) => table !== except && list.some((p) => pattern.test(`${p.using ?? ""} ${p.check ?? ""}`)));
}

// Whether other rules depend on what a fix changes: a policy that reads the table or
// view, or a bucket's files that may be meant for everyone. Such fixes are the likely
// cause when a set of fixes takes something away, so they're tried apart.
function entangled(fix, report) {
  switch (fix.kind) {
    case "definer-function":
      return namedInPolicies(report, fix.where.replace(/\(.*$/, ""));
    case "rls-off":
    case "rls-off-users":
    case "view-bypass":
      return namedInPolicies(report, fix.where, fix.where);
    case "public-bucket":
      return true;
    default:
      return false;
  }
}

// Whether a fix can change what happens on a table or bucket (as named in harm): it's a fix
// to it, or to a table or function its policies name, directly or inside the functions they
// call. reach(where): that text.
function affects(fix, where, reach) {
  if (fix.where === where || (fix.bucket && where === `storage bucket ${fix.bucket}`)) return true;
  const name = fix.kind === "definer-function" ? fix.where.replace(/\(.*$/, "") : fix.bucket ? null : fix.where;
  return Boolean(name) && new RegExp(`\\b${name.replace(/\W/g, "\\$&")}\\b`).test(reach(where));
}

// A table's (or bucket's) policies and triggers, and the bodies of the functions they call,
// up to three calls deep.
function policyReach(where, report) {
  const policies = report.policies?.[where.startsWith("storage bucket ") ? "storage.objects" : where] ?? [];
  let text = [...policies.map((p) => `${p.using ?? ""} ${p.check ?? ""}`), ...(report.triggers?.[where] ?? []).map((fn) => `${fn}()`)].join("\n");
  const bodies = Object.entries(report.functionBodies ?? {});
  const seen = new Set();
  for (let depth = 0; depth < 3; depth++) {
    const called = bodies.filter(([name]) => !seen.has(name) && new RegExp(`\\b${name.replace(/\W/g, "\\$&")}\\s*\\(`).test(text));
    if (!called.length) break;
    for (const [name, body] of called) {
      seen.add(name);
      text += `\n${body}`;
    }
  }
  return text;
}

// The fixes that, applied together, close their problems and harm nothing. When the
// set harms something, a table only one fix can affect convicts that fix at once, the
// fixes that can't affect any harmed table are tried apart from those that can, then the
// entangled ones apart from the rest, and any part that still harms is halved, until the
// fixes at fault are found. settled: the fixes with a verdict, passed or failed, before
// the deadline.
async function keep(fixes, run, how, settled) {
  if (!fixes.length) return [];
  const result = await run(fixes);
  if (!result) return [];
  const closing = fixes.filter(result.closes);
  // Not closing its problem fails a fix, whatever else happened; harm fails one tried alone.
  for (const fix of fixes) if (!closing.includes(fix) || !result.harm.length || fixes.length === 1) settled.add(fix);
  if (!result.harm.length) return closing;
  if (fixes.length === 1) return [];
  // Every fix in the try counts here, including those that didn't close their problem: they
  // ran too. A harmed table only one fix can affect convicts that fix when it's a fix to that
  // table itself; one that reaches it through policies, functions or triggers might not be
  // the only way there, so it's tried apart instead (an innocent fix was convicted that way).
  const own = (f, where) => f.where === where || (f.bucket && where === `storage bucket ${f.bucket}`);
  const blamed = result.harm.map((h) => [h, fixes.filter((f) => how.affects(f, h.where))])
    .filter(([h, t]) => t.length === 1 && own(t[0], h.where)).map(([, t]) => t[0]);
  const convicted = new Set(blamed.filter((f) => closing.includes(f)));
  for (const fix of convicted) settled.add(fix);
  const left = closing.filter((f) => !convicted.has(f));
  // Suspects: the fixes that can affect a harmed table. The others are tried together first,
  // so most fixes get their verdict from one more try, and the suspects among themselves.
  // Then fixes other rules depend on. A few fixes are tried one by one; more are halved.
  const suspects = left.filter((f) => result.harm.some((h) => how.affects(f, h.where)));
  const tangled = left.filter(how.isEntangled);
  const apart = (some) => some.length && some.length < left.length ? [left.filter((f) => !some.includes(f)), some] : null;
  const half = Math.ceil(left.length / 2);
  const parts = apart(suspects) ?? (left.length < fixes.length ? [left] : null) ?? apart(tangled)
    ?? (left.length <= 3 ? left.map((f) => [f]) : [left.slice(0, half), left.slice(half)]);
  const kept = [];
  for (const part of parts) {
    const ok = await keep(part, run, how, settled);
    if (ok.length) kept.push(ok);
  }
  if (kept.length < 2) return kept[0] ?? [];
  // Each part is harmless on its own; check they still are together. Out of time for that,
  // the parts after the first weren't tried with it, which isn't the same as failing.
  const both = await run(kept.flat());
  if (!both) for (const fix of kept.slice(1).flat()) settled.delete(fix);
  return !both || both.harm.length ? kept[0] : kept.flat().filter(both.closes);
}

async function tryFixes({ migrations, report, snapshot, migrated, fixes }) {
  // No comments: the loader reports a failed statement with its leading comments.
  const sql = fixes.map((f) => f.sql).join("\n");
  const fix = { name: FIX_FILE, sql };
  // Functions aren't called again: whether a function's fix works shows in its grants.
  const after = await runProbe(migrated
    ? { migrations: [fix], grants: report.grants, snapshot, from: migrated, call: false }
    : { migrations: [...migrations, fix], grants: report.grants, snapshot, call: false });
  const failed = after.load.failed.filter((x) => x.file === FIX_FILE).map((x) => x.statement);
  const closes = (f) => !after.findings.some((x) => x.kind === f.kind && x.where === f.where)
    && !f.sql.split(/;$/m).filter((s) => s.trim()).some((s) => failed.some((p) => sameStatement(p, s)));
  // New problems only: not ones the report already had or accepted, and not functions it
  // called and judged, since a try doesn't call them (one that refused every call isn't a
  // finding, but would look like one uncalled).
  const known = [...report.findings, ...(report.accepted ?? [])];
  const called = new Set((report.functions ?? []).map((f) => `${f.name}(${f.args})`));
  const appeared = after.findings.filter((x) => x.severity !== "review" && !known.some((y) => y.kind === x.kind && y.where === x.where)
    && !(x.kind === "definer-function" && called.has(x.where)));
  const lockedDown = new Set(fixes.filter((f) => f.lockdown).map((f) => f.where));
  return { closes, harm: [...ownerLosses(report, after).filter((h) => !lockedDown.has(h.where)), ...appeared.map((x) => ({ what: x.kind, where: x.where }))] };
}

// Every table and bucket where the owner (user A), or A's teammate (D, when the app
// has groups), could do something with A's rows before that they can't after, as
// { what: who lost it, where }.
function ownerLosses(before, after) {
  const can = (x, k) => (k === "read" ? x.read > 0 : Boolean(x[k]));
  const lost = (was, now) => was && ["read", "update", "delete", "insert"].some((k) => can(was, k) && !(now && can(now, k)));
  const out = [];
  for (const r of before.results) {
    const now = after.results.find((x) => x.table === r.table);
    if (lost(r.A, now?.A)) out.push({ what: "A", where: r.table });
    // The teammate keeps what they could do as a member, not what everyone could.
    if (["read", "update", "delete"].some((k) => memberCan(r, k) && !(now?.D && can(now.D, k)))) out.push({ what: "D", where: r.table });
  }
  for (const b of before.storage?.buckets ?? []) if (lost(b.A, after.storage?.buckets?.find((x) => x.bucket === b.bucket)?.A)) out.push({ what: "A", where: `storage bucket ${b.bucket}` });
  return out;
}

// The loader reports a failed statement as a one-line preview, cut at 140 characters.
function sameStatement(preview, statement) {
  const line = statement.replace(/\s+/g, " ").trim();
  return preview.replace(/\.\.\.$/, "") === (line.length > 140 ? line.slice(0, 137) : line);
}

function literal(text) {
  return `'${String(text).replace(/'/g, "''")}'`;
}

function list(words) {
  return words.length > 1 ? `${words.slice(0, -1).join(", ")} or ${words.at(-1)}` : words[0] ?? "";
}

// The tested fixes for problems, as a migration. Fixes for things that may be on
// purpose stay commented out, and problems without a tested fix are named.
export function fixesMigration(report, version) {
  const tested = (review) => report.findings
    .filter((f) => (f.severity === "review") === review)
    .map((f) => ({ f, fix: report.fixes.find((x) => x.kind === f.kind && x.where === f.where && x.verified) }));
  const lines = [
    `-- Security fixes written by rls-probe ${version}. Each one was applied to a copy of`,
    "-- the database and probed again: it closes its problem, and the owner of each row",
    "-- can still do what they could before.",
  ];
  const about = (f, fix) => [`-- ${f.title} (${f.where}).`, ...comment(`Afterwards, ${fix.effect}`)];
  for (const { f, fix } of tested(false).filter((x) => x.fix)) lines.push("", ...about(f, fix), fix.sql);
  const optional = tested(true).filter((x) => x.fix);
  if (optional.length) {
    lines.push("", "-- Worth a look, and fine if it's on purpose. Uncomment a fix only if it isn't.");
    for (const { f, fix } of optional) lines.push("", ...about(f, fix), ...fix.sql.split("\n").map((l) => `-- ${l}`));
  }
  const left = tested(false).filter((x) => !x.fix);
  const inCode = left.filter(({ f }) => CODE_KINDS.includes(f.kind));
  const late = ({ f }) => report.fixes.some((x) => x.kind === f.kind && x.where === f.where && x.untested);
  const inDatabase = left.filter((x) => !CODE_KINDS.includes(x.f.kind) && !late(x));
  const untested = left.filter(late);
  if (inDatabase.length) lines.push("", "-- No fix passed the test for these; see rls-probe's report for what to change:", ...inDatabase.map(({ f }) => `--   ${f.title} (${f.where})`));
  if (untested.length) lines.push("", "-- Not tested in time (a very large database); run rls-probe again after applying this:", ...untested.map(({ f }) => `--   ${f.title} (${f.where})`));
  if (inCode.length) lines.push("", "-- Fix these in the code, not the database:", ...inCode.map(({ f }) => `--   ${f.title} (${f.where})`));
  return `${lines.join("\n")}\n`;
}

// Text as SQL comment lines of at most 88 characters.
function comment(text) {
  const lines = [""];
  for (const word of text.split(" ")) {
    if (lines.at(-1) && lines.at(-1).length + word.length >= 85) lines.push("");
    lines[lines.length - 1] += `${lines.at(-1) ? " " : ""}${word}`;
  }
  return lines.map((l) => `-- ${l}`);
}
