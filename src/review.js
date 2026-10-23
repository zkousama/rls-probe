// The findings as a brief for an AI agent that can read the app's code (Claude Code,
// Cursor, Codex). rls-probe sees the database a migration builds; the agent sees the rest:
// the app's code, its server functions, what's meant to be public. So each finding comes
// with what rls-probe did and saw, where it comes from, a check to run on a local
// database, the reasons it might not apply, and the tested fix. The agent sorts each one
// before changing anything, and records the ones it rules out in rls-probe.json, so the
// next run lists them as accepted instead of flagging them again.
import { CONFIG, findingId } from "./accept.js";
import { explain } from "./explain.js";

const LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", review: "CHECK" };
const DID = { read: "read", update: "change", delete: "delete", insert: "add" };
const CMD = { read: "SELECT", update: "UPDATE", delete: "DELETE", insert: "INSERT" };
// A signed-in user who owns nothing: whatever they reach belongs to someone else.
const NOBODY = "11111111-1111-4111-8111-111111111111";
const CODE_KINDS = ["service-key", "secret", "browser-secret", "open-function"];

export function reviewBrief(report) {
  const e = explain(report);
  const items = [...e.problems, ...e.notes];
  if (!items.length) return `rls-probe found nothing to review${e.accepted.length ? `; ${CONFIG} accepts ${e.accepted.map((a) => a.id).join(", ")}` : ""}.\n`;
  const out = [
    `# rls-probe review: grade ${e.grade}, ${e.verdict}`,
    "",
    "You can read this app's code; rls-probe can't. It ran the app's Supabase migrations in a copy of the database, signed in test users, and tried every table, bucket and function as a visitor and as a user who owns nothing there. Some findings may already be handled elsewhere (a policy changed in the Supabase dashboard, server code that never exposes a table) or be on purpose (a public catalog). Please go through them one by one:",
    "",
    "1. Check each against the code and, if you can, the live policies. Decide whether it's real, already handled (say where), meant to be that way (say why), or wrong (say why).",
    "2. Fix the real ones in a new migration in supabase/migrations. Prefer the tested SQL where there is one: rls-probe applied it to a copy of the database and probed again, and it closed the problem without taking anything from the rows' owners or their teammates. Its \"afterwards\" line says what it changes for the app.",
    `3. Record the ones you rule out in ${CONFIG} at the app's root, each with its reason, so rls-probe lists them as accepted instead of flagging them:`,
    "",
    "```json",
    `{ "accept": [{ "finding": "${items[0].id}", "reason": "why it's fine" }] }`,
    "```",
    "",
    "4. Run `npx rls-probe .` again and report what changed. Ask before making private anything that may be public on purpose.",
    "",
    "The SQL checks below are for a local database (`supabase start`, then `psql` on the database URL it prints). Each runs in a transaction that's rolled back, as a user id that owns nothing, so whatever comes back belongs to someone else and nothing is kept. Don't run them on production.",
  ];
  for (const [i, item] of items.entries()) {
    const f = report.findings.find((x) => findingId(x) === item.id);
    out.push("", `## ${i + 1}. ${LABEL[item.severity]} \`${item.id}\``, "", item.headline, "");
    out.push(`What rls-probe saw: ${evidence(f, report)}`, "");
    const at = where(f, report);
    if (at.length) out.push(`Where: ${at.join("; ")}.`, "");
    const sql = check(f, report);
    if (sql) out.push("Check it:", "", "```sql", sql, "```", "");
    out.push(`It may not apply if ${caveats(f).join("; or if ")}.`, "", `What to change: ${item.ask}`);
    if (item.selfFix?.tested) out.push("", `Tested fix (afterwards, ${item.selfFix.effect.replace(/\.$/, "")}):`, "", "```sql", item.selfFix.code, "```");
  }
  if (e.accepted.length) out.push("", `## Already accepted in ${CONFIG}`, "", ...e.accepted.map((a) => `- \`${a.id}\`: ${a.reason}`));
  return `${out.join("\n")}\n`;
}

// What the probe did, as whom, and what came of it.
function evidence(f, report) {
  const t = f.where;
  const r = report.results.find((x) => x.table === t);
  const acts = list((f.actions ?? []).map((a) => DID[a]));
  const rows = (n) => `${n} of user A's row${n === 1 ? "" : "s"}`;
  const cols = f.columns?.length ? `, including ${list(f.columns)}` : "";
  const stranger = "signed in as user B, who owns nothing of user A's, has no role and is in another organization";
  switch (f.kind) {
    case "rls-off":
      return `row-level security is off on ${t}. Without signing in, it could ${acts} ${r?.owned ? "user A's rows" : "every row"}${cols}.`;
    case "rls-off-users":
      return `row-level security is off on ${t}, and only missing grants keep visitors out. ${cap(stranger)}, it could ${acts} user A's rows${cols}.`;
    case "visitor-write":
      return `without signing in, it could ${acts} ${r?.owned ? "user A's rows" : "rows"} in ${t}.`;
    case "visitor-read":
      return `without signing in, it read ${rows(r?.anon?.read ?? 1)} in ${t}${cols}.`;
    case "user-read":
      return `${stranger}, it read ${rows(r?.B?.read ?? 1)} in ${t}${cols}.`;
    case "user-write":
      return `${stranger}, it could ${acts} user A's row in ${t}.`;
    case "shared-write":
      return `signed in as an ordinary user with no role, it could ${acts} rows of ${t}, which every user shares.`;
    case "impersonation":
      return `${stranger}, it added a row to ${t} whose owner is user A.`;
    case "storage-visitor-write":
    case "storage-visitor-read":
      return `without signing in, it could ${acts} a file in user A's folder (${f.bucket}/<user A's id>/...).`;
    case "storage-user-write":
    case "storage-user-upload":
    case "storage-user-read":
      return `${stranger}, it could ${acts} a file in user A's folder (${f.bucket}/<user A's id>/...).`;
    default:
      return f.detail;
  }
}

// The migration lines behind a finding: the table, view or function, and its policies.
function where(f, report) {
  if (CODE_KINDS.includes(f.kind)) return [];
  const name = f.kind === "definer-function" ? f.function : f.kind.startsWith("storage") || f.kind === "public-bucket" ? null : f.where;
  const at = (loc) => `${loc.file}:${loc.line}`;
  const out = [];
  if (name && report.createdAt?.[name]) out.push(`${name} is created at ${at(report.createdAt[name])}`);
  const table = f.kind.startsWith("storage") ? "storage.objects" : f.where;
  const cmds = new Set((f.actions ?? []).map((a) => CMD[a]));
  // For files, the policies for this bucket and those for every bucket.
  const forBucket = (p) => !f.bucket || !/bucket_id/.test(`${p.using ?? ""} ${p.check ?? ""}`) || `${p.using ?? ""} ${p.check ?? ""}`.includes(`'${f.bucket}'`);
  for (const p of (report.policies?.[table] ?? []).filter((p) => (p.cmd === "ALL" || cmds.has(p.cmd)) && forBucket(p))) {
    const loc = report.policyAt?.[table]?.[p.name];
    out.push(`policy "${p.name}" (${p.cmd.toLowerCase()}, to ${p.roles.join(", ")})${loc ? ` at ${at(loc)}` : ""}`);
  }
  return out;
}

// A read-only look, in a transaction that's rolled back, as a visitor or as a user who
// owns nothing.
function check(f, report) {
  if (CODE_KINDS.includes(f.kind) || f.kind === "public-bucket") return null;
  const visitor = /^(rls-off|visitor-|storage-visitor-|view-bypass)/.test(f.kind) && f.kind !== "rls-off-users";
  const as = visitor
    ? [`select set_config('request.jwt.claims', '{"role":"anon"}', true);`, "set local role anon;"]
    : [`select set_config('request.jwt.claims', '{"sub":"${NOBODY}","role":"authenticated"}', true);`, "set local role authenticated;"];
  const t = `public.${q(f.where)}`;
  const r = report.results.find((x) => x.table === f.where);
  const column = q(r?.columns?.find((c) => c !== "id") ?? r?.columns?.[0] ?? "id");
  const steps = [];
  const actions = f.actions ?? ["read"];
  if (f.kind === "view-bypass") steps.push(`select * from ${t} limit 5; -- rows a visitor sees through the view`);
  else if (f.kind === "definer-function") steps.push(`select * from public.${q(f.function)}(/* ${f.where.replace(/^[^(]*\(|\)$/g, "") || "no arguments"}: use another user's ids */); -- what it changes or returns`);
  else if (f.kind.startsWith("storage")) {
    if (actions.includes("read")) steps.push(`select name from storage.objects where bucket_id = '${f.bucket.replace(/'/g, "''")}' limit 5; -- other users' files`);
    if (actions.some((a) => a !== "read")) steps.push(`-- ${list(actions.filter((a) => a !== "read").map((a) => DID[a]))}: try it from the app with storage.from("${f.bucket}") on a path under another user's id`);
  } else {
    if (actions.includes("read")) steps.push(`select * from ${t} limit 5; -- ${r?.owned ? "every row here belongs to someone else" : "rows this caller can read"}`);
    if (actions.includes("update")) steps.push(`update ${t} set ${column} = ${column} returning *; -- rows this user could change`);
    if (actions.includes("delete")) steps.push(`delete from ${t} returning *; -- rows this user could delete`);
    if (actions.includes("insert")) steps.push(r?.owned ? "-- add: insert a row whose owner column holds another user's id; it goes in" : "-- add: insert any row; it goes in");
  }
  return ["begin;", ...as, ...steps, "rollback;"].join("\n");
}

// Why a finding might not hold for the real app.
function caveats(f) {
  const t = f.where;
  const dashboard = `a policy changed in the Supabase dashboard, and not in the migrations, already limits it (compare with \`select policyname, cmd, roles, qual, with_check from pg_policies where tablename = '${f.kind.startsWith("storage") ? "objects" : t}'\` on the live project)`;
  const seedData = "the rule relies on data rls-probe's test rows don't have, such as a published flag or a status";
  switch (f.kind) {
    case "rls-off":
    case "rls-off-users":
    case "visitor-read":
    case "user-read":
      return [`${t} is meant to be readable this way (a feed, a catalog, public profiles)`, dashboard, seedData];
    case "visitor-write":
      return f.actions.every((a) => a === "insert")
        ? ["visitors are meant to add rows (a contact or booking form); then check the insert policy limits what they can write", dashboard]
        : [dashboard, seedData];
    case "user-write":
    case "shared-write":
      return [dashboard, seedData, ...(f.kind === "shared-write" ? ["every signed-in user is meant to edit it (a shared board)"] : [])];
    case "impersonation":
      return ["a trigger sets the owner column from auth.uid() anyway", dashboard];
    case "definer-function":
      return ["only server code calls it, with the service role (then the tested revoke is safe)", "it checks the caller in a way rls-probe's arguments, guessed from their names, didn't reach", "its grants were changed in the dashboard"];
    case "view-bypass":
      return ["the view only shows what's meant for everyone"];
    case "public-bucket":
    case "storage-visitor-read":
    case "storage-user-read":
      return ["the files are meant to be public, like avatars or product photos", dashboard];
    case "storage-visitor-write":
    case "storage-user-write":
    case "storage-user-upload":
      return [dashboard, "the app keeps files under paths other than <user id>/..., which rls-probe assumes"];
    case "service-key":
    case "secret":
      return ["the file only runs on a server (an edge function or an API route) and never reaches a browser", "it's a placeholder, or a key already replaced (then take it out of the code anyway)"];
    case "browser-secret":
      return ["the value isn't secret, like a publishable key"];
    case "open-function":
      return ["it checks a signature or a token in a way rls-probe didn't recognise"];
    default:
      return [dashboard];
  }
}

// A quoted identifier (seed.js has the same; this keeps the web page's first load small).
function q(identifier) {
  return `"${identifier.replace(/"/g, '""')}"`;
}

function cap(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function list(words) {
  return words.length > 1 ? `${words.slice(0, -1).join(", ")} and ${words.at(-1)}` : words[0] ?? "";
}
