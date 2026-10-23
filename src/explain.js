// What a report means for someone who doesn't read SQL, and what to ask an AI
// builder (Lovable, Bolt, Cursor, Claude) to change. Every sentence comes from the
// report: the policy names, owner columns and grants are the app's own.
import { findingId } from "./accept.js";
import { teamReach } from "./report.js";

const SEE = { read: "see", update: "change", delete: "delete", insert: "add" };
const CMD = { read: "SELECT", update: "UPDATE", delete: "DELETE", insert: "INSERT" };
const LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", review: "CHECK" };

export function explain(report) {
  const items = report.findings.map((f) => ({ id: findingId(f), severity: f.severity, kind: f.kind, where: f.where, ...say(f, report), selfFix: selfFix(f, report) }));
  const g = report.grantsChange;
  return {
    grade: grade(report),
    verdict: verdict(report),
    problems: items.filter((i) => i.severity !== "review"),
    notes: items.filter((i) => i.severity === "review"),
    grants: g ? grantsPart(g) : null,
    missing: report.load.missing ?? [],
    team: teamPart(report),
    // Accepted in the app's rls-probe.json: listed with the reason, never counted.
    accepted: (report.accepted ?? []).map((f) => ({ id: findingId(f), severity: f.severity, headline: say(f, report).headline, reason: f.reason })),
    acceptNotes: report.acceptNotes ?? [],
  };
}

// What a plain member of the same group can do with another member's rows: shown so
// the owner can check it's what members should share, never counted as a problem.
function teamPart(report) {
  if (!report.teams?.length) return null;
  const reach = teamReach(report.results);
  const via = list(report.teams, "and");
  return {
    reach,
    headline: reach.length
      ? `Teammates: a plain member of the same group (through ${via}) can ${list(reach.map((t) => `${list(t.actions.map((a) => SEE[a]), "and")} ${t.table}`), "and")} of other members. Check that's what members should share.`
      : `Teammates: a plain member of the same group (through ${via}) can't reach other members' rows anywhere. If members are meant to share, check the policies.`,
  };
}

// A letter grade anyone reads at a glance: F with any critical problem, D with a
// high one, C with a medium one, B with only things to check, grants to add or
// tables it couldn't see, A when clean. Null when nothing was checked.
export function grade(report) {
  if (!report.results.length) return null;
  const has = (severity) => report.findings.some((f) => f.severity === severity);
  if (has("critical")) return "F";
  if (has("high")) return "D";
  if (has("medium")) return "C";
  const g = report.grantsChange;
  const grants = g && (g.breaks.length || g.server.length || g.unsafe.length || g.closedNoRls.length);
  return has("review") || grants || report.load.missing?.length ? "B" : "A";
}

// A README badge with the grade, in the grade card's colour, linking to the web page.
// It shows the grade on the day it was made: re-running rls-probe keeps it honest.
const BADGE_COLOUR = { A: "1d3b8c", B: "1f7a4d", C: "b45a00", D: "c2410c", F: "c2142d" };
export const SITE = "https://zkousama.github.io/rls-probe/";
export function badge(report) {
  const g = grade(report);
  return g ? `[![rls-probe: grade ${g}](https://img.shields.io/badge/rls--probe-grade%20${g}-${BADGE_COLOUR[g]})](${SITE})` : null;
}

// The text the CLI prints first, before the details.
export function renderPlain(report) {
  const e = explain(report);
  const out = [`rls-probe: ${e.grade ? `grade ${e.grade}. ` : ""}${capitalize(e.verdict)}`, ""];
  for (const p of e.problems) out.push(`  ${LABEL[p.severity].padEnd(8)}  ${p.headline}`);
  if (e.problems.length) out.push("");
  if (e.notes.length) {
    out.push("Worth a look, and fine if it's on purpose:");
    for (const n of e.notes) out.push(`  - ${n.headline}`);
    out.push("");
  }
  if (e.grants) out.push(e.grants.headline, "");
  if (e.team) out.push(e.team.headline, "");
  if (e.accepted.length) {
    out.push("Accepted in rls-probe.json, so not counted:");
    for (const a of e.accepted) out.push(`  - ${a.id}: ${a.reason}`);
    out.push("");
  }
  for (const note of e.acceptNotes) out.push(note, "");
  if (e.missing.length) out.push(`Not checked: ${e.missing.join(", ")}. Your migrations use these tables but never create them (were they made in the dashboard?).`, "");
  if (e.problems.length || e.grants?.lines.length) out.push("To fix them with Lovable or Bolt: run rls-probe with --prompt and paste what it prints.", "");
  if (e.problems.length || e.notes.length) out.push("To have an agent that reads your code (Claude Code, Cursor, Codex) check each one and fix the real ones: run it with --review and paste what it prints.", "");
  if (e.problems.length) out.push("To write the fixes that pass rls-probe's own test as a migration: run it with --fix-policies.", "");
  return out.join("\n");
}

// A prompt to paste into an AI builder: what's wrong, what to change, and what
// must keep working.
export function fixPrompt(report) {
  const e = explain(report);
  if (!e.problems.length && !e.grants?.lines.length) return "rls-probe found nothing to fix.\n";
  const out = [
    "Please fix these database security problems in my Supabase app. Make each change in a new SQL migration in supabase/migrations.",
    "Keep every user able to see, change and delete their own data, and keep anything that is meant to be public working.",
    "",
  ];
  e.problems.forEach((p, i) => {
    out.push(`${i + 1}. ${p.headline}`, `   ${p.ask}`, "");
    if (p.selfFix?.tested) out.push(`   rls-probe tested this SQL on a copy of the database. It closes the problem, and afterwards ${p.selfFix.effect}`, "", ...p.selfFix.code.split("\n").map((l) => `   ${l}`), "");
  });
  if (e.grants?.lines.length) {
    out.push("Supabase no longer gives new tables access by default (from October 30, 2026). Add a migration with exactly these lines:", "", ...e.grants.lines, "");
    if (e.grants.holdBack.length) out.push(`Don't grant anon or authenticated anything on ${list(e.grants.holdBack, "or")} until the problems above are fixed.`, "");
  }
  if (e.notes.length) {
    out.push("Also check these, and change them only if they aren't meant to be public:");
    for (const n of e.notes) out.push(`- ${n.headline} ${n.ask}`);
    out.push("");
  }
  out.push("When you're done, tell me, so I can run rls-probe again to check.");
  return `${out.join("\n")}\n`;
}

// For GitHub's job summary and pull requests, and for AI agents.
export function renderMarkdown(report, details = "") {
  const e = explain(report);
  const out = [`### rls-probe: ${e.grade ? `grade ${e.grade}. ` : ""}${capitalize(e.verdict)}`, ""];
  if (e.problems.length || e.notes.length) {
    out.push("| | Problem | Where |", "|---|---|---|");
    for (const p of [...e.problems, ...e.notes]) out.push(`| ${LABEL[p.severity]} | ${p.headline} | \`${p.where}\` |`);
    out.push("");
  }
  if (e.grants) out.push(e.grants.headline, "");
  if (e.team) out.push(e.team.headline, "");
  if (e.accepted.length) out.push(`Accepted in \`rls-probe.json\`, so not counted: ${e.accepted.map((a) => `\`${a.id}\` (${a.reason})`).join(", ")}.`, "");
  for (const note of e.acceptNotes) out.push(note, "");
  if (e.missing.length) out.push(`Not checked: ${e.missing.map((t) => `\`${t}\``).join(", ")}. The migrations use these tables but never create them.`, "");
  if (e.problems.length || e.grants?.lines.length) {
    out.push("<details><summary>Fix prompt for Lovable, Bolt, Cursor or Claude</summary>", "", "```text", fixPrompt(report).trimEnd(), "```", "", "</details>", "");
  }
  if (details) out.push("<details><summary>Full report</summary>", "", "```text", details.trimEnd(), "```", "", "</details>", "");
  return out.join("\n");
}

function verdict(report) {
  const tables = report.results.length;
  if (!tables) return "nothing was checked. The migrations create no tables in public, so this is not an all clear.";
  const problems = report.findings.filter((f) => f.severity !== "review").length;
  const notes = report.findings.length - problems;
  const checked = `${tables} table${tables === 1 ? "" : "s"} checked`;
  if (problems) return `${problems} problem${problems === 1 ? "" : "s"} to fix (${checked}).`;
  return `no problems found (${checked})${notes ? `, ${notes} thing${notes === 1 ? "" : "s"} worth a look` : ""}.`;
}

function grantsPart(g) {
  const lines = [...g.breaks.flatMap((b) => b.grant), ...g.server.flatMap((s) => s.grant)];
  const holdBack = [...g.unsafe.map((u) => u.table), ...g.closedNoRls.map((c) => c.table)];
  const stop = g.breaks.length + g.unsafe.length;
  const parts = [];
  if (stop) parts.push(`${stop} table${stop === 1 ? "" : "s"} will answer "permission denied" to your users in a fresh database until they're granted access${g.breaks.length ? `; ${g.breaks.length} ${g.breaks.length === 1 ? "is" : "are"} safe to grant now` : ""}${holdBack.length ? `, and ${list(holdBack, "and")} must be fixed first` : ""}.`);
  if (g.server.length) parts.push(`Your edge functions and server code need grants on ${g.server.length} table${g.server.length === 1 ? "" : "s"} too.`);
  // summary: what changes, said anywhere; headline adds how to act from the command line.
  const summary = parts.length ? parts.join(" ") : "Every table already has the grants it needs.";
  const headline = `After October 30: ${summary}${parts.length ? " Run rls-probe with --fix to write the safe grants as a migration." : ""}`;
  return { headline, summary, lines, holdBack };
}

// The headline and the ask for one finding.
function say(f, report) {
  const t = f.where;
  const result = report.results.find((r) => r.table === t);
  const owner = ownerCondition(result);
  const including = f.columns?.length ? `, including ${list(f.columns.map(human), "and")}` : "";
  const acts = (f.actions ?? []).map((a) => SEE[a]);
  const policies = (actions, role) => policyRef(report.policies?.[t] ?? [], actions, role);
  // When the policies at fault are named for the service role, that is the whole fix.
  const unlessServerOnly = (actions, role, rest) => {
    const hint = serviceRoleHint(report.policies?.[t] ?? [], actions, role);
    return hint.all ? hint.text : `${hint.text}${rest}`;
  };
  switch (f.kind) {
    case "rls-off":
    case "rls-off-users":
      return {
        headline: `${f.kind === "rls-off" ? "Anyone on the internet" : "Any signed-in user"} can ${list(acts, "and")} every row in the ${t} table${including}.`,
        ask: result && !result.owned
          ? `Turn on row-level security for the "${t}" table (alter table public.${t} enable row level security;). With no policies, only server code using the service role can reach it; then add a policy only for what visitors or users need${f.columns?.length ? `, never one that lets them read ${list(f.columns.map(human), "or")}` : ""}.`
          : `Turn on row-level security for the "${t}" table (alter table public.${t} enable row level security;) and add policies so ${owner ? `each user can only see and change their own rows (${owner})` : "only the right people can see and change it"}.`,
      };
    case "visitor-write":
      return {
        headline: `Anyone on the internet, without signing in, can ${list(acts, "and")} rows in the ${t} table.`,
        ask: unlessServerOnly(f.actions, "anon", `If visitors are meant to ${list(acts, "or")} rows in "${t}" (a booking, contact or feedback form, say), keep ${policies(f.actions, "anon")} but make it accept only the values it should. Otherwise ${result?.owned ? `only signed-in users should ${list(acts, "or")} their own rows: change it so it applies to the authenticated role and checks ${owner}` : "limit it to signed-in users"}.`),
      };
    case "visitor-read":
      return {
        headline: `Anyone on the internet can see your users' ${t}${including}.`,
        ask: f.columns?.length
          ? `The "${t}" table is readable by anyone, including ${list(f.columns, "and")}. If it must stay public, move those columns into a separate table that only the owner can read. Otherwise change ${policies(["read"], "anon")} so users only see their own rows (${owner}).`
          : `Check that everything in "${t}" is meant to be public. If not, change ${policies(["read"], "anon")} so users only see their own rows (${owner}).`,
      };
    case "user-read":
      return {
        headline: `Any signed-in user can see other users' ${t}${including}.`,
        ask: `Change ${policies(["read"], "authenticated")} on "${t}" so a user only sees their own rows (${owner}), plus anything that is meant to be shared.`,
      };
    case "user-write":
      return {
        headline: `Any signed-in user can ${list(acts, "and")} other users' ${t}.`,
        ask: unlessServerOnly(f.actions, "authenticated", `Change ${policies(f.actions, "authenticated")} on "${t}" so a user can only ${list(acts, "or")} rows where ${owner}. Use that condition in both "using" and "with check".`),
      };
    case "shared-write":
      return {
        headline: `Any signed-in user can ${list(acts, "and")} rows in the ${t} table, which everyone shares.`,
        ask: unlessServerOnly(f.actions, "authenticated", `Only admins should ${list(acts, "or")} rows in "${t}". Change ${policies(f.actions, "authenticated")} to require an admin (for example a check against a roles table) instead of any signed-in user.`),
      };
    case "impersonation":
      return {
        headline: `A signed-in user can add rows to ${t} in someone else's name.`,
        ask: `In ${policies(["insert"], "authenticated")} on "${t}", add with check (${owner}) so users can only create rows as themselves.`,
      };
    case "view-bypass":
      return {
        headline: `The ${t} view shows its rows to anyone, skipping the rules on the tables underneath.`,
        ask: `Make the "${t}" view follow the tables' rules (alter view public.${t} set (security_invoker = true);), or check it shows nothing private.`,
      };
    case "definer-function": {
      const who = f.callers === "anyone" ? "anyone on the internet" : "any signed-in user";
      // The worst thing the call did: deleting, then changing, then adding.
      const did = ["deleted", "changed", "added"].map((how) => f.proof?.changed.find((c) => c.how === how)).find(Boolean);
      return {
        headline: did?.how === "added"
          ? `${capitalize(who)} can call the database function ${f.function}() to add rows to ${did.table} in other users' names: rls-probe tried it, and one was added for the test user. Fine if that's what it's for, like a public booking form.`
          : did
          ? `${capitalize(who)} can call the database function ${f.function}() to ${did.how === "deleted" ? "delete" : "change"} other users' ${did.table}: rls-probe tried it, and the test user's row in ${did.table} was ${did.how}.`
          : f.leak
            ? `${capitalize(who)} can call the database function ${f.function}() and get other users' private data back: rls-probe tried it.`
            : f.counter
              ? `${capitalize(who)} can call the database function ${f.function}(), which changes ${list(f.counter.columns.map(human), "and")} on other users' ${f.counter.table}. It looks like a counter: check that's all it does.`
              : f.refusal
                ? `The database function ${f.function}() runs with full rights and ${who} can call it, but it turned rls-probe away ("${f.refusal.slice(0, 80)}").`
                : f.checks
                  ? `The database function ${f.function}() runs with full rights and ${who} can call it; it checks who's calling, so it's likely fine. Worth a read to confirm.`
                : `The database function ${f.function}() runs with full rights, and ${who} can call it${f.writes ? " to change data" : ""}.${f.tried ? " rls-probe tried it on another user's rows and nothing changed." : ""}`,
        ask: `In ${f.function}, check that the caller is allowed (with auth.uid()) before it reads or changes anything, or stop ${f.callers === "anyone" ? "visitors and users" : "users"} calling it: revoke execute on function public.${t} from public, anon, authenticated; (revoking only from anon isn't enough: Postgres lets public run every function).`,
      };
    }
    case "storage-visitor-write":
    case "storage-visitor-read":
    case "storage-user-write":
    case "storage-user-upload":
    case "storage-user-read": {
      const b = f.bucket;
      // The storage policies for this bucket, and those for every bucket.
      const files = (report.policies?.["storage.objects"] ?? []).filter((p) => {
        const rule = `${p.using ?? ""} ${p.check ?? ""}`;
        return !/bucket_id/.test(rule) || rule.includes(`'${b}'`);
      });
      const ref = (actions, role) => policyRef(files, actions, role).replace(/ policies$/, " policies on storage.objects");
      const own = "(storage.foldername(name))[1] = (select auth.uid())::text";
      const says = {
        "storage-visitor-write": [`Anyone on the internet, without signing in, can ${list(acts, "and")} files in other people's folders in the "${b}" bucket.`,
          f.actions.some((a) => a !== "insert")
            ? `Change ${ref(f.actions, "anon")} so only signed-in users can ${list(acts, "or")} files, and only in their own folder: ${own}.`
            : `If visitors are meant to upload here (a form, say), keep ${ref(["insert"], "anon")} but limit the bucket's file size and types. Otherwise change it so only signed-in users upload, into their own folder: ${own}.`],
        "storage-visitor-read": [`Anyone on the internet can list and download users' files in the private "${b}" bucket.`, `If these files are meant to be public (a gallery or product photos, say), make the bucket public instead. Otherwise change ${ref(["read"], "anon")} so only signed-in users read files, and only their own: ${own}.`],
        "storage-user-write": [`Any signed-in user can ${list(acts, "and")} other users' files in the "${b}" bucket.`, `Change ${ref(f.actions, "authenticated")} so users can only ${list(acts, "or")} files in their own folder: ${own}.`],
        "storage-user-upload": [`A signed-in user can upload files into someone else's folder in the "${b}" bucket.`, `In ${ref(["insert"], "authenticated")}, add with check (${own}) so users can only upload into their own folder.`],
        "storage-user-read": [`Any signed-in user can download other users' files in the "${b}" bucket.`, `If these files are private, change ${ref(["read"], "authenticated")} so users only read their own folder: ${own}.`],
      }[f.kind];
      return { headline: says[0], ask: says[1] };
    }
    case "public-bucket":
      return {
        headline: `Files in the "${f.bucket}" storage bucket can be downloaded by anyone who has the link.`,
        ask: `If "${f.bucket}" holds anything private, make the bucket private and share files with signed URLs.`,
      };
    case "service-key":
      if (f.test) return { headline: `What looks like a secret Supabase key (${f.key === "secret" ? "an sb_secret_ key" : "a service role key"}) is in a test file, ${t}; probably made up for the test.`, ask: `If it's a real key, remove it from ${t} and replace it in the Supabase dashboard: in a public repository anyone can read it. If it's made up, accept it in rls-probe.json.` };
      return {
        headline: `Your secret Supabase key (${f.key === "secret" ? "an sb_secret_ key" : "the service role key"}) is in your app's code at ${t}, so anyone can copy it and skip every rule.`,
        ask: `Remove the key from ${t}. Anything that needs it must run in a Supabase edge function, never in the browser. Then replace the key, because it has already been exposed.`,
      };
    case "secret":
      if (f.test) return { headline: `What looks like ${/^[aeiou]/i.test(f.title) ? "an" : "a"} ${f.title} is in a test file, ${t}; probably made up for the test.`, ask: `If it's a real key, remove it from ${t} and rotate it with the provider: in a public repository anyone can read it. If it's made up, accept it in rls-probe.json.` };
      return {
        headline: `${/^[aeiou]/i.test(f.title) ? "An" : "A"} ${f.title} is in your app's code at ${t}.`,
        ask: `Remove it from ${t}, use it only in server code (an edge function), and rotate it with the provider, because it has already been exposed.`,
      };
    case "browser-secret":
      return {
        headline: `${f.variable} sends a secret to every visitor's browser (${t}).`,
        ask: `Variables starting with VITE_, NEXT_PUBLIC_, PUBLIC_ or EXPO_PUBLIC_ are built into the website. Rename ${f.variable} without that prefix and use it only in server code.`,
      };
    case "open-function":
      if (f.missing) return { headline: `The edge function ${f.function} accepts calls without a login, and its code isn't in the repository to check.`, ask: `Confirm that ${f.function} checks a user token or, for a webhook, the sender's signature.` };
      return f.severity === "review"
        ? { headline: `The edge function ${f.function} accepts calls without a login; its code seems to check them itself.`, ask: `Confirm that ${f.function} rejects calls without a valid user token or webhook signature.` }
        : { headline: `The edge function ${f.function} can be run by anyone on the internet.`, ask: `In the edge function ${f.function}, check who's calling before doing anything: verify the user's token, or the webhook's signature.` };
    default:
      return { headline: `${f.title} (${t}).`, ask: f.fix ?? f.detail };
  }
}

// For people who run their own Supabase project: the change as a step they can take
// themselves. Only for fixes that are a single safe statement or setting; changing
// what a policy allows is left to the request above. (Lovable Cloud projects have no
// Supabase dashboard, so the request stays the main path.)
function selfFix(f, report) {
  // When the fixes were tested, a change to the database is offered only if it worked.
  if (report.fixes && !["service-key", "secret", "browser-secret", "open-function"].includes(f.kind)) {
    const fix = report.fixes.find((x) => x.kind === f.kind && x.where === f.where);
    return fix?.verified ? { where: "SQL Editor", code: fix.sql, tested: true, effect: fix.effect } : null;
  }
  const t = f.where;
  switch (f.kind) {
    case "rls-off":
    case "rls-off-users": {
      const route = report.results.find((r) => r.table === t)?.ownedThrough;
      const owner = route?.length === 1 ? route[0].column : null;
      return {
        where: "SQL Editor",
        code: owner
          ? `alter table public.${t} enable row level security;\ncreate policy "Owners manage their rows" on public.${t} for all to authenticated\n  using (${owner} = (select auth.uid())) with check (${owner} = (select auth.uid()));`
          : `alter table public.${t} enable row level security;\n-- Then add policies for who may read and change it: until then, nobody can.`,
      };
    }
    case "view-bypass":
      return { where: "SQL Editor", code: `alter view public.${t} set (security_invoker = true);` };
    case "definer-function":
      return { where: "SQL Editor", code: `revoke execute on function public.${t} from public, anon, authenticated;` };
    case "public-bucket":
      return { where: "SQL Editor", code: `update storage.buckets set public = false where id = '${f.bucket.replace(/'/g, "''")}';` };
    case "service-key":
      return { where: "Settings → API Keys", code: "Create a new secret key, put it wherever your server code used the old one, then delete the old secret key (or deactivate a legacy service_role key)." };
    case "open-function":
      return f.severity === "review" ? null : { where: "supabase/config.toml", code: `# Under [functions.${f.function}], remove this line, then deploy the function again:\nverify_jwt = false` };
    default:
      return null;
  }
}

// "user_id = auth.uid()", or the route through a parent row.
function ownerCondition(result) {
  const route = result?.ownedThrough;
  if (!route?.length) return "the row belongs to the signed-in user";
  if (route.length === 1) return `${route[0].column} = auth.uid()`;
  const [first, ...rest] = route;
  return `${first.column} points to a ${first.table} row whose ${rest[0].column}${rest.length > 1 ? " leads to the signed-in user" : " = auth.uid()"}`;
}

// The policies behind a finding: those for its commands that apply to the role.
function policyRef(policies, actions, role) {
  const cmds = new Set((actions ?? []).map((a) => CMD[a]));
  const named = policies.filter((p) => (p.cmd === "ALL" || cmds.has(p.cmd)) && p.roles.some((r) => r === role || r === "public"));
  if (!named.length) return `its ${list([...cmds].map((c) => c.toLowerCase()), "and")} policies`;
  const quoted = named.map((p) => `"${p.name}"${p.using === "true" || p.check === "true" ? ` (${p.using === "true" ? "using" : "with check"} true)` : ""}`);
  return `${named.length === 1 ? "the policy" : "the policies"} ${list(quoted, "and")}`;
}

// Policies named for the service role (or "system") but written for everyone: a
// common slip. The service role skips row-level security anyway. all: whether
// they're the only policies at fault.
function serviceRoleHint(policies, actions, role) {
  const cmds = new Set((actions ?? []).map((a) => CMD[a]));
  const atFault = policies.filter((p) => (p.cmd === "ALL" || cmds.has(p.cmd)) && p.roles.some((r) => r === role || r === "public"));
  const meant = atFault.filter((p) => /service[ _-]?role|\bsystem\b|\bbackend\b|\bserver\b/i.test(p.name));
  if (!meant.length) return { text: "", all: false };
  const one = meant.length === 1;
  const text = `${one ? "The policy" : "The policies"} ${list(meant.map((p) => `"${p.name}"`), "and")} ${one ? "is" : "are"} named for the service role but ${one ? "applies" : "apply"} to everyone. The service role skips row-level security anyway, so drop ${one ? "it" : "them"}, or add "to service_role".`;
  return { text: meant.length === atFault.length ? text : `${text} `, all: meant.length === atFault.length };
}

function capitalize(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function human(column) {
  return column.replace(/_/g, " ");
}

function list(words, joiner) {
  const w = [...new Set(words)];
  return w.length > 1 ? `${w.slice(0, -1).join(", ")} ${joiner} ${w.at(-1)}` : w[0] ?? "";
}
