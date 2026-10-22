// What a report means for someone who doesn't read SQL, and what to ask an AI
// builder (Lovable, Bolt, Cursor, Claude) to change. Every sentence comes from the
// report: the policy names, owner columns and grants are the app's own.

const SEE = { read: "see", update: "change", delete: "delete", insert: "add" };
const CMD = { read: "SELECT", update: "UPDATE", delete: "DELETE", insert: "INSERT" };
const LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", review: "CHECK" };

export function explain(report) {
  const items = report.findings.map((f) => ({ severity: f.severity, where: f.where, ...say(f, report) }));
  const g = report.grantsChange;
  return {
    verdict: verdict(report),
    problems: items.filter((i) => i.severity !== "review"),
    notes: items.filter((i) => i.severity === "review"),
    grants: g ? grantsPart(g) : null,
    missing: report.load.missing ?? [],
  };
}

// The text the CLI prints first, before the details.
export function renderPlain(report) {
  const e = explain(report);
  const out = [`rls-probe: ${e.verdict}`, ""];
  for (const p of e.problems) out.push(`  ${LABEL[p.severity].padEnd(8)}  ${p.headline}`);
  if (e.problems.length) out.push("");
  if (e.notes.length) {
    out.push("Worth a look, and fine if it's on purpose:");
    for (const n of e.notes) out.push(`  - ${n.headline}`);
    out.push("");
  }
  if (e.grants) out.push(e.grants.headline, "");
  if (e.missing.length) out.push(`Not checked: ${e.missing.join(", ")}. Your migrations use these tables but never create them (were they made in the dashboard?).`, "");
  if (e.problems.length || e.grants?.lines.length) out.push("To fix them with Lovable, Bolt, Cursor or Claude: run rls-probe with --prompt and paste what it prints.", "");
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
  e.problems.forEach((p, i) => out.push(`${i + 1}. ${p.headline}`, `   ${p.ask}`, ""));
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
  const out = [`### rls-probe: ${e.verdict}`, ""];
  if (e.problems.length || e.notes.length) {
    out.push("| | Problem | Where |", "|---|---|---|");
    for (const p of [...e.problems, ...e.notes]) out.push(`| ${LABEL[p.severity]} | ${p.headline} | \`${p.where}\` |`);
    out.push("");
  }
  if (e.grants) out.push(e.grants.headline, "");
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
  const headline = parts.length
    ? `After October 30: ${parts.join(" ")} Run rls-probe with --fix to write the safe grants as a migration.`
    : "After October 30: every table already has the grants it needs.";
  return { headline, lines, holdBack };
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
        ask: `Turn on row-level security for the "${t}" table (alter table public.${t} enable row level security;) and add policies so ${owner ? `each user can only see and change their own rows (${owner})` : "only the right people can see and change it"}.`,
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
    case "definer-function":
      return {
        headline: `The database function ${f.function}() runs with full rights, and ${f.callers === "anyone" ? "anyone on the internet" : "any signed-in user"} can call it${f.writes ? " to change data" : ""}.`,
        ask: `In ${f.function}, check that the caller is allowed (with auth.uid()) before it reads or changes anything, or stop ${f.callers === "anyone" ? "visitors" : "users"} calling it: revoke execute on function public.${t} from ${f.callers === "anyone" ? "anon, authenticated" : "authenticated"};`,
      };
    case "public-bucket":
      return {
        headline: `Files in the "${f.bucket}" storage bucket can be downloaded by anyone who has the link.`,
        ask: `If "${f.bucket}" holds anything private, make the bucket private and share files with signed URLs.`,
      };
    case "service-key":
      return {
        headline: `Your secret Supabase key (the service role key) is in your app's code at ${t}, so anyone can copy it and skip every rule.`,
        ask: `Remove the service role key from ${t}. Anything that needs it must run in a Supabase edge function, never in the browser. Then rotate the key in the Supabase dashboard (Project Settings, API keys), because it has already been exposed.`,
      };
    case "secret":
      return {
        headline: `A ${f.title.replace(/^./, (c) => c.toLowerCase())} is in your app's code at ${t}.`,
        ask: `Remove it from ${t}, use it only in server code (an edge function), and rotate it with the provider, because it has already been exposed.`,
      };
    case "browser-secret":
      return {
        headline: `${f.variable} sends a secret to every visitor's browser (${t}).`,
        ask: `Variables starting with VITE_, NEXT_PUBLIC_, PUBLIC_ or EXPO_PUBLIC_ are built into the website. Rename ${f.variable} without that prefix and use it only in server code.`,
      };
    case "open-function":
      return f.severity === "review"
        ? { headline: `The edge function ${f.function} accepts calls without a login; its code seems to check them itself.`, ask: `Confirm that ${f.function} rejects calls without a valid user token or webhook signature.` }
        : { headline: `The edge function ${f.function} can be run by anyone on the internet.`, ask: `In the edge function ${f.function}, check who's calling before doing anything: verify the user's token, or the webhook's signature.` };
    default:
      return { headline: `${f.title} (${t}).`, ask: f.fix ?? f.detail };
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

function human(column) {
  return column.replace(/_/g, " ");
}

function list(words, joiner) {
  const w = [...new Set(words)];
  return w.length > 1 ? `${w.slice(0, -1).join(", ")} ${joiner} ${w.at(-1)}` : w[0] ?? "";
}
