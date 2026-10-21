export const SENSITIVE = /(email|phone|address|latitude|longitude|zip_code|postal|password|token|secret|iban|ssn|birth|salary|stripe|customer_id|api_key)/i;
const ORDER = { critical: 0, high: 1, medium: 2, review: 3 };

export function findingsFrom(results, views, functions, buckets) {
  const findings = [];
  for (const r of results) {
    if (r.skipped || !r.anon) continue;
    const { anon, B } = r;
    const exposedTo = (who) => (who.exposed?.length ? ` That includes ${who.exposed.join(", ")}.` : "");
    const anonWrites = ["update", "delete", "insert"].filter((k) => anon[k]);
    const userWrites = ["update", "delete"].filter((k) => B[k]);
    if (!r.rls && (anon.read || anonWrites.length)) {
      findings.push({ severity: "critical", where: r.table, title: "Row-level security is off",
        detail: `Anyone with the public key can ${verbs(["read", ...anonWrites])} every row.${exposedTo(anon)}`,
        fix: `alter table public.${r.table} enable row level security; then add policies${r.owned ? " that compare the owner column to auth.uid()" : ""}.` });
      continue;
    }
    if (anonWrites.length) {
      findings.push({ severity: r.owned ? "critical" : "high", where: r.table, title: "Visitors who aren't signed in can change data",
        detail: `Without signing in, anyone can ${verbs(anonWrites)} rows.`, fix: "Limit the insert, update and delete policies to the authenticated role, and check ownership with auth.uid()." });
    }
    if (r.owned && anon.read) {
      findings.push({ severity: anon.exposed?.length ? "high" : "review", where: r.table, title: "Visitors can read users' data",
        detail: `Without signing in, anyone can read rows that belong to users.${exposedTo(anon)} If the table is meant to be public, like published posts, make sure nothing private is in it.`, fix: "Drop the `using (true)` select policy, or move public columns into a view and keep the table private." });
    } else if (r.owned && B.read) {
      findings.push({ severity: B.exposed?.length ? "high" : "review", where: r.table, title: "Users can read each other's data",
        detail: `A signed-in user can read rows that belong to someone else.${exposedTo(B)}`, fix: "Change the select policy to compare the owner column to auth.uid()." });
    }
    if (userWrites.length) {
      findings.push({ severity: "high", where: r.table, title: r.owned ? "Users can change each other's data" : "Any signed-in user can change shared data",
        detail: `A signed-in user can ${verbs(userWrites)} ${r.owned ? "rows that belong to someone else" : "rows of this table"}.`,
        fix: r.owned ? "Add `using (owner = auth.uid())` to the update and delete policies." : "Keep writes to an admin role, for example with a check on a role claim or an admins table." });
    }
    if (r.owned && B.insert) {
      findings.push({ severity: "medium", where: r.table, title: "Users can create rows in someone else's name",
        detail: "A signed-in user can insert a row whose owner is another user.", fix: "Add `with check (owner = auth.uid())` to the insert policy." });
    }
  }
  for (const v of views) {
    if (v.anonRows > 0 && !v.invoker) {
      findings.push({ severity: "review", where: v.view, title: "View readable by anyone, without the table's rules",
        detail: `Views run as their owner, so row-level security on the tables underneath doesn't apply. A visitor sees ${v.anonRows} rows.`,
        fix: `alter view public.${v.view} set (security_invoker = true); or revoke select from anon.` });
    }
  }
  for (const f of functions) {
    if (!f.definer || f.returns === "trigger" || !(f.anon || f.authenticated)) continue;
    const checks = /auth\.(uid|jwt|role)\(\)/.test(f.body);
    if (checks && !f.anon) continue;
    const writes = /\b(insert\s+into|update\s+[\w."]+\s+set|delete\s+from)\b/i.test(f.body);
    findings.push({ severity: checks || !writes ? "review" : "high", where: `${f.name}(${f.args})`, title: "Function runs with full rights and anyone can call it",
      detail: `It's security definer, so it skips row-level security, and ${f.anon ? "visitors who aren't signed in" : "any signed-in user"} can call it${checks ? "." : ". It never checks auth.uid()."}${writes ? "" : " It only reads, but it can still reveal data the tables would hide."}`,
      fix: `revoke execute on function public.${f.name}(${f.args}) from anon${f.anon ? ", authenticated" : ""}; or check auth.uid() inside it.` });
  }
  for (const b of buckets) {
    if (b.public) findings.push({ severity: "review", where: `storage bucket ${b.id}`, title: "Public storage bucket",
      detail: "Every file in it can be downloaded by anyone who has or guesses its path.", fix: "Fine for avatars and product photos. For anything private, make the bucket private and use signed URLs." });
  }
  return findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

export function renderText({ target, load, seedProblems, results, findings }) {
  const out = [];
  out.push(`rls-probe ${target}`, "");
  out.push(`Migrations: ${load.applied} statements applied, ${load.skipped.length} skipped, ${load.failed.length} failed.`);
  if (load.failed.length) for (const f of load.failed.slice(0, 10)) out.push(`  failed in ${f.file}: ${f.error}`, `    ${f.statement}`);
  for (const p of seedProblems) out.push(`  couldn't seed ${p.table}: ${p.error}`);
  out.push("", "Who can reach a user's rows (user A's), other than A:", "");
  const yes = (v) => (v ? "yes" : "-");
  const rows = results.filter((r) => r.anon).map((r) => [
    r.table, r.rls ? "on" : "OFF", r.owned ? "users" : "shared",
    yes(r.anon.read), yes(r.anon.update), yes(r.anon.delete), yes(r.anon.insert),
    yes(r.B.read), yes(r.B.update), yes(r.B.delete), yes(r.B.insert),
  ]);
  const head = [["table", "RLS", "rows", "read", "edit", "delete", "create", "read", "edit", "delete", "create"]];
  const widths = head[0].map((_, i) => Math.max(...[...head, ...rows].map((r) => r[i].length)));
  const line = (r) => r.map((c, i) => c.padEnd(widths[i])).join("  ").trimEnd();
  const lead = widths.slice(0, 3).reduce((a, w) => a + w + 2, 0);
  const visitor = widths.slice(3, 7).reduce((a, w) => a + w + 2, 0);
  out.push(`${" ".repeat(lead)}${"visitor (not signed in)".padEnd(visitor)}another signed-in user`);
  out.push(line(head[0]));
  for (const r of rows) out.push(line(r));
  for (const r of results.filter((x) => x.skipped)) out.push(`${r.table}: not probed (${r.skipped})`);
  out.push("", "\"shared\" tables have no owner, like a list of categories: being readable by everyone is often intended.");
  out.push("", findings.length ? `${findings.length} finding${findings.length === 1 ? "" : "s"}` : "No findings.", "");
  for (const f of findings) {
    out.push(`${f.severity.toUpperCase().padEnd(8)} ${f.where}: ${f.title}`);
    out.push(`         ${f.detail}`);
    if (f.fix) out.push(`         Fix: ${f.fix}`);
    out.push("");
  }
  return out.join("\n");
}

function verbs(list) {
  const words = list.map((v) => ({ read: "read", update: "edit", delete: "delete", insert: "create" })[v]);
  return words.length > 1 ? `${words.slice(0, -1).join(", ")} and ${words.at(-1)}` : words[0];
}
