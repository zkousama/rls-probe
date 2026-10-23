import { findingId } from "./accept.js";

export const SENSITIVE = /(email|phone|address|latitude|longitude|zip_code|postal|password|token|secret|iban|ssn|birth|salary|stripe|customer_id|api_key)/i;
export const ORDER = { critical: 0, high: 1, medium: 2, review: 3 };
const TALLY = /(count|views?|likes?|votes?|score|clicks?|plays?|hits?|visits?|seconds|minutes|duration|attempts|usage|streak|updated_at|last_seen|last_active|last_\w+_at)/i;
// Tables a function writes a record to, about whoever it was called for.
const LOG = /(^|_)(logs?|audits?|audit_log|events?|alerts?|history|activity|activities|sessions?|attempts)$/i;

export function findingsFrom(results, views, functions, buckets, storage) {
  const findings = [];
  for (const r of results) {
    if (r.skipped || !r.anon) continue;
    const { anon, B } = r;
    const exposedTo = (who) => (who.exposed?.length ? ` That includes ${who.exposed.join(", ")}.` : "");
    const anonWrites = ["update", "delete", "insert"].filter((k) => anon[k]);
    const userWrites = ["update", "delete"].filter((k) => B[k]);
    if (!r.rls && (anon.read || anonWrites.length)) {
      findings.push({ kind: "rls-off", actions: ["read", ...anonWrites], columns: anon.exposed ?? [], severity: "critical", where: r.table, title: "Row-level security is off",
        detail: `Anyone with the public key can ${verbs(["read", ...anonWrites])} every row.${exposedTo(anon)}`,
        fix: `alter table public.${r.table} enable row level security; then add policies${r.owned ? " that compare the owner column to auth.uid()" : ""}.` });
      continue;
    }
    // Visitors kept out only by missing grants still leave every row to any signed-in user.
    const userReach = [...(B.read ? ["read"] : []), ...userWrites, ...(B.insert ? ["insert"] : [])];
    if (!r.rls && userReach.length) {
      findings.push({ kind: "rls-off-users", actions: userReach, columns: B.exposed ?? [], severity: r.owned || userReach.length > 1 ? "high" : "review", where: r.table, title: "Row-level security is off",
        detail: `Any signed-in user can ${verbs(userReach)} every row.${exposedTo(B)} Visitors are kept out only by missing grants.`,
        fix: `alter table public.${r.table} enable row level security; then add policies${r.owned ? " that compare the owner column to auth.uid()" : ""}.` });
      continue;
    }
    if (anonWrites.length) {
      // Changing or deleting is worse than adding rows, which forms and page counters do on purpose.
      const adds = anonWrites.every((a) => a === "insert");
      findings.push({ kind: "visitor-write", actions: anonWrites, severity: adds ? (r.owned ? "high" : "medium") : r.owned ? "critical" : "high", where: r.table, title: adds ? "Visitors who aren't signed in can add rows" : "Visitors who aren't signed in can change data",
        detail: `Without signing in, anyone can ${verbs(anonWrites)} rows.`, fix: "Limit the insert, update and delete policies to the authenticated role, and check ownership with auth.uid()." });
    }
    if (r.owned && anon.read) {
      findings.push({ kind: "visitor-read", actions: ["read"], columns: anon.exposed ?? [], severity: anon.exposed?.length ? "high" : "review", where: r.table, title: "Visitors can read users' data",
        detail: `Without signing in, anyone can read rows that belong to users.${exposedTo(anon)} If the table is meant to be public, like published posts, make sure nothing private is in it.`, fix: "Drop the `using (true)` select policy, or move public columns into a view and keep the table private." });
    } else if (r.owned && B.read) {
      findings.push({ kind: "user-read", actions: ["read"], columns: B.exposed ?? [], severity: B.exposed?.length ? "high" : "review", where: r.table, title: "Users can read each other's data",
        detail: `A signed-in user can read rows that belong to someone else.${exposedTo(B)}`, fix: "Change the select policy to compare the owner column to auth.uid()." });
    }
    if (userWrites.length) {
      findings.push({ kind: r.owned ? "user-write" : "shared-write", actions: userWrites, severity: "high", where: r.table, title: r.owned ? "Users can change each other's data" : "Any signed-in user can change shared data",
        detail: `A signed-in user can ${verbs(userWrites)} ${r.owned ? "rows that belong to someone else" : "rows of this table"}.`,
        fix: r.owned ? "Add `using (owner = auth.uid())` to the update and delete policies." : "Keep writes to an admin role, for example with a check on a role claim or an admins table." });
    }
    if (r.owned && B.insert) {
      findings.push({ kind: "impersonation", actions: ["insert"], severity: "medium", where: r.table, title: "Users can create rows in someone else's name",
        detail: "A signed-in user can insert a row whose owner is another user.", fix: "Add `with check (owner = auth.uid())` to the insert policy." });
    }
  }
  for (const v of views) {
    if (v.anonRows > 0 && !v.invoker) {
      findings.push({ kind: "view-bypass", severity: "review", where: v.view, title: "View readable by anyone, without the table's rules",
        detail: `Views run as their owner, so row-level security on the tables underneath doesn't apply. A visitor sees ${v.anonRows} rows.`,
        fix: `alter view public.${v.view} set (security_invoker = true); or revoke select from anon.` });
    }
  }
  for (const f of functions) {
    if (!f.definer || f.returns === "trigger" || !(f.anon || f.authenticated)) continue;
    const checks = /auth\.(uid|jwt|role)\(\)/.test(f.body);
    const writes = /\b(insert\s+into|update\s+[\w."]+\s+set|delete\s+from)\b/i.test(f.body);
    // What calling it did to user A's rows, aimed at them, as a visitor or as user B.
    // A counter going up (views, likes) or a log entry about the user is how such
    // functions are meant to work.
    const harm = (who) => (f.calls?.[who]?.changed ?? []).filter((c) => !(c.how === "changed" && c.columns.length && c.columns.every((col) => TALLY.test(col))) && !(c.how === "added" && LOG.test(c.table)));
    const by = harm("anon").length ? "anon" : harm("B").length ? "B" : null;
    const leak = f.calls?.anon?.returned ? "anon" : f.calls?.B?.returned ? "B" : null;
    if (!by && !leak && checks && !f.anon) continue;
    // Called, and all it did was move a counter.
    const counted = !by && !leak ? ["anon", "B"].find((w) => f.calls?.[w]?.changed.length) : null;
    const who = by ?? leak ?? counted ?? (f.anon ? "anon" : "B");
    const proof = by ? { changed: harm(by), called: f.called } : null;
    // Deleting or changing another user's data is worse than adding rows in their name,
    // which a booking form, say, does on purpose.
    const destroys = proof?.changed.some((c) => c.how !== "added");
    const aimed = f.called?.length ? ` with ${f.called.join(" and ")}` : "";
    // Called, aimed at A, and nothing of A's changed or came back.
    const tried = !by && !leak && !counted && Object.values(f.calls ?? {}).some((c) => c.ok);
    const caller = who === "anon" ? "visitors who aren't signed in" : "any signed-in user";
    findings.push({ kind: "definer-function", function: f.name, callers: who === "anon" ? "anyone" : "users", writes, proof, leak: Boolean(leak), tried,
      counter: counted ? { table: f.calls[counted].changed[0].table, columns: f.calls[counted].changed.flatMap((c) => c.columns) } : null,
      severity: by ? (destroys ? (by === "anon" ? "critical" : "high") : by === "anon" ? "high" : "medium") : leak ? "high" : counted || checks || !writes ? "review" : "high", where: `${f.name}(${f.args})`, title: "Function runs with full rights and anyone can call it",
      detail: proof
        ? `It's security definer, so it skips row-level security. Called by ${who === "anon" ? "a visitor" : "another signed-in user"}${aimed}, it ${proof.changed.map((c) => `${c.how} user A's row in ${c.table}${c.how === "changed" && c.columns.length ? ` (${c.columns.join(", ")})` : ""}`).join(", and ")}.`
        : leak
          ? `It's security definer, so it skips row-level security. Called by ${who === "anon" ? "a visitor" : "another signed-in user"}${aimed}, it returned user A's private data.`
          : counted
            ? `It's security definer, and ${caller} can call it. Called${aimed}, it only changed ${f.calls[counted].changed.flatMap((c) => c.columns).join(", ")} on user A's rows, which looks like a counter. Check that's all it's meant to do.`
            : `It's security definer, so it skips row-level security, and ${caller} can call it${checks ? "." : ". It never checks auth.uid()."}${writes ? "" : " It only reads, but it can still reveal data the tables would hide."}${tried ? ` rls-probe called it${aimed}, and nothing of user A's changed or came back; other arguments may still reach them.` : ""}`,
      fix: `revoke execute on function public.${f.name}(${f.args}) from public, anon, authenticated; (Postgres lets public run every function unless revoked) or check auth.uid() inside it.` });
  }
  // Files: what a visitor and another user managed to do in user A's folder.
  const own = "only in their own folder: (storage.foldername(name))[1] = auth.uid()::text";
  for (const s of (storage?.buckets ?? []).filter((b) => !b.skipped)) {
    const where = `storage bucket ${s.bucket}`;
    const anonWrites = ["update", "delete", "insert"].filter((k) => s.anon[k]);
    const userChanges = ["update", "delete"].filter((k) => s.B[k]);
    if (anonWrites.length) {
      // Replacing or deleting someone's files is worse than adding new ones, which a
      // public upload form may do on purpose.
      const changes = anonWrites.some((k) => k !== "insert");
      findings.push({ kind: "storage-visitor-write", bucket: s.bucket, actions: anonWrites, severity: changes ? "critical" : "high", where,
        title: changes ? "Visitors can change users' files" : "Visitors can upload files into users' folders",
        detail: `Without signing in, anyone can ${verbs(anonWrites)} files in a user's folder.`, fix: `Limit the storage.objects policies for this bucket to the authenticated role, ${own}.` });
    }
    // Reading a public bucket's files is what public means; that's its own finding.
    if (!s.public && s.anon.read) {
      findings.push({ kind: "storage-visitor-read", bucket: s.bucket, actions: ["read"], severity: "high", where, title: "Visitors can list and download users' files",
        detail: "The bucket is private, but its policies let anyone read the files in a user's folder without signing in.", fix: `Limit the select policy to the authenticated role, ${own}.` });
    } else if (!s.public && s.B.read) {
      findings.push({ kind: "storage-user-read", bucket: s.bucket, actions: ["read"], severity: "review", where, title: "Users can read each other's files",
        detail: "Any signed-in user can download files in someone else's folder. Fine for shared files, not for private ones.", fix: `Limit the select policy ${own}.` });
    }
    if (userChanges.length) {
      findings.push({ kind: "storage-user-write", bucket: s.bucket, actions: userChanges, severity: "high", where, title: "Users can change each other's files",
        detail: `A signed-in user can ${verbs(userChanges)} files in someone else's folder.`, fix: `Limit the update and delete policies ${own}.` });
    }
    if (s.B.insert) {
      findings.push({ kind: "storage-user-upload", bucket: s.bucket, actions: ["insert"], severity: "medium", where, title: "Users can upload into someone else's folder",
        detail: "A signed-in user can put files in another user's folder, where they look like that user's.", fix: `Add with check, ${own}, to the insert policy.` });
    }
  }
  for (const b of buckets) {
    if (b.public) findings.push({ kind: "public-bucket", bucket: b.id, severity: "review", where: `storage bucket ${b.id}`, title: "Public storage bucket",
      detail: "Every file in it can be downloaded by anyone who has or guesses its path.", fix: "Fine for avatars and product photos. For anything private, make the bucket private and use signed URLs." });
  }
  return findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

export function renderText({ target, load, seedProblems, results, findings, storage, teams = [] }) {
  const out = [];
  out.push(`rls-probe ${target}`, "");
  out.push(`Migrations: ${load.applied} statements applied, ${load.skipped.length} skipped, ${load.failed.length} failed.`);
  if (load.failed.length) for (const f of load.failed.slice(0, 10)) out.push(`  failed in ${f.file}: ${f.error}`, `    ${f.statement}`);
  if (load.missing?.length) {
    out.push("", `Never created, so not checked: ${load.missing.join(", ")}. The migrations use these tables but no file creates them; often they were made in the dashboard before migrations were kept.`);
  }
  for (const p of seedProblems) out.push(`  couldn't seed ${p.table}: ${p.error}`);
  if (!results.length) {
    out.push("", "No tables in public, so nothing was checked. This is not an all clear: the tables may have been made in the dashboard, outside these migrations.");
  } else {
    out.push("", "Who can reach a user's rows (user A's), other than A:", "");
    const yes = (v) => (v ? "yes" : "-");
    const rows = results.filter((r) => r.anon).map((r) => [
      r.table, r.rls ? "on" : "OFF", r.owned ? "users" : "shared",
      yes(r.anon.read), yes(r.anon.update), yes(r.anon.delete), yes(r.anon.insert),
      yes(r.B.read), yes(r.B.update), yes(r.B.delete), yes(r.B.insert),
    ]).concat((storage?.buckets ?? []).filter((s) => !s.skipped).map((s) => [
      `files: ${s.bucket}`, storage.rls ? "on" : "OFF", s.public ? "public" : "users",
      yes(s.anon.read), yes(s.anon.update), yes(s.anon.delete), yes(s.anon.insert),
      yes(s.B.read), yes(s.B.update), yes(s.B.delete), yes(s.B.insert),
    ]));
    const head = [["table", "RLS", "rows", "read", "edit", "delete", "create", "read", "edit", "delete", "create"]];
    const widths = head[0].map((_, i) => Math.max(...[...head, ...rows].map((r) => r[i].length)));
    const line = (r) => r.map((c, i) => c.padEnd(widths[i])).join("  ").trimEnd();
    const lead = widths.slice(0, 3).reduce((a, w) => a + w + 2, 0);
    const visitor = widths.slice(3, 7).reduce((a, w) => a + w + 2, 0);
    out.push(`${" ".repeat(lead)}${"visitor (not signed in)".padEnd(visitor)}another signed-in user`);
    out.push(line(head[0]));
    for (const r of rows) out.push(line(r));
    for (const r of results.filter((x) => x.skipped)) out.push(`${r.table}: not probed (${r.skipped})`);
    for (const r of results.filter((x) => x.anon)) {
      for (const who of ["anon", "B"]) {
        if (r[who].insertUntested) out.push(`${r.table}: couldn't test creating rows as ${who === "anon" ? "a visitor" : "another user"} (${r[who].insertUntested})`);
      }
    }
    out.push("", "\"shared\" tables have no owner, like a list of categories: being readable by everyone is often intended.");
    const team = teamReach(results);
    if (teams.length) {
      out.push("", `A teammate (a plain member of user A's group, through ${teams.join(", ")}) reached user A's rows in: ${team.length ? team.map((t) => `${t.table} (${verbs(t.actions)})`).join(", ") : "nothing"}.`);
      out.push("Sharing with teammates is usually the point, so this is not a finding. Fixes from rls-probe keep it working.");
    }
  }
  out.push("", findings.length ? `${findings.length} finding${findings.length === 1 ? "" : "s"}` : "No findings.", "");
  for (const f of findings) {
    out.push(`${f.severity.toUpperCase().padEnd(8)} ${findingId(f)}  ${f.title}`);
    out.push(`         ${f.detail}`);
    if (f.fix) out.push(`         Fix: ${f.fix}`);
    out.push("");
  }
  return out.join("\n");
}

// What A's teammate (D) can do with A's rows as a member: on a table that belongs to
// the group, anything; elsewhere, only what a stranger (B) can't. Adding a row in A's
// name isn't sharing.
export function memberCan(r, action) {
  const can = (x) => Boolean(x && (action === "read" ? x.read > 0 : x[action]));
  return action !== "insert" && can(r.D) && (!can(r.B) || Boolean(r.groups?.length));
}

export function teamReach(results) {
  return results.filter((r) => r.owned && r.D)
    .map((r) => ({ table: r.table, actions: ["read", "update", "delete"].filter((k) => memberCan(r, k)) }))
    .filter((t) => t.actions.length);
}

function verbs(list) {
  const words = list.map((v) => ({ read: "read", update: "edit", delete: "delete", insert: "create" })[v]);
  return words.length > 1 ? `${words.slice(0, -1).join(", ")} and ${words.at(-1)}` : words[0];
}
