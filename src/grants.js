// Supabase's 2026 grants change: tables created in projects without the old
// defaults get no grant for anon or authenticated, so the Data API answers
// "permission denied" (42501) until the migrations grant access themselves.
// This compares what each table's policies allow with what is actually granted
// once the old defaults are gone, and says whether granting the rest is safe.

const COMMANDS = ["SELECT", "INSERT", "UPDATE", "DELETE"];

export async function grantsReport(explicitDb, findings) {
  const tables = (await explicitDb.query(`
    select c.relname as name, c.relrowsecurity as rls
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname`)).rows;
  const policies = (await explicitDb.query(`select tablename as table, cmd, roles::text[] as roles, qual, with_check as check, permissive = 'PERMISSIVE' as permissive from pg_policies where schemaname = 'public'`)).rows;

  const out = { breaks: [], unsafe: [], closedNoRls: [], fine: [], noPolicies: [], server: [] };
  for (const t of tables) {
    // The service role key, used by edge functions and server code, loses the old
    // grants too. It skips row-level security and never reaches a browser, so
    // granting it every table is always safe, policies or not.
    const serverMissing = [];
    for (const cmd of COMMANDS) if (!(await hasTablePrivilege(explicitDb, "service_role", t.name, cmd))) serverMissing.push({ role: "service_role", cmd });
    const serverSequences = [];
    for (const seq of await serialSequences(explicitDb, t.name)) {
      if (!(await hasSequencePrivilege(explicitDb, "service_role", seq))) serverSequences.push({ role: "service_role", seq });
    }
    if (serverMissing.length || serverSequences.length) {
      out.server.push({ table: t.name, missing: serverMissing, grant: [...grantLines(t.name, serverMissing), ...sequenceLines(serverSequences)] });
    }

    const needed = neededFor(t.name, policies);
    const missing = [];
    for (const key of needed) {
      const [role, cmd] = key.split(" ");
      if (!(await hasTablePrivilege(explicitDb, role, t.name, cmd))) missing.push({ role, cmd });
    }
    const problems = findings.filter((f) => f.where === t.name && f.severity !== "review").map((f) => f.title);
    if (!t.rls) {
      const granted = await anyGrant(explicitDb, t.name);
      if (!granted) out.closedNoRls.push({ table: t.name });
      continue;
    }
    if (!needed.size) {
      out.noPolicies.push({ table: t.name });
      continue;
    }
    if (!missing.length) {
      out.fine.push({ table: t.name });
      continue;
    }
    // Inserting into a serial column calls nextval(), which needs usage on its sequence.
    // Identity columns don't: their sequence is checked through the table.
    const sequences = [];
    for (const role of new Set(missing.filter((m) => m.cmd === "INSERT").map((m) => m.role))) {
      for (const seq of await serialSequences(explicitDb, t.name)) {
        if (!(await hasSequencePrivilege(explicitDb, role, seq))) sequences.push({ role, seq });
      }
    }
    if (problems.length) out.unsafe.push({ table: t.name, missing, problems });
    else out.breaks.push({ table: t.name, missing, grant: [...grantLines(t.name, missing), ...sequenceLines(sequences)] });
  }

  // Views lose the old grants too. One that follows the tables' rules (security_invoker)
  // is as safe to grant as the tables under it. One that runs as its owner, or a
  // materialized view, shows every row it selects: safe only for a role those tables hide
  // nothing from. A view on a view is judged by the tables at the bottom and by every view
  // on the way. A role is granted a view when it may read every table under it.
  const views = (await explicitDb.query(`
    select c.relname as name, c.relkind = 'm' as materialized,
      coalesce((select lower(option_value) in ('true', 'on', '1') from pg_options_to_table(c.reloptions) where option_name = 'security_invoker'), false) as invoker,
      array(select distinct case when tn.nspname = 'public' then '' else tn.nspname || '.' end || t.relname || ':' || t.relkind::text
        from pg_rewrite r join pg_depend d on d.objid = r.oid join pg_class t on t.oid = d.refobjid join pg_namespace tn on tn.oid = t.relnamespace
        where r.ev_class = c.oid and d.refobjid <> c.oid and t.relkind in ('r', 'p', 'v', 'm')) as uses
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('v', 'm') order by c.relname`).catch(() => ({ rows: [] }))).rows;
  const byName = new Map(views.map((v) => [v.name, v]));
  // What a view reads in the end: tables in public, tables elsewhere (auth.users), and the
  // views on the way that run as their owner (or keep their own copy).
  const bottom = (v, seen = new Set()) => {
    const out = { tables: new Set(), elsewhere: new Set(), owner: [] };
    if (seen.has(v.name)) return out;
    seen.add(v.name);
    if (!v.invoker || v.materialized) out.owner.push(v);
    for (const use of v.uses) {
      const at = use.lastIndexOf(":");
      const [rel, kind] = [use.slice(0, at), use.slice(at + 1)];
      const table = kind === "r" || kind === "p";
      if (rel.includes(".")) {
        if (table) out.elsewhere.add(rel);
      } else if (table) out.tables.add(rel);
      else if (byName.has(rel)) {
        const inner = bottom(byName.get(rel), seen);
        for (const t of inner.tables) out.tables.add(t);
        for (const t of inner.elsewhere) out.elsewhere.add(t);
        out.owner.push(...inner.owner);
      }
    }
    return out;
  };
  for (const v of views) {
    const serverMissing = [];
    for (const cmd of COMMANDS) if (!(await hasTablePrivilege(explicitDb, "service_role", v.name, cmd))) serverMissing.push({ role: "service_role", cmd });
    if (serverMissing.length) out.server.push({ table: v.name, view: true, missing: serverMissing, grant: grantLines(v.name, serverMissing) });
    const under = bottom(v);
    const tables = [...under.tables];
    if (!tables.length) continue;
    const missing = [];
    for (const role of ["anon", "authenticated"]) {
      if (tables.every((t) => neededFor(t, policies).has(`${role} SELECT`)) && !(await hasTablePrivilege(explicitDb, role, v.name, "SELECT"))) missing.push({ role, cmd: "SELECT" });
    }
    if (!missing.length) continue;
    const who = (list) => list.map((m) => (m.role === "anon" ? "visitors" : "signed-in users")).join(" and ");
    const problems = tables.flatMap((t) => findings.filter((f) => f.where === t && f.severity !== "review").map((f) => `${t}: ${f.title}`));
    if (under.elsewhere.size) {
      // Following the caller's rules, it can't read those tables for them: a grant wouldn't help.
      if (!under.owner.length) continue;
      const shown = [...under.elsewhere].join(", ");
      problems.push(`it shows ${shown}, which the API never shows anyone, so a grant would show ${who(missing)} what's in it${under.elsewhere.has("auth.users") ? " (users' emails, for auth.users)" : ""}; leave it out of the view, or serve it through a function that checks the caller`);
    } else {
      const exposed = under.owner.length ? missing.filter((m) => !tables.every((t) => readsAll(t, m.role, policies))) : [];
      if (exposed.length) {
        const culprit = under.owner[0];
        const fix = `alter view public.${quote(culprit.name)} set (security_invoker = true);`;
        problems.push(culprit.materialized
          ? `${culprit === v ? "a materialized view" : `${culprit.name} is a materialized view: it`} keeps its own copy of the rows, with no row-level security, so a grant would show ${who(exposed)} every row of ${tables.join(", ")}`
          : culprit === v
            ? `it runs as its owner, so a grant would show ${who(exposed)} every row of ${tables.join(", ")}; make it security_invoker first (${fix})`
            : `${culprit.name} runs as its owner, so a grant on this view would show ${who(exposed)} every row of ${tables.join(", ")}; make ${culprit.name} security_invoker first (${fix})`);
      }
    }
    if (problems.length) out.unsafe.push({ table: v.name, view: true, missing, problems });
    else out.breaks.push({ table: v.name, view: true, missing, grant: grantLines(v.name, missing) });
  }
  return out;
}

// The grants a table's policies call for, as "role COMMAND" ("anon SELECT").
function neededFor(table, policies) {
  const needed = new Set();
  for (const p of policies.filter((x) => x.table === table)) {
    // A policy for everyone only lets signed-in users through when every alternative
    // in its rule needs auth.uid(). "Public games, or the host's own" lets visitors in;
    // "the sender or the recipient" doesn't. (An approximation: it splits on OR.)
    const rule = `${p.qual ?? ""} ${p.check ?? ""}`.trim();
    const needsUser = rule !== "" && rule.split(/\bOR\b/i).every((part) => /auth\.uid\(\)/.test(part));
    const cmds = p.cmd === "ALL" ? COMMANDS : [p.cmd];
    for (const cmd of cmds) {
      // Visitors get writes only from a policy that names anon. Through a policy for
      // everyone, visitor writes are what the probe reports as a hole.
      const visitorsToo = cmd === "SELECT" ? !needsUser : false;
      const roles = p.roles.flatMap((r) => (r === "public" ? (visitorsToo ? ["anon", "authenticated"] : ["authenticated"]) : [r]))
        .filter((r) => r === "anon" || r === "authenticated");
      for (const role of roles) needed.add(`${role} ${cmd}`);
    }
  }
  return needed;
}

// Whether a role reads every row of a table: a permissive select policy of "true" for it,
// and no restrictive one that holds rows back.
function readsAll(table, role, policies) {
  const reads = policies.filter((p) => p.table === table && (p.cmd === "SELECT" || p.cmd === "ALL") && p.roles.some((r) => r === role || r === "public"));
  return reads.some((p) => p.permissive && (p.qual ?? "").trim() === "true") && !reads.some((p) => !p.permissive && (p.qual ?? "").trim() !== "true");
}

// "2 tables and 3 views".
export function howMany(entries) {
  const count = (view, word) => {
    const n = entries.filter((e) => Boolean(e.view) === view).length;
    return n ? `${n} ${word}${n === 1 ? "" : "s"}` : null;
  };
  return [count(false, "table"), count(true, "view")].filter(Boolean).join(" and ");
}

async function anyGrant(db, table) {
  for (const role of ["anon", "authenticated"]) {
    for (const cmd of COMMANDS) if (await hasTablePrivilege(db, role, table, cmd)) return true;
  }
  return false;
}

async function hasTablePrivilege(db, role, table, cmd) {
  return (await db.query(`select has_table_privilege($1, $2, $3) as ok`, [role, `public.${quote(table)}`, cmd])).rows[0].ok;
}

async function hasSequencePrivilege(db, role, seq) {
  return (await db.query(`select has_sequence_privilege($1, $2, 'USAGE') as ok`, [role, `public.${quote(seq)}`])).rows[0].ok;
}

async function serialSequences(db, table) {
  return (await db.query(`
    select s.relname as name from pg_class s
    join pg_depend d on d.objid = s.oid and d.deptype = 'a'
    join pg_class t on t.oid = d.refobjid join pg_namespace n on n.oid = t.relnamespace
    where s.relkind = 'S' and n.nspname = 'public' and t.relname = $1`, [table])).rows.map((r) => r.name);
}

function sequenceLines(sequences) {
  const bySeq = {};
  for (const { role, seq } of sequences) (bySeq[seq] ??= []).push(role);
  return Object.entries(bySeq).map(([seq, roles]) => `grant usage on sequence public.${quote(seq)} to ${roles.join(", ")};`);
}

function grantLines(table, missing) {
  const byRole = {};
  for (const { role, cmd } of missing) (byRole[role] ??= new Set()).add(cmd.toLowerCase());
  // Roles that need the same commands share one line.
  const byCmds = {};
  for (const [role, cmds] of Object.entries(byRole)) {
    const list = COMMANDS.map((c) => c.toLowerCase()).filter((c) => cmds.has(c)).join(", ");
    (byCmds[list] ??= []).push(role);
  }
  return Object.entries(byCmds).map(([list, roles]) => `grant ${list} on public.${quote(table)} to ${roles.join(", ")};`);
}

function quote(name) {
  return /^[a-z_][a-z0-9_]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

export function renderGrants(report) {
  const out = ["", "Supabase grants change (from May 30, 2026 for new projects; October 30, 2026 for new tables everywhere)", ""];
  const n = report.breaks.length + report.unsafe.length;
  out.push(n
    ? `${howMany([...report.breaks, ...report.unsafe])} get their API access only from Supabase's old default grants. Those that already exist keep their grants, but in a new project, a fresh database, a preview branch, or for any created like this from October 30, the API answers "permission denied" (42501) until the migrations grant it.`
    : "Every table with policies already has the grants its policies need.");
  if (report.breaks.length) {
    out.push("", "Safe to grant: row-level security already limits these to the right rows.");
    for (const b of report.breaks) for (const line of b.grant) out.push(`  ${line}`);
  }
  if (report.server.length) {
    out.push("", "Your server too: edge functions and server code using the service role key get 42501 on these. The key skips row-level security and never reaches a browser, so granting it is safe.");
    for (const s of report.server) for (const line of s.grant) out.push(`  ${line}`);
  }
  if (report.unsafe.length) {
    out.push("", "Fix before granting: a grant would open these up.");
    for (const u of report.unsafe) out.push(`  ${u.table}: ${[...new Set(u.problems)].join("; ")}`);
  }
  if (report.closedNoRls.length) {
    out.push("", "Closed only because nothing grants them: row-level security is off, so the quick fix for 42501, a grant on every table, would expose every row.");
    for (const c of report.closedNoRls) out.push(`  ${c.table}: enable row level security and add policies before granting anything.`);
  }
  if (report.noPolicies.length) {
    out.push("", `No policies, so no rows reach the API either way: ${report.noPolicies.map((t) => t.table).join(", ")}.`);
  }
  return out.join("\n");
}

// The safe grants as a Supabase migration, so the fix is a file to review and commit.
export function migrationFor(report, version) {
  const lines = [`-- Grants for Supabase's 2026 grants change, written by rls-probe ${version}.`];
  if (report.breaks.length) {
    lines.push(
      "-- Each table here has row-level security whose policies already limit which rows",
      "-- a role reaches; these grants only let those policies take effect.",
      "",
      ...report.breaks.flatMap((b) => b.grant),
    );
  }
  if (report.server.length) {
    lines.push(
      "",
      "-- The service role key, used by edge functions and server code, skips row-level",
      "-- security and never reaches a browser, so it gets every table and view.",
      ...report.server.flatMap((s) => s.grant),
    );
  }
  const held = [
    ...report.unsafe.map((u) => `--   ${u.table}: ${[...new Set(u.problems)].join("; ")}`),
    ...report.closedNoRls.map((c) => `--   ${c.table}: row-level security is off`),
  ];
  if (held.length) lines.push("", "-- Not granted: a grant would expose data until these are fixed.", ...held);
  return `${lines.join("\n")}\n`;
}
