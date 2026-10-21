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
  const policies = (await explicitDb.query(`select tablename as table, cmd, roles::text[] as roles, qual, with_check as check from pg_policies where schemaname = 'public'`)).rows;

  const out = { breaks: [], unsafe: [], closedNoRls: [], fine: [], noPolicies: [] };
  for (const t of tables) {
    const needed = new Set();
    for (const p of policies.filter((x) => x.table === t.name)) {
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
    const missing = [];
    for (const key of needed) {
      const [role, cmd] = key.split(" ");
      const ok = (await explicitDb.query(`select has_table_privilege($1, $2, $3) as ok`, [role, `public.${quote(t.name)}`, cmd])).rows[0].ok;
      if (!ok) missing.push({ role, cmd });
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
        if (!(await explicitDb.query(`select has_sequence_privilege($1, $2, 'USAGE') as ok`, [role, `public.${quote(seq)}`])).rows[0].ok) {
          sequences.push({ role, seq });
        }
      }
    }
    if (problems.length) out.unsafe.push({ table: t.name, missing, problems });
    else out.breaks.push({ table: t.name, missing, grant: [...grantLines(t.name, missing), ...sequenceLines(sequences)] });
  }
  return out;
}

async function anyGrant(db, table) {
  for (const role of ["anon", "authenticated"]) {
    for (const cmd of COMMANDS) {
      if ((await db.query(`select has_table_privilege($1, $2, $3) as ok`, [role, `public.${quote(table)}`, cmd])).rows[0].ok) return true;
    }
  }
  return false;
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
    ? `${n} tables get their API access only from Supabase's old default grants. Tables that already exist keep their grants, but in a new project, a fresh database, a preview branch, or for any table created like this from October 30, the API answers "permission denied" (42501) until the migrations grant it.`
    : "Every table with policies already has the grants its policies need.");
  if (report.breaks.length) {
    out.push("", "Safe to grant: row-level security already limits these to the right rows.");
    for (const b of report.breaks) for (const line of b.grant) out.push(`  ${line}`);
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
