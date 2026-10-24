import { SENSITIVE } from "./report.js";
import { USERS, ownerOf, ownerPath, q, rowFor } from "./seed.js";

const AS = {
  anon: { role: "anon", claims: { role: "anon" } },
  // A on their own rows: what the app needs to keep working, not a finding.
  A: { role: "authenticated", claims: { sub: USERS.A.id, role: "authenticated", aud: "authenticated", email: USERS.A.email } },
  B: { role: "authenticated", claims: { sub: USERS.B.id, role: "authenticated", aud: "authenticated", email: USERS.B.email } },
  // A's teammate, when the app has groups: what members share, not a finding.
  D: { role: "authenticated", claims: { sub: USERS.D.id, role: "authenticated", aud: "authenticated", email: USERS.D.email } },
};

// Runs probes as a visitor or as user B inside one transaction that is rolled
// back to a savepoint after every statement, so probes never change the data the
// next probe sees. Setting the role once per table rather than once per statement
// saves most of the round trips.
async function session(db, who, probes) {
  const { role, claims } = AS[who];
  await db.exec(`begin;
    select set_config('request.jwt.claims', ${literal(JSON.stringify(claims))}, true),
      set_config('request.jwt.claim.sub', ${literal(claims.sub ?? "")}, true),
      set_config('request.jwt.claim.role', ${literal(claims.role)}, true);
    set local role ${role};
    savepoint probe`);
  try {
    return await probes((sql, params = []) => attempt(db, sql, params));
  } finally {
    await db.exec("rollback");
  }
}

async function attempt(db, sql, params) {
  try {
    const res = await db.query(sql, params);
    return { ok: true, rows: res.rows, affected: res.affectedRows ?? 0 };
  } catch (error) {
    return { ok: false, error: error.message, rows: [], affected: 0 };
  } finally {
    await db.exec("rollback to savepoint probe");
  }
}

const DENIED = /row-level security|permission denied/;

function literal(text) {
  return `'${text.replace(/'/g, "''")}'`;
}

export async function probeTables(db, tables, known, { teammate = false } = {}) {
  const real = tables.filter((t) => t.kind === "r" || t.kind === "p");
  const results = [];
  for (const table of real) {
    // ctid identifies a row without relying on the table having a primary key.
    const owned = Boolean(ownerPath(table, real));
    let rows;
    try {
      rows = (await db.query(`select ctid::text as __ctid, * from ${q(table.name)}`)).rows
        .map((row) => ({ ctid: row.__ctid, owner: ownerOf(table, row, known), row }));
    } catch (error) {
      results.push({ table: table.name, rls: table.rls, owned, seeded: 0, columns: table.columns.map((c) => c.name), skipped: error.message });
      continue;
    }
    const target = owned ? rows.find((r) => r.owner === "A") : rows[0];
    const result = { table: table.name, rls: table.rls, owned, seeded: rows.length, columns: table.columns.map((c) => c.name) };
    if (!target) {
      result.skipped = "no seeded row to probe";
      results.push(result);
      continue;
    }
    const aRows = new Set(rows.filter((r) => (owned ? r.owner === "A" : true)).map((r) => r.ctid));
    // When a table hides some columns (column grants), ctid can't be selected
    // either. The primary key identifies A's rows instead.
    const keyOf = (row) => JSON.stringify(table.pk.map((c) => String(row[c])));
    const aKeys = new Set(rows.filter((r) => (owned ? r.owner === "A" : true)).map((r) => keyOf(r.row)));
    const sensitive = table.columns.map((c) => c.name).filter((c) => SENSITIVE.test(c));
    const setColumn = table.columns.find((c) => !table.pk.includes(c.name) && c.generated !== "s" && c.identity !== "a")?.name
      ?? table.columns.find((c) => c.generated !== "s" && c.identity !== "a")?.name;

    for (const who of teammate ? ["anon", "B", "A", "D"] : ["anon", "B", "A"]) {
      result[who] = await session(db, who, async (as) => {
        let read = await as(`select ctid::text as c from ${q(table.name)}`);
        let readA = read.rows.filter((r) => aRows.has(r.c)).length;
        if (!read.ok && table.pk.length) {
          read = await as(`select ${table.pk.map(q).join(", ")} from ${q(table.name)}`);
          readA = read.rows.filter((r) => aKeys.has(keyOf(r))).length;
        }
        // Which private-looking columns of A's rows this role can actually read.
        const exposed = [];
        if (readA > 0) {
          for (const col of sensitive) {
            const probe = await as(`select ${q(col)} from ${q(table.name)} limit 1`);
            if (probe.ok) exposed.push(col);
          }
        }
        // Rows are found by ctid, or by primary key when hidden columns make ctid unreadable.
        const byKey = table.pk.map((c, i) => `${q(c)} = $${i + 1}`).join(" and ");
        const keyValues = table.pk.map((c) => target.row[c]);
        const tryBoth = async (sqlByCtid, sqlByKey) => {
          const first = await as(sqlByCtid, [target.ctid]);
          return !first.ok && /permission denied/.test(first.error) && table.pk.length ? as(sqlByKey, keyValues) : first;
        };
        const update = setColumn
          ? await tryBoth(`update ${q(table.name)} set ${q(setColumn)} = ${q(setColumn)} where ctid = $1::tid`,
              `update ${q(table.name)} set ${q(setColumn)} = ${q(setColumn)} where ${byKey}`)
          : { ok: false, affected: 0 };
        const del = await tryBoth(`delete from ${q(table.name)} where ctid = $1::tid`, `delete from ${q(table.name)} where ${byKey}`);
        // B tries to create a row that belongs to A; a visitor tries to create any row.
        const values = rowFor(table, owned ? "A" : "shared", known, 9000 + results.length);
        let insert = { ok: false };
        if (values) {
          const cols = Object.keys(values);
          const type = (c) => table.columns.find((x) => x.name === c).type;
          insert = await as(cols.length
            ? `insert into ${q(table.name)} (${cols.map(q).join(", ")}) values (${cols.map((c, i) => `$${i + 1}::${type(c)}`).join(", ")})`
            : `insert into ${q(table.name)} default values`, cols.map((c) => values[c]));
        }
        return {
          read: readA,
          readTotal: read.rows.length,
          exposed,
          update: update.affected > 0,
          delete: del.affected > 0,
          insert: insert.ok,
          // Refused by something other than the access rules (a unique key, a trigger):
          // the probe couldn't tell whether this role may create rows.
          insertUntested: who !== "A" && insert.error && !DENIED.test(insert.error) ? insert.error : undefined,
        };
      });
    }
    results.push(result);
  }
  return results;
}

export async function probeViews(db, tables) {
  const out = [];
  for (const view of tables.filter((t) => t.kind === "v" || t.kind === "m")) {
    const anon = await session(db, "anon", (as) => as(`select count(*)::int as n from ${q(view.name)}`));
    out.push({ view: view.name, invoker: view.invoker, anonRows: anon.ok ? anon.rows[0].n : null, error: anon.ok ? null : anon.error });
  }
  return out;
}

// Storage: a file of each user's in every bucket, stored the way Supabase's own
// examples do (under a folder named for the user, with owner set), then a visitor
// and user B try to see, replace, delete and upload into user A's folder. Buckets
// are the ones the migrations create plus any a storage policy names, since those
// are often made in the dashboard.
// declared: buckets from supabase/config.toml, [{ id, public }], set up before probing.
export async function probeStorage(db, declared = []) {
  for (const b of declared) {
    await db.query(`insert into storage.buckets (id, name, public) values ($1, $1, $2) on conflict (id) do update set public = excluded.public`, [b.id, b.public]);
  }
  const policies = (await db.query(`select policyname as name, cmd, roles::text[] as roles, qual, with_check as check
    from pg_policies where schemaname = 'storage' and tablename = 'objects' order by policyname`)).rows;
  const rls = (await db.query(`select relrowsecurity as on from pg_class where oid = 'storage.objects'::regclass`)).rows[0].on;
  const buckets = (await db.query(`select id, public from storage.buckets order by id`)).rows;
  const named = new Set(policies.flatMap((p) => [...`${p.qual ?? ""} ${p.check ?? ""}`.matchAll(/bucket_id\s*=\s*'([^']+)'/g)].map((m) => m[1])));
  for (const id of [...named].sort()) {
    if (buckets.some((b) => b.id === id)) continue;
    await db.query(`insert into storage.buckets (id, name, public) values ($1, $1, false)`, [id]);
    buckets.push({ id, public: false, assumed: true });
  }
  const results = [];
  for (const bucket of buckets) {
    const file = {};
    try {
      for (const who of ["A", "B"]) {
        const user = USERS[who].id;
        file[who] = (await db.query(`insert into storage.objects (bucket_id, name, owner, owner_id) values ($1, $2, $3::uuid, $3::text) returning id`,
          [bucket.id, `${user}/rls-probe-${who.toLowerCase()}.txt`, user])).rows[0]?.id;
      }
    } catch (error) {
      // A trigger or a changed storage table: the bucket is listed as not probed.
      results.push({ bucket: bucket.id, public: bucket.public, assumed: Boolean(bucket.assumed), skipped: error.message });
      continue;
    }
    if (!file.A) {
      results.push({ bucket: bucket.id, public: bucket.public, assumed: Boolean(bucket.assumed), skipped: "a trigger dropped the file before it was stored" });
      continue;
    }
    const result = { bucket: bucket.id, public: bucket.public, assumed: Boolean(bucket.assumed) };
    for (const who of ["anon", "B", "A"]) {
      result[who] = await session(db, who, async (as) => {
        const read = await as("select id from storage.objects where id = $1", [file.A]);
        const update = await as("update storage.objects set metadata = coalesce(metadata, '{}'::jsonb) where id = $1", [file.A]);
        const del = await as("delete from storage.objects where id = $1", [file.A]);
        // An upload names its path, and the storage server sets owner to whoever is signed in.
        const insert = await as("insert into storage.objects (bucket_id, name, owner, owner_id) values ($1, $2, $3::uuid, $3::text)",
          [bucket.id, `${USERS.A.id}/rls-probe-from-${who.toLowerCase()}.txt`, who === "anon" ? null : USERS[who].id]);
        return { read: read.rows.length > 0, update: update.affected > 0, delete: del.affected > 0, insert: insert.ok };
      });
    }
    results.push(result);
  }
  return { rls, buckets: results, policies };
}

// A security definer function skips row-level security, so what it lets a caller do
// shows only when it's called. Each one a visitor or any signed-in user may run is
// called as the visitor and as user B, with arguments that point at user A's rows,
// and A's rows are compared before and after. Each call is rolled back.
export async function probeFunctions(db, functions, tables, known) {
  const real = tables.filter((t) => t.kind === "r" || t.kind === "p");
  const owned = real.filter((t) => ownerPath(t, real));
  const aRows = await rowsOfA(db, owned, known);
  // What would give A away in a result: their email, and private-looking values of theirs.
  const tells = new Set([USERS.A.email]);
  for (const t of owned) {
    for (const row of aRows[t.name]) for (const c of t.columns) if (SENSITIVE.test(c.name) && typeof row[c.name] === "string" && row[c.name].length >= 4) tells.add(row[c.name]);
  }
  const aJson = new Set(Object.values(aRows).flat().map((r) => JSON.stringify(r)));
  // One query tells which tables a call touched at all; only those are read again.
  // A call can only change the tables its function names, so only those are checked.
  const prints = async (tables) => tables.length
    ? (await db.query(`select ${tables.map((t) => `(select md5(coalesce(string_agg(x::text, ',' order by x::text), '')) from public.${q(t.name)} x) as ${q(t.name)}`).join(", ")}`).catch(() => ({ rows: [{}] }))).rows[0]
    : {};
  const before = await prints(owned);
  const out = [];
  for (const f of functions) {
    if (!f.definer || f.returns === "trigger" || !(f.anon || f.authenticated)) continue;
    if (/pg_sleep/i.test(f.body)) continue;
    const args = argumentsFor(f, owned, aRows);
    // The tables it names, which are all a call can change; none if it never writes.
    const writes = /\b(insert\s+into|update\s|delete\s+from|perform|select\s+[\w.]+\s*\()/i.test(f.body);
    // A function that runs another (perform) may change any table.
    const named = !writes ? [] : /\bperform\b/i.test(f.body) ? owned : owned.filter((t) => new RegExp(`\\b${t.name.replace(/\W/g, "\\$&")}\\b`, "i").test(f.body));
    if (!args) {
      out.push({ name: f.name, args: f.args, untested: "it takes an argument type the probe can't fill" });
      continue;
    }
    const calls = {};
    // Secrets it reads from Supabase Vault by name get a stand-in value for the call, so
    // handing one out shows in what comes back. A project's URL or host isn't a secret.
    const secrets = /\bvault\./i.test(f.body)
      ? [...new Set([...f.body.matchAll(/\bname\s*=\s*'([^']+)'/gi)].map((m) => m[1]))].filter((n) => !/url|host|endpoint|domain|region|project_?ref/i.test(n))
      : [];
    const stand = Object.fromEntries(secrets.map((n) => [n, `rls-probe-secret-${n}-${Math.random().toString(36).slice(2, 10)}`]));
    const plant = secrets.map((n) => `delete from vault.secrets where name = ${literal(n)}; insert into vault.secrets (name, secret) values (${literal(n)}, ${literal(stand[n])});`).join("\n");
    for (const who of ["anon", "B"]) {
      if (who === "anon" ? !f.anon : !f.authenticated) continue;
      const { role, claims } = AS[who];
      await db.exec(`begin;
        ${plant}
        select set_config('request.jwt.claims', ${literal(JSON.stringify(claims))}, true),
          set_config('request.jwt.claim.sub', ${literal(claims.sub ?? "")}, true),
          set_config('request.jwt.claim.role', ${literal(claims.role)}, true);
        set local role ${role}`);
      try {
        const call = await db.query(`select * from public.${q(f.name)}(${args.map((a, i) => `$${i + 1}::${a.type}`).join(", ")})`, args.map((a) => a.value))
          .then((res) => ({ ok: true, rows: res.rows }), (error) => ({ ok: false, error: error.message, rows: [] }));
        // A failed call leaves the transaction aborted, and nothing it did survives.
        if (call.ok) await db.exec("reset role");
        let changed = [];
        if (call.ok && named.length) {
          const after = await prints(named);
          const touched = named.filter((t) => after[t.name] !== before[t.name]);
          changed = changes(touched, aRows, await rowsOfA(db, touched, known));
        }
        const text = JSON.stringify(call.rows);
        const returned = call.rows.some((r) => aJson.has(JSON.stringify(r))) || [...tells].some((t) => text.includes(t));
        const handed = secrets.filter((n) => text.includes(stand[n]));
        calls[who] = { ok: call.ok, ...(call.ok ? {} : { error: call.error }), changed, returned, ...(handed.length ? { secrets: handed } : {}) };
      } finally {
        await db.exec("rollback");
      }
    }
    // How the call was aimed at A, in words: only the arguments that point somewhere.
    out.push({ name: f.name, args: f.args, called: [...new Set(args.map((a) => a.about).filter(Boolean))], calls });
  }
  return out;
}

// A's rows in each owned table, as the database's owner sees them.
async function rowsOfA(db, owned, known) {
  const out = {};
  for (const t of owned) {
    const rows = await db.query(`select * from ${q(t.name)}`).then((r) => r.rows, () => []);
    out[t.name] = rows.filter((row) => ownerOf(t, row, known) === "A");
  }
  return out;
}

// Which tables' A rows a call deleted, added or changed, and which columns changed.
function changes(owned, before, after) {
  const out = [];
  for (const t of owned) {
    const was = before[t.name];
    const now = after[t.name];
    // Rows come back in any order after an update.
    const all = (rows) => rows.map((r) => JSON.stringify(r)).sort().join("\n");
    if (all(was) === all(now)) continue;
    const how = now.length < was.length ? "deleted" : now.length > was.length ? "added" : "changed";
    const key = (row) => JSON.stringify(t.pk.map((c) => row[c]));
    const columns = new Set();
    if (how === "changed" && t.pk.length) {
      for (const row of was) {
        const next = now.find((r) => key(r) === key(row));
        if (next) for (const c of Object.keys(row)) if (JSON.stringify(row[c]) !== JSON.stringify(next[c])) columns.add(c);
      }
    }
    out.push({ table: t.name, how, columns: [...columns] });
  }
  return out;
}

const USER_ARG = /^(user|uid|owner|profile|author|member|account|customer|player|creator|created_by|userid)(_?id)?$/;
const NUMBER = /^(smallint|integer|bigint|numeric|real|double precision)$/;

// Arguments that aim at A: A's id for a user, the id of A's row for a table's id,
// A's email for an email. Null when an argument's type can't be filled.
function argumentsFor(f, owned, aRows) {
  const names = f.argModes.length ? f.argNames.filter((_, i) => ["i", "b", "v"].includes(f.argModes[i])) : f.argNames;
  // The tables the body works on, in the order it names them: the likeliest target of a bare "id".
  const word = (t) => t.name.replace(/\W/g, "\\$&");
  const mentioned = owned.filter((t) => new RegExp(`\\b(from|update|into|join)\\s+(public\\.)?"?${word(t)}\\b`, "i").test(f.body))
    .sort((a, b) => f.body.search(new RegExp(`\\b${word(a)}\\b`)) - f.body.search(new RegExp(`\\b${word(b)}\\b`)));
  const rowId = (table, type) => {
    const row = table && aRows[table.name][0];
    const pk = table?.pk.length === 1 ? table.columns.find((c) => c.name === table.pk[0]) : null;
    if (!row || !pk || row[pk.name] == null) return null;
    const kind = pk.type === "uuid" ? "uuid" : NUMBER.test(pk.type) ? "number" : "text";
    return (type === "uuid" ? kind === "uuid" : NUMBER.test(type) ? kind === "number" : true) ? { value: String(row[pk.name]), about: `the id of user A's row in ${table.name}` } : null;
  };
  const tableFor = (base) => owned.find((t) => [base, `${base}s`, `${base}es`, base.replace(/y$/, "ies")].includes(t.name));
  const out = [];
  for (const [i, type] of f.argTypes.entries()) {
    const name = (names[i] ?? "").toLowerCase().replace(/^(p_|_|in_|arg_|target_|the_)/, "");
    const idOf = name.endsWith("_id") || name.endsWith("id") && name !== "id" ? tableFor(name.replace(/_?id$/, "")) : null;
    let pick;
    if (type === "uuid" || NUMBER.test(type) || /^(text|character varying|citext)$/.test(type)) {
      if (USER_ARG.test(name) && (type === "uuid" || !NUMBER.test(type))) pick = { value: USERS.A.id, about: "user A's id" };
      else if (/email/.test(name) && !NUMBER.test(type)) pick = { value: USERS.A.email, about: "user A's email" };
      // Text is an id only when it's named like one.
      else pick = rowId(idOf, type) ?? (type === "uuid" || NUMBER.test(type) || /id$/.test(name) ? rowId(mentioned[0], type) : null)
        ?? (type === "uuid" ? { value: USERS.A.id, about: "user A's id" } : NUMBER.test(type) ? { value: "1" } : { value: "rls-probe" });
    } else if (type === "boolean") pick = { value: "true" };
    else if (type === "jsonb" || type === "json") pick = { value: "{}" };
    else if (/^(date|timestamp)/.test(type)) pick = { value: "2026-01-01" };
    else return null;
    out.push({ ...pick, type });
  }
  return out;
}
