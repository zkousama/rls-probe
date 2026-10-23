import { SENSITIVE } from "./report.js";
import { USERS, ownerOf, ownerPath, q, rowFor } from "./seed.js";

const AS = {
  anon: { role: "anon", claims: { role: "anon" } },
  // A on their own rows: what the app needs to keep working, not a finding.
  A: { role: "authenticated", claims: { sub: USERS.A.id, role: "authenticated", aud: "authenticated", email: USERS.A.email } },
  B: { role: "authenticated", claims: { sub: USERS.B.id, role: "authenticated", aud: "authenticated", email: USERS.B.email } },
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

export async function probeTables(db, tables, known) {
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

    for (const who of ["anon", "B", "A"]) {
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
export async function probeStorage(db) {
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
