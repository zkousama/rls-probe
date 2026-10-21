import { SENSITIVE } from "./report.js";
import { USERS, ownerOf, ownerPath, q, rowFor } from "./seed.js";

const AS = {
  anon: { role: "anon", claims: { role: "anon" } },
  // A on their own rows: what the app needs to keep working, not a finding.
  A: { role: "authenticated", claims: { sub: USERS.A.id, role: "authenticated", aud: "authenticated", email: USERS.A.email } },
  B: { role: "authenticated", claims: { sub: USERS.B.id, role: "authenticated", aud: "authenticated", email: USERS.B.email } },
};

// Runs one statement as a visitor or as user B, inside a transaction that is
// always rolled back, so probes never change the data the next probe sees.
async function as(db, who, sql, params = []) {
  const { role, claims } = AS[who];
  await db.exec("begin");
  try {
    await db.query(`select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true),
      set_config('request.jwt.claim.role', $3, true)`, [JSON.stringify(claims), claims.sub ?? "", claims.role]);
    await db.exec(`set local role ${role}`);
    const res = await db.query(sql, params);
    return { ok: true, rows: res.rows, affected: res.affectedRows ?? 0 };
  } catch (error) {
    return { ok: false, error: error.message, rows: [], affected: 0 };
  } finally {
    await db.exec("rollback");
  }
}

export async function probeTables(db, tables, known) {
  const real = tables.filter((t) => t.kind === "r" || t.kind === "p");
  const results = [];
  for (const table of real) {
    // ctid identifies a row without relying on the table having a primary key.
    const rows = (await db.query(`select ctid::text as __ctid, * from ${q(table.name)}`)).rows
      .map((row) => ({ ctid: row.__ctid, owner: ownerOf(table, row, known), row }));
    const owned = Boolean(ownerPath(table, real));
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
      let read = await as(db, who, `select ctid::text as c from ${q(table.name)}`);
      let readA = read.rows.filter((r) => aRows.has(r.c)).length;
      if (!read.ok && table.pk.length) {
        read = await as(db, who, `select ${table.pk.map(q).join(", ")} from ${q(table.name)}`);
        readA = read.rows.filter((r) => aKeys.has(keyOf(r))).length;
      }
      // Which private-looking columns of A's rows this role can actually read.
      const exposed = [];
      if (readA > 0) {
        for (const col of sensitive) {
          const probe = await as(db, who, `select ${q(col)} from ${q(table.name)} limit 1`);
          if (probe.ok) exposed.push(col);
        }
      }
      // Rows are found by ctid, or by primary key when hidden columns make ctid unreadable.
      const byKey = table.pk.map((c, i) => `${q(c)} = $${i + 1}`).join(" and ");
      const keyValues = table.pk.map((c) => target.row[c]);
      const tryBoth = async (sqlByCtid, sqlByKey) => {
        const first = await as(db, who, sqlByCtid, [target.ctid]);
        return !first.ok && /permission denied/.test(first.error) && table.pk.length ? as(db, who, sqlByKey, keyValues) : first;
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
        insert = await as(db, who, cols.length
          ? `insert into ${q(table.name)} (${cols.map(q).join(", ")}) values (${cols.map((c, i) => `$${i + 1}::${type(c)}`).join(", ")})`
          : `insert into ${q(table.name)} default values`, cols.map((c) => values[c]));
      }
      result[who] = {
        read: readA,
        readTotal: read.rows.length,
        exposed,
        update: update.affected > 0,
        delete: del.affected > 0,
        insert: insert.ok,
      };
    }
    results.push(result);
  }
  return results;
}

export async function probeViews(db, tables) {
  const out = [];
  for (const view of tables.filter((t) => t.kind === "v" || t.kind === "m")) {
    const anon = await as(db, "anon", `select count(*)::int as n from ${q(view.name)}`);
    out.push({ view: view.name, invoker: view.invoker, anonRows: anon.ok ? anon.rows[0].n : null, error: anon.ok ? null : anon.error });
  }
  return out;
}
