// Gives each of two users, A and B, their own row in every table, so the probe
// can ask whether B (or a visitor who isn't signed in) can reach A's rows. C is
// a third user who only appears as the other side of a row (the friend in a
// friendship, the recipient of a message), so B is never a party to A's rows.
export const USERS = {
  A: { id: "00000000-0000-4000-8000-00000000000a", email: "alice@example.com" },
  B: { id: "00000000-0000-4000-8000-00000000000b", email: "bob@example.com" },
  C: { id: "00000000-0000-4000-8000-00000000000c", email: "carol@example.com" },
};

export async function seed(db, tables) {
  for (const [key, user] of Object.entries(USERS)) {
    await db.query(
      `insert into auth.users (id, email, aud, role, raw_user_meta_data, raw_app_meta_data, email_confirmed_at)
       values ($1, $2, 'authenticated', 'authenticated', $3, '{"provider":"email"}', now())`,
      [user.id, user.email, JSON.stringify({ full_name: `User ${key}`, name: `User ${key}`, username: `user_${key.toLowerCase()}` })],
    );
  }
  const real = tables.filter((t) => t.kind === "r" || t.kind === "p");
  const known = new Map(real.map((t) => [t.name, []]));
  const problems = [];
  let counter = 0;

  for (const table of order(real)) {
    const existing = (await db.query(`select * from ${q(table.name)}`)).rows;
    for (const row of existing) known.get(table.name).push({ row, owner: ownerOf(table, row, known) });
    const owners = new Set(known.get(table.name).map((r) => r.owner));
    const wanted = ownerPath(table, real) ? ["A", "B"] : ["shared", "shared"];
    for (const owner of wanted) {
      if (owner !== "shared" && owners.has(owner)) continue;
      if (owner === "shared" && known.get(table.name).length >= 2) break;
      const values = rowFor(table, owner, known, ++counter);
      if (!values) {
        problems.push({ table: table.name, error: "no parent row to point a required foreign key at" });
        break;
      }
      try {
        const cols = Object.keys(values);
        const res = await db.query(
          cols.length
            ? `insert into ${q(table.name)} (${cols.map(q).join(", ")}) values (${cols.map((c, i) => `$${i + 1}::${typeOf(table, c)}`).join(", ")}) returning *`
            : `insert into ${q(table.name)} default values returning *`,
          cols.map((c) => values[c]),
        );
        known.get(table.name).push({ row: res.rows[0], owner: owner === "shared" ? ownerOf(table, res.rows[0], known) : owner });
      } catch (error) {
        problems.push({ table: table.name, error: error.message });
        break;
      }
    }
  }
  return { known, problems };
}

// A table belongs to users if a chain of foreign keys leads to auth.users.
export function ownerPath(table, tables, seen = new Set()) {
  if (seen.has(table.name)) return false;
  seen.add(table.name);
  return table.fks.some((fk) => {
    if (fk.refSchema === "auth" && fk.refTable === "users") return true;
    const parent = tables.find((t) => t.name === fk.refTable && fk.refSchema === "public");
    return parent ? ownerPath(parent, tables, seen) : false;
  });
}

export function ownerOf(table, row, known) {
  for (const fk of table.fks) {
    const value = row[fk.column];
    if (value == null) continue;
    if (fk.refSchema === "auth" && fk.refTable === "users") {
      for (const [key, user] of Object.entries(USERS)) if (value === user.id) return key;
    } else if (fk.refSchema === "public" && fk.refTable !== table.name) {
      const parent = known.get(fk.refTable)?.find((r) => String(r.row[fk.refColumn]) === String(value));
      if (parent && parent.owner !== "shared") return parent.owner;
    }
  }
  return "shared";
}

export function rowFor(table, owner, known, n) {
  const values = {};
  let userColumns = 0;
  const parentUses = {};
  for (const col of table.columns) {
    if (col.generated === "s" || col.identity === "a") continue;
    const fk = table.fks.find((f) => f.column === col.name);
    if (fk) {
      if (fk.refSchema === "auth" && fk.refTable === "users") {
        // The first user column is the owner; any other (a friend, a recipient) is C,
        // which also satisfies rules like "you can't befriend yourself".
        if (userColumns++ === 0) values[col.name] = (USERS[owner] ?? USERS.A).id;
        else values[col.name] = USERS.C.id;
        continue;
      }
      if (fk.refSchema === "public" && fk.refTable !== table.name) {
        const rows = known.get(fk.refTable) ?? [];
        // A second pointer to the same table (reviewer and reviewee) gets C's row, as with user columns.
        const repeat = (parentUses[fk.refTable] = (parentUses[fk.refTable] ?? 0) + 1) > 1;
        const pick = (repeat ? rows.find((r) => r.owner === "C") : undefined)
          ?? rows.find((r) => r.owner === owner) ?? rows.find((r) => r.owner === "shared") ?? rows[0];
        if (pick) values[col.name] = pick.row[fk.refColumn];
        else if (col.notnull && !col.hasdefault) return null;
        continue;
      }
      if (!col.notnull) continue;
    }
    // Visibility-like columns are set even when they have a default, so seeded rows are private ones.
    const privacy = col.labels?.length && /visib|privacy|audience|access|scope/.test(col.name.toLowerCase());
    if (!privacy && (col.hasdefault || !col.notnull)) continue;
    values[col.name] = sample(col, n, table.checks?.[col.name]);
  }
  return values;
}

const LOW_ROLES = /^(user|member|viewer|player|customer|student|guest|basic|reader|client|participant)$/i;

function sample(col, n, check) {
  const type = col.type.toLowerCase();
  const name = col.name.toLowerCase();
  if (col.labels?.length) {
    // Seeding everyone as "admin" would hide every rule that admins bypass.
    if (/role/.test(name)) return col.labels.find((l) => LOW_ROLES.test(l)) ?? col.labels.at(-1);
    // Private rows are the ones worth testing: a public game is meant to be seen.
    if (/visib|privacy|audience|access|scope/.test(name)) return col.labels.find((l) => !/public|open|everyone|all/i.test(l)) ?? col.labels[0];
    return col.labels[0];
  }
  if (check) {
    const allowed = /'([^']*)'/.exec(check);
    if (allowed) return allowed[1];
    const between = /between\s+\(?(-?[\d.]+)/i.exec(check) ?? />=\s*\(?(-?[\d.]+)/.exec(check);
    if (between) return Number(between[1]);
    const above = />\s*\(?(-?[\d.]+)/.exec(check);
    if (above) return Number(above[1]) + 1;
  }
  if (col.typcategory === "A") return "{}";
  if (type === "uuid") return crypto.randomUUID();
  if (/^(smallint|integer|bigint|int|serial)/.test(type)) return n;
  if (/^(numeric|real|double|decimal|money)/.test(type)) return n;
  if (type === "boolean") return false;
  if (/^(json|jsonb)/.test(type)) return "{}";
  if (/^time(\(\d\))? with/.test(type) || type === "time") return "12:00:00";
  // A year ahead passes rules like "a game can't be in the past".
  if (type === "date") return new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10);
  if (/^timestamp/.test(type)) return new Date(Date.now() + 365 * 864e5).toISOString();
  if (type === "interval") return "1 day";
  if (type === "inet" || type === "cidr") return "127.0.0.1";
  if (type === "bytea") return "\\x00";
  if (name.includes("email")) return `seed${n}@example.com`;
  if (name.includes("url") || name.includes("link") || name.includes("website")) return `https://example.com/${n}`;
  if (name.includes("phone")) return `+21260000${String(n).padStart(4, "0")}`;
  if (name.includes("slug") || name.includes("username")) return `seed-${n}`;
  return `${col.name} ${n}`;
}

function typeOf(table, column) {
  return table.columns.find((c) => c.name === column).type;
}

// Parents before children, so required foreign keys have something to point at.
function order(tables) {
  const done = new Set();
  const out = [];
  const visit = (t, stack = new Set()) => {
    if (done.has(t.name) || stack.has(t.name)) return;
    stack.add(t.name);
    for (const fk of t.fks) {
      if (fk.refSchema !== "public" || fk.refTable === t.name) continue;
      const parent = tables.find((p) => p.name === fk.refTable);
      if (parent) visit(parent, stack);
    }
    done.add(t.name);
    out.push(t);
  };
  for (const t of tables) visit(t);
  return out;
}

export function q(identifier) {
  return `"${identifier.replace(/"/g, '""')}"`;
}
