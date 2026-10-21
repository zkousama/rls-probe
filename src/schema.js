const OWNER_NAME = /^(user|owner|author|creator|created_by|sender|requester|addressee|recipient|member|account|customer)(_id)?$|_user_id$/i;

// Reads what the probe needs from the catalog: tables, their columns, primary
// keys and foreign keys, for the public schema.
export async function readSchema(db) {
  const tables = (await db.query(`
    select c.oid, c.relname as name, c.relkind as kind, c.relrowsecurity as rls,
      coalesce((select bool_or(o = 'security_invoker=true' or o = 'security_invoker=on') from unnest(c.reloptions) o), false) as invoker
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
    order by c.relname`)).rows;

  const columns = (await db.query(`
    select a.attrelid as oid, a.attname as name, format_type(a.atttypid, a.atttypmod) as type,
      t.typtype, t.typcategory, a.attnotnull as notnull, a.atthasdef as hasdefault,
      a.attidentity as identity, a.attgenerated as generated, a.attnum as num,
      case when t.typtype = 'e' then (select array_agg(enumlabel order by enumsortorder) from pg_enum where enumtypid = t.oid) end as labels
    from pg_attribute a join pg_type t on t.oid = a.atttypid
    join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and a.attnum > 0 and not a.attisdropped
    order by a.attrelid, a.attnum`)).rows;

  const keys = (await db.query(`
    select con.conrelid as oid, con.contype as type, con.conkey as cols, con.confkey as refcols,
      rn.nspname as refschema, rc.relname as reftable
    from pg_constraint con
    join pg_class c on c.oid = con.conrelid join pg_namespace n on n.oid = c.relnamespace
    left join pg_class rc on rc.oid = con.confrelid left join pg_namespace rn on rn.oid = rc.relnamespace
    where n.nspname = 'public' and con.contype in ('p', 'f', 'u')`)).rows;

  const checks = (await db.query(`
    select con.conrelid as oid, con.conkey as cols, pg_get_constraintdef(con.oid) as def
    from pg_constraint con join pg_class c on c.oid = con.conrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and con.contype = 'c'`)).rows;

  const byOid = new Map();
  for (const t of tables) {
    byOid.set(t.oid, { name: t.name, kind: t.kind, rls: t.rls, invoker: t.invoker, columns: [], pk: [], fks: [], uniques: [], checks: {} });
  }
  for (const c of columns) byOid.get(c.oid)?.columns.push(c);
  for (const k of keys) {
    const t = byOid.get(k.oid);
    if (!t) continue;
    const names = k.cols.map((num) => t.columns.find((c) => c.num === num)?.name);
    if (k.type === "p") t.pk = names;
    else if (k.type === "u") t.uniques.push(names);
    else {
      // Multi-column foreign keys are rare in generated apps; the first pair is enough to follow ownership.
      t.fks.push({ column: names[0], refSchema: k.refschema, refTable: k.reftable, refColumnNum: k.refcols[0] });
    }
  }
  for (const c of checks) {
    const t = byOid.get(c.oid);
    if (!t || c.cols?.length !== 1) continue;
    const name = t.columns.find((col) => col.num === c.cols[0])?.name;
    if (name) t.checks[name] = c.def;
  }
  const result = [...byOid.values()];
  // Generated apps often store the user's id without a foreign key. A uuid
  // column with an owner-like name is treated as pointing at auth.users.
  for (const t of result) {
    for (const col of t.columns) {
      if (col.type !== "uuid" || t.fks.some((f) => f.column === col.name) || t.pk.includes(col.name)) continue;
      if (OWNER_NAME.test(col.name)) t.fks.push({ column: col.name, refSchema: "auth", refTable: "users", refColumn: "id", implicit: true });
    }
  }
  const byName = new Map(result.map((t) => [t.name, t]));
  for (const t of result) {
    for (const fk of t.fks) {
      if (fk.refSchema === "public") {
        const parent = byName.get(fk.refTable);
        fk.refColumn = parent?.columns.find((c) => c.num === fk.refColumnNum)?.name;
      } else if (fk.refSchema === "auth" && fk.refTable === "users") {
        fk.refColumn = "id";
      }
    }
  }
  return result;
}

export async function readFunctions(db) {
  return (await db.query(`
    select p.proname as name, pg_get_function_identity_arguments(p.oid) as args, p.prosecdef as definer,
      pg_get_functiondef(p.oid) as body,
      has_function_privilege('anon', p.oid, 'execute') as anon,
      has_function_privilege('authenticated', p.oid, 'execute') as authenticated,
      t.typname as returns
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_type t on t.oid = p.prorettype
    where n.nspname = 'public' and p.prokind = 'f'
    order by p.proname`)).rows;
}

export async function readPolicies(db) {
  return (await db.query(`
    select tablename as table, policyname as name, cmd, roles, qual, with_check as check
    from pg_policies where schemaname = 'public' order by tablename, policyname`)).rows;
}

export async function readBuckets(db) {
  return (await db.query(`select id, public from storage.buckets order by id`)).rows;
}
