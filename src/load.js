import { PGlite } from "@electric-sql/pglite";
import { LEGACY_GRANTS } from "./legacy-grants.js";
import { CONTRIB, PREINSTALLED, START_PARAMS } from "./pglite.js";
import { splitStatements } from "./split.js";

const CREATE_EXTENSION = /^create\s+extension\s+(if\s+not\s+exists\s+)?"?([\w-]+)"?/i;
const BUILT_IN = new Set(["plpgsql", "pgcrypto", "uuid-ossp"]);

// Statements that only matter to a hosted Supabase project. They are skipped on
// purpose and listed in the report, so nothing is dropped silently.
const SKIP = [
  [CREATE_EXTENSION, (m, available) => (BUILT_IN.has(m[2].toLowerCase()) || available[m[2].toLowerCase()] ? null : `extension ${m[2]} isn't available offline`)],
  [/^(alter|create|drop)\s+publication\b/i, () => "realtime publication"],
  // Statements run one by one, so a failure stays a failure of that statement.
  // Inside an explicit transaction, it would roll back everything around it.
  [/^(begin|start\s+transaction|commit|end|rollback|abort|savepoint|release)\b(?!\s+atomic)[\w\s]*$/i, () => "transaction control"],
  [/^create\s+(unique\s+)?index\b[\s\S]*\busing\s+(hnsw|ivfflat)\b/i, () => "vector index"],
  [/^comment\s+on\b/i, () => "comment"],
  [/^alter\s+(table|function|view|schema|type|sequence)\s+.+\s+owner\s+to\s+/is, () => "ownership change"],
  [/^select\s+(cron|net|vault)\./i, () => "scheduled job or vault call"],
];

// Types the in-memory Postgres can't create. Columns of these types hold
// embeddings and the like, which play no part in who can read a row.
const REWRITE = [
  [/(?:"?extensions"?\.)?"?\b(vector|halfvec|sparsevec)\b"?\s*\(\s*\d+\s*\)/gi, "text"],
  [/\bgeography\s*\([^)]*\)|\bgeometry\s*\([^)]*\)/gi, "text"],
];

// migrations: [{ name, sql }] in the order they run. snapshot: the base database
// to start from (see snapshot.js). grants: "legacy" gives anon, authenticated and
// service_role every table, as Supabase did by default; "explicit" gives them
// only what the migrations grant. from: a saved copy of a database these steps
// already built ({ dataDir, extensions }), to run more migrations on.
export async function loadDatabase(migrations, { grants = "legacy", snapshot, from }) {
  const statements = migrations.map((m) => ({ file: m.name, statements: splitStatements(m.sql) }));
  // Each extension PGlite loads slows its start, so beyond the ones every Supabase
  // project has, it loads only those the migrations create.
  const wanted = new Set([...(from?.extensions ?? []), ...statements.flatMap((f) => f.statements).map((s) => CREATE_EXTENSION.exec(withoutComments(s))?.[2].toLowerCase()).filter(Boolean)]);
  const available = await loadable(wanted);
  const start = from?.dataDir ?? snapshot;
  const db = new PGlite({
    loadDataDir: start instanceof Blob ? start : new Blob([start]),
    extensions: { ...PREINSTALLED, ...available },
    startParams: START_PARAMS,
  });
  // A saved copy has its grants already, and the app's revokes on top of them.
  if (grants === "legacy" && !from) await db.exec(LEGACY_GRANTS);
  const skipped = [];
  const failed = [];
  let applied = 0;
  for (const { file: name, statements: list } of statements) {
    for (let statement of list) {
      const reason = skipReason(statement, available);
      if (reason) {
        skipped.push({ file: name, reason, statement: preview(statement) });
        continue;
      }
      for (const [pattern, replacement] of REWRITE) statement = statement.replace(pattern, replacement);
      try {
        await db.exec(statement);
        applied++;
      } catch (error) {
        failed.push({ file: name, error: error.message, statement: preview(statement) });
      }
    }
    // Supabase runs each file in its own session. Settings a file changes, like the
    // empty search_path or "row_security = off" at the top of a pg_dump, end with it.
    await db.exec("reset all").catch(() => {});
  }
  // Tables the migrations use but never create, often made in the dashboard before
  // migrations were kept. They can't be checked, and the report says so.
  const exists = new Set((await db.query(`select relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public'`)).rows.map((r) => r.relname));
  const missing = [...new Set(failed.map((f) => /relation "(?:public\.)?([^".]+)" does not exist/.exec(f.error)?.[1]).filter((t) => t && !exists.has(t)))].sort();
  return { db, applied, skipped, failed, missing, extensions: [...wanted] };
}

// The PGlite modules for the extensions named, by their `create extension` name,
// leaving out the ones PGlite doesn't ship.
async function loadable(names) {
  const out = {};
  for (const name of names) {
    if (BUILT_IN.has(name)) continue;
    const module = name.replace(/-/g, "_");
    // Not shipped with PGlite: the statement is skipped and listed.
    if (!CONTRIB[module]) continue;
    out[name] = (await CONTRIB[module]())[module];
  }
  return out;
}

function withoutComments(statement) {
  return statement.replace(/^(\s*--[^\n]*\n)+/, "").trim();
}

function skipReason(statement, available) {
  const body = withoutComments(statement);
  for (const [pattern, why] of SKIP) {
    const m = pattern.exec(body);
    if (m) {
      const reason = why(m, available);
      if (reason) return reason;
    }
  }
  return null;
}

function preview(statement) {
  const line = statement.replace(/\s+/g, " ").trim();
  return line.length > 140 ? `${line.slice(0, 137)}...` : line;
}
