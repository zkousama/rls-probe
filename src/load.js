import fs from "node:fs";
import path from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { citext } from "@electric-sql/pglite/contrib/citext";
import { hstore } from "@electric-sql/pglite/contrib/hstore";
import { ltree } from "@electric-sql/pglite/contrib/ltree";
import { moddatetime } from "@electric-sql/pglite/contrib/moddatetime";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { unaccent } from "@electric-sql/pglite/contrib/unaccent";
import { uuid_ossp } from "@electric-sql/pglite/contrib/uuid_ossp";
import { splitStatements } from "./split.js";

const SHIM = fs.readFileSync(new URL("./shim.sql", import.meta.url), "utf8");
const AVAILABLE = new Set(["citext", "hstore", "ltree", "moddatetime", "pg_trgm", "pgcrypto", "unaccent", "uuid-ossp", "plpgsql"]);

// Statements that only matter to a hosted Supabase project. They are skipped on
// purpose and listed in the report, so nothing is dropped silently.
const SKIP = [
  [/^create\s+extension\s+(if\s+not\s+exists\s+)?"?([\w-]+)"?/i, (m) => (AVAILABLE.has(m[2].toLowerCase()) ? null : `extension ${m[2]} isn't available offline`)],
  [/^(alter|create|drop)\s+publication\b/i, () => "realtime publication"],
  [/^comment\s+on\b/i, () => "comment"],
  [/^alter\s+(table|function|view|schema|type|sequence)\s+.+\s+owner\s+to\s+/is, () => "ownership change"],
  [/^select\s+(cron|net|vault)\./i, () => "scheduled job or vault call"],
];

// Types the in-memory Postgres can't create. Columns of these types hold
// embeddings and the like, which play no part in who can read a row.
const REWRITE = [
  [/\b(extensions\.)?(vector|halfvec|sparsevec)\s*\(\s*\d+\s*\)/gi, "text"],
  [/\bgeography\s*\([^)]*\)|\bgeometry\s*\([^)]*\)/gi, "text"],
];

export function findMigrations(target) {
  const candidates = [path.join(target, "supabase", "migrations"), path.join(target, "migrations"), target];
  for (const dir of candidates) {
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
      const files = fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
      if (files.length) return files.map((f) => path.join(dir, f));
    }
  }
  return [];
}

export async function loadDatabase(files) {
  const db = new PGlite({ extensions: { citext, hstore, ltree, moddatetime, pg_trgm, pgcrypto, unaccent, uuid_ossp } });
  await db.exec(SHIM);
  const skipped = [];
  const failed = [];
  let applied = 0;
  for (const file of files) {
    const name = path.basename(file);
    for (let statement of splitStatements(fs.readFileSync(file, "utf8"))) {
      const reason = skipReason(statement);
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
  }
  return { db, applied, skipped, failed };
}

function skipReason(statement) {
  const body = statement.replace(/^(\s*--[^\n]*\n)+/, "").trim();
  for (const [pattern, why] of SKIP) {
    const m = pattern.exec(body);
    if (m) {
      const reason = why(m);
      if (reason) return reason;
    }
  }
  return null;
}

function preview(statement) {
  const line = statement.replace(/\s+/g, " ").trim();
  return line.length > 140 ? `${line.slice(0, 137)}...` : line;
}
