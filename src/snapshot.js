import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { PGlite } from "@electric-sql/pglite";
import { PREINSTALLED } from "./pglite.js";

// A fresh in-memory Postgres runs initdb, which takes two to three seconds. The
// probe starts instead from a copy of a database that already holds the shim:
// the one shipped with the package, or one built on the first run and kept in
// the user's cache. Its name changes with PGlite's version, the shim and the
// code that builds it, so a copy never outlives any of them. (Node only: the web
// page fetches the shipped copy.)
const SHIM = fs.readFileSync(new URL("./shim.sql", import.meta.url), "utf8");
const PGLITE = JSON.parse(fs.readFileSync(path.join(path.dirname(createRequire(import.meta.url).resolve("@electric-sql/pglite")), "..", "package.json"), "utf8")).version;
const RECIPE = crypto.createHash("sha256").update(SHIM).update(fs.readFileSync(new URL(import.meta.url))).update(fs.readFileSync(new URL("./pglite.js", import.meta.url))).digest("hex").slice(0, 12);
export const SNAPSHOT_NAME = `base-${PGLITE}-${RECIPE}.tar.gz`;
export const SHIPPED = new URL(`../snapshot/${SNAPSHOT_NAME}`, import.meta.url);
const CACHED = path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "rls-probe", SNAPSHOT_NAME);

let base;
// The base database as a tar of its data directory, built at most once per run.
export function baseSnapshot() {
  return (base ??= find());
}

async function find() {
  for (const file of [SHIPPED, CACHED]) {
    try {
      return zlib.gunzipSync(fs.readFileSync(file));
    } catch {
      // Missing or unreadable: try the next place, then build it.
    }
  }
  const raw = await buildSnapshot();
  try {
    fs.mkdirSync(path.dirname(CACHED), { recursive: true });
    const tmp = `${CACHED}.${process.pid}`;
    fs.writeFileSync(tmp, zlib.gzipSync(raw, { level: 1 }));
    fs.renameSync(tmp, CACHED);
  } catch {
    // A read-only home only costs the next run its head start.
  }
  return raw;
}

export async function buildSnapshot() {
  // A 1 MB write-ahead log and no template databases cut the copy from 40 MB to
  // 15, which starts about a fifth faster. Nothing the probe runs needs a template.
  const db = new PGlite({ initDbStartParams: ["--wal-segsize=1"], extensions: PREINSTALLED });
  await db.exec(SHIM);
  // DROP DATABASE refuses to run in a transaction, so one statement at a time.
  for (const sql of [
    "update pg_database set datistemplate = false where datname in ('template0', 'template1')",
    "drop database template0",
    "drop database template1",
    "checkpoint",
  ]) await db.exec(sql);
  const dump = await db.dumpDataDir("none");
  await db.close();
  return Buffer.from(await dump.arrayBuffer());
}
